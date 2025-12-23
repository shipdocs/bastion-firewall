# Bastion Firewall – Implementation Plan (Zorin 18, eBPF-Only)

## 1. Goals & Constraints

- **Target OS**: Zorin 18 (Ubuntu 24.04 base) only.
- **Modes**:
  - **Learning**: never block by default; observe, prompt, and build rules.
  - **Enforcement**: same logic, but unknown traffic is blocked.
- **App Identification**: mandatory **eBPF/BCC** (no silent fallbacks). If not available, install/start must fail cleanly and leave networking unchanged.
- **Backend Direction**: move away from NFQUEUE; use an **eBPF `cgroup/connect`-based firewall** as the main enforcement mechanism.
- **UX Goal**: minimal popups via Zorin-aware defaults + learning, while still giving meaningful control.

### 1.1 Known Trade-off: Enforcement Mode Requires App Retry

In enforcement mode, when a connection has no matching rule:
1. BPF program blocks the `connect()` call immediately (returns 0).
2. App sees `EPERM` or similar error.
3. Daemon prompts user via GUI.
4. User allows → rule written to BPF map and disk.
5. **App must retry the connection** for it to succeed.

This is an inherent limitation of cgroup/connect enforcement (unlike NFQUEUE which can "hold" packets). Accepted as reasonable trade-off for cleaner architecture.

---

## 2. Phase 0 – Codebase Cleanup

**Goal:** Remove legacy code before implementing the new backend.

### 2.1 Code to Remove

| File/Component | What | Why |
|----------------|------|-----|
| `bastion/firewall_core.py` → `IPTablesManager` | NFQUEUE iptables rule management | Replaced by cgroup/connect |
| `bastion/firewall_core.py` → `PacketProcessor` | NFQUEUE packet handling | Replaced by BPF events |
| `bastion/daemon.py` → `NetfilterQueue` usage | NFQUEUE binding | No longer needed |
| `bastion/firewall_core.py` → psutil fallback in `ApplicationIdentifier` | Unreliable PID guessing | eBPF mandatory |
| Any `/proc/net/tcp` parsing | Socket→PID mapping | eBPF provides this |

### 2.2 Interfaces to Keep

| Component | Purpose |
|-----------|---------|
| `RulesManager` | Disk-based rule storage (adapt for new rule format) |
| `AppResolver` | Path→app metadata (keep, may simplify) |
| GUI IPC protocol | Keep socket-based daemon↔GUI communication |
| `ConnectInfo` | Rename/adapt from `PacketInfo` for connection events |

### 2.3 New Modules to Create

| Module | Purpose |
|--------|---------|
| `bastion/ebpf_backend.py` | BPF program loading, map management, event loop |
| `bastion/bpf/connect_filter.c` | The actual BPF C program |
| `bastion/profiles/zorin18.py` | Zorin 18 default app rules |

---

## 3. Phase 1 – Mandatory eBPF & Clean Failure

**Goal:** Bastion runs only on systems that properly support eBPF/BCC. Otherwise, installation or startup fails without touching firewall state.

### 3.1 Packaging (Deb for Zorin 18)

- Add hard package `Depends` on:
  - `python3-bcc` (and any other BCC bindings/tools needed).
  - Additional kernel tools if required by the eBPF code.
- Implement a `postinst` check that:
  - Runs a small Python script that imports `bcc`, loads a tiny test BPF program, then detaches.
  - On failure: prints a clear message and aborts install (non-zero exit), so no partially configured service or rules are left.

### 3.2 Daemon Startup Checks

- In `bastion-daemon.py` / `DouaneDaemon`:
  - Initialize the new eBPF backend **before** any firewall manipulation.
  - If backend init fails:
    - Log a fatal error ("eBPF/BCC not available; Bastion cannot run").
    - Exit non-zero.
    - Do **not** touch iptables/nftables.

### 3.3 Remove Legacy Fallbacks

- Remove psutil + `/proc` based PID guessing as the normal path.
- If kept at all, gate it with a **debug-only** config flag (off by default) and document it as unsupported for end users.

---

## 4. Phase 2 – eBPF `cgroup/connect` Backend Implementation

**Goal:** Replace NFQUEUE with an eBPF backend that enforces policy at `connect()` instead of per-packet.

### 4.1 Cgroup Attachment Strategy

**Target cgroup:** `/sys/fs/cgroup` (root cgroup v2)

On Zorin 18 (Ubuntu 24.04), systemd uses cgroup v2 unified hierarchy. Attaching to the root cgroup covers all processes system-wide.

```python
# Attach to root cgroup
cgroup_fd = os.open("/sys/fs/cgroup", os.O_RDONLY)
b.attach_func(fn, cgroup_fd, BPFAttachType.CGROUP_INET4_CONNECT)
b.attach_func(fn6, cgroup_fd, BPFAttachType.CGROUP_INET6_CONNECT)
```

### 4.2 BPF Program Design (`bastion/bpf/connect_filter.c`)

**Attach types:**
- `SEC("cgroup/connect4")` → `BPF_CGROUP_INET4_CONNECT`
- `SEC("cgroup/connect6")` → `BPF_CGROUP_INET6_CONNECT`
- `SEC("cgroup/sendmsg4")` → `BPF_CGROUP_UDP4_SENDMSG` (for UDP)
- `SEC("cgroup/sendmsg6")` → `BPF_CGROUP_UDP6_SENDMSG` (for UDP)

**Context available (`struct bpf_sock_addr`):**
- `user_ip4` / `user_ip6` – destination IP
- `user_port` – destination port (network byte order)
- `family`, `type`, `protocol` – socket info

**Helper functions used:**
- `bpf_get_current_pid_tgid()` → PID/TGID
- `bpf_get_current_uid_gid()` → UID/GID
- `bpf_get_current_comm()` → 16-byte process name
- `bpf_ringbuf_output()` → send events to userspace

**Return values:**
- `return 1;` → allow connection
- `return 0;` → block connection (app sees EPERM)

### 4.3 BPF Map Schemas

```c
// Map 1: Global config (mode flag)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct config {
    u8 mode;           // 0 = learning (allow all), 1 = enforcement
    u8 _reserved[7];
};

// Map 2: PID → app_id mapping (populated by execve hook or userspace)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);           // PID
    __type(value, u64);         // app_id (hash of exe path)
} pid_to_app SEC(".maps");

// Map 3: Rules (app_id + dest → action)
struct rule_key {
    u64 app_id;         // 0 = wildcard (any app)
    u32 dest_ip;        // 0 = wildcard (any IP)
    u16 dest_port;      // 0 = wildcard (any port)
    u8  protocol;       // IPPROTO_TCP, IPPROTO_UDP, or 0 = any
    u8  _pad;
};

struct rule_value {
    u8 action;          // 0 = deny, 1 = allow
    u8 _reserved[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} rules SEC(".maps");

// Map 4: Ring buffer for events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} events SEC(".maps");
```

### 4.4 Executable Path Resolution

**Problem:** BPF context doesn't provide the full exe path, only `comm` (16-byte truncated name).

**Solution:** Hybrid approach:
1. **Separate eBPF program hooks `sched_process_exec`** (tracepoint) to capture PID→exe path mappings.
2. Populate `pid_to_app` map with `app_id = hash(exe_path)`.
3. On `connect()`, BPF looks up `pid_to_app[pid]` to get `app_id`.
4. If PID not in map (edge case), use `comm` as fallback key and emit event for userspace to resolve.

```c
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // Read exe path from ctx, hash it, store in pid_to_app
    ...
}
```

### 4.5 Connect Hook Logic (Pseudocode)

```c
SEC("cgroup/connect4")
int bastion_connect4(struct bpf_sock_addr *ctx) {
    // 1. Get config
    u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &zero);

    // 2. Get process info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // 3. Lookup app_id
    u64 *app_id_ptr = bpf_map_lookup_elem(&pid_to_app, &pid);
    u64 app_id = app_id_ptr ? *app_id_ptr : 0;

    // 4. Build rule key and lookup (try exact match, then wildcards)
    struct rule_key key = {
        .app_id = app_id,
        .dest_ip = ctx->user_ip4,
        .dest_port = ctx->user_port,
        .protocol = ctx->protocol,
    };
    struct rule_value *rule = bpf_map_lookup_elem(&rules, &key);

    // Try wildcard lookups if no exact match...
    // (port=0, ip=0, app_id=0 combinations)

    // 5. Decision
    if (rule) {
        return rule->action;  // 0=block, 1=allow
    }

    // 6. No rule found
    // Emit event to userspace
    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = pid;
        e->app_id = app_id;
        e->dest_ip = ctx->user_ip4;
        e->dest_port = ctx->user_port;
        e->protocol = ctx->protocol;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    // Learning mode = allow, Enforcement mode = block
    return cfg && cfg->mode == 0 ? 1 : 0;
}
```

### 4.6 User-Space Backend (`bastion/ebpf_backend.py`)

```python
class EBPFBackend:
    def __init__(self, mode: str = "learning"):
        self.mode = mode
        self.bpf = None
        self.cgroup_fd = None

    def start(self):
        """Load BPF program, attach to cgroup, start event loop."""
        self.bpf = BPF(src_file="bastion/bpf/connect_filter.c")
        self.cgroup_fd = os.open("/sys/fs/cgroup", os.O_RDONLY)

        # Attach programs
        fn = self.bpf.load_func("bastion_connect4", BPF.CGROUP_SOCK_ADDR)
        self.bpf.attach_func(fn, self.cgroup_fd, BPFAttachType.CGROUP_INET4_CONNECT)
        # ... attach connect6, sendmsg4, sendmsg6 similarly

        # Set mode in config map
        self._set_mode(self.mode)

        # Start event consumer thread
        self._start_event_loop()

    def add_rule(self, app_id: int, dest_ip: int, dest_port: int,
                 protocol: int, action: bool):
        """Add/update a rule in the BPF map."""
        key = self.bpf["rules"].Key(app_id, dest_ip, dest_port, protocol, 0)
        val = self.bpf["rules"].Leaf(1 if action else 0, bytes(7))
        self.bpf["rules"][key] = val

    def set_mode(self, mode: str):
        """Switch between learning and enforcement."""
        self._set_mode(mode)

    def stop(self):
        """Detach programs, close cgroup fd."""
        # Cleanup...
```

---

## 5. Phase 3 – Learning vs Enforcement Semantics

**Goal:** Preserve current semantics (learning = do not block, enforcement = block unknown) on top of the eBPF backend.

### 5.1 Learning Mode

- eBPF `connect` programs always **allow** connections (config mode = 0).
- For connects without a rule:
  - Emit an event to user space via ring buffer.
  - Daemon may prompt the user (GUI) and create rules based on decisions.
- Network behavior matches stock Linux; Bastion quietly builds rules and optionally prompts.
- **This is the default mode on fresh install.**

### 5.2 Enforcement Mode

- eBPF programs enforce rules at `connect()` (config mode = 1):
  - If rule matches: allow or deny accordingly.
  - If no rule: **deny** and emit an "unknown blocked" event.
- Daemon:
  - Prompts the user when unknown attempts are blocked.
  - If user allows permanently, daemon writes a new rule to disk and to the BPF map.
  - The application must retry the connection; the next attempt is allowed.

### 5.3 Mode Switching

```python
def switch_mode(self, mode: str):
    """Switch between learning and enforcement."""
    if mode == "enforcement":
        # Warn user: "Unknown connections will be blocked. Apps may need to retry."
        self._set_config_mode(1)
    else:
        self._set_config_mode(0)
    self._save_mode_to_disk(mode)
```

---

## 6. Phase 4 – Zorin 18 Profile & Baseline Rules

**Goal:** Minimize prompts on Zorin 18 by pre-allowing a curated set of default applications and services.

### 6.1 Zorin 18 Profile Module (`bastion/profiles/zorin18.py`)

```python
ZORIN18_DEFAULTS = [
    # System
    {"path": "/usr/lib/apt/methods/https", "ports": [443], "proto": "tcp"},
    {"path": "/usr/lib/apt/methods/http", "ports": [80], "proto": "tcp"},
    {"path": "/usr/bin/snap", "ports": [443], "proto": "tcp"},
    {"path": "/usr/lib/snapd/snapd", "ports": [443], "proto": "tcp"},
    {"path": "/usr/lib/ubuntu-release-upgrader/*", "ports": [80, 443], "proto": "tcp"},
    {"path": "/usr/bin/gnome-software", "ports": [80, 443], "proto": "tcp"},

    # Networking
    {"path": "/usr/lib/systemd/systemd-resolved", "ports": [53], "proto": "udp"},
    {"path": "/usr/lib/systemd/systemd-timesyncd", "ports": [123], "proto": "udp"},
    {"path": "/usr/sbin/NetworkManager", "ports": [67, 68], "proto": "udp"},

    # Browsers (common)
    {"path": "/usr/bin/firefox", "ports": [80, 443], "proto": "tcp"},
    {"path": "/opt/google/chrome/chrome", "ports": [80, 443], "proto": "tcp"},
    {"path": "/usr/bin/chromium-browser", "ports": [80, 443], "proto": "tcp"},

    # ... more entries
]
```

### 6.2 First-Run Baseline Generation

- On first daemon run, or when rules DB is nearly empty:
  - Iterate `ZORIN18_DEFAULTS`.
  - For each entry where the binary exists on disk:
    - Compute `app_id = hash(path)`.
    - Create rules in on-disk DB and BPF map.
  - Mark `bootstrap_done = true` in config.
  - Log summary: "Created N baseline rules for Zorin 18 defaults."

### 6.3 GUI Support

- In the rules UI, show a "Zorin defaults" section:
  - List baseline rules that were auto-created.
  - Allow users to review, disable, or modify them.
  - Tag these rules with `source: "zorin-profile"` for easy identification.

---

## 7. Phase 5 – UX, Hardening & Rollback

**Goal:** Make the new backend practical for users, tighten security, and provide a safety net.

### 7.1 Mode Visibility & Control

- GUI always shows current mode (Learning / Enforcement) prominently.
- Show simple progress indicators:
  - Whether Zorin baseline rules are loaded.
  - Count of additional learned rules.
- Provide a single toggle for switching to enforcement with a short explanation dialog.

### 7.2 Prompt Quality of Life

- Group similar events by `(app, dest_ip, dest_port)` to reduce repeated prompts.
- Offer "temporary allow for X minutes" (rules with TTL) in learning mode.
- In enforcement, clearly label prompts as **blocked attempts** that require user decision and a retry by the app.

### 7.3 Emergency Rollback / Panic Button

**Problem:** If enforcement mode breaks networking, user needs an escape hatch.

**Solution:**

1. **CLI panic command** (works without network):
   ```bash
   sudo bastion-ctl panic
   # Immediately switches to learning mode
   # Equivalent to: echo 0 > /sys/fs/bpf/bastion/config_mode
   ```

2. **Systemd watchdog** (optional):
   - If daemon crashes or is killed, BPF programs remain attached.
   - On daemon restart, check if previous shutdown was clean.
   - If unclean, auto-switch to learning mode and warn user.

3. **Desktop notification** on mode switch to enforcement:
   - "Bastion is now in enforcement mode. If you lose network access, run: `sudo bastion-ctl panic`"

### 7.4 File & Socket Security

- Move the daemon Unix socket to `/run/bastion/bastion-daemon.sock`:
  - Use systemd `RuntimeDirectory=bastion` with `0750 root:bastion`.
- Ensure logs and rule/config files are restricted (e.g. `0640 root:bastion`).
- Keep existing protections for config/rules (symlink checks, atomic writes).

---

## 8. Phase 6 – Testing & Validation

**Goal:** Avoid regressions in critical behavior while keeping the test suite lightweight.

### 8.1 Unit Tests (`pytest`)

- Mode semantics (learning vs enforcement) at the backend abstraction level.
- Zorin baseline generation (given a mock filesystem of installed apps).
- Rule load/save behavior, including permission and symlink checks.
- `app_id` hashing consistency.

### 8.2 Integration Self-Test

Add `bastion-ctl self-test` command that:
1. Loads the eBPF programs.
2. Attaches to a test cgroup (not root).
3. Creates a test rule.
4. Spawns a subprocess that attempts a connection.
5. Verifies the rule was hit (via event or map counter).
6. Reports clear success/failure.

### 8.3 Manual Test Checklist

- [ ] Fresh install on Zorin 18 VM
- [ ] Baseline rules created for installed defaults
- [ ] Learning mode: connections allowed, events logged
- [ ] Create rule via GUI prompt
- [ ] Switch to enforcement mode
- [ ] Unknown connection blocked, retry after allow works
- [ ] Panic command restores network access
- [ ] Daemon restart preserves rules

