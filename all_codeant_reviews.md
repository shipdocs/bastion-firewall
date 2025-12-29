--- COMMENT ---
CodeAnt AI is reviewing your PR.

---

### Thanks for using CodeAnt! 🎉

We're free for open-source projects. if you're enjoying it, help us grow by sharing.

[Share on X](https://twitter.com/intent/tweet?text=Just%20tried%20%40CodeAntAI%20for%20automated%20code%20review%20and%20I%27m%20impressed%21%20Free%20for%20open%20source%20with%20a%20free%20trial%20for%20private%20repos.%20Worth%20checking%20out%3A&url=https%3A//codeant.ai) ·
[Reddit](https://www.reddit.com/submit?title=Check%20out%20CodeAnt%20for%20automated%20code%20review&text=Just%20tried%20CodeAnt%20for%20automated%20code%20review%20and%20I%27m%20impressed%21%20Free%20for%20open%20source%20with%20a%20free%20trial%20for%20private%20repos.%20Worth%20checking%20out%3A%20https%3A//codeant.ai) ·
[LinkedIn](https://www.linkedin.com/sharing/share-offsite/?url=https%3A%2F%2Fcodeant.ai&mini=true&title=Check%20out%20CodeAnt%20for%20automated%20code%20review&summary=Just%20tried%20CodeAnt%20for%20automated%20code%20review%20and%20I%27m%20impressed%21%20Free%20for%20open%20source%20with%20a%20free%20trial%20for%20private%20repos)

--- COMMENT ---
## Nitpicks 🔍

<table>
<tr><td>🔒&nbsp;<strong>No security issues identified</strong></td></tr>
<tr><td>⚡&nbsp;<strong>Recommended areas for review</strong><br><br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-abdc9834062723adc38853e0643790eedfc75342782c0bd3e7f9e156fecbc0e2R9-R24'><strong>sys.path manipulation</strong></a><br>The script mutates `sys.path` with global system paths (e.g. `/usr/share/bastion-firewall`, `/usr/local/lib/.../dist-packages`, `/usr/lib/python3/dist-packages`) and inserts the script directory at index 0. This affects import resolution order and can be abused if any of those paths are writable by untrusted users. Validate paths and prefer controlled loading mechanisms or restrict to trusted directories.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-abdc9834062723adc38853e0643790eedfc75342782c0bd3e7f9e156fecbc0e2R33-R53'><strong>FileHandler override correctness</strong></a><br>`PermissionFileHandler._open` calls `super()._open()` but does not return the opened file object and swallows many exceptions. Also it attempts `os.chown`/`grp.getgrnam` unconditionally; calling chown when not root will raise (caught, but silently). This might break logging initialization or hide real failures. Ensure the override follows `logging.FileHandler._open` contract (return stream) and restrict chown to when running as root.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-abdc9834062723adc38853e0643790eedfc75342782c0bd3e7f9e156fecbc0e2R27-R62'><strong>Privileged file setup</strong></a><br>The script creates and secures /var/log/bastion-daemon.log (mkdir + handler that chowns/chmods) before calling `require_root()` in `main()`. This can cause permission errors for non-root runs, or create a window where an attacker could influence file creation/ownership if the process runs without expected privileges. Consider deferring privileged filesystem operations until after a root check or fall back to a safe user-writable location when not root.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-794e65e0ee6053d90c158cf942f93caee8a9fb1473830f1ccd660cf865c90828R76-R85'><strong>Incomplete iptables cleanup</strong></a><br>The cleanup only targets a single NFQUEUE rule (`--queue-num 1`) and only the `OUTPUT` chain (IPv4 iptables). If the daemon used other queue numbers, other chains, or if the system used nftables/ip6tables, leftover rules may persist and continue affecting packet flow. Consider a more generic removal approach that searches for rules by comment/target or removes matching lines across IPv4/IPv6/nftables.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-f5c88428df02a75793d2429f5f9b8cb893cade30f44b37f82608a050b01448a9R57-R67'><strong>Potential info exposure</strong></a><br>GUI stdout/stderr is redirected to `/tmp/bastion-gui-$session_user.log`, a world-writable directory which may allow other users to read sensitive information. Logs should be sent to the journal or to a protected per-user location with appropriate ownership/permissions.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-8155b3e9f214baacbf16aadb39c6bbc9a913e8ef313ff1f48849fd9018ce4c34R424-R429'><strong>Insecure socket permissions</strong></a><br>The Unix socket at `SOCKET_PATH` is made world-writable/readable (`0o666`). Any local user can connect and potentially send forged GUI responses, causing unauthorized allow/block decisions or rule changes.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-03259569799f86b64ca1183f13eb7e316a579c0ba1bc8a28f79b3484b607061dR31-R36'><strong>Risky global policy fallback</strong></a><br>If NFQUEUE rules persist, the script falls back to flushing OUTPUT and setting policy ACCEPT. This could temporarily open the host to traffic if executed in a different context than intended; it should be a last-resort action with minimal blast radius and explicit logging/guarding.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-03259569799f86b64ca1183f13eb7e316a579c0ba1bc8a28f79b3484b607061dR11-R14'><strong>Aggressive process killing</strong></a><br>The script uses multiple unconditional `pkill -9 -f <pattern>` invocations which can kill unrelated processes that match the pattern and does so without attempting graceful shutdown first. This is risky on systems where process names overlap or when systemd-managed services are present. Consider a staged termination (SIGTERM, wait, then SIGKILL) or using `systemctl`/`pgrep` to limit scope.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-4c7599eee277596ba6fcfe58891e36682de025d205bf06cc30c04a69193d01d9R87-R98'><strong>Symlink TOCTOU</strong></a><br>The code checks whether the socket path is a symlink using `symlink_metadata` then calls `remove_file`. This is susceptible to a time-of-check/time-of-use (TOCTOU) race: an attacker could replace the file between the metadata check and the removal, potentially allowing deletion of an arbitrary target or enabling symlink attacks. Use an unlink operation that refuses to follow symlinks (e.g. unlinkat with AT_SYMLINK_NOFOLLOW) or create/bind to a temporary path and atomically rename.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-6ef817fa21be7006cbf746ace6de4a67b9e7133d44e799445e2731dfa4ef26a0R119-R130'><strong>TOCTOU / Existence Check</strong></a><br>The code calls `path.exists()` before opening the file. This creates a TOCTOU window and negates some of the security benefits of opening with `O_NOFOLLOW`. Prefer attempting to open the file and handle NotFound errors instead of a separate exists() check.<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-937a7f41c555573f431cef9c8d0a21808ffd5eab76a727af3fa167760b4eeb9cR86-R89'><strong>DNS auto-allow policy</strong></a><br>The code currently auto-allows any connection where `dest_port == 53` (DNS) regardless of the calling binary. This conflicts with the comment that "essential ports and localhost are only auto-allowed for trusted binaries" and may let untrusted/malicious processes perform DNS-based exfiltration or reach remote resolvers unrestricted. Consider restricting DNS to trusted binaries or localhost only, or add stricter checks (e.g., allow only system resolvers or require the app to be trusted).<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-937a7f41c555573f431cef9c8d0a21808ffd5eab76a727af3fa167760b4eeb9cR18-R41'><strong>Path-matching / canonicalization</strong></a><br>`SYSTEM_PATHS.contains(app_path)` requires an exact string match. Real-world `app_path` may be a symlink, contain different canonical forms, or be an argv/comm value rather than a full path, causing trusted system services to be missed or misclassified. Consider normalizing/canonicalizing paths before lookup or provide fallback checks (e.g., check the executable basename against a whitelist).<br>

- [ ] <a href='https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-937a7f41c555573f431cef9c8d0a21808ffd5eab76a727af3fa167760b4eeb9cR145-R157'><strong>Unnecessary allocations / inefficiency</strong></a><br>`get_app_category` lowercases the `name` once into `name_lower`, but each pattern comparison calls `to_lowercase()` on the literal, allocating new Strings repeatedly. This is wasteful in hot paths (many connections). Consider using lowercase literals or a precomputed static set of lowercase patterns to avoid repeated allocations.<br>

</td></tr>
</table>

--- COMMENT ---
## PR Code Suggestions ✨

<!-- ab3c5d7 -->

<table><thead><tr><td>Category</td><td align=left>Suggestion&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; </td><td align=center>Score</td></tr><tbody><tr><td rowspan=15><strong>Logic error</strong></td>
<td>



<details><summary>The custom logging file handler does not return the opened stream, causing file logging to break at runtime</summary>

___


**The overridden <code>_open</code> method in the custom logging handler calls the parent <code>_open</code> but <br>does not return the resulting stream, so <code>logging.FileHandler</code> ends up with <br><code>self.stream = None</code>, causing logging to the file to fail at runtime with <br>AttributeError and silently breaking file logging.**

[bastion-daemon-legacy.py [37-53]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-abdc9834062723adc38853e0643790eedfc75342782c0bd3e7f9e156fecbc0e2R37-R53)

```diff
 def _open(self):
-    # Call parent's _open to create the file
-    super()._open()
+    # Call parent's _open to create the file and get the stream
+    stream = super()._open()
     # Set proper permissions (640 = rw-r-----)
     try:
         import grp
         os.chmod(self.baseFilename, 0o640)
         # Try to set group to bastion if the group exists
         try:
             bastion_gid = grp.getgrnam('bastion').gr_gid
             os.chown(self.baseFilename, 0, bastion_gid)  # root:bastion
         except KeyError:
             # Group doesn't exist, just keep default
             pass
     except (OSError, ImportError):
         # Fail silently if we can't set permissions
         pass
+    return stream
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The override of logging.FileHandler._open() currently calls super()._open() but does not return the stream. The base implementation returns an open file object which FileHandler expects to assign to self.stream. Without returning it, self.stream will be None and attempts to write to the file handler will raise AttributeError or silently fail. Returning the stream (stream = super()._open(); ...; return stream) fixes a real runtime bug in the PR change.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>✅ <s>Checking <code>$?</code> after a backgrounded <code>systemd-run</code> never detects runtime failures so the fallback launch path may never be used even when the GUI fails to start</s></summary>

___

<details><summary><b>Suggestion Impact:</b></summary>The commit removed the trailing '&' from the systemd-run invocation, making $? reflect systemd-run's exit status so the fallback block can trigger on failure.


code diff:

```diff
             systemd-run --user --machine="${session_user}@.host" \
                 --setenv=QT_QPA_PLATFORM=wayland \
-                /usr/bin/bastion-gui &
-            
+                /usr/bin/bastion-gui
+
             # Alternative fallback if systemd-run doesn't work
             if [ $? -ne 0 ]; then
```

</details>


___


**The exit status check for the <code>systemd-run</code> call is unreliable because the command is <br>run in the background with <code>&</code>, so <code>$?</code> only reflects that the background job was <br>spawned, not whether <code>systemd-run</code> itself succeeded; this means the fallback block <br>will not execute even if <code>systemd-run</code> fails at runtime and the GUI never starts.**

[bastion-launch-gui.sh [41-48]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-f5c88428df02a75793d2429f5f9b8cb893cade30f44b37f82608a050b01448a9R41-R48)

```diff
 # Use systemd-run to launch as the user in their session
 # This properly inherits the user's environment
 systemd-run --user --machine="${session_user}@.host" \
     --setenv=QT_QPA_PLATFORM=wayland \
-    /usr/bin/bastion-gui &
+    /usr/bin/bastion-gui
 
 # Alternative fallback if systemd-run doesn't work
 if [ $? -ne 0 ]; then
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: This is a legitimate logic issue. Backgrounding the command with `&` returns the shell job-spawn success, not the exit status of the launched program. `$?` in that spot will generally only tell you the spawn succeeded, so the fallback branch will rarely trigger even if `systemd-run` fails to start the service. Removing the backgrounding (or using a synchronous variant like `systemd-run --wait` / checking the unit activation via `systemctl`/`busctl` or capturing the exit of `systemd-run` directly) is necessary to correctly detect failures and execute the fallback block.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Wayland fallback uses <code>sudo</code> in a way that strips critical environment variables so the GUI cannot connect to the user's Wayland and DBus session</summary>

___


**In the Wayland fallback path, environment variables like <code>XDG_RUNTIME_DIR</code>, <br><code>WAYLAND_DISPLAY</code>, <code>DBUS_SESSION_BUS_ADDRESS</code>, and <code>QT_QPA_PLATFORM</code> are passed as <br>arguments to <code>sudo</code>, but with default <code>sudo</code> configuration they are typically stripped <br>by <code>env_reset</code>, so the launched GUI process will not receive the required Wayland and <br>DBus environment and is likely to fail to display.**

[bastion-launch-gui.sh [51-57]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-f5c88428df02a75793d2429f5f9b8cb893cade30f44b37f82608a050b01448a9R51-R57)

```diff
 if [[ "$session_type" == "wayland" ]]; then
-    sudo -u "$session_user" \
+    sudo -u "$session_user" env \
         XDG_RUNTIME_DIR="/run/user/$user_uid" \
         WAYLAND_DISPLAY="wayland-0" \
         DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$user_uid/bus" \
         QT_QPA_PLATFORM="wayland;xcb" \
         setsid /usr/bin/bastion-gui </dev/null >/tmp/bastion-gui-$session_user.log 2>&1 &
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: Also correct: environment assignments placed before `sudo` do not guarantee those environment variables reach the target process when `sudo` resets the environment (default `env_reset`). Many distros' sudoers will strip such variables, so the launched GUI will often lack XDG_RUNTIME_DIR/DBUS address and fail to connect. Using `sudo -u user env VAR=... cmd` or `runuser`, `su -c 'env ... cmd'`, or adjusting sudoers (or using systemd user services) is required to preserve the required environment for Wayland/DBus.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>X11 fallback loses the display and session environment when passing variables through <code>sudo</code>, causing the GUI to start without a working X server or DBus connection</summary>

___


**In the X11 fallback path, <code>DISPLAY</code>, <code>XAUTHORITY</code>, <code>XDG_RUNTIME_DIR</code>, and <br><code>DBUS_SESSION_BUS_ADDRESS</code> are also passed as environment assignments to <code>sudo</code>, but <br>default <code>sudo</code> settings will usually drop these, so the GUI process often starts <br>without a valid X11 or DBus environment and fails to show a window.**

[bastion-launch-gui.sh [58-66]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-f5c88428df02a75793d2429f5f9b8cb893cade30f44b37f82608a050b01448a9R58-R66)

```diff
 else
     display=$(loginctl show-session "$session" -p Display --value 2>/dev/null)
     display="${display:-:0}"
-    sudo -u "$session_user" \
+    sudo -u "$session_user" env \
         DISPLAY="$display" \
         XAUTHORITY="$user_home/.Xauthority" \
         XDG_RUNTIME_DIR="/run/user/$user_uid" \
         DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$user_uid/bus" \
         setsid /usr/bin/bastion-gui </dev/null >/tmp/bastion-gui-$session_user.log 2>&1 &
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: Same real problem as the Wayland case. `sudo` commonly clears environment variables, so passing DISPLAY/XAUTHORITY/XDG_RUNTIME_DIR/DBUS_* as assignments before `sudo` won't reliably propagate them into the launched process. The GUI will often start without a valid X11/DBus context and fail to display. Use `sudo -u user env ...`, `runuser`, or a systemd user session to ensure the environment is preserved.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Using rustup without first verifying it is installed and on PATH will cause the script to abort with a command-not-found error</summary>

___


**The script checks only for <code>cargo</code> but then unconditionally uses <code>rustup</code> later; if Rust <br>was installed without <code>rustup</code> or <code>rustup</code> is not on PATH, the <code>rustup</code> calls will fail <br>with "command not found" under <code>set -e</code>, terminating the script with a confusing error <br>instead of clearly reporting the missing tool.**

[bastion-rs/build_ebpf.sh [14-19]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-2baf370452cb204afe39e9c380dc40eba70f8c62c11246f9f61a3d176245d121R14-R19)

```diff
 # Check for Rust
+export PATH="$HOME/.cargo/bin:$PATH"
+
 if ! command -v cargo >/dev/null 2>&1; then
-    echo "ERROR: Rust not installed"
+    echo "ERROR: Rust (cargo) not installed or not in PATH"
     echo "Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
     exit 1
 fi
 
+if ! command -v rustup >/dev/null 2>&1; then
+    echo "ERROR: rustup not installed or not in PATH"
+    echo "Please install Rust using rustup from https://rustup.rs/"
+    exit 1
+fi
+
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The PR's final script calls rustup later (rustup toolchain list and rustup component list) but only verifies cargo is present here. If rustup is not installed or not on PATH the script will fail under set -e with a cryptic "command not found" from rustup instead of a clear, actionable error. The proposed check (export PATH and explicit rustup existence test) is practical, prevents confusing failures, and directly fixes a real usability/robustness issue in this script. The change is small and local to this script.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Re-running the script adds duplicate root bypass rules because it never checks if the iptables rule already exists</summary>

___


**The root bypass iptables rule is inserted unconditionally on every run, so <br>re-running the script will keep adding duplicate <code>BASTION_BYPASS</code> rules for UID 0, <br>bloating the OUTPUT chain and making rule ordering/cleanup harder; checking for the <br>rule first makes the script idempotent.**

[bastion-rs/start_daemon.sh [12]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-1fe9c90b2aaf50e35cbb74dba6415c8d301833c0bd3e06629ff5ba8e81c9916cR12-R12)

```diff
+iptables -C OUTPUT -m owner --uid-owner 0 -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || \
 iptables -I OUTPUT 1 -m owner --uid-owner 0 -m comment --comment "BASTION_BYPASS" -j ACCEPT
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The PR's final file unconditionally inserts a UID 0 bypass rule (see the existing code). Running the script multiple times will prepend identical ACCEPT rules repeatedly, which bloats the chain and can change rule ordering unexpectedly. Using `iptables -C ... || iptables -I ...` makes the operation idempotent and addresses a real operational bug rather than a cosmetic nit.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>The script adds duplicate systemd-network bypass rules because it never checks whether that iptables rule is already present</summary>

___


**The <code>systemd-network</code> group bypass rule is also inserted unconditionally on each run, <br>so every invocation of the script adds another identical <code>BASTION_BYPASS</code> rule for <br>that group, leading to multiple redundant ACCEPT rules and complicating debugging <br>and cleanup.**

[bastion-rs/start_daemon.sh [15]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-1fe9c90b2aaf50e35cbb74dba6415c8d301833c0bd3e06629ff5ba8e81c9916cR15-R15)

```diff
+iptables -C OUTPUT -m owner --gid-owner systemd-network -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || \
 iptables -I OUTPUT 1 -m owner --gid-owner systemd-network -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || true
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The script always inserts the group-based bypass if the `iptables -I` runs; even though the command suppresses errors, it doesn't avoid creating duplicates. The suggested `iptables -C ... || iptables -I ...` pattern makes this idempotent and prevents accumulating redundant rules when the script or other services run the same rule.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>NFQUEUE is added multiple times because the script does not verify whether the queue rule already exists before inserting it</summary>

___


**The NFQUEUE rule is always inserted without checking for an existing identical rule, <br>so repeated runs of this script or running it alongside the systemd service (which <br>also installs the same NFQUEUE rule) will create duplicate, redundant NFQUEUE <br>entries in the OUTPUT chain.**

[bastion-rs/start_daemon.sh [19]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-1fe9c90b2aaf50e35cbb74dba6415c8d301833c0bd3e06629ff5ba8e81c9916cR19-R19)

```diff
+iptables -C OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || \
 iptables -I OUTPUT 3 -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The PR adds an NFQUEUE rule unconditionally at a fixed position. Duplicate NFQUEUE rules are a real operational problem (confusing packet handling, unexpected ordering). Checking with `iptables -C` before inserting is a simple, correct fix to make the script safe to re-run.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Cleanup no longer matches the NFQUEUE rule created with <code>--queue-bypass</code>, so rules are not removed and accumulate over time</summary>

___


**The NFQUEUE rule inserted by the setup function now includes the <code>--queue-bypass</code> <br>flag, but the cleanup function deletes rules using a spec that omits this flag, so <br><code>iptables -D</code> will no longer match and the NFQUEUE rules will accumulate across <br>restarts instead of being cleaned up, leading to multiple active NFQUEUE rules and <br>inconsistent firewall state.**

[bastion/firewall_core.py [435-438]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-addda00e3f7b10a3d93cf521c8ac77493dd72e358d3b82659fbff2a4d7517850R435-R438)

```diff
 nfqueue_spec = [
     '-m', 'state', '--state', 'NEW',
-    '-j', 'NFQUEUE', '--queue-num', str(queue_num)
+    '-j', 'NFQUEUE', '--queue-num', str(queue_num), '--queue-bypass'
 ]
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: Correct. setup_nfqueue inserts the rule with '--queue-bypass', but cleanup_nfqueue builds a spec without that flag. iptables requires the exact rule match for '-D' to succeed, so the current cleanup will fail to remove the rules that include '--queue-bypass' and they will accumulate. Updating nfqueue_spec to include '--queue-bypass' (or attempting deletion of both variants) fixes a real logic bug affecting runtime firewall state.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>The installer uses a .deb filename that does not match the actual package name, causing a file-not-found error during installation</summary>

___


**The installer hardcodes the .deb filename as <code>bastion-firewall_2.0.0_all.deb</code>, but the <br>documented/package name in the repo is <code>bastion-firewall_2.0.0_amd64.deb</code>, so the <br>script will exit with "not found" even when the correct package is present.**

[install.sh [12-17]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-043df5bdbf6639d7a77e1d44c5226fd7371e5259a1e4df3a0dd5d64c30dca44fR12-R17)

```diff
-DEB_FILE="bastion-firewall_2.0.0_all.deb"
+DEB_FILE="bastion-firewall_2.0.0_amd64.deb"
 
 if [ ! -f "$DEB_FILE" ]; then
     echo "ERROR: $DEB_FILE not found in current directory"
     exit 1
 fi
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: Verified: the repo's TESTING.md documents the package as bastion-firewall_2.0.0_amd64.deb while the script looks for bastion-firewall_2.0.0_all.deb.
That mismatch will cause the script to fail with "not found" even when the correct .deb is present. Changing the filename to the documented amd64 name (or making the script accept either) fixes a real, reproducible install failure — not a mere stylistic change.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>✅ <s>The unit runs a post-start command referencing a non-existent GUI launcher binary, causing the service activation to fail</s></summary>

___

<details><summary><b>Suggestion Impact:</b></summary>The committed patch removes the entire systemd unit content, which includes deleting the problematic ExecStartPost=/usr/bin/bastion-launch-gui line (thus eliminating the failure mode), though it does so by deleting everything rather than commenting out just that line.


code diff:

```diff
-ExecStart=/usr/bin/bastion-daemon
-ExecStartPost=/usr/bin/bastion-launch-gui
-Restart=on-failure
```

</details>


___


**The service uses an <code>ExecStartPost</code> command to launch a GUI helper that is not present <br>anywhere else in the repository, so on a standard installation following the <br>provided install script this binary will not exist and the post-start step will <br>fail, causing the unit to be marked as failed even though the daemon itself may be <br>running.**

[bastion-daemon.service [11]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-688c0f4218bd1a9503b3d8930a05d34394e57ad608e093de7dce9d01c48f4ae4R11-R11)

```diff
-ExecStartPost=/usr/bin/bastion-launch-gui
+# ExecStartPost=/usr/bin/bastion-launch-gui
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: ExecStartPost is present in the final unit file and if that binary is not installed or fails, systemd will mark the unit as failed despite the main ExecStart succeeding (ExecStartPost failures affect the unit state by default). This is a real operational/runtime issue, not mere style. The suggestion to remove or neutralize the ExecStartPost is reasonable unless the packaging/install process guarantees that /usr/bin/bastion-launch-gui is provided and reliable. At minimum the unit should either ensure the helper is installed, prefix the ExecStartPost with "-" to ignore failures, or make the step conditional. Leaving the raw ExecStartPost as-is can cause unexpected failed units on installs that don't include the GUI helper.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Ignoring the pkill exit status makes the script claim success even when the daemon is not reloaded</summary>

___


**Because the script forces <code>pkill</code> to be ignored (<code>|| true</code>) and always exits with status <br>0, the GUI will report a successful configuration save even if the daemon is not <br>running and no reload occurred, which is misleading behavior and can hide real <br>failures.**

[bastion-reload-config [33-34]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-67e8af6fb87ff1c8e72c7e6a5dc6f9f5fb0245674bdf14947e37d9bfff8e7edcR33-R34)

```diff
 # Signal the daemon to reload config and clear cache
-pkill -HUP -f bastion-daemon || true
+if ! pkill -HUP -f bastion-daemon; then
+    echo "Error: bastion-daemon is not running; could not reload configuration" >&2
+    exit 1
+fi
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The current code masks pkill failures by swallowing the exit status (pkill ... || true) so the script will return success even if no bastion-daemon process existed or the signal failed. That can mislead a GUI or calling process into believing the reload succeeded. Making the script surface the failure (or at least log and return non-zero) is appropriate because reloading the daemon is a core part of this helper's responsibility; the suggested change correctly makes failures visible.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>✅ <s>NFQUEUE rule insertion is not idempotent and can create duplicate iptables rules on restart</s></summary>

___

<details><summary><b>Suggestion Impact:</b></summary>The commit removed the entire `bastion-daemon.service` unit content, including the non-idempotent `ExecStartPre` iptables insertion line. This eliminates the duplication issue by removing the rule insertion from this unit, rather than implementing the suggested `iptables -C ... || iptables -I ...` check.


code diff:

```diff
-[Service]
-Type=simple
-ExecStartPre=/usr/sbin/iptables -I OUTPUT 1 -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass
-ExecStart=/usr/bin/bastion-daemon
-ExecStopPost=/usr/sbin/iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass
-Restart=on-failure
```

</details>


___


**The <code>ExecStartPre</code> command always inserts a new NFQUEUE iptables rule without first <br>checking if an identical rule already exists, so if a similar rule was added <br>manually or by a previous version of the service, restarting this unit will <br>accumulate duplicate NFQUEUE rules and can break assumptions in the code that expect <br>exactly one such rule to be present.**

[bastion-rs/bastion-daemon.service [9]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-8b0db3141377c66f2eb8b3302b416dbf655072e6d90dc8657c6d2625785f5e28R9-R9)

```diff
-ExecStartPre=/usr/sbin/iptables -I OUTPUT 1 -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass
+ExecStartPre=/bin/sh -c 'iptables -C OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || iptables -I OUTPUT 1 -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass'
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The current ExecStartPre unconditionally inserts an iptables rule which will create duplicates on repeated starts/reloads. The proposed change makes the operation idempotent by checking for the rule first (iptables -C) and only inserting if missing. This fixes a real operational bug (rule accumulation) rather than being purely cosmetic.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Missing file handling leaves stale rules in memory instead of clearing them when the rules file is removed</summary>

___


**When <code>load_rules</code> is called after the rules file has been deleted, the in-memory rules <br>map is left unchanged, so stale rules continue to be enforced even though the file <br>is gone, contradicting the documented behavior that a missing file leaves the map <br>empty; you should explicitly clear the map when the file does not exist.**

[bastion-rs/src/rules.rs [67-74]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-c47d2760f80166076349ea945cbb73c168ebf9fd66ff57caff99298ded2e2a41R67-R74)

```diff
 pub fn load_rules(&self) {
     let path = Path::new(RULES_PATH);
     if !path.exists() {
         info!("No rules file at {}, starting with empty rules", RULES_PATH);
+        let mut rules = self.rules.write();
+        rules.clear();
         return;
     }
     
     match fs::read_to_string(path) {
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The suggestion correctly points out a real logic bug: when the rules file is removed, load_rules returns early but does not clear the in-memory map, leaving stale rules active. The improved code simply clears the rules map before returning which matches the function documentation and expected behavior. This is a small, correct, and localized fix.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>The UDP handler decodes the <code>msg_name</code> pointer assuming little-endian representation, which breaks on big-endian systems and can cause invalid memory reads</summary>

___


**In <code>try_udp_sendmsg</code>, the code reconstructs the <code>msg_name</code> pointer using <br><code>u64::from_le_bytes</code>, which assumes little-endian layout and will produce a wrong <br>pointer value on big-endian architectures, leading to failed or unsafe <br><code>bpf_probe_read_user</code> calls; using <code>u64::from_ne_bytes</code> preserves correctness across <br>endianness.**

[bastion-rs/ebpf/src/main.rs [258]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-d989f00c672d286cc345dbbb7ede04f61840f66a577f697ff16bc5a5df47639eR258-R258)

```diff
-let msg_name = u64::from_le_bytes(msg_name_ptr);
+let msg_name = u64::from_ne_bytes(msg_name_ptr);
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: Decoding a raw pointer from byte bytes should use native-endian interpretation (from_ne_bytes) because the pointer bytes in memory are in the platform's endianness. Using from_le_bytes hardcodes little-endian and could produce wrong pointers on big-endian targets. Switching to from_ne_bytes is a correct, low-risk fix to produce the correct pointer value across architectures.

</details></details></td><td align=center>10

</td></tr><tr><td rowspan=6><strong>Possible bug</strong></td>
<td>



<details><summary>The non-modal dialog can be garbage-collected after the method returns, preventing the user decision from being sent and leaving the daemon blocked<!-- not_implemented --></summary>

___


**The non-modal dialog instance is only stored in a local variable; after <br><code>handle_connection_request</code> returns there is no strong Python reference to it, so the <br><code>FirewallDialog</code> can be garbage-collected prematurely, causing the popup to disappear <br>or never receive its <code>finished</code> signal and leaving the daemon blocked waiting for a <br>response. Keep a reference on <code>self</code> for the lifetime of the dialog and clear it when <br>the dialog finishes.**

[bastion-gui.py [233-269]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-187b1e5910f096aae7417e760f849b9a564ea1ed82afd7d450e58fa8cced9a57R233-R269)

```diff
 def handle_connection_request(self, req):
     """
     Display a non-modal firewall decision dialog for an incoming connection request and send the user's decision back to the daemon.
 
     Parameters:
         req (dict): Incoming request payload used to populate the dialog. May include a numeric 'decision_id' (defaults to 0) which will be echoed back in the response.
 
     Behavior:
         - Shows a non-modal FirewallDialog with a 60-second timeout to obtain the user's decision and permanence choice.
         - Dialog doesn't steal focus, allowing user to continue working.
         - If connected to the daemon, sends a JSON line containing `allow` (boolean), `permanent` (boolean), and `decision_id` back over the socket.
         - If sending the response fails, the client disconnects and resets its connection state.
     """
     dialog = FirewallDialog(req, timeout=60)
+    self._current_dialog = dialog  # Keep a strong reference to prevent GC
     decision_id = req.get('decision_id', 0)
 
     # Handle dialog completion (non-modal)
     def on_dialog_finished():
         decision = (dialog.decision == 'allow')
         permanent = dialog.permanent
 
         # Send response with decision_id
         if self.connected and self.sock:
             resp = json.dumps({
                 'allow': decision,
                 'permanent': permanent,
                 'decision_id': decision_id
             }) + '\n'
             try:
                 self.sock.sendall(resp.encode())
             except:
                 self.handle_disconnect()
 
         dialog.deleteLater()  # Clean up dialog
+        self._current_dialog = None  # Release reference once finished
 
     dialog.finished.connect(on_dialog_finished)
     dialog.show()  # Non-modal - doesn't steal focus!
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: This is a real, practical bug in PyQt/PySide-based applications: if the dialog has no QObject parent and only a local Python reference exists, the Python GC can collect it after the method returns, which may remove the underlying C++ object or stop signals from being delivered. The suggested change (keep a strong reference on self and clear it in the finished handler) directly prevents premature GC and ensures the finished signal fires and the response is sent. It's a small, targeted fix that resolves a possible race/bug introduced by making the dialog non-modal.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>The package may ship stale eBPF-related files because the target share directory is never cleaned before reuse</summary>

___


**The new directory <code>debian/usr/share/bastion-firewall</code> is created without clearing any <br>existing contents, whereas the previous v2 build script explicitly removed this <br>tree; running the new script after an older build can therefore leave stale or <br>renamed eBPF or support files in the package, which may confuse the daemon that <br>expects a single <code>bastion-ebpf.o</code>.**

[build_deb.sh [42]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-5ff8ce75532c01d42d4af24ef679dd19b1a225266046c14cd5d4493e144a30ebR42-R42)

```diff
-mkdir -p debian/usr/share/bastion-firewall
+rm -rf debian/usr/share/bastion-firewall && mkdir -p debian/usr/share/bastion-firewall
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The script creates debian/usr/share/bastion-firewall but does not remove existing contents. Older builds could leave stale or renamed eBPF/support files in that directory which would then be packaged. Cleaning the dir before populating it (rm -rf && mkdir -p) is a reasonable and low-risk fix to ensure reproducible packages and avoid shipping unintended files.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>The script unconditionally edits the control file with sed even when it may not exist, causing a hard build failure despite the preceding existence check</summary>

___


**The comment claims the control file is checked before editing, but <code>sed</code> is still run <br>unconditionally on <code>debian/DEBIAN/control</code>; if that file is missing (for example in a <br>fresh packaging skeleton), the script will exit with a <code>sed: can't read</code> error despite <br>the guard, making the build fragile.**

[build_deb_v2.sh [195-206]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-3bf64863e0e24bea916400a769a41a0f2b0c7da374ae38d2ce6d89b967902d87R195-R206)

```diff
-# FIX #16: Check if control file exists before editing
+# FIX #16: Check if control file exists before editing and updating Installed-Size
 if [ -f "debian/DEBIAN/control" ]; then
     chmod 644 debian/DEBIAN/control
+    # Calculate installed size
+    INSTALLED_SIZE=$(du -sk debian/usr debian/lib 2>/dev/null | awk '{s+=$1} END {print s}')
+    sed -i "s/^Installed-Size:.*/Installed-Size: $INSTALLED_SIZE/" debian/DEBIAN/control
+else
+    print_warning "debian/DEBIAN/control not found; skipping Installed-Size update"
 fi
 
-# Calculate installed size
-INSTALLED_SIZE=$(du -sk debian/usr debian/lib 2>/dev/null | awk '{s+=$1} END {print s}')
-sed -i "s/^Installed-Size:.*/Installed-Size: $INSTALLED_SIZE/" debian/DEBIAN/control
-
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The suggestion is correct: the script currently runs sed unconditionally on debian/DEBIAN/control after only conditionally chmod'ing it. If the control file is missing the sed invocation will fail and, because set -e is enabled, the whole script will exit. Wrapping the Installed-Size calculation and the sed update inside the existing file-exists branch (or guarding the sed separately) prevents a fragile hard-fail on fresh packaging skeletons. This fixes a real robustness bug rather than being mere style nit.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Cleanup of the NFQUEUE iptables rule causes the service stop to fail when the rule is already absent<!-- not_implemented --></summary>

___


**The <code>ExecStopPost</code> iptables deletion is treated as mandatory cleanup, so if the <br>NFQUEUE rule has already been removed or was never inserted, stopping the service <br>will fail due to the non-zero exit status of iptables, even though this cleanup <br>should be best-effort and not cause the unit stop to be marked as failed.**

[bastion-rs/bastion-daemon.service [11]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-8b0db3141377c66f2eb8b3302b416dbf655072e6d90dc8657c6d2625785f5e28R11-R11)

```diff
-ExecStopPost=/usr/sbin/iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass
+ExecStopPost=/bin/sh -c 'iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || true'
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: ExecStopPost runs during stop/kill handling; an iptables -D that fails returns non-zero and can mark the stop as failed. Making the deletion best-effort (redirect errors to /dev/null and || true) prevents spurious unit failures when the rule is already gone. This is a practical and appropriate fix.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>The IPv4 extraction helper performs a potentially unaligned <code>u32</code> dereference, which is undefined behavior and may fail under the eBPF verifier</summary>

___


**The <code>ipv4_from_sockaddr</code> helper casts a <code>*const u8</code> derived from a <code>[u8; 16]</code> stack buffer <br>to <code>*const u32</code> and dereferences it, which is undefined behavior in Rust because the <br>buffer has alignment 1 and thus may not satisfy the 4-byte alignment required for <br><code>u32</code>, potentially causing verifier rejection or subtle runtime misbehavior on some <br>targets; instead, load the four bytes individually (or via <code>read_unaligned</code>) and <br>reconstruct the <code>u32</code>.**

[bastion-rs/ebpf/src/main.rs [52-66]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-d989f00c672d286cc345dbbb7ede04f61840f66a577f697ff16bc5a5df47639eR52-R66)

```diff
 #[inline]
 fn ipv4_from_sockaddr(addr: *const core::ffi::c_void) -> u32 {
     // sockaddr_in structure:
     // struct sockaddr_in {
     //     sa_family_t    sin_family;   // AF_INET
     //     in_port_t      sin_port;     // Port number
     //     struct in_addr sin_addr;     // IPv4 address
     // };
     unsafe {
         let addr = addr as *const u8;
-        // Skip sin_family (2 bytes) and sin_port (2 bytes)
-        let ip_ptr = addr.add(4) as *const u32;
-        *ip_ptr  // Already in network byte order
+        // Skip sin_family (2 bytes) and sin_port (2 bytes) and read 4 bytes of IP
+        let b0 = *addr.add(4);
+        let b1 = *addr.add(5);
+        let b2 = *addr.add(6);
+        let b3 = *addr.add(7);
+        // Preserve the raw bit pattern as in the original memory
+        u32::from_ne_bytes([b0, b1, b2, b3])
     }
 }
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The suggestion correctly identifies an unaligned dereference: casting a byte pointer to *const u32 and dereferencing can be UB and is likely to be rejected by the eBPF verifier or cause issues on architectures with strict alignment. Reconstructing the 4 bytes (or using read_unaligned) avoids alignment pitfalls while preserving the original memory pattern. This fixes a real correctness/verifier risk rather than being a cosmetic change.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>The port extraction helper uses a potentially unaligned <code>u16</code> dereference, which is undefined behavior and may cause eBPF verifier or runtime issues</summary>

___


**The <code>port_from_sockaddr</code> helper similarly casts a <code>*const u8</code> derived from a <code>[u8; 16]</code> <br>stack buffer to <code>*const u16</code> and dereferences it, which is undefined behavior because <br>the buffer is only 1-byte aligned and may not meet the 2-byte alignment requirement <br>for <code>u16</code>, risking verifier rejection or subtle bugs; instead, read the two bytes and <br>reconstruct the <code>u16</code> with <code>from_be_bytes</code>.**

[bastion-rs/ebpf/src/main.rs [89-97]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-d989f00c672d286cc345dbbb7ede04f61840f66a577f697ff16bc5a5df47639eR89-R97)

```diff
 #[inline]
 fn port_from_sockaddr(addr: *const core::ffi::c_void) -> u16 {
     unsafe {
         let addr = addr as *const u8;
-        // Skip sin_family (2 bytes)
-        let port_ptr = addr.add(2) as *const u16;
-        u16::from_be(*port_ptr)  // Network byte order to host
+        // Skip sin_family (2 bytes) and read the two port bytes
+        let b0 = *addr.add(2);
+        let b1 = *addr.add(3);
+        u16::from_be_bytes([b0, b1])  // Network byte order to host
     }
 }
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: This is the same class of problem as the IPv4 case: casting to *const u16 and dereferencing can be unaligned UB. Reading the two bytes and using from_be_bytes (or read_unaligned) yields the correct host-order port without alignment issues and prevents verifier/runtime failures. It's a functional fix, not just style.

</details></details></td><td align=center>10

</td></tr><tr><td rowspan=4><strong>Security</strong></td>
<td>



<details><summary>Running the daemon as unrestricted root without capability bounding unnecessarily increases the impact of a compromise<!-- not_implemented --></summary>

___


**The daemon is run as full root without any capability bounding, whereas the existing <br>Rust service unit in this repo restricts it to only CAP_NET_ADMIN and CAP_NET_RAW; <br>dropping the bounding here means any compromise of the daemon yields unrestricted <br>root privileges instead of a minimized capability set, which is an avoidable <br>security regression.**

[bastion-daemon.service [9]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-688c0f4218bd1a9503b3d8930a05d34394e57ad608e093de7dce9d01c48f4ae4R9-R9)

```diff
 User=root
+CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
+AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The unit currently runs the service as root (User=root) with no capability restrictions in the final file. For a network/eBPF daemon the attack surface is sensitive; restricting capabilities (CapabilityBoundingSet and AmbientCapabilities) to only what's required (e.g., CAP_NET_ADMIN CAP_NET_RAW) reduces blast radius if the daemon is compromised. This is a legitimate security hardening suggestion rather than a cosmetic change. It directly improves runtime safety and aligns with least-privilege practices.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>✅ <s>Unvalidated config file path allows arbitrary root file overwrite when the helper is invoked via pkexec</s></summary>

___

<details><summary><b>Suggestion Impact:</b></summary>The commit adds a case statement that restricts CONFIG_FILE to /etc/bastion/* and exits with an error otherwise, before performing mv "$TEMP_FILE" "$CONFIG_FILE".


code diff:

```diff
+# Ensure the config file lives under the expected Bastion config directory
+case "$CONFIG_FILE" in
+    /etc/bastion/*) ;;
+    *)
+        echo "Error: Invalid config file path: $CONFIG_FILE" >&2
+        exit 1
+        ;;
+esac
+
 # Move the temporary file to the config location
 mv "$TEMP_FILE" "$CONFIG_FILE"
```

</details>


___


**The script blindly trusts the <code>CONFIG_FILE</code> argument, so when it is executed via <br><code>pkexec</code>/polkit an authorized unprivileged user can point it at any path and <br>overwrite/chmod arbitrary root-owned files, which is a privilege-escalation risk; <br>you should restrict the target path to the expected Bastion config directory before <br>moving the file.**

[bastion-reload-config [27-28]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-67e8af6fb87ff1c8e72c7e6a5dc6f9f5fb0245674bdf14947e37d9bfff8e7edcR27-R28)

```diff
+# Ensure the config file lives under the expected Bastion config directory
+case "$CONFIG_FILE" in
+    /etc/bastion/*) ;;
+    *)
+        echo "Error: Invalid config file path: $CONFIG_FILE" >&2
+        exit 1
+        ;;
+esac
+
 # Move the temporary file to the config location
 mv "$TEMP_FILE" "$CONFIG_FILE"
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: The PR's script accepts an arbitrary CONFIG_FILE and immediately moves the temp file there as root (lines show mv "$TEMP_FILE" "$CONFIG_FILE"). If this helper is invoked via a privilege-escalation helper (pkexec/polkit) or any other mechanism that runs it as root on behalf of an unprivileged user, an attacker could point CONFIG_FILE at any root-owned file under the filesystem and overwrite it. Restricting the allowed destination (for example to /etc/bastion/*) is a real security hardening step, not mere style. The improved code properly validates the path before performing the mv, which mitigates the privilege-escalation risk.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>✅ <s>Directly moving a user-controlled temp file without rejecting symlinks can expose sensitive root-owned files by moving and chmodding them to a world-readable rules path</s></summary>

___

<details><summary><b>Suggestion Impact:</b></summary>The commit added a symlink rejection guard (`if [ -L "$TEMP_FILE" ] ... exit 1`) before the `mv` operation, implementing the core security mitigation suggested.


code diff:

```diff
+# Reject symlinks to avoid clobbering arbitrary root-owned files
+if [ -L "$TEMP_FILE" ]; then
+    echo "Error: Temporary file must not be a symlink: $TEMP_FILE" >&2
+    exit 1
+fi
```

</details>


___


**Moving a user-controlled temporary file directly with <code>mv</code> and then making it <br>world-readable allows a symlink attack where an attacker replaces the temp file path <br>with a symlink to a sensitive root-owned file (e.g. <code>/etc/shadow</code>), causing that file <br>to be moved to the rules path and chmodded <code>644</code>, effectively exposing its contents; <br>you should explicitly reject symlinks before performing the move.**

[bastion-reload-rules [21-31]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-2d74c49518987e8487fe7795778d1eee184a28d5389f1c3dd2e48d798ea41af2R21-R31)

```diff
 # Validate paths
 if [ ! -f "$TEMP_FILE" ]; then
     echo "Error: Temporary file does not exist: $TEMP_FILE" >&2
+    exit 1
+fi
+
+# Reject symlinks to avoid clobbering arbitrary root-owned files
+if [ -L "$TEMP_FILE" ]; then
+    echo "Error: Temporary file must not be a symlink: $TEMP_FILE" >&2
     exit 1
 fi
 
 # Move the temporary file to the rules location
 mv "$TEMP_FILE" "$RULES_FILE"
 
 # Set proper permissions (readable by all, writable by root)
 chmod 644 "$RULES_FILE"
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: This is a real security issue. The script runs as root and accepts a user-controlled path; if that path is a symlink an attacker can cause mv/chmod to affect an arbitrary target (e.g. /etc/shadow). On typical Linux semantics, moving a symlink and then running chmod can end up changing the target's permissions or creating a symlink at the destination that points at a sensitive file — both lead to information disclosure or tampering. Rejecting symlinks (or verifying ownership and using a safe install/rename pattern) fixes a genuine vulnerability rather than a cosmetic change.

</details></details></td><td align=center>10

</td></tr><tr><td>



<details><summary>Running the daemon as root without bounding Linux capabilities gives it more kernel privileges than necessary and increases security risk</summary>

___


**The service runs a network-facing firewall daemon as root without any capability <br>bounding, whereas the existing Rust daemon unit (<code>bastion-rs/bastion-daemon.service</code>) <br>explicitly restricts it to <code>CAP_NET_ADMIN</code> and <code>CAP_NET_RAW</code>; leaving this service with <br>full capabilities unnecessarily increases the impact of any compromise of the daemon <br>process.**

[bastion-firewall.service [6]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-e7fb5e23b406b2e65df33e223870991c4323949fa38b560fa624ac74f131e4e0R6-R6)

```diff
 Type=simple
+CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
+AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
 
```
<details><summary>Suggestion importance[1-10]: 5</summary>

Why it matters? 🤔: Limiting capabilities (CapabilityBoundingSet / AmbientCapabilities) is a valid defense-in-depth control for a network-facing root daemon that only needs NET_ADMIN/NET_RAW. The PR currently runs the process as root with no capability restrictions (User=root, Group=root present in the unit), so adding capability bounding reduces blast radius if the daemon is compromised. This is a genuine security improvement, not merely stylistic.

</details></details></td><td align=center>5

</td></tr><tr><td rowspan=1><strong>Resource leak</strong></td>
<td>



<details><summary>✅ <s>Writing logs via systemd to a file that logrotate rotates with <code>create</code> causes logs to keep going to the rotated file and defeats rotation</s></summary>

___

<details><summary><b>Suggestion Impact:</b></summary>The service unit was changed from appending to /var/log/bastion-daemon.log to using journald (StandardOutput=journal and StandardError=journal), resolving the logrotate interaction issue. The commit also added capabilities settings, but the journald change directly implements the suggestion.


code diff:

```diff
-StandardOutput=append:/var/log/bastion-daemon.log
-StandardError=append:/var/log/bastion-daemon.log
+CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
+AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
+StandardOutput=journal
+StandardError=journal
```

</details>


___


**Logging directly to <code>/var/log/bastion-daemon.log</code> via <code>StandardOutput=append:</code> and <br><code>StandardError=append:</code> conflicts with the existing logrotate config (which uses <br><code>create</code> and a <code>systemctl reload</code> hook): after rotation, systemd will keep writing to <br>the old, renamed file instead of the newly created one, so log rotation will not <br>actually limit log size and can lead to unbounded log growth.**

[bastion-firewall.service [14-15]](https://github.com/shipdocs/bastion-firewall/pull/19/files#diff-e7fb5e23b406b2e65df33e223870991c4323949fa38b560fa624ac74f131e4e0R14-R15)

```diff
-StandardOutput=append:/var/log/bastion-daemon.log
-StandardError=append:/var/log/bastion-daemon.log
+StandardOutput=journal
+StandardError=journal
 
```
<details><summary>Suggestion importance[1-10]: 10</summary>

Why it matters? 🤔: This is a real, practical problem: when systemd keeps a file descriptor open to a log file, logrotate's 'create' (or moving/renaming) will not make systemd switch to the new file and rotated logs will continue to grow unchecked. Switching to journald (StandardOutput=journal / StandardError=journal) fixes the rotation issue and centralizes logs in the journal. The suggestion directly addresses a resource / log-rotation bug introduced by the PR.

</details></details></td><td align=center>10

</td></tr></tr></tbody></table>


--- COMMENT ---
CodeAnt AI finished reviewing your PR.
