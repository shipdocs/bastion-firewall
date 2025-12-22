# Security Audit Report - Bastion Firewall

**Date:** 2025-12-22  
**Version:** 1.3.2  
**Auditor:** Security Analysis Team  
**Platform:** Zorin OS 18 (Ubuntu 24.04 LTS base)

---

## Executive Summary

This comprehensive security audit evaluates the Bastion Firewall, an application-level outbound firewall for Linux systems. The audit identified **11 security vulnerabilities** ranging from **CRITICAL** to **LOW** severity, along with several recommendations for security hardening.

### Overall Security Rating: **MEDIUM-HIGH RISK**

**Critical Issues:** 2  
**High Issues:** 3  
**Medium Issues:** 4  
**Low Issues:** 2  

---

## Table of Contents

1. [Critical Vulnerabilities](#critical-vulnerabilities)
2. [High-Severity Vulnerabilities](#high-severity-vulnerabilities)
3. [Medium-Severity Vulnerabilities](#medium-severity-vulnerabilities)
4. [Low-Severity Vulnerabilities](#low-severity-vulnerabilities)
5. [Security Strengths](#security-strengths)
6. [Recommendations](#recommendations)
7. [Remediation Roadmap](#remediation-roadmap)

---

## Critical Vulnerabilities

### VULN-001: Command Injection via shell=True in Statistics Collection
**Severity:** CRITICAL  
**CVSS Score:** 9.8  
**File:** `bastion/gui_qt.py:852, 856`

**Description:**  
The GUI control panel uses `shell=True` with unvalidated file paths when collecting statistics:

```python
# Line 852
res = subprocess.run(f"wc -l {self.log_path}", shell=True, capture_output=True, text=True)

# Line 856
res = subprocess.run(f"grep -c 'decision: deny' {self.log_path}", shell=True, capture_output=True, text=True)
```

**Risk:**  
If `self.log_path` can be manipulated (e.g., via symlink attack or configuration injection), an attacker could execute arbitrary commands with user privileges. While the GUI runs as a normal user, this could still lead to data exfiltration or privilege escalation.

**Attack Scenario:**
1. Attacker creates malicious config with `log_path: "/var/log/test.log; rm -rf ~/*"`
2. User opens control panel
3. Statistics update triggers command injection
4. User's home directory is deleted

**Remediation:**
```python
# Secure version - NO shell=True
res = subprocess.run(['wc', '-l', str(self.log_path)], capture_output=True, text=True)
res = subprocess.run(['grep', '-c', 'decision: deny', str(self.log_path)], capture_output=True, text=True)
```

---

### VULN-002: Insecure Unix Socket Permissions (World-Writable)
**Severity:** CRITICAL  
**CVSS Score:** 9.1  
**File:** `bastion/daemon.py:158`

**Description:**  
The daemon creates a Unix socket with world-writable permissions (0o666):

```python
os.chmod(self.SOCKET_PATH, 0o666)  # rwrw-rw-
```

**Risk:**  
ANY user on the system can connect to the daemon socket and send malicious commands, potentially:
- Injecting fake connection requests to confuse users
- Sending malicious "user decisions" to allow/deny arbitrary traffic
- Exhausting daemon resources (DoS)
- Information disclosure via stats updates

**Attack Scenario:**
1. Malicious user connects to `/tmp/bastion-daemon.sock`
2. Sends fake connection requests for `/usr/bin/firefox -> malicious.com:443`
3. User approves thinking it's legitimate Firefox
4. Malware is allowed through

**Remediation:**
```python
# Restrict to root and bastion group only
os.chmod(self.SOCKET_PATH, 0o660)  # rw-rw----
os.chown(self.SOCKET_PATH, 0, bastion_gid)  # root:bastion
```

---

## High-Severity Vulnerabilities

### VULN-003: Race Condition in Application Identification
**Severity:** HIGH  
**CVSS Score:** 7.5  
**File:** `bastion/firewall_core.py:280-296`

**Description:**  
The packet processor attempts to identify applications by scanning `/proc/net/tcp` with retry logic. However, there's a race condition window where:
1. Packet arrives and is queued
2. Application identification starts
3. Malicious app quickly creates socket, gets identified
4. Malicious app closes, benign app opens same port
5. Decision is cached for wrong app

**Risk:**  
Port reuse attacks could bypass firewall rules. While the 2-minute cache (TTL=120) helps, rapid port cycling could still exploit this.

**Remediation:**
- Reduce cache TTL for unverified identifications
- Add PID validation before using cached entries
- Implement eBPF-based identification (already partially implemented but not mandatory)

---

### VULN-004: Localhost Bypass for Anonymous IPC
**Severity:** HIGH  
**CVSS Score:** 7.2  
**File:** `bastion/service_whitelist.py:119-123`

**Description:**  
The whitelist auto-allows ANY localhost connection on ports > 1024 without authentication:

```python
if dest_port > 1024:
    logger.info(f"Auto-allowing anonymous localhost IPC: {app_name or 'unidentified'} -> {dest_ip}:{dest_port}")
    return (True, "Anonymous Localhost IPC")
```

**Risk:**  
Malware can bypass firewall by:
1. Setting up a local SOCKS/HTTP proxy on port 8080
2. Connecting to it from any application
3. Proxy forwards traffic to internet
4. All traffic appears as "localhost IPC" and is auto-allowed

**Remediation:**
Remove the blanket exception or add application whitelisting for IPC.

---

### VULN-005: No Validation of pkexec Commands
**Severity:** HIGH  
**CVSS Score:** 7.0  
**File:** `bastion/gui_qt.py:867, 931, 1007, etc.`

**Description:**  
Multiple locations use `pkexec` with user-controllable parameters without proper validation:

```python
subprocess.run(['pkexec', 'systemctl', action, 'bastion-firewall'], check=True)
subprocess.run(['pkexec', 'ufw', 'disable'], check=True)
```

While pkexec provides authentication, the commands themselves aren't validated. If `action` variable could be manipulated, it could lead to unintended system changes.

**Risk:**  
If variables like `action` can be influenced by configuration files or user input, privilege escalation is possible.

**Remediation:**
Add strict input validation:
```python
ALLOWED_ACTIONS = ['start', 'stop', 'restart', 'enable', 'disable']
if action not in ALLOWED_ACTIONS:
    raise ValueError(f"Invalid action: {action}")
```

---

## Medium-Severity Vulnerabilities

### VULN-006: Insufficient Input Validation on JSON Configuration
**Severity:** MEDIUM  
**CVSS Score:** 6.5  
**File:** `bastion/config.py:25-36`

**Description:**  
Configuration is loaded from `/etc/bastion/config.json` without validation:

```python
with open(cls.CONFIG_PATH) as f:
    config = json.load(f)
    return {**cls.DEFAULT_CONFIG, **config}
```

**Risk:**  
Malicious configuration values could cause:
- Path traversal via log_file paths
- Integer overflow via timeout_seconds
- Unexpected behavior via mode changes

**Remediation:**
Add schema validation:
```python
def validate_config(config):
    if not isinstance(config.get('timeout_seconds'), int) or config['timeout_seconds'] < 0:
        raise ValueError("Invalid timeout")
    if config.get('mode') not in ['learning', 'enforcement']:
        raise ValueError("Invalid mode")
    # ... more validation
```

---

### VULN-007: Symlink Attack on Rules File
**Severity:** MEDIUM  
**CVSS Score:** 6.3  
**File:** `bastion/rules.py:24-43`

**Description:**  
Rules are saved to `/etc/bastion/rules.json` without checking for symlinks:

```python
with open(self.RULES_PATH, 'w') as f:
    json.dump(self._rules, f, indent=2)
```

**Risk:**  
If an attacker can create a symlink at `/etc/bastion/rules.json` pointing to a sensitive file (e.g., `/etc/shadow`), they could:
- Overwrite critical system files
- Read sensitive data via the control panel

**Remediation:**
```python
# Check for symlinks before writing
if self.RULES_PATH.is_symlink():
    raise SecurityError("Rules path is a symlink")
    
# Use safe file creation
fd = os.open(self.RULES_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
```

---

### VULN-008: Information Disclosure in Logs
**Severity:** MEDIUM  
**CVSS Score:** 5.5  
**File:** Multiple locations

**Description:**  
Logs contain sensitive information including:
- Full application paths (reveals installed software)
- Destination IPs and ports (browsing history)
- User decisions (privacy concern)

Log file at `/var/log/bastion-daemon.log` is readable by bastion group (chmod 644 in postinst).

**Risk:**  
- Privacy violation
- Reconnaissance for attackers
- Compliance issues (GDPR)

**Remediation:**
- Restrict log permissions to 640 (root:bastion)
- Add log rotation with encryption
- Implement optional privacy mode (hash IPs, redact paths)

---

### VULN-009: Denial of Service via Packet Flooding
**Severity:** MEDIUM  
**CVSS Score:** 5.0  
**File:** `bastion/daemon.py:184-258`

**Description:**  
No rate limiting on connection requests. An application making rapid connection attempts could:
- Flood the GUI with popup dialogs
- Exhaust daemon memory via pending_requests dictionary
- Cause NFQUEUE to drop legitimate packets

Current rate limiting (line 238-244) only prevents multiple popups for same flow, not total request volume.

**Risk:**  
DoS of firewall → system loses network protection

**Remediation:**
Add global rate limiting:
```python
from collections import deque
import time

class RateLimiter:
    def __init__(self, max_per_second=10):
        self.max = max_per_second
        self.requests = deque()
    
    def allow(self):
        now = time.time()
        # Remove requests older than 1 second
        while self.requests and now - self.requests[0] > 1.0:
            self.requests.popleft()
        
        if len(self.requests) >= self.max:
            return False
        
        self.requests.append(now)
        return True
```

---

## Low-Severity Vulnerabilities

### VULN-010: Weak Cryptographic Randomness Not Used for Security
**Severity:** LOW  
**CVSS Score:** 3.0  
**File:** N/A (Observation)

**Description:**  
No cryptographic operations use weak randomness, but there's also no encryption/signing of:
- Socket communications
- Configuration files
- Rule files

**Risk:**  
If configuration/rules could be tampered with, firewall could be disabled. However, these files are root-owned, mitigating the risk.

**Remediation:**
Consider signing configuration and rules files with a system key to detect tampering.

---

### VULN-011: Potential Integer Overflow in Timeout
**Severity:** LOW  
**CVSS Score:** 2.5  
**File:** `bastion/config.py`, `bastion/daemon.py:332`

**Description:**  
Timeout value is not validated for reasonable bounds:

```python
self.gui_socket.settimeout(60.0)  # Hardcoded
```

While config allows `timeout_seconds`, it's not used in socket operations. If it were, extreme values could cause issues.

**Risk:**  
- Negative timeout = immediate timeout
- Very large timeout = hung connections

**Remediation:**
```python
MIN_TIMEOUT = 5
MAX_TIMEOUT = 300
timeout = max(MIN_TIMEOUT, min(config['timeout_seconds'], MAX_TIMEOUT))
```

---

## Security Strengths

### ✅ Positive Security Features

1. **Privilege Separation**
   - Daemon runs as root, GUI as user
   - Unix socket communication for isolation
   - PolicyKit (pkexec) for privileged operations

2. **Defense in Depth (Service Whitelist)**
   - 5-phase security validation
   - Exact name matching (not substring)
   - Path validation for system services
   - Port restrictions for trusted apps

3. **Learning Mode**
   - Safe default that doesn't break connectivity
   - Allows testing before enforcement

4. **Thread Safety**
   - Proper locking for shared resources (rules, pending_requests)
   - RLock usage in RuleManager

5. **Graceful Shutdown**
   - Proper cleanup of iptables rules
   - Socket cleanup
   - Signal handling

6. **No Dangerous Functions**
   - No eval(), exec(), pickle, or YAML unsafe loading
   - Minimal use of shell=True (only 2 instances found, both vulnerable)

7. **Comprehensive Logging**
   - Audit trail of all decisions
   - Helpful for debugging and forensics

---

## Recommendations

### Immediate Actions (High Priority)

1. **Fix VULN-001 & VULN-002** - These are critical
2. **Add input validation** - Config, rules, file paths
3. **Implement rate limiting** - Prevent DoS attacks
4. **Review localhost bypass logic** - Too permissive

### Short-Term Improvements (Medium Priority)

5. **Harden file operations** - Check symlinks, use O_NOFOLLOW
6. **Add configuration schema** - JSON Schema validation
7. **Implement log rotation** - With proper permissions
8. **Add integrity checks** - Sign config/rules files

### Long-Term Enhancements (Low Priority)

9. **Mandatory eBPF** - More reliable than /proc scanning
10. **Encrypted socket** - Protect daemon-GUI communication
11. **AppArmor/SELinux profile** - Additional confinement
12. **Audit logging** - Separate security event log
13. **Web dashboard** - Secure remote management
14. **Anomaly detection** - ML-based suspicious behavior detection

---

## Remediation Roadmap

### Phase 1: Critical Fixes (Week 1)
- [ ] VULN-001: Remove shell=True, use list arguments
- [ ] VULN-002: Fix Unix socket permissions to 0o660
- [ ] VULN-003: Add PID validation to cache
- [ ] Add comprehensive test suite for security

### Phase 2: High-Priority Hardening (Week 2)
- [ ] VULN-004: Review localhost whitelist logic
- [ ] VULN-005: Add strict input validation for pkexec
- [ ] VULN-006: Implement JSON schema validation
- [ ] Add rate limiting for packet processing

### Phase 3: Medium-Priority Improvements (Week 3-4)
- [ ] VULN-007: Fix symlink attacks on files
- [ ] VULN-008: Restrict log permissions, add rotation
- [ ] VULN-009: Implement global rate limiter
- [ ] Add integrity checking for config files

### Phase 4: Testing & Validation (Week 5)
- [ ] Penetration testing
- [ ] Fuzzing packet processor
- [ ] Code review by security team
- [ ] Update documentation

### Phase 5: Long-Term Security (Ongoing)
- [ ] AppArmor/SELinux profiles
- [ ] Encrypted communications
- [ ] Anomaly detection
- [ ] Bug bounty program

---

## Compliance & Standards

### Security Standards Alignment

- **CWE-78**: OS Command Injection (VULN-001) ❌
- **CWE-732**: Incorrect Permission Assignment (VULN-002) ❌
- **CWE-362**: Race Condition (VULN-003) ⚠️
- **CWE-20**: Improper Input Validation (VULN-006) ⚠️
- **CWE-59**: Symlink Following (VULN-007) ⚠️
- **CWE-532**: Information Exposure Through Log Files (VULN-008) ⚠️
- **CWE-400**: Uncontrolled Resource Consumption (VULN-009) ⚠️

### Best Practices Compliance

- ✅ OWASP Top 10 (2021): Mostly compliant except injection
- ⚠️ NIST Cybersecurity Framework: Partial compliance
- ✅ CIS Controls: Good defensive posture
- ⚠️ GDPR: Log retention needs review

---

## Testing Recommendations

### Security Test Suite

1. **Injection Testing**
   ```bash
   # Test command injection
   echo '{"log_file": "/var/log/test.log; touch /tmp/pwned"}' > /etc/bastion/config.json
   ```

2. **Socket Security Testing**
   ```python
   # Test unauthorized socket access
   import socket
   s = socket.socket(socket.AF_UNIX)
   s.connect('/tmp/bastion-daemon.sock')
   s.send(b'malicious data')
   ```

3. **Race Condition Testing**
   ```python
   # Rapid port cycling
   for i in range(1000):
       sock = socket.socket()
       sock.connect(('example.com', 80))
       sock.close()
   ```

4. **DoS Testing**
   ```python
   # Connection flooding
   import threading
   def flood():
       for i in range(100):
           socket.socket().connect(('1.1.1.1', 53))
   
   threads = [threading.Thread(target=flood) for _ in range(10)]
   ```

---

## Conclusion

Bastion Firewall demonstrates **good security architecture** with proper privilege separation and defense-in-depth principles. However, the **2 critical vulnerabilities** (command injection and world-writable socket) pose significant risks that must be addressed immediately.

With the recommended fixes, Bastion can achieve a **HIGH security rating** suitable for production use on Zorin OS 18 and similar distributions.

### Recommended Next Steps

1. Apply critical patches (VULN-001, VULN-002)
2. Conduct security testing
3. Update documentation with security guidelines
4. Consider professional security audit
5. Establish security update process

---

**Report Version:** 1.0  
**Last Updated:** 2025-12-22  
**Classification:** Public  
**Distribution:** Unlimited
