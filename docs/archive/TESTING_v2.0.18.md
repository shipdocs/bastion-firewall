# Testing Guide for v2.0.18 Security Improvements

## 🎯 Test Objectives

Verify that all 5 security phases work correctly while maintaining normal functionality.

---

## ✅ **PHASE 1: Localhost Bypass Fix**

### Test 1.1: Legitimate Localhost Services (Should Auto-Allow)

**Test systemd-resolved:**
```bash
# Check if systemd-resolved is running
systemctl status systemd-resolved

# Test DNS query (should work without prompt)
nslookup google.com 127.0.0.53
dig @127.0.0.53 google.com
```

**Expected Result:** ✅ No prompt, DNS works automatically

**Test dnsmasq (if installed):**
```bash
# Check if dnsmasq is running
systemctl status dnsmasq

# Test DNS query
nslookup google.com 127.0.0.1
```

**Expected Result:** ✅ No prompt, DNS works automatically

---

### Test 1.2: Unknown Localhost Connections (Should Prompt)

**Test SSH tunnel (simulated malware bypass):**
```bash
# Create SSH tunnel to localhost
ssh -D 127.0.0.1:1080 localhost

# Try to use the tunnel (in another terminal)
curl --socks5 127.0.0.1:1080 http://example.com
```

**Expected Result:** ⚠️ Bastion should prompt for the SSH connection to localhost
**Action:** This is CORRECT behavior - malware often uses SSH tunnels to bypass firewalls

---

### Test 1.3: Development Tools Localhost IPC (Should Prompt Once)

**Test VSCode/IDE localhost communication:**
```bash
# Start VSCode or your IDE
code .
```

**Expected Result:** 
- ⚠️ May see 1 prompt for localhost IPC
- ✅ Click "Allow Always"
- ✅ No more prompts after that

---

## ✅ **PHASE 2: DHCP Hardening**

### Test 2.1: Legitimate DHCP (Should Auto-Allow)

**Test DHCP renewal:**
```bash
# Release and renew DHCP lease
sudo dhclient -r  # Release
sudo dhclient     # Renew

# OR for NetworkManager
sudo nmcli connection down <connection-name>
sudo nmcli connection up <connection-name>
```

**Expected Result:** ✅ No prompt, DHCP works automatically

**Verify in logs:**
```bash
sudo journalctl -u douane-firewall -n 50 | grep -i dhcp
```

**Expected Log:** `Auto-allowed: DHCP client: NetworkManager` or similar

---

### Test 2.2: Fake DHCP to Arbitrary IP (Should Block)

**Simulate malware DHCP exfiltration:**
```python
# Create test script: test_fake_dhcp.py
import socket

# Try to send "DHCP" to attacker IP (should be blocked)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"FAKE_DHCP_DATA", ("8.8.8.8", 67))  # Google DNS, not broadcast
```

**Expected Result:** 
- ⚠️ Should prompt (not auto-allowed)
- 🔴 Deny this - it's suspicious DHCP to non-broadcast IP

---

## ✅ **PHASE 3: Application Identification**

### Test 3.1: Identified Applications (Should Work Normally)

**Test Firefox/Chrome:**
```bash
firefox &
# Browse to https://google.com
```

**Expected Result:** 
- ⚠️ First time: Prompt for Firefox
- ✅ Click "Allow Always"
- ✅ Subsequent requests: No prompt

---

### Test 3.2: Short-lived Unidentified Process (Should Block)

**Simulate quick malware process:**
```bash
# Create and immediately delete a binary
cp /bin/curl /tmp/quick_malware
/tmp/quick_malware http://example.com &
rm /tmp/quick_malware
```

**Expected Result:** 
- ⚠️ Should prompt or block (app cannot be identified after deletion)
- 🔴 This is CORRECT - prevents malware from using short-lived processes

---

## ✅ **PHASE 4: String Matching Hardening**

### Test 4.1: Legitimate System Services (Should Auto-Allow)

**Test system DNS:**
```bash
# Normal DNS query via system resolver
ping google.com
host google.com
```

**Expected Result:** ✅ No prompt, works automatically

---

### Test 4.2: Spoofed Service Name (Should Block)

**Simulate malware with spoofed name:**
```bash
# Create fake systemd-resolved in /tmp
cp /bin/curl /tmp/systemd-resolved
chmod +x /tmp/systemd-resolved

# Try to make connection
/tmp/systemd-resolved http://example.com
```

**Expected Result:** 
- ⚠️ Should prompt (NOT auto-allowed)
- 🔴 Deny this - it's not in a system directory
- ✅ Check logs for warning: "Suspicious: systemd-resolved not in system path"

---

## ✅ **PHASE 5: Trusted App Port Restrictions**

### Test 5.1: Trusted App on Expected Port (Should Auto-Allow)

**Test systemd-resolved on port 53:**
```bash
# Normal DNS query
dig @127.0.0.53 google.com
```

**Expected Result:** ✅ No prompt, works automatically

---

### Test 5.2: Trusted App on Unexpected Port (Should Prompt)

This is harder to test without modifying system services, but the logic is:
- If systemd-resolved tries to connect to port 80 (HTTP) → Prompt
- If dhclient tries to connect to port 443 (HTTPS) → Prompt

**Manual verification:**
```bash
# Check the code in service_whitelist.py
grep -A 10 "TRUSTED_APP_PORTS" douane/service_whitelist.py
```

**Expected:** Each service has specific allowed ports only

---

## 🛡️ **INBOUND PROTECTION FEATURE**

### Test 6.1: Firewall Detection

**Open Control Panel:**
```bash
./douane_control_panel.py
```

**Steps:**
1. Click "Inbound Protection" tab
2. Click "Refresh Status"

**Expected Results:**

**If UFW is active:**
- ✅ Inbound Status: "✅ Active (UFW)"
- ✅ Recommendation: "Your system is protected!"

**If UFW is inactive:**
- ⚠️ Inbound Status: "⚠️ Not Detected"
- ⚠️ Recommendation: "UFW is installed but not active"
- ✅ Button enabled: "Enable UFW"

**If no firewall:**
- 🔴 Inbound Status: "⚠️ Not Detected"
- 🔴 Recommendation: "No inbound firewall detected"
- ✅ Button enabled: "Install & Configure UFW"

---

### Test 6.2: UFW Installation & Configuration

**Only if you want to test UFW setup:**

**Steps:**
1. In Control Panel → Inbound Protection tab
2. Click "Install & Configure UFW" (or "Enable UFW")
3. Enter password when prompted
4. Wait for completion

**Expected Result:**
- ✅ Success message
- ✅ UFW status changes to "Active"
- ✅ Recommendation shows "Your system is protected!"

**Verify UFW rules:**
```bash
sudo ufw status verbose
```

**Expected Output:**
```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
```

---

## 🧪 **INTEGRATION TESTS**

### Test 7: Normal Daily Usage

**Scenario: Typical desktop usage**
```bash
# 1. Start firewall
sudo systemctl start douane-firewall

# 2. Browse the web
firefox https://google.com &

# 3. Check email (if you use Thunderbird)
thunderbird &

# 4. Update system
sudo apt update

# 5. SSH to server
ssh user@example.com
```

**Expected Result:**
- ✅ First time: Prompts for each new app
- ✅ After "Allow Always": No more prompts
- ✅ Internet works normally
- ✅ No broken connections

---

### Test 8: Check Logs for Security Events

**View daemon logs:**
```bash
sudo journalctl -u douane-firewall -f
```

**Look for:**
- ✅ `Auto-allowed: Trusted service: systemd-resolved`
- ✅ `Auto-allowed: DHCP client: NetworkManager`
- ⚠️ `Suspicious: <app> not in system path` (if you ran spoofing tests)
- ⚠️ `Blocked: Unknown localhost connection` (if you ran tunnel tests)

---

## 📊 **TEST CHECKLIST**

- [ ] Phase 1.1: systemd-resolved localhost works
- [ ] Phase 1.2: SSH tunnel prompts (correct)
- [ ] Phase 1.3: IDE localhost IPC prompts once
- [ ] Phase 2.1: DHCP renewal works
- [ ] Phase 2.2: Fake DHCP prompts (correct)
- [ ] Phase 3.1: Firefox works after allow
- [ ] Phase 3.2: Short-lived process blocked (correct)
- [ ] Phase 4.1: System DNS works
- [ ] Phase 4.2: Spoofed name prompts (correct)
- [ ] Phase 5: Port restrictions in code verified
- [ ] Phase 6.1: Firewall detection works
- [ ] Phase 6.2: UFW setup works (optional)
- [ ] Test 7: Normal usage works
- [ ] Test 8: Logs show security events

---

## 🐛 **IF SOMETHING BREAKS**

**Internet completely broken:**
```bash
# Emergency: Stop firewall
sudo systemctl stop douane-firewall

# Check what's wrong
sudo journalctl -u douane-firewall -n 100

# Report issue with logs
```

**Too many prompts:**
- This is expected for first-time setup
- Click "Allow Always" for legitimate apps
- After initial setup, prompts should be rare

**Legitimate app blocked:**
- Check logs to see why
- May need to add to whitelist
- Report as bug if it's a common system service

---

## ✅ **SUCCESS CRITERIA**

1. ✅ All legitimate traffic works (DNS, DHCP, browsing, email)
2. ✅ Security tests correctly block/prompt for suspicious activity
3. ✅ No broken internet connections
4. ✅ Logs show security improvements working
5. ✅ Inbound protection feature detects firewall status
6. ✅ UFW setup works (if tested)

