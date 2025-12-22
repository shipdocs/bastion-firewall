# Security Best Practices for Bastion Firewall

This document provides security guidance for administrators and users of Bastion Firewall.

## Table of Contents

1. [Installation Security](#installation-security)
2. [Configuration Hardening](#configuration-hardening)
3. [Operational Security](#operational-security)
4. [Monitoring and Auditing](#monitoring-and-auditing)
5. [Incident Response](#incident-response)
6. [Security Updates](#security-updates)

---

## Installation Security

### System Requirements

- **Operating System**: Zorin OS 18 or Ubuntu 24.04 LTS (recommended)
- **Kernel**: Linux 5.0+ with netfilter support
- **Python**: 3.8+ (3.10+ recommended)
- **User Privileges**: Root access required for daemon installation

### Secure Installation Steps

1. **Verify Package Integrity**
   ```bash
   # Check package signature (if available)
   gpg --verify bastion-firewall_1.3.2_all.deb.sig
   
   # Verify checksums
   sha256sum bastion-firewall_1.3.2_all.deb
   ```

2. **Install from Trusted Sources Only**
   ```bash
   # Official repository installation (recommended)
   sudo apt update
   sudo apt install bastion-firewall
   
   # OR from verified GitHub release
   wget https://github.com/shipdocs/bastion-firewall/releases/download/v1.3.2/bastion-firewall_1.3.2_all.deb
   sudo dpkg -i bastion-firewall_1.3.2_all.deb
   ```

3. **Create Bastion Group**
   ```bash
   # The bastion group controls socket access
   sudo groupadd bastion
   
   # Add authorized users to the group
   sudo usermod -a -G bastion $USER
   
   # Log out and back in for group changes to take effect
   ```

4. **Verify File Permissions**
   ```bash
   # Config files should be readable by root only
   sudo chmod 600 /etc/bastion/config.json
   sudo chmod 600 /etc/bastion/rules.json
   
   # Socket should be group-accessible only
   ls -la /tmp/bastion-daemon.sock  # Should show: srw-rw---- root bastion
   
   # Log directory should be restricted
   sudo chmod 750 /var/log/bastion
   ```

---

## Configuration Hardening

### Daemon Configuration

Edit `/etc/bastion/config.json` with security-focused settings:

```json
{
  "mode": "learning",              // Start in learning mode for initial setup
  "cache_decisions": true,          // Enable for performance
  "default_action": "deny",         // Deny by default (fail-secure)
  "timeout_seconds": 30,            // Reasonable timeout (5-300 seconds)
  "allow_localhost": true,          // Allow localhost DNS (required)
  "allow_lan": false,               // Disable LAN auto-allow (more secure)
  "log_decisions": true             // Enable for auditing
}
```

**Security Notes:**
- **Never set `timeout_seconds` to 0** - this disables timeout and can hang the system
- **Start in `learning` mode** - prevents breaking your system during initial configuration
- **Keep `default_action: deny`** - fail-secure principle
- **Disable `allow_lan`** - only enable if you explicitly trust your local network

### Service Whitelist

Review and customize `/etc/bastion/service_whitelist.py`:

```python
# Only whitelist services you actually use
SERVICE_WHITELIST = {
    53: ['systemd-resolved'],      # DNS only (remove dnsmasq if not used)
    123: ['systemd-timesyncd'],    # NTP only (remove ntpd/chronyd if not used)
    # Remove DHCP if using static IP
    # 67: ['dhclient', 'NetworkManager'],
    # 68: ['dhclient', 'NetworkManager'],
}
```

**Principle:** Minimize the whitelist to reduce attack surface.

### Rule Management

```bash
# Review rules regularly
sudo cat /etc/bastion/rules.json

# Remove suspicious rules
sudo vim /etc/bastion/rules.json
# Then reload
sudo kill -HUP $(pgrep bastion-daemon)

# Or use the control panel
bastion-control-panel
```

**Warning Signs:**
- Rules for applications in `/tmp` or `/home` directories
- Rules for unknown applications
- Excessive "allow all" rules

---

## Operational Security

### Principle of Least Privilege

1. **Limit Bastion Group Membership**
   ```bash
   # Only add users who need firewall control
   sudo gpasswd -d untrusted_user bastion
   ```

2. **Review Decisions Carefully**
   - **Never blindly click "Allow Always"**
   - Verify application path is legitimate
   - Check destination IP/port makes sense
   - Research unknown applications before allowing

3. **Use Learning Mode Initially**
   ```bash
   # Start in learning mode
   bastion-control-panel  # Set mode to "Learning"
   
   # After configuration stabilizes, switch to enforcement
   bastion-control-panel  # Set mode to "Enforcement"
   ```

### Network Segmentation

Combine Bastion with other security layers:

```bash
# 1. Inbound firewall (UFW)
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing  # Bastion handles outbound

# 2. Bastion for outbound control
sudo systemctl start bastion-firewall

# 3. AppArmor/SELinux for application confinement
sudo aa-enforce /etc/apparmor.d/*
```

### Secure Remote Access

If managing Bastion remotely:

```bash
# SSH with key authentication only
sudo vim /etc/ssh/sshd_config
# Set: PasswordAuthentication no
#      PermitRootLogin no

# Use SSH port forwarding for GUI
ssh -L 6000:localhost:6000 user@remote-host
DISPLAY=localhost:0 bastion-control-panel
```

---

## Monitoring and Auditing

### Log Analysis

1. **Regular Log Review**
   ```bash
   # View recent decisions
   sudo tail -100 /var/log/bastion-daemon.log
   
   # Search for denied connections
   sudo grep "decision: deny" /var/log/bastion-daemon.log
   
   # Find unknown applications
   sudo grep "Unknown Application" /var/log/bastion-daemon.log
   ```

2. **Automated Monitoring**
   ```bash
   # Create log analysis script
   cat > /usr/local/bin/bastion-audit.sh << 'EOF'
   #!/bin/bash
   LOG="/var/log/bastion-daemon.log"
   
   echo "=== Bastion Security Audit ==="
   echo "Suspicious patterns in last 24 hours:"
   
   # Check for applications in /tmp
   grep -c "/tmp/" "$LOG" | grep -v "^0$" && \
     echo "WARNING: Connections from /tmp detected"
   
   # Check for rate limiting
   grep -c "Rate limit exceeded" "$LOG" | grep -v "^0$" && \
     echo "WARNING: Rate limiting triggered (possible DoS)"
   
   # Check for unknown apps
   grep -c "Unknown Application" "$LOG" | grep -v "^0$" && \
     echo "INFO: Unknown applications detected"
   
   echo "=== End Audit ==="
   EOF
   
   chmod +x /usr/local/bin/bastion-audit.sh
   
   # Run daily via cron
   echo "0 0 * * * /usr/local/bin/bastion-audit.sh | mail -s 'Bastion Audit' admin@example.com" | sudo crontab -
   ```

3. **SIEM Integration**
   ```bash
   # Forward logs to syslog
   sudo rsyslog -i /var/log/bastion-daemon.log -t bastion-firewall
   
   # Or use filebeat for Elasticsearch
   sudo apt install filebeat
   # Configure filebeat to send to your SIEM
   ```

### Performance Monitoring

```bash
# Check daemon health
sudo systemctl status bastion-firewall

# Monitor resource usage
top -p $(pgrep bastion-daemon)

# Check rate limiter stats
sudo grep "Rate limit" /var/log/bastion-daemon.log | tail -20
```

---

## Incident Response

### Signs of Compromise

1. **Firewall Disabled Unexpectedly**
   ```bash
   # Check if firewall is running
   sudo systemctl is-active bastion-firewall
   
   # If stopped, check who stopped it
   sudo journalctl -u bastion-firewall | grep "Stopped"
   ```

2. **Suspicious Rules Added**
   ```bash
   # Check for rules allowing /tmp or unusual paths
   sudo jq 'to_entries[] | select(.key | contains("/tmp"))' /etc/bastion/rules.json
   
   # Check rule modification time
   stat /etc/bastion/rules.json
   ```

3. **Unusual Connection Patterns**
   ```bash
   # High volume of connections
   sudo grep -c "connection_request" /var/log/bastion-daemon.log
   
   # Connections to suspicious ports
   sudo grep ":6666\|:4444\|:31337" /var/log/bastion-daemon.log
   ```

### Response Procedures

1. **Immediate Actions**
   ```bash
   # Switch to enforcement mode
   bastion-control-panel  # Set mode to "Enforcement"
   
   # Disconnect network if severely compromised
   sudo ifdown eth0
   
   # Backup evidence
   sudo cp /etc/bastion/rules.json /tmp/rules-backup-$(date +%s).json
   sudo cp /var/log/bastion-daemon.log /tmp/daemon-log-backup-$(date +%s).log
   ```

2. **Investigation**
   ```bash
   # Review all rules
   sudo cat /etc/bastion/rules.json | jq .
   
   # Check for malicious processes
   sudo ps aux | grep -E "/tmp|/dev/shm"
   
   # Review network connections
   sudo netstat -tunap
   ```

3. **Remediation**
   ```bash
   # Clear all rules (nuclear option)
   echo "{}" | sudo tee /etc/bastion/rules.json
   sudo kill -HUP $(pgrep bastion-daemon)
   
   # Restart in learning mode
   bastion-control-panel  # Set mode to "Learning"
   
   # Rebuild rules carefully
   # Use the GUI to approve only known applications
   ```

---

## Security Updates

### Update Policy

1. **Subscribe to Security Advisories**
   - Watch GitHub repository: https://github.com/shipdocs/bastion-firewall
   - Subscribe to release notifications
   - Follow @bastionfw on Twitter (if available)

2. **Regular Update Schedule**
   ```bash
   # Check for updates weekly
   sudo apt update
   sudo apt list --upgradable | grep bastion
   
   # Install security updates promptly
   sudo apt upgrade bastion-firewall
   
   # Verify version
   bastion-daemon --version
   ```

3. **Emergency Updates**
   ```bash
   # For critical security patches, update immediately:
   sudo apt update && sudo apt install bastion-firewall
   sudo systemctl restart bastion-firewall
   ```

### Rollback Procedure

If an update causes issues:

```bash
# 1. Stop the service
sudo systemctl stop bastion-firewall

# 2. Reinstall previous version
sudo apt install bastion-firewall=1.3.1

# 3. Prevent auto-upgrade
sudo apt-mark hold bastion-firewall

# 4. Report issue
# Visit: https://github.com/shipdocs/bastion-firewall/issues

# 5. Once fixed, remove hold
sudo apt-mark unhold bastion-firewall
```

---

## Security Checklist

Use this checklist for regular security reviews:

- [ ] Bastion group has minimal membership
- [ ] Config file permissions are 600 (root only)
- [ ] Rules file permissions are 600 (root only)
- [ ] Socket permissions are 660 (root:bastion)
- [ ] Logs are reviewed weekly
- [ ] Unknown applications are investigated
- [ ] No rules exist for `/tmp` or `/home` applications
- [ ] Whitelist is minimized to only used services
- [ ] System is up to date (bastion-firewall package)
- [ ] Backup of rules exists
- [ ] Incident response plan is tested
- [ ] UFW is enabled for inbound protection
- [ ] AppArmor/SELinux is active
- [ ] Rate limiting is functioning (check logs)
- [ ] No symlinks exist at config/rules paths
- [ ] Daemon starts automatically at boot

---

## Contact

For security issues:
- **Email**: security@bastionfw.org (if available)
- **GitHub**: https://github.com/shipdocs/bastion-firewall/security
- **CVE**: Report to MITRE for CVE assignment

For general support:
- **Documentation**: https://github.com/shipdocs/bastion-firewall
- **Issues**: https://github.com/shipdocs/bastion-firewall/issues
- **Community**: (Discord/Forum if available)

---

**Last Updated:** 2025-12-22  
**Version:** 1.0  
**Applies to:** Bastion Firewall v1.3.2+
