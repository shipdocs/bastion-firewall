# UFW Firewall GUI - Implementation Guide

## Overview

This project implements a GUI-based firewall for Linux that monitors outbound network connections and provides interactive allow/deny dialogs, integrating with UFW (Uncomplicated Firewall).

## Problem Statement

Linux by default allows all outbound connections, which can be a security risk. This tool addresses that by:
- Monitoring outbound network connection attempts
- Showing popup dialogs for user decisions
- Integrating with UFW to persist firewall rules
- Providing per-application network control

## Architecture

### Components

1. **Network Monitor** (`ufw_firewall_gui.py`)
   - Uses netfilter queue to intercept outbound packets
   - Identifies the application making the connection
   - Presents GUI dialogs for user decision

3. **Internal Rule Engine**
   - Manages whitelist and blacklist internally
   - Persists rules to JSON storage
   - Decoupled from UFW (avoids port conflicts)

2. **UFW Coexistence**
   - UFW handles Inbound traffic
   - UFW set to "Allow Outbound" (Pass-through)
   - Bastion handles Outbound filtering via NFQUEUE

4. **GUI System**
   - Tkinter-based popup dialogs
   - Shows application name, destination IP, and port
   - Options to allow/deny temporarily or permanently

### Technical Approach

#### Network Monitoring
- Uses `iptables` NFQUEUE target to queue packets for userspace processing
- Python `NetfilterQueue` library to process queued packets
- `/proc/net/tcp` and `/proc/<pid>/cmdline` to identify applications

#### Internal Rule Management
- Rules stored in `/etc/douane/rules.json`
- In-memory caching for performance
- Application-based matching (Path + Port)
- No dependency on system firewall rule syntax

## System Requirements

- Linux operating system with kernel netfilter support
- Python 3.6+
- UFW installed and enabled
- Root/sudo privileges (required for packet inspection)
- X11 or Wayland display server (for GUI)

## Dependencies

- `python3-tk` - Tkinter GUI framework
- `NetfilterQueue` - Python bindings for libnetfilter_queue
- `scapy` - Packet manipulation library
- `psutil` - Process and system utilities

## Security Considerations

1. **Root Privileges**: The application requires root access to:
   - Monitor network packets
   - Modify iptables/UFW rules
   - Read process information

2. **Default Policy**: UFW's default outbound policy should be set to allow initially
   - The application intercepts and prompts for specific connections
   - Users can gradually build their ruleset

3. **Race Conditions**: Connection attempts are queued, preventing bypass

4. **Logging**: All decisions are logged for audit purposes

## Limitations

1. **Performance**: Inspecting every outbound packet adds overhead
2. **GUI Requirement**: Requires active X session (not suitable for headless servers)
3. **Application Identification**: May not work perfectly for all applications
4. **Existing Connections**: Only new connections trigger prompts

## Future Enhancements

- Rule learning mode
- Network activity dashboard
- Application groups/profiles
- Temporary time-based rules
- Integration with application reputation systems
- Support for systemd socket activation
