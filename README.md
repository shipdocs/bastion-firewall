<p align="center">
  <a href="http://blog.zedroot.org/" target="_blank">
    <img src="https://gitlab.com/zedtux/gpair/raw/master/media/developpeur_breton_logo.png" alt="Je suis un developpeyr Breton!"/>
  </a>
</p>

# UFW Firewall GUI

A modern firewall GUI for Linux that monitors outbound network connections and provides interactive allow/deny dialogs with UFW integration.

> **Note**: The original Douane project has moved to GitLab at https://gitlab.com/douaneapp/Douane. This repository now contains a new UFW-based implementation.

## Features

- 🔍 **Monitor Outbound Connections**: Track all outbound network requests in real-time
- 🖱️ **Interactive Dialogs**: Get popup prompts to allow or deny connections
- 🛡️ **UFW Integration**: Store decisions as persistent UFW firewall rules
- 🎯 **Per-Application Control**: Manage network access on a per-application basis
- 📝 **Audit Logging**: Keep track of all firewall decisions

## Why This Tool?

Linux by default allows all outbound connections. While convenient, this can be a security risk in modern times where:
- Malware can phone home
- Applications can track usage without consent
- Data exfiltration is a real threat

This tool helps you control what applications can access the network.

## Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk ufw iptables

# Enable UFW if not already enabled
sudo ufw enable
```

### Installation

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Try the component demo (no root required)
python3 demo.py

# Run the firewall GUI (requires root)
sudo python3 ufw_firewall_gui.py
```

### Basic Usage

1. **Start the application** with sudo privileges
2. **Make a network request** from any application
3. **Review the popup** showing the application and destination
4. **Choose an action**:
   - **Allow Once**: Permit this connection only
   - **Allow Always**: Add UFW rule to always allow
   - **Deny Once**: Block this connection only
   - **Deny Always**: Add UFW rule to always block

## Configuration

Edit `config.json` to customize:
- Default action timeout
- Logging preferences
- GUI appearance
- Rule matching criteria

## System Requirements

- Linux with kernel 3.0+
- Python 3.6 or higher
- UFW (Uncomplicated Firewall)
- X11 or Wayland display server
- Root/sudo privileges

## Security Notice

⚠️ **This tool requires root privileges** to:
- Monitor network packets via netfilter
- Modify firewall rules
- Read process information

Only run if you understand the security implications.

## Documentation

- [Implementation Guide](IMPLEMENTATION.md) - Technical details and architecture
- [FAQ](FAQ.md) - Common questions and troubleshooting

## Contributing

This is a community-driven project. Contributions are welcome!

## License

See LICENSE file for details.

## Disclaimer

This tool is provided as-is for educational and security purposes. The authors are not responsible for any damage or data loss resulting from its use. Always test in a safe environment first.
