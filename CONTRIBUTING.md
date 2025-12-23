# Contributing to Bastion Firewall

## Development Setup

```bash
git clone https://github.com/shipdocs/bastion-firewall.git
cd bastion-firewall

# Install dependencies
sudo apt-get install python3-pip python3-dev build-essential \
    libnetfilter-queue-dev iptables python3-gi python3-bcc \
    gir1.2-ayatanaappindicator3-0.1
pip3 install -r requirements.txt

# Run tests
pytest tests/
```

## Project Structure

```
bastion/
├── daemon.py          # Root daemon (packet interception)
├── gui.py             # GUI client (user prompts)
├── gui_manager.py     # GUI/daemon coordination
├── ebpf.py            # eBPF process identification
├── firewall_core.py   # Packet processing
├── rules.py           # Rule storage
└── config.py          # Configuration
```

## Code Style

- Follow PEP 8
- 4 spaces for indentation
- 100 character line limit
- Google-style docstrings

## Testing

```bash
pytest tests/
pytest tests/test_rules.py -v  # Single file
```

## Submitting Changes

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Run tests: `pytest tests/`
3. Commit with conventional commits: `feat(scope): description`
4. Open a pull request

## Building

```bash
./build_deb.sh
sudo dpkg -i bastion-firewall_*.deb
```

## License

Contributions are licensed under GPL-3.0.
