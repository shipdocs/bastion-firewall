# Contributing to Douane Firewall

Thank you for your interest in contributing to Douane Firewall! This document provides guidelines and information for developers who want to contribute to the project.

## Table of Contents

- [Development Setup](#development-setup)
- [Architecture Overview](#architecture-overview)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Development Setup

### Prerequisites

- Python 3.6 or higher
- Linux system (Ubuntu 20.04+ or Fedora 30+ recommended)
- Root access for testing firewall functionality
- Git for version control

### Setting Up Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/shipdocs/Douane-Application-firewall-for-Linux.git
   cd Douane-Application-firewall-for-Linux
   ```

2. **Install dependencies:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install python3-pip python3-tk python3-dev build-essential \
                        libnetfilter-queue-dev iptables ufw python3-gi \
                        gir1.2-ayatanaappindicator3-0.1

   # Fedora/RHEL
   sudo dnf install python3-pip python3-tkinter python3-devel gcc \
                    libnetfilter_queue-devel iptables python3-gobject

   # Install Python packages
   pip3 install --user psutil tabulate NetfilterQueue scapy pystray pillow
   ```

3. **Run tests:**
   ```bash
   python3 -m pytest tests/
   ```

4. **Test locally without installing:**
   ```bash
   # Terminal 1: Start daemon
   sudo python3 douane-daemon.py

   # Terminal 2: Start GUI client
   python3 douane-gui-client.py
   ```

## Architecture Overview

Douane follows a **client-server architecture** with privilege separation:

```
┌─────────────────────────────────────────────────────────────┐
│                     Douane Architecture                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │  GUI Client      │◄───────►│  Control Panel   │         │
│  │  (User Process)  │  Unix   │  (User Process)  │         │
│  │                  │  Socket │                  │         │
│  └────────┬─────────┘         └──────────────────┘         │
│           │                                                  │
│           │ Unix Socket (/var/run/douane.sock)             │
│           │                                                  │
│  ┌────────▼─────────────────────────────────────┐          │
│  │         Daemon (Root Process)                 │          │
│  │  ┌──────────────────────────────────────┐    │          │
│  │  │  Packet Processor                     │    │          │
│  │  │  - NetfilterQueue Integration         │    │          │
│  │  │  - Application Identification         │    │          │
│  │  │  - Service Whitelist                  │    │          │
│  │  └──────────────────────────────────────┘    │          │
│  │  ┌──────────────────────────────────────┐    │          │
│  │  │  Rules Engine                         │    │          │
│  │  │  - Rule Matching                      │    │          │
│  │  │  - Persistence                        │    │          │
│  │  └──────────────────────────────────────┘    │          │
│  └───────────────────┬──────────────────────────┘          │
│                      │                                       │
│                      │ iptables NFQUEUE                     │
│                      │                                       │
│  ┌───────────────────▼──────────────────────────┐          │
│  │         Linux Kernel (Netfilter)             │          │
│  └──────────────────────────────────────────────┘          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

1. **Daemon (`douane/daemon.py`)**
   - Runs as root for network access
   - Intercepts packets via NetfilterQueue
   - Manages rules and configuration
   - Communicates with GUI via Unix socket

2. **GUI Client (`douane/gui.py`)**
   - Runs as normal user
   - Shows popups for user decisions
   - Manages system tray icon
   - Sends decisions back to daemon

3. **Control Panel (`douane_control_panel.py`)**
   - Full-featured management interface
   - Tab-based UI (Status, Settings, Rules, Logs, Inbound)
   - Uses pkexec for privilege escalation

4. **Core Modules:**
   - `firewall_core.py`: Packet processing and app identification
   - `rules.py`: Rule management and persistence
   - `config.py`: Configuration management
   - `service_whitelist.py`: Smart whitelist for system services
   - `inbound_firewall.py`: UFW integration for inbound protection

## Code Style

### Python Style Guide

We follow **PEP 8** with some project-specific conventions:

- **Indentation**: 4 spaces (no tabs)
- **Line length**: 100 characters (soft limit), 120 (hard limit)
- **Imports**: Group in order: stdlib, third-party, local
- **Naming**:
  - Classes: `PascalCase`
  - Functions/methods: `snake_case`
  - Constants: `UPPER_SNAKE_CASE`
  - Private members: `_leading_underscore`

### Documentation

- **Docstrings**: Use Google-style docstrings for all public functions/classes
- **Comments**: Explain *why*, not *what* (code should be self-documenting)
- **Security**: Always document security-critical code sections

Example:
```python
def process_packet(self, packet_data: dict) -> bool:
    """Process an intercepted network packet.

    Args:
        packet_data: Dictionary containing packet information with keys:
            - src_ip: Source IP address
            - dest_ip: Destination IP address
            - dest_port: Destination port
            - protocol: Protocol (TCP/UDP)

    Returns:
        True if packet should be accepted, False if denied.

    Security:
        This function runs in the packet processing thread and must be
        thread-safe. All rule lookups use locks to prevent race conditions.
    """
    # Implementation
```

## Testing

### Test Structure

```
tests/
├── test_config.py          # Configuration management tests
├── test_daemon_logic.py    # Daemon logic tests
├── test_rules.py           # Rule engine tests
├── test_integration.py     # Integration tests (to be added)
└── test_gui.py            # GUI tests (to be added)
```

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/

# Run specific test file
python3 -m pytest tests/test_rules.py

# Run with coverage
python3 -m pytest --cov=douane tests/

# Run with verbose output
python3 -m pytest -v tests/
```

### Writing Tests

- **Unit tests**: Test individual functions in isolation
- **Integration tests**: Test component interactions
- **Security tests**: Verify security-critical functionality

Example test:
```python
def test_rule_matching():
    """Test that rules are matched correctly."""
    rules = RuleEngine()
    rules.add_rule("/usr/bin/firefox", "allow")

    assert rules.check_rule("/usr/bin/firefox", "1.1.1.1", 443) == "allow"
    assert rules.check_rule("/usr/bin/unknown", "1.1.1.1", 443) is None
```

### Manual Testing Checklist

Before submitting a PR, test these scenarios:

- [ ] Fresh installation on clean system
- [ ] Upgrade from previous version
- [ ] Daemon starts and stops cleanly
- [ ] GUI connects to daemon
- [ ] Popup appears for new connections
- [ ] Rules are persisted across restarts
- [ ] Control Panel shows correct status
- [ ] Uninstallation removes all files

## Submitting Changes

### Workflow

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make your changes:**
   - Write code following style guidelines
   - Add tests for new functionality
   - Update documentation

3. **Test your changes:**
   ```bash
   python3 -m pytest tests/
   ./build_deb.sh  # Test packaging
   ```

4. **Commit with descriptive message:**
   ```bash
   git commit -m "Add feature: Brief description

   - Detailed point 1
   - Detailed point 2

   Fixes #123"
   ```

5. **Push and create Pull Request:**
   ```bash
   git push origin feature/my-new-feature
   ```

### Commit Message Format

Use conventional commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Example:**
```
feat(daemon): Add eBPF packet filtering support

- Implement eBPF program for kernel-level filtering
- Add fallback to NetfilterQueue for older kernels
- Update documentation with eBPF requirements

Closes #456
```

### Pull Request Guidelines

- **Title**: Clear and descriptive
- **Description**: Explain what and why, not how
- **Tests**: Include test results
- **Documentation**: Update relevant docs
- **Breaking changes**: Clearly mark and explain

## Release Process

### Version Numbering

We use **Semantic Versioning** (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backwards compatible)
- **PATCH**: Bug fixes

### Release Checklist

1. **Update version numbers:**
   - `debian/DEBIAN/control`
   - `douane.spec`
   - `setup.py`

2. **Update documentation:**
   - `RELEASE_NOTES.md`
   - `README.md` (Latest Updates section)
   - `index.html` (hero badges)

3. **Run full test suite:**
   ```bash
   python3 -m pytest tests/
   ./build_deb.sh
   sudo dpkg -i douane-firewall_*.deb
   # Manual testing
   ```

4. **Create git tag:**
   ```bash
   git tag -a v2.0.19 -m "Release v2.0.19 - Description"
   git push origin v2.0.19
   ```

5. **Build packages:**
   ```bash
   ./build_deb.sh  # Debian package
   ./build_rpm.sh  # RPM package (if available)
   ```

6. **Create GitHub Release:**
   - Upload packages
   - Copy release notes
   - Mark as latest release

## Development Guidelines

### Security Considerations

- **Input validation**: Always validate user input and packet data
- **Privilege separation**: Keep root code minimal
- **Thread safety**: Use locks for shared data structures
- **Fail-closed**: Default to deny on errors
- **Logging**: Log security-relevant events

### Performance Best Practices

- **Minimize packet processing**: Cache decisions when possible
- **Efficient lookups**: Use dictionaries for O(1) rule lookups
- **Avoid blocking**: Use threads for I/O operations
- **Resource cleanup**: Always close sockets and files

### Common Pitfalls

1. **Race conditions**: Always use locks when accessing shared state
2. **Socket errors**: Handle disconnections gracefully
3. **GUI freezing**: Never block GUI thread with long operations
4. **Memory leaks**: Clean up packet data after processing
5. **Privilege escalation**: Validate all data from user processes

## Getting Help

- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact maintainer at shipdocs@users.noreply.github.com

## License

By contributing to Douane Firewall, you agree that your contributions will be licensed under the GPLv3 license.

---

Thank you for contributing to Douane Firewall! 🚀
            - src_ip: Source IP address
            - dest_ip: Destination IP address
            - dest_port: Destination port
            - protocol: Protocol (TCP/UDP)

    Returns:
        True if packet should be accepted, False if denied.

    Security:
        This function runs in the packet processing thread and must be
        thread-safe. All rule lookups use locks to prevent race conditions.
    """
    # Implementation
```


