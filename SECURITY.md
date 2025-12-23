# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities by opening a private security advisory on GitHub or contacting the maintainer directly.

## Security Model

Bastion uses privilege separation:
- **Daemon**: Runs as root for packet interception
- **GUI**: Runs as unprivileged user for display

Communication between components uses a Unix domain socket with restricted permissions.

## Dependencies

The project uses eBPF (via BCC) for process identification. Ensure your kernel supports eBPF and that BCC is installed from trusted repositories.
