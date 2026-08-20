# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities by opening a private security advisory on GitHub or contacting the maintainer directly.

## Security Model

Bastion uses privilege separation:
- **Daemon**: Runs as root for packet interception
- **GUI**: Runs as unprivileged user for display

### Control socket

Communication between the daemon and the GUI uses a Unix domain socket at
`/var/run/bastion/bastion-daemon.sock`. It is created with mode `0o660` and
owned `root:bastion`, so only root and members of the `bastion` group can
connect. On every connection the daemon additionally verifies the peer's
credentials via `SO_PEERCRED` and rejects any peer that is neither root nor a
member of the `bastion` group. If the peer credentials cannot be determined the
connection is rejected (fail closed). Only one GUI session may be connected at a
time; while one is active, further connection attempts are refused to prevent a
second process from hijacking the control channel.

### Fail-open vs. fail-closed filtering

By default the OUTPUT NFQUEUE rule is installed with `--queue-bypass` and the
daemon accepts any packet it cannot parse or inspect. This is **fail open**: if
the daemon stops or crashes, traffic keeps flowing so the machine is never
locked off the network.

Setting `"fail_closed": true` in `/etc/bastion/config.json` reverses this
trade-off:
- the NFQUEUE rule is installed **without** `--queue-bypass`, so if the daemon
  is not running, matching new connections are dropped rather than passed;
- in enforcement mode the daemon **drops** packets it cannot parse or inspect
  (malformed headers, unknown protocols) instead of accepting them.

Fail-closed is more secure but can interrupt connectivity if the daemon is down
or a packet is unusual; choose it only where that trade-off is acceptable. The
default remains fail open.

## Dependencies

The project uses eBPF (via BCC) for process identification. Ensure your kernel supports eBPF and that BCC is installed from trusted repositories.
