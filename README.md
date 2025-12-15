<p align="center">
  <a href="http://blog.zedroot.org/" target="_blank">
    <img src="https://gitlab.com/zedtux/gpair/raw/master/media/developpeur_breton_logo.png" alt="Je suis un developpeyr Breton!"/>
  </a>
</p>

# UFW Firewall GUI

Douane is an intelligent application firewall that filters and limits outgoing network traffic **per application**, not per IP address.

## Features

✨ **Smart Per-Application Control** - Filter network access by application, not IP address
- Your web browser can access multiple sites without separate rules
- Each application gets its own permission

🔔 **Interactive Popup Dialogs** - Get asked when an application wants to connect
- Clear information about which app is requesting access
- See the destination IP and port
- Make informed decisions in real-time

⏱️ **Flexible Permission Duration**
- **Once**: Allow/deny this specific connection only
- **Always**: Remember the decision for this application

🧠 **Smart Decision Logic**
- Rules are cached and applied automatically
- "Once" rules expire after use
- "Always" rules persist across sessions
- Connections are logged for audit purposes

## Architecture

Douane consists of two main components:

1. **douane_daemon.py** - Background service that monitors network connections
   - Monitors all outgoing network connections in real-time
   - Identifies which application is making each connection
   - Applies stored rules or requests user permission
   - Logs all connection attempts

2. **douane_gui.py** - GTK3-based popup dialog for permission requests
   - Shows when an application requests internet access
   - Displays application name, executable path, and destination
   - Allows user to allow/deny with "once" or "always" duration

## Installation

### Requirements
- Python 3.6+
- GTK3
- psutil library

### Install on Ubuntu/Debian

```bash
# Clone the repository
git clone https://github.com/shipdocs/Douane.git
cd Douane

# Run the installation script
sudo bash install.sh
```

### Manual Installation

```bash
# Install system dependencies
sudo apt-get install python3 python3-pip python3-gi gir1.2-gtk-3.0

# Install Python dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x douane_daemon.py douane_gui.py
```

## Usage

### Start the Daemon

The daemon must run as root to monitor network connections:

```bash
sudo ./douane_daemon.py
```

Or if installed system-wide:

```bash
sudo douane-daemon
```

### Using systemd (after installation)

```bash
# Enable the service to start on boot
sudo systemctl enable douane

# Start the service
sudo systemctl start douane

# Check status
sudo systemctl status douane

# View logs
sudo journalctl -u douane -f
```

### Test the GUI

Test the permission dialog without running the daemon:

```bash
./douane_gui.py --test
```

## How It Works

1. **Connection Detection**: The daemon continuously monitors network connections using psutil
2. **Application Identification**: When a new connection is detected, the daemon identifies the application
3. **Rule Lookup**: Checks if there's an existing rule for the application
4. **User Prompt**: If no rule exists, shows a popup dialog asking for permission
5. **Rule Application**: The user's decision is stored and applied to future connections
6. **Smart Caching**: "Once" rules are applied immediately then deleted, "Always" rules persist

## Configuration

Rules and logs are stored in: `~/.config/douane/`

- `rules.db` - SQLite database containing application rules
- `douane.log` - Daemon logs
- `douane-gui.log` - GUI logs

## Examples

### Example 1: Web Browser
When Firefox tries to connect to a website, you'll get a popup:
- **Application**: firefox
- **Connecting to**: 93.184.216.34:443

Choose "Always allow" so Firefox can access any website without repeated prompts.

### Example 2: Unknown Application
When an unknown application tries to connect:
- Review the executable path
- Check the destination
- Choose "Once" if you're unsure
- Choose "Deny" + "Always" to permanently block it

## Development Status

This is an active implementation of per-application firewall functionality. The current implementation provides:

✅ Application-level network monitoring
✅ Interactive permission dialogs
✅ Rule database with "once" and "always" support
✅ Connection logging
✅ Smart rule caching

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

See LICENSE file for details.

## Links

- Original project (moved): [GitLab](https://gitlab.com/douaneapp/Douane)
