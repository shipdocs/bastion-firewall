# Douane Usage Examples

## Quick Start

### 1. Installation

```bash
# Install dependencies
pip3 install -r requirements.txt

# For full installation (requires root)
sudo bash install.sh
```

### 2. Test the Installation

```bash
# Run basic tests (no GUI)
python3 test_douane.py

# Test the GUI dialog (requires display)
./douane_gui.py --test
```

### 3. Start the Daemon

```bash
# Start in foreground (requires root for full monitoring)
sudo ./douane_daemon.py

# Or use systemd (after installation)
sudo systemctl start douane
```

## Command-Line Interface (CLI)

The `douane_cli.py` tool lets you manage rules from the command line.

### List All Rules

```bash
./douane_cli.py list
```

Output:
```
+-------------+------------+----------+---------------------+---------------------+
| Application | Permission | Duration | Created             | Updated             |
+=============+============+==========+=====================+=====================+
| firefox     | ALLOW      | always   | 2025-12-15 10:30:00 | 2025-12-15 10:30:00 |
+-------------+------------+----------+---------------------+---------------------+
| curl        | DENY       | always   | 2025-12-15 10:31:00 | 2025-12-15 10:31:00 |
+-------------+------------+----------+---------------------+---------------------+
```

### Add a Rule

```bash
# Always allow Firefox
./douane_cli.py add /usr/bin/firefox allow always

# Deny curl this time only
./douane_cli.py add /usr/bin/curl deny once
```

### Delete a Rule

```bash
./douane_cli.py delete /usr/bin/firefox
```

### View Connection Logs

```bash
# Show last 50 connections (default)
./douane_cli.py logs

# Show last 100 connections
./douane_cli.py logs --limit 100
```

Output:
```
+-------------+------------------+------+----------+--------+---------------------+
| Application | Destination      | Port | Protocol | Action | Time                |
+=============+==================+======+==========+========+=====================+
| firefox     | 93.184.216.34    | 443  | tcp      | ALLOW  | 2025-12-15 10:35:22 |
+-------------+------------------+------+----------+--------+---------------------+
| curl        | 192.168.1.1      | 80   | tcp      | DENY   | 2025-12-15 10:36:15 |
+-------------+------------------+------+----------+--------+---------------------+
```

### Show Statistics

```bash
./douane_cli.py stats
```

Output:
```
=== Douane Statistics ===

Rules:
  Total:   5
  Allowed: 3
  Denied:  2

Connections:
  Total:   142
  Allowed: 98
  Denied:  44
```

### Clear Logs

```bash
./douane_cli.py clear-logs
```

## GUI Examples

### Show Permission Dialog

The GUI can be invoked programmatically:

```bash
./douane_gui.py \
  --app-name "firefox" \
  --exe-path "/usr/bin/firefox" \
  --dest-ip "93.184.216.34" \
  --port 443
```

This will display a popup dialog and output the user's decision as JSON:

```json
{
  "permission": "allow",
  "duration": "always",
  "exe_path": "/usr/bin/firefox"
}
```

## Real-World Scenarios

### Scenario 1: First-Time Setup

1. Start the daemon:
   ```bash
   sudo ./douane_daemon.py
   ```

2. Open your web browser (e.g., Firefox)
3. A popup appears asking for permission
4. Choose "Allow" + "Always" so Firefox can access any website
5. Browse normally - no more prompts for Firefox

### Scenario 2: Testing an Application

1. You're testing a new application and want temporary access:
   ```bash
   # Run your application
   ./my-test-app
   ```

2. When the popup appears:
   - Choose "Allow" + "This time only"
   - The app can connect for this session
   - Next time, you'll be asked again

### Scenario 3: Blocking Suspicious Software

1. An unknown application tries to connect
2. Review the popup information:
   - Application name
   - Executable path
   - Destination IP and port
3. If suspicious:
   - Choose "Deny" + "Always"
   - The application is permanently blocked

### Scenario 4: Managing Rules

```bash
# List all current rules
./douane_cli.py list

# Remove a rule you no longer need
./douane_cli.py delete /path/to/app

# Add a rule manually without waiting for popup
./douane_cli.py add /usr/bin/wget allow always
```

### Scenario 5: Auditing Connections

```bash
# View recent connection attempts
./douane_cli.py logs --limit 100

# Check which applications were denied
./douane_cli.py logs | grep DENY

# Get statistics on network usage
./douane_cli.py stats
```

## Integration with Other Tools

### Using with systemd

```bash
# Enable automatic start on boot
sudo systemctl enable douane

# Start the service
sudo systemctl start douane

# Check status
sudo systemctl status douane

# View logs
sudo journalctl -u douane -f
```

### Scripting

You can script the daemon and GUI:

```python
#!/usr/bin/env python3
from douane_daemon import RulesDatabase
from pathlib import Path

# Add rules programmatically
db = RulesDatabase(Path.home() / ".config/douane/rules.db")
db.set_rule("/usr/bin/firefox", "allow", "always")
db.set_rule("/usr/bin/curl", "allow", "always")
print("Rules added successfully!")
```

## Configuration Files

All configuration is stored in `~/.config/douane/`:

- `rules.db` - SQLite database with rules and logs
- `douane.log` - Daemon log file
- `douane-gui.log` - GUI log file

## Tips and Best Practices

1. **Start with "This time only"**: When unsure, use temporary permissions
2. **Review logs regularly**: Check `douane_cli.py logs` to see connection patterns
3. **Use "Always allow" for trusted apps**: Avoid repeated prompts for known applications
4. **Block by default**: Deny unknown applications and investigate before allowing
5. **Clean up old rules**: Periodically review and remove unused rules

## Troubleshooting

### Daemon not detecting connections

- Ensure running as root: `sudo ./douane_daemon.py`
- Check logs: `tail -f ~/.config/douane/douane.log`

### GUI not appearing

- Check if GTK3 is installed: `python3 -c "import gi; gi.require_version('Gtk', '3.0')"`
- Install if missing: `sudo apt-get install python3-gi gir1.2-gtk-3.0`

### Database locked errors

- Only one instance of the daemon should run
- Check for hung processes: `ps aux | grep douane`

## Next Steps

- Explore the source code to understand the implementation
- Customize the GUI dialog appearance
- Add additional features like network statistics
- Integrate with system notifications
