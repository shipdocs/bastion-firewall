# ✅ Clean Start/Stop Fixed

## Problem

When stopping the Douane Firewall, iptables NFQUEUE rules were left behind, causing:
- WiFi shows connected but with question mark
- No internet access
- Only rebooting would fix it

## Root Cause

1. **Missing cleanup function** - `IPTablesManager.cleanup_nfqueue()` was called but didn't exist
2. **No signal handlers** - Daemon didn't clean up on Ctrl+C or kill
3. **Single rule removal** - Only tried to remove the rule once, but duplicates could exist

## Solution

### 1. Added Aggressive Cleanup Function

**File: `firewall_core.py`**

New `cleanup_nfqueue()` method that:
- Tries to remove the rule multiple times (handles duplicates)
- Lists all OUTPUT rules and removes any NFQUEUE rules found
- Logs how many rules were removed
- Ensures complete cleanup

### 2. Added Signal Handlers

**File: `douane-daemon.py`**

Added handlers for:
- `SIGINT` (Ctrl+C)
- `SIGTERM` (kill command)
- `atexit` (backup cleanup)
- Exception handling

Now the daemon ALWAYS cleans up iptables rules on exit.

### 3. Created Clean Start/Stop Scripts

**`douane-start.sh`**
- Ensures clean state before starting
- Removes any leftover iptables rules
- Tests connectivity before starting
- Starts GUI client (which starts daemon)
- Verifies it's running

**`douane-stop.sh`**
- Stops GUI client
- Stops daemon
- Removes socket file
- Aggressively removes ALL NFQUEUE rules
- Ensures UFW allows outbound
- Tests connectivity after stopping
- Shows verification commands

## Usage

### Start the Firewall
```bash
./douane-start.sh
```

### Stop the Firewall
```bash
./douane-stop.sh
```

### Verify Clean State
```bash
# Should show nothing
sudo iptables -L OUTPUT -n | grep NFQUEUE

# Should work
ping google.com
```

## Emergency Recovery

If your connection is still broken after stopping:

```bash
# Remove all OUTPUT rules
sudo iptables -F OUTPUT

# Reload UFW
sudo ufw reload

# Test
ping google.com
```

## Testing

1. **Start the firewall**
   ```bash
   ./douane-start.sh
   ```

2. **Verify it's running**
   ```bash
   ps aux | grep douane
   sudo iptables -L OUTPUT -n | grep NFQUEUE  # Should show 1 rule
   ```

3. **Stop the firewall**
   ```bash
   ./douane-stop.sh
   ```

4. **Verify clean state**
   ```bash
   sudo iptables -L OUTPUT -n | grep NFQUEUE  # Should show nothing
   ping google.com  # Should work
   ```

5. **Test Ctrl+C cleanup**
   ```bash
   ./douane-start.sh
   # Press Ctrl+C in the terminal
   sudo iptables -L OUTPUT -n | grep NFQUEUE  # Should show nothing
   ```

## What Changed

### Before
- Daemon crashed → iptables rules left behind → no internet
- Had to reboot to fix

### After
- Daemon exits cleanly → iptables rules removed → internet works
- Can start/stop safely without breaking connection

## Files Modified

1. **`firewall_core.py`** - Added `cleanup_nfqueue()` method (67 lines)
2. **`douane-daemon.py`** - Added signal handlers and cleanup
3. **`douane-start.sh`** - New clean start script
4. **`douane-stop.sh`** - New clean stop script

## Next Steps

1. Install the new package: `sudo dpkg -i douane-firewall_2.0.0_all.deb`
2. Test start/stop cycle multiple times
3. Verify connection never breaks
4. Test the restrictive whitelist with popups

