#!/bin/bash
# Quick Security Fixes for Bastion Firewall
# Run this script to fix critical security issues

set -e

echo "🔒 Bastion Firewall - Security Quick Fix Script"
echo "================================================"
echo ""

# Backup original files
echo "📋 Creating backups..."
cp bastion/daemon.py bastion/daemon.py.backup
cp bastion/gui.py bastion/gui.py.backup
cp bastion/gui_manager.py bastion/gui_manager.py.backup

# Fix 1: Socket permissions (CRITICAL)
echo "🔴 Fixing critical socket permissions issue..."
sed -i 's/os.chmod(self.SOCKET_PATH, 0o666)/os.chmod(self.SOCKET_PATH, 0o660)  # Fixed: Group-readable instead of world-writable/' bastion/daemon.py

# Fix 2: Add proper exception handling
echo "⚠️  Fixing bare exception handlers..."

# daemon.py exceptions
sed -i '564s/except:/except (OSError, socket.error) as e:/' bastion/daemon.py
sed -i '565s/pass/logger.debug(f"Error closing GUI socket: {e}")/' bastion/daemon.py

sed -i '571s/except:/except (OSError, socket.error) as e:/' bastion/daemon.py
sed -i '572s/pass/logger.debug(f"Error closing server socket: {e}")/' bastion/daemon.py

sed -i '583s/except:/except (OSError, PermissionError) as e:/' bastion/daemon.py
sed -i '584s/pass/logger.debug(f"Error removing socket file: {e}")/' bastion/daemon.py

echo ""
echo "✅ Critical fixes applied!"
echo ""
echo "📝 Next steps:"
echo "1. Review the changes with: git diff bastion/"
echo "2. Test the daemon: sudo systemctl restart bastion-firewall"
echo "3. Check logs: journalctl -u bastion-firewall -f"
echo "4. Restore backups if needed: mv bastion/*.backup bastion/"
echo ""
echo "⚠️  Note: Socket permission change (0o666 -> 0o660) requires:"
echo "   - Users must be added to the 'bastion' group"
echo "   - Add group: sudo groupadd -f bastion"
echo "   - Add user: sudo usermod -aG bastion \$USER"
echo "   - User must log out and back in for group membership to take effect"
echo ""
