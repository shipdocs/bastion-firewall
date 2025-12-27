#!/bin/bash
# Safety script: Auto-restore internet after 2 minutes

echo "⏰ Safety timer started - will restore internet in 2 minutes"
sleep 120

echo ""
echo "⏰ 2 minutes elapsed - restoring internet..."
echo 'Texel21' | sudo -S pkill -9 bastion-daemon
echo 'Texel21' | sudo -S iptables -F OUTPUT
echo ""
echo "✅ Internet restored automatically"
echo "✅ Daemon stopped"
