#!/bin/bash
# Remove the bad /proc/self/exe rule from rules.json

RULES_FILE="/etc/bastion/rules.json"

if [ ! -f "$RULES_FILE" ]; then
    echo "Rules file not found: $RULES_FILE"
    exit 1
fi

echo "Backing up rules file..."
sudo cp "$RULES_FILE" "${RULES_FILE}.backup"

echo "Removing /proc/self/exe rule..."
sudo sed -i '/"\/proc\/self\/exe:443": true,/d' "$RULES_FILE"

echo "Done! Backup saved to ${RULES_FILE}.backup"
echo ""
echo "Updated rules file:"
sudo cat "$RULES_FILE"

