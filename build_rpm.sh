#!/bin/bash
set -e

VERSION="1.4.7"
NAME="bastion-firewall"
BUILD_DIR="rpmbuild"

echo "Building RPM package version $VERSION..."

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Prepare Source Tarball
echo "Creating source tarball..."
# Temporarily copy files to a versioned directory to tar them
TEMP_DIR="${NAME}-${VERSION}"
mkdir -p "$TEMP_DIR"

# Copy Python Source
cp -r bastion "$TEMP_DIR/"

# Copy Executables/Scripts (Renaming them to match target if needed, or just copying)
# Note: RPM spec usually handles installation, so we just need to provide the files in the tarball
cp bastion_firewall.py "$TEMP_DIR/bastion-firewall"
cp bastion-daemon.py "$TEMP_DIR/bastion-daemon"
cp bastion-gui.py "$TEMP_DIR/bastion-gui"
cp bastion_control_panel.py "$TEMP_DIR/bastion-control-panel"
cp setup_firewall.sh "$TEMP_DIR/bastion-setup-firewall"
cp launch_bastion.sh "$TEMP_DIR/bastion-launch"

# Copy Configs & Desktop Files
cp config.json "$TEMP_DIR/"
cp bastion-firewall.service "$TEMP_DIR/"
cp com.bastion.firewall.desktop "$TEMP_DIR/"
cp bastion-control-panel.desktop "$TEMP_DIR/"
cp bastion-tray.desktop "$TEMP_DIR/"

# Copy Docs
cp README.md "$TEMP_DIR/"
cp LICENSE "$TEMP_DIR/"

# Create AppStream/Metainfo
cat > "$TEMP_DIR/com.bastion.firewall.metainfo.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.bastion.firewall</id>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0+</project_license>
  <name>Bastion Firewall</name>
  <summary>Application Firewall - Control which applications can access the network</summary>
  <description>
    <p>
      🏰 Bastion Firewall is an outbound application firewall built specifically for Zorin OS 18
      (and compatible with all Debian-based distributions). Like a medieval bastion protecting a
      fortress, Bastion stands guard over your system's network connections, giving you control
      over which applications can access the network.
    </p>
    <p>Features:</p>
    <ul>
      <li>Real-time packet interception using NetfilterQueue</li>
      <li>Beautiful GUI dialogs for permission requests</li>
      <li>Independent tray icon with visual status indicators</li>
      <li>Security hardened (5-phase implementation, score: 2/10 LOW RISK)</li>
      <li>Per-application, per-port rules</li>
      <li>UFW integration for complete firewall coverage</li>
      <li>Control panel for managing settings and rules</li>
      <li>Auto-start support with systemctl controls</li>
    </ul>
  </description>
  <launchable type="desktop-id">com.bastion.firewall.desktop</launchable>
  <icon type="stock">security-high</icon>
  <url type="homepage">https://github.com/shipdocs/bastion-firewall</url>
  <url type="bugtracker">https://github.com/shipdocs/bastion-firewall/issues</url>
  <url type="help">https://github.com/shipdocs/bastion-firewall/blob/master/README.md</url>
  <developer id="com.bastion">
    <name>Martin</name>
  </developer>
  <update_contact>shipdocs@users.noreply.github.com</update_contact>
  <content_rating type="oars-1.1" />
  <provides>
    <binary>bastion-daemon</binary>
    <binary>bastion-gui</binary>
    <binary>bastion-control-panel</binary>
    <binary>bastion-firewall</binary>
    <id>com.bastion.firewall.desktop</id>
  </provides>
  <recommends>
    <control>pointing</control>
    <control>keyboard</control>
  </recommends>
  <requires>
    <display_length compare="ge">768</display_length>
  </requires>
  <categories>
    <category>System</category>
    <category>Security</category>
    <category>Network</category>
  </categories>
  <keywords>
    <keyword>firewall</keyword>
    <keyword>security</keyword>
    <keyword>network</keyword>
    <keyword>outbound</keyword>
    <keyword>application</keyword>
  </keywords>
  <releases>
    <release version="1.4.7" date="2025-12-26">
      <description>
        <p>🏰 Release v1.4.7 - Production Ready</p>
        <ul>
          <li>Critical bug fixes</li>
          <li>Security hardening</li>
          <li>Full test coverage for core modules</li>
        </ul>
      </description>
    </release>
  </releases>
</component>
EOF

tar -czf "$BUILD_DIR/SOURCES/${NAME}-${VERSION}.tar.gz" "$TEMP_DIR"
rm -rf "$TEMP_DIR"

# Copy Spec File
cp bastion.spec "$BUILD_DIR/SPECS/"

# Build RPM
echo "Running rpmbuild..."
rpmbuild --define "_topdir $(pwd)/$BUILD_DIR" -bb "$BUILD_DIR/SPECS/bastion.spec"

# Move artifact
find "$BUILD_DIR/RPMS" -name "*.rpm" -exec mv {} . \;
echo "Build complete."
