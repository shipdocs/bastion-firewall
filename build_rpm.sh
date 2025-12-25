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

tar -czf "$BUILD_DIR/SOURCES/${NAME}-${VERSION}.tar.gz" "$TEMP_DIR"
rm -rf "$TEMP_DIR"

# Copy Spec File
cp bastion.spec "$BUILD_DIR/SPECS/"

# Build RPM
echo "Running rpmbuild..."
rpmbuild --define "_topdir $(pwd)/$BUILD_DIR" -bb "$BUILD_DIR/SPECS/bastion.spec"

# Move artifact
mv "$BUILD_DIR/RPMS/noarch/${NAME}-${VERSION}-1.*.rpm" .
echo "Build complete: ${NAME}-${VERSION}-1.noarch.rpm"
