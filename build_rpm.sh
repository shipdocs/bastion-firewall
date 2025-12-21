#!/bin/bash
set -e

VERSION="2.0.10"
NAME="douane-firewall"
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
cp -r douane "$TEMP_DIR/"
cp douane-firewall douane-daemon douane-gui-client douane-control-panel douane-setup-firewall "$TEMP_DIR/"
cp config.json douane-firewall.service douane-firewall.desktop douane-control-panel.desktop "$TEMP_DIR/"

tar -czf "$BUILD_DIR/SOURCES/${NAME}-${VERSION}.tar.gz" "$TEMP_DIR"
rm -rf "$TEMP_DIR"

# Copy Spec File
cp douane.spec "$BUILD_DIR/SPECS/"

# Build RPM
echo "Running rpmbuild..."
rpmbuild --define "_topdir $(pwd)/$BUILD_DIR" -bb "$BUILD_DIR/SPECS/douane.spec"

# Move artifact
mv "$BUILD_DIR/RPMS/noarch/${NAME}-${VERSION}-1.*.rpm" .
echo "Build complete: ${NAME}-${VERSION}-1.noarch.rpm"
