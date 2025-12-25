#!/bin/bash
set -e

# Usage: ./release_tool.sh 1.4.8
if [ -z "$1" ]; then
    echo "Usage: $0 <new_version>"
    echo "Example: $0 1.4.8"
    exit 1
fi

NEW_VERSION="$1"
CURRENT_VERSION=$(grep "version=" setup.py | cut -d'"' -f2)

echo "============================================================"
echo "Preparing Release: $CURRENT_VERSION -> $NEW_VERSION"
echo "============================================================"

# 1. Update Version Numbers
echo "[1/6] Updating version numbers..."

# setup.py
sed -i "s/version=\"$CURRENT_VERSION\"/version=\"$NEW_VERSION\"/" setup.py
# bastion.spec
sed -i "s/Version:        $CURRENT_VERSION/Version:        $NEW_VERSION/" bastion.spec
# debian/control
sed -i "s/Version: $CURRENT_VERSION/Version: $NEW_VERSION/" debian/DEBIAN/control
# __init__.py
sed -i "s/__version__ = '$CURRENT_VERSION'/__version__ = '$NEW_VERSION'/" bastion/__init__.py
# build_deb.sh
sed -i "s/VERSION=\"$CURRENT_VERSION\"/VERSION=\"$NEW_VERSION\"/" build_deb.sh
# build_rpm.sh
sed -i "s/VERSION=\"$CURRENT_VERSION\"/VERSION=\"$NEW_VERSION\"/" build_rpm.sh

# 2. Build Packages Locally
echo "[2/6] Building packages locally..."
./build_deb.sh
./build_rpm.sh

# 3. Commit and Tag
echo "[3/6] Committing and tagging..."
git add .
git commit -m "Release v$NEW_VERSION"
git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"
git push origin master
git push origin "v$NEW_VERSION"

# 4. Extract Changelog (simplified - assumes top section is new release)
# Ideally, you should update CHANGELOG.md manually BEFORE running this script to include notes.
NOTES=$(grep -A 20 "## \[$NEW_VERSION\]" CHANGELOG.md | sed '/^## \[/d' | head -n 20)
if [ -z "$NOTES" ]; then
    NOTES="Release v$NEW_VERSION"
fi

# 5. Create GitHub Release
echo "[4/6] Creating GitHub Release..."
gh release create "v$NEW_VERSION" --title "Release v$NEW_VERSION" --notes "$NOTES"

# 6. Upload Artifacts
echo "[5/6] Uploading Artifacts..."
gh release upload "v$NEW_VERSION" "bastion-firewall_${NEW_VERSION}_all.deb"
gh release upload "v$NEW_VERSION" "bastion-firewall-${NEW_VERSION}-1.noarch.rpm"

echo "============================================================"
echo "SUCCESS! Release v$NEW_VERSION is live."
echo "============================================================"
