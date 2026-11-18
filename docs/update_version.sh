#!/bin/bash
# Write the release version and date into the static parts of the website, so
# search engines and AI agents (which often don't run JavaScript) see the current
# release. Called by release_tool.sh; can also be run by hand.
#
# Usage: docs/update_version.sh 2.0.42 [YYYY-MM-DD]
set -e

VERSION="$1"
DATE="${2:-$(date +%F)}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ ! "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "Usage: $0 <x.y.z> [YYYY-MM-DD]" >&2
    exit 1
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
V='[0-9]+\.[0-9]+\.[0-9]+'
D='[0-9]{4}-[0-9]{2}-[0-9]{2}'

sed -E -i \
    -e "s/\"softwareVersion\": \"$V\"/\"softwareVersion\": \"$VERSION\"/" \
    -e "s/\"dateModified\": \"$D\"/\"dateModified\": \"$DATE\"/" \
    -e "s#releases/tag/v$V\"#releases/tag/v$VERSION\"#" \
    -e "s/id=\"stable-version\">v$V</id=\"stable-version\">v$VERSION</" \
    -e "s/id=\"footer-version\">v$V</id=\"footer-version\">v$VERSION</" \
    -e "s/Released $D ·/Released $DATE ·/" \
    "$DIR/index.html"
sed -E -i "s#<lastmod>$D</lastmod>#<lastmod>$DATE</lastmod>#" "$DIR/sitemap.xml"
sed -E -i "s/^Latest release: v$V \($D\)$/Latest release: v$VERSION ($DATE)/" "$DIR/llms.txt"

# Fail loudly if a marker was not found, instead of publishing stale data.
for check in "\"softwareVersion\": \"$VERSION\"" "id=\"stable-version\">v$VERSION<" \
             "id=\"footer-version\">v$VERSION<" "releases/tag/v$VERSION\"" "Released $DATE ·"; do
    grep -qF "$check" "$DIR/index.html" || { echo "update_version.sh: '$check' not found in index.html" >&2; exit 1; }
done
grep -qF "<lastmod>$DATE</lastmod>" "$DIR/sitemap.xml" || { echo "update_version.sh: sitemap not updated" >&2; exit 1; }
grep -qF "Latest release: v$VERSION ($DATE)" "$DIR/llms.txt" || { echo "update_version.sh: llms.txt not updated" >&2; exit 1; }
echo "Website updated to v$VERSION ($DATE)"
