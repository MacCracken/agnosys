#!/usr/bin/env bash
set -euo pipefail

# Bump version in VERSION file
NEW_VERSION="${1:?Usage: $0 <new-version>}"

echo "$NEW_VERSION" > VERSION

echo "Bumped to $NEW_VERSION"
echo ""
echo "Next steps:"
echo "  git add VERSION"
echo "  git commit -m 'release: $NEW_VERSION'"
echo "  git tag $NEW_VERSION"
echo "  git push origin main --tags"
