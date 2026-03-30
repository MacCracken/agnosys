#!/usr/bin/env bash
set -euo pipefail

# Bump version in VERSION file and Cargo.toml
NEW_VERSION="${1:?Usage: $0 <new-version>}"

echo "$NEW_VERSION" > VERSION

# Update Cargo.toml version
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml

# Update Cargo.lock
cargo check --quiet 2>/dev/null || true

echo "Bumped to $NEW_VERSION"
echo ""
echo "Next steps:"
echo "  git add VERSION Cargo.toml Cargo.lock"
echo "  git commit -m 'release: $NEW_VERSION'"
echo "  git tag $NEW_VERSION"
echo "  git push origin main --tags"
