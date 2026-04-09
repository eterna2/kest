#!/usr/bin/env bash
# sync-spec.sh
#
# Copies spec/SPEC.md (source of truth) into the website content directory
# so the documentation site always renders the latest specification.
#
# Source of truth : <repo-root>/spec/SPEC.md
# Destination     : website/content/design/07_spec.md
#
# This script is invoked automatically by the `build` npm script and therefore
# runs on every `moon run website:build` or `bun run build` invocation inside
# the website directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBSITE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WEBSITE_DIR/.." && pwd)"

SRC="$REPO_ROOT/spec/SPEC-v0.3.0.md"
DEST="$WEBSITE_DIR/content/design/07_kest_spec_v0.3.0.md"

if [[ ! -f "$SRC" ]]; then
  echo "ERROR: Source file not found: $SRC" >&2
  exit 1
fi

cp "$SRC" "$DEST"
echo "[sync-spec] Copied $SRC → $DEST"
