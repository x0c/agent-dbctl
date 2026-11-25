#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-dev}"
COMMIT="${2:-dev}"

mkdir -p dist
TMP_FILE="dist/.manifest.json.tmp"
{
  printf '{\n'
  printf '  "version": "%s",\n' "$VERSION"
  printf '  "commit": "%s",\n' "$COMMIT"
  printf '  "artifacts": [\n'
  first=1
  for f in dist/agent-dbctl-*; do
    [ -f "$f" ] || continue
    sum="$(shasum -a 256 "$f" | awk '{print $1}')"
    base="$(basename "$f")"
    if [ "$first" -eq 0 ]; then
      printf ',\n'
    fi
    first=0
    printf '    {"name": "%s", "sha256": "%s"}' "$base" "$sum"
  done
  printf '\n  ]\n}\n'
} > "$TMP_FILE"
mv "$TMP_FILE" dist/manifest.json
