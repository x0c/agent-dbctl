#!/usr/bin/env bash
set -euo pipefail
repository="x0c/agent-dbctl"
version="${AGENT_DBCTL_VERSION:-latest}"
case "$(uname -s)" in
  Darwin) platform=darwin ;;
  Linux) platform=linux ;;
  *) echo "Use scripts/install.ps1 on Windows." >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [[ "$version" == "latest" ]]; then
  version="$(curl -fsSL "https://api.github.com/repos/$repository/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$ ]] || { echo "Invalid release version: $version" >&2; exit 1; }

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
asset="agent-dbctl_${version}_${platform}_${arch}.tar.gz"
base="https://github.com/$repository/releases/download/$version"
curl -fsSL "$base/$asset" -o "$tmp_dir/$asset"
curl -fsSL "$base/SHA256SUMS" -o "$tmp_dir/SHA256SUMS"

expected="$(awk -v asset="$asset" '$2 == asset {print $1}' "$tmp_dir/SHA256SUMS")"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "Missing release checksum for $asset." >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp_dir/$asset" | cut -d ' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp_dir/$asset" | cut -d ' ' -f1)"
fi
[[ "$expected" == "$actual" ]] || { echo "Release checksum mismatch." >&2; exit 1; }

tar -xzf "$tmp_dir/$asset" -C "$tmp_dir"
reported="$(AGENT_DBCTL_NO_SKILL_SYNC=1 "$tmp_dir/agent-dbctl" version --json | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' | head -1)"
[[ "$reported" == "$version" ]] || { echo "Release version mismatch: got $reported, want $version" >&2; exit 1; }

destination="${AGENT_DBCTL_INSTALL_DIR:-${HOME}/.local/bin}"
mkdir -p "$destination"
install -m 755 "$tmp_dir/agent-dbctl" "$destination/agent-dbctl"
printf 'Installed agent-dbctl %s to %s/agent-dbctl. Add this directory to PATH if needed.\n' "$version" "$destination"
