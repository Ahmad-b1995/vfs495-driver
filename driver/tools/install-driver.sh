#!/bin/bash
# Build the vfs495-driver package from this tree and install it (first install or update).
#
#   sudo driver/tools/install-driver.sh
#
# The package replaces vfs495-fprint if present, turns on Ubuntu's fingerprint login on first
# install, has fprintd log match results (vfs495-scores) and restarts fprintd. Enrolled prints
# are kept. See driver/packaging/build-deb.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -n "${SUDO_USER:-}" ] || { echo "run with sudo from your own account (the build runs as you)" >&2; exit 1; }

deb="$(sudo -u "$SUDO_USER" "$ROOT/driver/packaging/build-deb.sh" | sed -n 's/^built //p')"
[ -f "$deb" ] || { echo "package build failed" >&2; exit 1; }
# a copy apt's unprivileged _apt user can read (captures/ is private)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 0755 "$tmp"
install -m 0644 "$deb" "$tmp/"
apt-get install -y --reinstall "$tmp/$(basename "$deb")"
echo "installed $(basename "$deb")"
