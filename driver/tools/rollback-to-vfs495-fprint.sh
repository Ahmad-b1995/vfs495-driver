#!/bin/bash
# Go back from the native driver to vfs495-fprint (HP's tool behind a virtual reader).
#
#   sudo driver/tools/rollback-to-vfs495-fprint.sh [path/to/vfs495-fprint_0.1.5_amd64.deb]
#
# The old package's own install script restores its fprintd drop-in, bridge and PAM profile.
# Prints enrolled with vfs495-fprint work again; prints enrolled with the native driver stay
# stored and come back if the native driver is reinstalled.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEB="${1:-$ROOT/captures/vfs495-fprint_0.1.5_amd64.deb}"
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$DEB" ] || { echo "missing $DEB (rebuild with ~/Projects/vfs495-linux/packaging/build-deb.sh)" >&2; exit 1; }

echo "1/2 removing the native driver (both drivers would compete for the sensor)"
if dpkg -s vfs495-driver >/dev/null 2>&1; then
	apt-get remove -y vfs495-driver
fi
rm -f "$TOD_DIR/libfprint-tod-vfs495.so"   # a manual install from before the package

echo "2/2 reinstalling vfs495-fprint"
apt-get install -y --reinstall "$DEB"

echo "Done: back on vfs495-fprint."
