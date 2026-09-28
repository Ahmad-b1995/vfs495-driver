#!/bin/bash
# Undo switch-to-native.sh: remove the native driver and reinstall vfs495-fprint.
#
#   sudo driver/tools/rollback-to-vfs495-fprint.sh [path/to/vfs495-fprint_0.1.5_amd64.deb]
#
# The package's own install script restores its fprintd drop-in, bridge and PAM profile.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEB="${1:-$ROOT/captures/vfs495-fprint_0.1.5_amd64.deb}"
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -f "$DEB" ] || { echo "missing $DEB (rebuild with ~/Projects/vfs495-linux/packaging/build-deb.sh)" >&2; exit 1; }

echo "1/2 removing the native driver (both drivers would compete for the sensor)"
rm -f "$TOD_DIR/libfprint-tod-vfs495.so"

echo "2/2 reinstalling vfs495-fprint"
apt-get install -y --reinstall "$DEB"

echo "Done: back on vfs495-fprint. Prints enrolled before the switch work again."
