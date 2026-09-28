#!/bin/bash
# Build the vfs495-driver Debian package for this machine.
#
#   driver/packaging/build-deb.sh          -> captures/vfs495-driver_<version>_amd64.deb
#   sudo apt install ./captures/vfs495-driver_<version>_amd64.deb
#
# The package contains the command data derived from HP's software (captures/
# vfs495-commands.bin), so it is written to the git-ignored captures/ folder and must not be
# shared. It replaces vfs495-fprint (apt removes it) and turns on Ubuntu's fingerprint login.
#
# libfprint-2-tod1 is pinned to 1.94.x: an incompatible libfprint would otherwise disable the
# driver silently, while with the pin apt holds the upgrade back and says so. To allow a new
# libfprint version, rebuild against it, test with driver/tools/fp-test.py, and raise
# TOD_MAX below.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG="$ROOT/driver/packaging"
BUILD="$ROOT/build/pkg"
STAGE="$ROOT/build/pkg-root"
COMMANDS="$ROOT/captures/vfs495-commands.bin"
TOD_MIN="1:1.94.9"
TOD_MAX="1:1.95~"

[ -f "$COMMANDS" ] || { echo "missing $COMMANDS: see driver/tools/make-commands.py" >&2; exit 1; }

# a clean release build for generic x86-64 (no -march=native)
rm -rf "$BUILD" "$STAGE"
meson setup "$BUILD" "$ROOT/driver" -Dnative=false -Dbuildtype=release >/dev/null 2>&1
ninja -C "$BUILD" >/dev/null 2>&1 || { ninja -C "$BUILD"; exit 1; }
VERSION="$(meson introspect --projectinfo "$BUILD" | python3 -c 'import json, sys; print(json.load(sys.stdin)["version"])')"
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"
MODULE="$STAGE$TOD_DIR/libfprint-tod-vfs495.so"

install -D -m 0644 "$BUILD/libfprint-tod-vfs495.so" "$MODULE"
strip --strip-unneeded "$MODULE"
install -D -m 0644 "$COMMANDS" "$STAGE/usr/lib/vfs495-driver/commands.bin"
install -D -m 0644 "$PKG/fprintd-vfs495-driver.conf" \
	"$STAGE/usr/lib/systemd/system/fprintd.service.d/vfs495-driver.conf"
install -D -m 0755 "$ROOT/driver/tools/scores.sh" "$STAGE/usr/bin/vfs495-scores"
install -d "$STAGE/usr/share/doc/vfs495-driver"
cat >"$STAGE/usr/share/doc/vfs495-driver/README" <<EOF
vfs495-driver $VERSION: native libfprint driver for the Validity VFS495 fingerprint reader
(138a:003f), built from $(git -C "$ROOT" describe --always --dirty 2>/dev/null || echo "an unknown revision").

Enroll:   fprintd-enroll -f right-index-finger
Test:     fprintd-verify
Scores:   vfs495-scores ["7 days ago"]

/usr/lib/vfs495-driver/commands.bin is derived from HP's software for this reader and is
for use on this machine only.
EOF
gzip -9n -c "$ROOT/README.md" >"$STAGE/usr/share/doc/vfs495-driver/project-README.md.gz"

# library dependencies, as Debian computes them
SHLIBS="$(cd "$(mktemp -d)" && mkdir debian && printf 'Source: vfs495-driver\n\nPackage: vfs495-driver\nArchitecture: amd64\n' >debian/control &&
	dpkg-shlibdeps -O -e"$MODULE" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
[ -n "$SHLIBS" ] || { echo "dpkg-shlibdeps found no dependencies" >&2; exit 1; }

find "$STAGE" -type d -exec chmod 0755 {} +
install -d "$STAGE/DEBIAN"
cat >"$STAGE/DEBIAN/control" <<EOF
Package: vfs495-driver
Version: $VERSION
Architecture: amd64
Maintainer: Ahmad <ahmad.b1995@gmail.com>
Installed-Size: $(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
Depends: $SHLIBS, libfprint-2-tod1 (>= $TOD_MIN), libfprint-2-tod1 (<< $TOD_MAX), fprintd, libpam-fprintd
Conflicts: vfs495-fprint
Section: misc
Priority: optional
Description: native libfprint driver for the Validity VFS495 fingerprint reader
 Loaded by libfprint's TOD support, so fprintd, GNOME and PAM use the reader directly.
 Contains command data derived from HP's software; for use on this machine only.
EOF
install -m 0755 "$PKG/postinst" "$PKG/postrm" "$STAGE/DEBIAN/"

OUT="$ROOT/captures/vfs495-driver_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT" >/dev/null
echo "built $OUT"
echo "install: sudo apt install $OUT"
