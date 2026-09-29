#!/bin/bash
# Build the vfs495-driver Debian package.
#
#   driver/packaging/build-deb.sh          -> build/deb/vfs495-driver_<version>_amd64.deb
#   sudo apt install ./build/deb/vfs495-driver_<version>_amd64.deb
#
# The sensor's command data is built from HP's own driver download (SoftPaq sp84530, fetched
# from HP and checksum-verified, or taken from $VFS495_HP_TAR) with driver/recipe/. The
# package therefore contains data derived from HP's software: build it yourself, do not
# redistribute it. It replaces vfs495-fprint (apt removes it) and turns on Ubuntu's
# fingerprint login.
#
# libfprint is not capped at a version: TOD modules keep working across libfprint releases
# (this one, built against 1.94.9, loads unchanged in 1.95.1), and a cap made Ubuntu's release
# upgrade remove the package. Instead the package watches libfprint's libraries (dpkg file
# triggers) and runs vfs495-check after every upgrade of them, which warns in apt's output and
# the system log if libfprint no longer loads the driver. A release upgrade can still remove
# the package (26.04 renamed libgusb2, which the build had depended on); an apt hook kept as a
# configuration file then warns after every apt run until the driver is rebuilt.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG="$ROOT/driver/packaging"
BUILD="$ROOT/build/pkg"
STAGE="$ROOT/build/pkg-root"
HP_CACHE="$ROOT/build/hp"
TOD_MIN="1:1.94.9"

# HP's driver download: $VFS495_HP_TAR, an earlier download, or a fresh one from HP
HP_TAR="${VFS495_HP_TAR:-}"
for c in "$ROOT/captures/hp/sp84530.tar" "$HP_CACHE/sp84530.tar"; do
	[ -n "$HP_TAR" ] || { [ -f "$c" ] && HP_TAR="$c"; }
done
if [ -z "$HP_TAR" ]; then
	HP_TAR="$HP_CACHE/sp84530.tar"
	mkdir -p "$HP_CACHE"
	url="$(python3 -c "import sys; sys.path.insert(0, '$ROOT/driver/recipe'); import hp_package; print(hp_package.SOFTPAQ_URL)")"
	echo "downloading HP's driver package (about 3 MB) from $url" >&2
	curl -fsSL -o "$HP_TAR.part" "$url" && mv "$HP_TAR.part" "$HP_TAR"
fi

# a clean release build for generic x86-64 (no -march=native)
rm -rf "$BUILD" "$STAGE"
meson setup "$BUILD" "$ROOT/driver" -Dnative=false -Dbuildtype=release >/dev/null 2>&1
ninja -C "$BUILD" >/dev/null 2>&1 || { ninja -C "$BUILD"; exit 1; }
VERSION="$(meson introspect --projectinfo "$BUILD" | python3 -c 'import json, sys; print(json.load(sys.stdin)["version"])')"
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"
MODULE="$STAGE$TOD_DIR/libfprint-tod-vfs495.so"

install -D -m 0644 "$BUILD/libfprint-tod-vfs495.so" "$MODULE"
strip --strip-unneeded "$MODULE"
install -d "$STAGE/usr/lib/vfs495-driver"
python3 "$ROOT/driver/recipe/build-commands.py" "$HP_TAR" "$STAGE/usr/lib/vfs495-driver/commands.bin" >/dev/null
chmod 0644 "$STAGE/usr/lib/vfs495-driver/commands.bin"
install -D -m 0644 "$PKG/fprintd-vfs495-driver.conf" \
	"$STAGE/usr/lib/systemd/system/fprintd.service.d/vfs495-driver.conf"
install -D -m 0755 "$ROOT/driver/tools/scores.sh" "$STAGE/usr/bin/vfs495-scores"
install -D -m 0755 "$ROOT/driver/tools/check.py" "$STAGE/usr/bin/vfs495-check"
# configuration files survive removal of the package: the hook warns if an upgrade removed it
install -D -m 0755 "$PKG/apt-hook.sh" "$STAGE/etc/vfs495-driver/apt-hook.sh"
install -D -m 0644 "$PKG/apt-hook.conf" "$STAGE/etc/apt/apt.conf.d/80vfs495-driver"
install -d "$STAGE/usr/share/doc/vfs495-driver"
cat >"$STAGE/usr/share/doc/vfs495-driver/README" <<EOF
vfs495-driver $VERSION: native libfprint driver for the Validity VFS495 fingerprint reader
(138a:003f), built from $(git -C "$ROOT" describe --always --dirty 2>/dev/null || echo "an unknown revision").

Enroll:   fprintd-enroll -f right-index-finger
Test:     fprintd-verify
Scores:   vfs495-scores ["7 days ago"]
Check:    vfs495-check        (runs by itself after every libfprint upgrade)

/usr/lib/vfs495-driver/commands.bin was built from HP's driver download (SoftPaq sp84530)
on this machine. It is derived from HP's software: do not redistribute this package.
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
Depends: $SHLIBS, libfprint-2-tod1 (>= $TOD_MIN), fprintd, libpam-fprintd, python3
Conflicts: vfs495-fprint
Section: misc
Priority: optional
Description: native libfprint driver for the Validity VFS495 fingerprint reader
 Loaded by libfprint's TOD support, so fprintd, GNOME and PAM use the reader directly.
 Contains command data built from HP's driver download; do not redistribute.
EOF
install -m 0755 "$PKG/postinst" "$PKG/postrm" "$STAGE/DEBIAN/"
# run vfs495-check whenever libfprint's libraries are upgraded
LIBDIR="$(pkg-config --variable=libdir libfprint-2-tod-1)"
printf 'interest-noawait %s\n' "$LIBDIR/libfprint-2-tod.so.1" "$LIBDIR/libfprint-2.so.2" >"$STAGE/DEBIAN/triggers"
chmod 0644 "$STAGE/DEBIAN/triggers"
printf '%s\n' /etc/vfs495-driver/apt-hook.sh /etc/apt/apt.conf.d/80vfs495-driver >"$STAGE/DEBIAN/conffiles"
chmod 0644 "$STAGE/DEBIAN/conffiles"

mkdir -p "$ROOT/build/deb"
OUT="$ROOT/build/deb/vfs495-driver_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT" >/dev/null
echo "built $OUT"
echo "install: sudo apt install $OUT"
