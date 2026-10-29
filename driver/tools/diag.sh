#!/bin/bash
# vfs495-diag: the driver's beta diagnostics (driver/src/vfs495-diag.h).
#
#   vfs495-diag status
#   sudo vfs495-diag on [DAYS]      record every swipe for DAYS days (default 30, at most 60)
#   sudo vfs495-diag off            stop and delete everything recorded
#   sudo vfs495-diag bundle [DIR]   pack it for analysis: one .tar.gz in DIR
#
# While on, the driver keeps every swipe (the decrypted scan lines, the stitched image, its
# measurements and timings) and a log of the sensor's sessions in /var/lib/vfs495-driver/diag,
# readable by root only; it keeps the newest 500 swipes, stops by itself after DAYS days, and
# systemd-tmpfiles deletes anything recorded more than 60 days ago.
# These are fingerprint scans: share a bundle only with whoever works on the driver.
set -euo pipefail
DIR=/var/lib/vfs495-driver/diag
SOURCE_DIR="@SOURCE_DIR@"

need_root() {
	[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo vfs495-diag $*" >&2; exit 1; }
}

swipes() {
	find "$DIR" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*' 2>/dev/null | wc -l
}

case "${1:-status}" in
status)
	if [ "$(id -u)" != 0 ]; then
		# the folder is root-only; the until file tells nothing sensitive, but needs root too
		sudo -n true 2>/dev/null && exec sudo "$0" status
		echo "run with sudo to see the diagnostics state: sudo vfs495-diag status"
		exit 0
	fi
	if [ ! -f "$DIR/until" ]; then
		echo "diagnostics are off"
		exit 0
	fi
	until="$(cat "$DIR/until")"
	if [ "$until" -le "$(date +%s)" ]; then
		echo "diagnostics stopped on $(date -d "@$until" '+%Y-%m-%d %H:%M'); $(swipes) swipes kept (sudo vfs495-diag off deletes them)"
	else
		echo "diagnostics are on until $(date -d "@$until" '+%Y-%m-%d %H:%M'): $(swipes) swipes, $(du -sh "$DIR" | cut -f1)"
	fi
	;;
on)
	need_root on
	days="${2:-30}"
	[[ "$days" =~ ^[0-9]+$ ]] && [ "$days" -ge 1 ] && [ "$days" -le 60 ] || { echo "DAYS: 1 to 60" >&2; exit 1; }
	install -d -m 0700 /var/lib/vfs495-driver "$DIR"
	[ -f "$DIR/started" ] || date +%s >"$DIR/started"
	echo $(($(date +%s) + days * 86400)) >"$DIR/until"
	chmod 0600 "$DIR/started" "$DIR/until"
	echo "diagnostics on until $(date -d "@$(cat "$DIR/until")" '+%Y-%m-%d %H:%M'); they start with the next fingerprint prompt"
	;;
off)
	need_root off
	n="$(swipes)"
	rm -rf "$DIR"
	echo "diagnostics off; deleted $n swipes"
	;;
bundle)
	need_root bundle
	[ -d "$DIR" ] || { echo "no diagnostics recorded" >&2; exit 1; }
	out="${2:-}"
	if [ -z "$out" ]; then
		out="$SOURCE_DIR/captures/bundles"
		[ -d "$SOURCE_DIR/captures" ] || out="$PWD"
	fi
	install -d -m 0700 "$out"
	name="vfs495-diag-$(date +%Y%m%d-%H%M%S)"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	mkdir -m 0700 "$tmp/$name"
	cp -a "$DIR" "$tmp/$name/diag"
	since="$(cat "$DIR/started" 2>/dev/null || echo $(($(date +%s) - 30 * 86400)))"
	journalctl -u fprintd --since "@$since" -o short-iso-precise --no-pager >"$tmp/$name/fprintd.log" 2>/dev/null || true
	journalctl --since "@$since" -o short-iso-precise --no-pager -g 'suspend|resume|Lid|vfs495|PM: ' \
		>"$tmp/$name/system.log" 2>/dev/null || true
	# the enrolled prints, so new swipes can be scored offline against them
	[ -d /var/lib/fprint ] && cp -a /var/lib/fprint "$tmp/$name/prints"
	{
		echo "bundle: $(date -Is)"
		uname -a
		dpkg-query -W -f='${Package} ${Version}\n' vfs495-driver fprintd libfprint-2-2 libfprint-2-tod1 libpam-fprintd 2>/dev/null
		sha256sum /usr/lib/vfs495-driver/commands.bin 2>/dev/null
		grep -h pam_fprintd /etc/pam.d/common-auth 2>/dev/null
	} >"$tmp/$name/versions.txt"
	tar -C "$tmp" -czf "$out/$name.tar.gz" "$name"
	chmod 0600 "$out/$name.tar.gz"
	if [ -n "${SUDO_USER:-}" ]; then
		chown "$SUDO_USER:" "$out/$name.tar.gz"
		[ "$out" = "$SOURCE_DIR/captures/bundles" ] && chown "$SUDO_USER:" "$out"
	fi
	echo "$out/$name.tar.gz ($(du -h "$out/$name.tar.gz" | cut -f1), $(swipes) swipes)"
	;;
*)
	sed -n '2,14s/^# \{0,1\}//p' "$0"
	exit 1
	;;
esac
