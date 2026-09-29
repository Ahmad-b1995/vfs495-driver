#!/bin/sh
# vfs495-driver apt hook (/etc/vfs495-driver/apt-hook.sh, run after every dpkg run).
#
# Installed as a configuration file, so it stays when the package is removed, as a release
# upgrade does when a library the package was built against is renamed. It then warns after
# every apt run until the driver is rebuilt, or the package is purged if the removal was
# intended. The driver's own checks after libfprint upgrades are done by the package's dpkg
# triggers (vfs495-check).
status="$(dpkg-query -W -f='${db:Status-Status}' vfs495-driver 2>/dev/null)"
if [ "$status" = config-files ]; then
	cat >&2 <<'MSG'

*** vfs495-driver was removed: fingerprint login is off.
*** Rebuild it:      cd ~/Projects/vfs495-driver && sudo driver/tools/install-driver.sh
*** If intended:     sudo apt purge vfs495-driver    (silences this message)

MSG
	logger -p auth.warning -t vfs495-driver "vfs495-driver was removed; fingerprint login is off" 2>/dev/null
fi
exit 0
