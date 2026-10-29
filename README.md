# vfs495-driver

A native Linux driver for the Validity VFS495 swipe fingerprint reader (USB `138a:003f`),
found in 2013–2015 HP EliteBook, ProBook and ZBook laptops. It plugs into the distribution's
own libfprint as a TOD module, so fprintd, GNOME's fingerprint settings, the login screen,
the lock screen and sudo all work with it.

Builds on the reverse engineering in
[saifulmd0/vfs495-linux](https://github.com/saifulmd0/vfs495-linux) (MIT). The research
scripts expect it as a sibling clone at `../vfs495-linux`; the driver does not.

## Install

Check that you have the reader: `lsusb | grep 138a:003f`. Tested on Ubuntu 25.10 and 26.04
(libfprint 1.94.9 and 1.95.1, both with TOD). Other distributions need a libfprint built with
TOD support.

```bash
sudo apt install git build-essential meson ninja-build pkg-config curl python3 \
  libfprint-2-tod-dev libgusb-dev libssl-dev libglib2.0-dev fprintd libpam-fprintd
git clone https://github.com/Ahmad-b1995/vfs495-driver.git
cd vfs495-driver
sudo driver/tools/install-driver.sh
fprintd-enroll
```

The build downloads HP's Linux driver package (SoftPaq sp84530, about 3 MB) from HP and
checks its MD5, then extracts the sensor's setup commands and firmware patches from it. No HP
code runs. This repository holds no HP code, firmware or configuration data: the recipe that
extracts them (`driver/recipe/`) refers to byte ranges and patch-table entries of HP's
download, and its only literal bytes are about 290 bytes of protocol framing and constants
(command bytes, TLV headers, read lengths). The package you build therefore contains data
derived from HP's download: build it yourself and do not redistribute the `.deb`. Updating is
`git pull` and the same install command; enrolled prints are kept. Removing is
`sudo apt purge vfs495-driver`, which also undoes the system changes below.

What the package changes on your system:

- **Fingerprint login with 2 tries.** It switches PAM from Ubuntu's fprintd profile (1 try) to
  its own (`max-tries=2 timeout=10`), once, on first install; removing the package switches
  back.
- **fprintd keeps running** (`--no-timeout`) instead of exiting after 30 s idle, so the reader
  is ready sooner at the lock screen; a unit restarts fprintd after every resume
  (`vfs495-driver-resume.service`).
- **fprintd logs** the matcher's scores and the driver's view of every swipe to the journal
  (`G_MESSAGES_DEBUG`), which `vfs495-scores` summarises. No images are logged.
- **Checks after upgrades.** `vfs495-check` runs after every libfprint upgrade and warns if the
  driver no longer loads; an apt hook (a configuration file, kept until purge) warns after
  every apt run if an upgrade removed the package.
- **Beta diagnostics, off by default.** `sudo vfs495-diag on [DAYS]` makes the driver keep every
  swipe (decrypted scan, stitched image, measurements, timings) in the root-only folder
  `/var/lib/vfs495-driver/diag` for up to 60 days, to improve the driver from real use;
  `sudo vfs495-diag off` deletes it. See "Beta diagnostics".

If your reader behaves differently (a sensor with other firmware may need other patches),
please open an issue with the output of `journalctl -b -u fprintd` and `lsusb -v -d 138a:003f`.

## License

LGPL-2.1-or-later, like libfprint (`LICENSE`). See `NOTICE` for the MIT-licensed upstream work.

## Status

**Open code captures from the sensor end to end, with no HP code involved.** The open client
(`research/session/vfs495.py`) reads the sensor's key from its flash, completes the secure
session, configures the sensor, arms finger detection with an image key it chooses itself,
polls for the finger, decrypts and decodes the swipe, and aborts cleanly
(`research/session/capture.py`). Five consecutive swipes in one session all produced full,
clear prints of the same finger. Setup takes 6.7 s once; re-arming between swipes 0.65 s.

**No recording of HP's tool is needed any more.** The command data (firmware patches and
configuration programs) is built from HP's own driver download, SoftPaq sp84530, by a recipe
that holds no HP data (`driver/recipe/`, see "Command data from HP's package"). Built that
way, it matches the data recorded from HP's tool on this machine byte for byte. The package
build downloads and verifies the SoftPaq itself. Whether other VFS495 units need other
patches is unknown without a second sensor; the driver handles a sensor that lacks this one's
cached patch signatures (finding 23).

**The libfprint driver works.** `driver/src/vfs495.c` is a libfprint TOD module: Ubuntu's own
libfprint loads it, so no patched libfprint is needed. Through libfprint it opens the sensor in
1.3 s, captures, enrolls and verifies: enrollment took 5 swipes with no retries, the enrolled
right index matched 4 of 4 verify swipes, and another finger matched 0 of 6. Waiting without a
finger re-arms every 50 s; cancelling and closing leave the sensor clean.

**It is installed and in use** on the ZBook as the `vfs495-driver` package
(`sudo driver/tools/install-driver.sh` builds and installs it). It replaced vfs495-fprint (HP's
tool behind libfprint's virtual reader) and uses Ubuntu's own fingerprint login; fprintd
enrolls, verifies, unlocks and survives suspend with it. `driver/tools/rollback-to-vfs495-fprint.sh`
goes back to vfs495-fprint.

**Surviving upgrades.** The upgrade to Ubuntu 26.04 removed the package: it capped libfprint
at 1.94.x (26.04 has 1.95.1), and it depended on `libgusb2`, which 26.04 renamed `libgusb2a`.
The driver itself was fine: the module built against 1.94.9 loads unchanged in 1.95.1, as the
TOD interface is meant to. The package no longer caps libfprint; after every upgrade of
libfprint's libraries a dpkg trigger runs `vfs495-check`, which warns in apt's output and the
system log if libfprint stops loading the driver; and an apt hook, kept as a configuration file
so it outlives the package, warns after every apt run if the package was removed, with the
command that rebuilds it. The module is linked against libfprint-2 with `-z defs`, so a symbol
libfprint does not export fails the build.

Verified on an HP ZBook 17 G3, Ubuntu 25.10, sensor firmware 04.60.00.0104 Falcon ROM.

## Findings

1. **The handshake construction in the upstream client is correct.** Recomputing a recorded
   HP session with it matches HP byte for byte: hashed handshake messages, client and server
   randoms, master secret, key block, Finished, and the encrypted Finished record on the wire
   (`research/handshake/verify.py`). The upstream "pairing gate" does not exist.
2. **HP loads two RSA public keys per session.**
   - Key 1 is a constant embedded in HP's `validity-sensor` binary. HP uses it only to verify a
     signature (PKCS#1 type 1 padding), most likely the sensor's certificate. It is never used
     for encryption.
   - Key 2 is per sensor. HP encrypts the premaster secret with it: modulus bytes read
     little-endian, exponent 65537, PKCS#1 v1.5 type 2, ciphertext sent big-endian.
3. **The sensor's flash holds everything per-device a driver needs.** The 4096-byte response
   to the second pre-session `0x1f` read contains:
   - key 2 at offset 1718;
   - a patch signature cache: 40-byte entries (8-byte label ending in `5053ff`, then a 32-byte
     HMAC) at offsets 3936, 3976, 4016 and 4056.
4. **Signed patches carry a cached HMAC instead of Validity's RSA signature.** HP's
   `scsReplaseRSASignatureByHMAC` rebuilds each signed patch as: first 2 bytes of the original,
   `20 00`, the 32-byte HMAC from the flash cache, then the body without the RSA signature. The
   signed patch bodies (1264, 368 and 2544 bytes) and the unsigned first pre-session patch
   (692 bytes) appear verbatim in HP's binary.
5. **The pre-handshake init sequence is deterministic.** Sessions send identical commands; only
   the `GetStartInfo` (0x19) reply differs.
6. **The sensor sends one unsolicited encrypted record right after its Finished** (sequence
   number 1, in the same USB transfer). A client must decrypt it to keep the CBC IV and MAC
   sequence in step; the upstream client ignored it.
7. **In-session commands are TLV lists and nearly deterministic.** After the command byte and
   4 header bytes, configuration commands (`02`) are lists of `u16 type, u16 length, value`.
   Across sessions only the first 64 bytes of each type `0x0006` field (106 bytes) differ. The
   sensor accepts that field as zeros, random bytes, or a value from another session, so it is
   not checked against the session. In the arming command it carries the image key (finding 11).
8. **The session protocol:** flash read (`1f`, 512 KB on the data endpoint), then repeated
   unload (`1a`) and load (`06`) of patches, seven configuration programs (`02`), `12`, a
   calibration program whose reply carries 2402 bytes, and finally a 17-byte capture command
   (`02`, single TLV type `0x0015`) followed by the frame stream on endpoint 0x82. The session
   ends with an encrypted close_notify alert (`01 00`) in both directions.
9. **Captures can repeat inside one session.** Re-sending HP's final capture block (`1a`,
   `06`, capture `02`, `1a`, `06`) in the same session produced three more full captures,
   0.37 s each, with no new handshake and no resets.
10. **Finger capture (HP's `getprintwait`):** after the same setup, the arming command is a
    3033-byte configuration program with a 338-byte type `0x0018` field (detection
    parameters). The host then polls `17` (finger state) about every 50 ms; the reply is
    status + 5 bytes, all zero until a finger is seen, then byte 2 becomes `02`. The image
    starts streaming about 18 ms after that poll reply. HP then sends `04` (abort, status
    `0412` after a swipe) and recalibrates. The only difference in setup from `getprint` is one
    register value in type `0x0005` fields (`...8000` becomes `...8200`).
11. **The swipe image is encrypted with a key the host chooses.** The image stream is
    AES-256-CBC with key = bytes 0–31 and IV = bytes 32–47 of the arming command's type
    `0x0006` field (random per session in HP's tool). Decrypted, it is a run of 272-byte frames
    (`01 fe <seq u16> <4 bytes>` + 264 pixels), descrambled by the upstream column table.
    Non-waiting `getprint` captures are not encrypted.
12. **Abort while armed pushes one frame before replying.** Without a finger, `04` makes the
    sensor send 272 bytes on the data endpoint; it does not deliver the reply until those are
    read. HP keeps a data read pending at all times.
13. **Swipe streams are continuous.** Five swipes arrived as 79–108 transfers each with at most
    21 ms between transfers and a single short transfer at the end. Reading until the data
    endpoint is quiet for 300 ms captures the whole swipe; a short transfer alone is not a
    reliable end marker.
14. **Re-arming inside a session is fast.** After an abort, re-sending the unload, patch load
    and calibration commands before the arming command took 0.65 s, versus 6.7 s for a fresh
    session.
15. **Every data-endpoint transfer must be drained before the next command.** Sending a command
   while the sensor is still streaming makes it reset (USB disconnect and re-enumeration).
16. **Patches survive a session until the sensor is suspended.** After a session the sensor
    keeps its patches, and the next session's first patch load fails (34-byte error reply),
    after which the sensor resets itself (USB disconnect). The kernel autosuspends the sensor
    2 s after the last user closes it, and suspend clears the patches: 1 s after a session the
    state is stale, 4 s after it is fresh. This is why a retry "20 seconds later" worked. A USB
    port reset also returns the sensor to its power-on state, in 0.24 s and without
    re-enumeration, so the driver resets the port on open. The state is visible in the `01`
    reply: bytes 17 and 37 are `00 00` after power-on, byte 37 is `15` with a patch loaded.
    HP ends each session with abort, unload (`1a`) and a reload of the pre-session patch before
    close_notify; the driver does the same.
17. **Setup data has no end marker.** The sensor sends the flash blocks (128 and 4096 bytes before
    the session, 512 KB inside it) and calibration data as whole 64-byte packets with no short
    packet after them. A read larger than the block only ends by timing out. pyusb returns the
    data of a timed-out read; GUsb (and so libfprint) discards its length. HP requests the exact
    length every time, and so does the driver: the command file stores each command's data
    length.
18. **The sensor resets if a command follows a flash read (`1f`) at once.** 1 ms of delay was
    enough in tests. HP never waits less than 12 ms (128-byte read) or 20 ms (4096-byte read);
    the driver waits 20 ms.
19. **Swipe streams are whole 272-byte frames** (every capture so far; the last one is a status
    frame, `01 01 00 14 ...`), but a quarter of them end on a 64-byte boundary with no short
    packet. The driver keeps four 1088-byte reads pending on the data endpoint from arming
    until after the abort, with no timeout. 1088 is the least common multiple of the packet
    and frame sizes, so every read either fills or ends on a short packet and no read is left
    holding part of a stream. Every swipe read this way had consecutive frame sequence
    numbers. HP's own recording of a swipe has 4 breaks (97 frames missing near the start),
    consistent with the sensor dropping lines when the host reads too slowly.
20. **A short read is not the end of a swipe.** The sensor flushes a short packet whenever it
    pauses, including a few frames into a swipe. Treating that as the end made the client
    abort while the sensor was still streaming (one swipe split in two, and once a sensor
    reset). A swipe ends after 300 ms without data.
21. **The finger-state poll does not reliably announce a swipe.** In HP's recordings the reply
    shows `02` just before the stream starts, but in open captures the stream often started
    between polls (up to 34 KB had arrived before the next poll). A poll that reaches the
    sensor as it starts streaming makes it reset (finding 15); this happened twice in about 60
    swipes. A finger resting without moving also triggers a capture; the stitcher rejects it
    for lack of motion.
22. **An armed sensor streams a swipe without any polls.** Eight swipes with no finger-state
    polls after arming were all captured, complete and without sequence gaps. The driver no
    longer polls: it arms, watches the data endpoint, and sends nothing until the swipe has
    ended, so no command can collide with a starting stream.
23. **The sensor accepts HP's RSA-signed patches as well as the cached-HMAC form.** Sent with
    HP's RSA signature, the 1301-byte patch took 0.11 s longer and the sensor replied with
    status and the 32-byte HMAC it computed, the value HP's software caches in the flash. The
    driver sends the cached form when the flash has the patch's entry and the RSA-signed patch
    otherwise.
24. **HP's patch table names each patch by id and version.** `validity-sensor` holds tables of
    0x60-byte entries (version at +0x20, id at +0x2c, size at +0x44, pointer at +0x48) for 27
    patches in two families (this sensor uses id 0x4000 v2, 1 v7 and 0x80 v1). The flash cache
    entry of a patch is labelled `u32 id, u8 version, "PS", ff` (HP's `LoadPatch` and
    `xvfsIsPatchSignatureCached`).
25. **The arming command's key field carries 96 per-session bytes.** Besides the image key and
    IV (bytes 0-47), bytes 48-95 of the type 0x0006 field differ in every HP session; the
    sensor accepts any value. The column descramble table is not stored in HP's program; it is
    four reversed runs (sensor columns 0-199 to image columns 199-0, 200-241 to 262-221, 242 to
    263, 243-263 to 220-200).
26. **Sensor setup takes 0.45 s instead of 1.29 s.** Timed per command: the port reset 240 ms,
    the handshake 271 ms (the sensor's RSA work), and HP's in-session read of 512 KB of flash
    540 ms. The driver skips the flash read (its data is unused; swipes without it were
    unchanged) and HP's second patch reload and calibration capture before arming (60 ms), as
    marked "omit" in the recipe, and resets the port only when the `01` status shows patches
    left from an earlier session, or after an error. Arming during a swipe does not capture
    it: with a finger swiping back and forth, the first data came 1.3 s after arming, so the
    sensor waits for a finger to arrive. Measured in fprintd, the reader was ready 0.53 s after
    the claim instead of 1.38 s. Two more savings: the stitcher's lag search (250-300 ms of
    about 340 ms) runs its 22 column offsets on all CPU cores and merges them in order, so the
    images are byte-identical and stitching takes 0.15 s instead of 0.4 s; and fprintd runs with
    `--no-timeout`, so unlocking does not wait about 0.3 s for it to start after 30 s idle.
27. **The lock screen's fingerprint attempt runs under `common-auth`.** GNOME starts both
    `gdm-password` (which includes `common-auth`, where Ubuntu's fprintd profile allows one
    try in 10 s) and `gdm-fingerprint` (3 tries); the password conversation claims the reader
    first and the other is refused. So one no-match ended the attempt. The package's own PAM
    profile allows two tries.
28. **A permanently running fprintd can keep a stale reader after resume.** On this laptop the
    USB controller is often reinitialised on resume ("xHC error in resume, Reinit") and the
    reader comes back at a new address. Once, libfprint added the new reader but kept the old
    entry, which GNOME used first: no fingerprint prompt (`libusb couldn't open USB device
    /dev/bus/usb/001/052`). fprintd was idle at the time, so the stale entry was not held open.
    Since fprintd runs with `--no-timeout`, the package restarts it after every resume, so it
    never carries devices across a suspend. From a systemd sleep hook the restart came while
    logind was still finishing the sleep, and fprintd could not take its sleep inhibitor
    (28 warnings in October); since 0.6.0 a unit ordered after the sleep targets restarts it.

## Image quality (Phase 2, in progress)

Reference set: 10 swipes recorded from HP's tool, each with the raw scan lines and HP's own
assembled 200x300 image (`research/reference/`). Scoring uses libfprint's matcher through the
`vfs495-match` tool of the vfs495-fprint package: each image is enrolled alone and verified
against every other (`research/quality/score.py`); fprintd accepts a score of 40.

| Images | Pairs matching | Median score |
|---|---|---|
| HP's assembled images | 64% | 44 |
| HP's images after our old post-processing | 7% | 20 |
| HP's images, column offsets removed only | 52% | 41 |
| Our stitching (near-raw output), 10 reference swipes | 83% | 60 |
| Our stitching, 15 right-index swipes (10 HP-session + 5 open-client) | 92% | 67 |
| Our stitching, 5 left-index swipes | 90% | 118 |
| Our stitching, 5 right-middle swipes | 100% | 116 |
| Our stitching, **different fingers** (350 pairs) | **0%** | 6 (max 18) |

Controls: upside-down copies of our images never match the originals (0 of 100 pairs, max 17),
so the scores come from fingerprint geometry, not the sensor's fixed column pattern. All 600
pairs of the 25 images were scored. Long single `vfs495-match` runs hit libfprint's thermal
protection ("Device disabled to prevent overheating"), which shows up as -1 scores and missing
pairs, so `research/quality/score_blocks.py` scores every pair of 5-image blocks in a fresh
process.

Findings:

1. **The sensor has two sensing lines.** Columns 200–263 of each line are a shorter auxiliary
   line with inverted polarity, over main columns ~68–131, that sits ahead of the main line in
   the swipe direction. A ridge reaches the main line `lag` lines after the aux line, so the
   finger moves D / lag pixels per line. This is the same two-scanner principle libfprint's
   `fpi_assemble_lines` uses.
2. **D ≈ 8 pixels**, calibrated by aligning stitched output with HP's images of the same swipes.
3. **Lags are reliable while the finger moves** (typical lag 25–60 lines). They are unreliable
   when the finger rests (every aux line matches the same frozen main line, giving a fake,
   steadily shrinking lag), at the very start and end of a swipe, and at lags of 1–5 lines
   (crosstalk). A resting finger is detected directly: a line nearly repeats the line 20 earlier.
4. **The matcher wants near-raw images.** Spatial filtering that looks cleaner to the eye (high
   pass, band pass, local contrast normalisation) sharply lowers match rates even on HP's own
   images. Output gets column offset and gain correction only; this change took our stitching
   from 24% to 83% matching pairs. The filtered lines are still used for speed estimation.
5. **A global alignment against HP's image is not a usable geometry metric**: small local speed
   errors accumulate and the correlation collapses, so it cannot guide fine tuning.

## Swipe feedback and enrollment

**Rejected swipes are retries, not failed matches.** fprintd restarts verification after a
retry and pam_fprintd shows its message without using up an attempt, while a poor image that
fails to match ends the attempt. The driver judges every swipe (`vfs495_swipe_verdict`) from
measurements the stitcher takes of the finger region, and reports a retry for bad ones:

| Verdict | Rule | Message (pam_fprintd) |
|---|---|---|
| finger resting | still >= 90% and < 10 trusted speed estimates | Remove your finger, and try swiping your finger again |
| off centre | fewer than 60% of columns carry ridges | Your finger was not centered, try swiping your finger again |
| too fast | >= 25% of confident lags below the trusted minimum | Swipe was too fast, try again |
| too short | under 100 lines, no usable motion, or under 185 rows | Swipe was too short, try again |

The limits sit between 44 normal swipes (three fingers, six sessions: at most 15% fast, at least
88% coverage, at most 36% still), all judged ok, and 11 deliberately bad ones (fast: at least
30% fast; off centre: at most 40% coverage; resting: 100% still, no motion), all judged
correctly (`captures/diag/`). Rejecting them costs nothing: the bad swipes that still stitched to
an image scored at most 36 against ten templates from another session, while the eight normal
swipes of the same sitting scored 83-120.

**A swipe ends after 80 ms of silence** (300 ms during its first 50 frames). The longest pause
inside 19 measured swipes was 4 ms and in HP's recordings 21 ms; one early test swipe paused
after its first 3 frames and resumed within 200 ms.

**Enrollment takes 8 swipes** (libfprint's default for image devices is 5). Simulated with
libfprint's matcher on 31 right-index swipes from five sessions (all 1640 pairs of 41 images
scored), enrolling in one sitting and verifying with swipes from other sessions: 1 template
missed 16.8% of good swipes, 5 templates 2.5%, 6 or more none. Other fingers never scored
above 18 (40 is a match) against any number of templates. fprintd adds one swipe of its own
before enrollment to refuse duplicates.

## Command data from HP's package

`driver/recipe/vfs495-recipe.json` describes the driver's 26 commands and the descramble table
as parts: 290 bytes of literals (command bytes, TLV headers, flash-read parameters, the
ClientHello frame, the finger-detection constants of the arming command and the 57-byte
finger-detection setup), zero runs, byte ranges of HP's `validity-sensor` (the configuration
programs), and patches by id, version, size and hash in HP's patch table.
`driver/recipe/build-commands.py` builds the command file from `sp84530.tar` (MD5-checked), the
RPM in it or the program (SHA-256-checked), reading the RPM and cpio archive in pure Python.

Signed patches are stored with their flash label and HP's RSA signature; the driver sends the
cached-HMAC form or the RSA-signed patch (finding 23). The per-session parts (ClientHello
random, arming key field) are left zero and filled by the driver.

Verification: built from the SoftPaq alone and sent as the driver sends it to this sensor, the
command data equals the data recorded from HP's tool for all 26 commands (`meson test`,
`recipe`); on the sensor, sessions open in 1.04 s and swipes are captured with it.
`research/hpdata/make_recipe.py` derives the recipe from a recorded command file, and
`research/hpdata/map_commands.py` shows which bytes of it occur in HP's files.

## Beta diagnostics

`vfs495-diag` (`driver/tools/diag.sh`, driver side in `driver/src/vfs495-diag.c`) records what
the journal cannot: the swipes themselves.

| Command | Effect |
|---|---|
| `vfs495-diag status` | on or off, until when, how many swipes |
| `sudo vfs495-diag on [DAYS]` | record for DAYS days (default 30, at most 60), from the next fingerprint prompt |
| `sudo vfs495-diag off` | stop and delete everything recorded |
| `sudo vfs495-diag bundle [DIR]` | one `.tar.gz` (default `captures/bundles/` of the checkout): the recordings, fprintd's journal since recording began, suspend and resume events, the enrolled prints, package versions |

Per swipe the driver writes a folder with `swipe.json` (action, verdict, the stitcher's
measurements, sequence gaps, abort status, setup, wait, swipe, decode and stitch times, port
resets, error recovery), `stream.dec` (the decrypted frames) and `image.pgm` (the stitched
image, also for rejected swipes); `events.log` lists every session step with millisecond
times. Everything is root-only (folders 0700, files 0600), the newest 500 swipes are kept,
recording stops by itself at the chosen date, and systemd-tmpfiles deletes anything older
than 60 days. Recording is off unless `/var/lib/vfs495-driver/diag/until` names a future time.
These are fingerprint scans: a bundle belongs only with whoever works on the driver.

## Tests

`meson test -C build/driver` runs four kinds:

- **unit** (`driver/tests/vfs495-unit.c`, 19 tests, no recorded data, runs in CI): the
  stitcher on simulated swipes (`driver/tests/vfs495-sim.c`: a synthetic fingertip with
  irregular ridges swiped over the two sensing lines with the measured pixel levels, noise and
  column pattern) for speed, scale, image fidelity and every verdict, a dead column, and
  thread-independent output; the stream decoder round trip through AES and frames, with lost
  frames and junk; the command file parser against malformed files; the record layer, and the
  key exchange against an RSA key made in the test (the sensor's side decrypts the pre-master
  secret and verifies the host's Finished); signed patches; the diagnostics' on/off switch,
  files, permissions and pruning.
- **regression** (`driver/tests/vfs495-test.c`): the same code against private recordings in
  `captures/` (below, "Layout").
- **umockdev** (`driver/tests/umockdev/`): libfprint's own way of testing drivers. A capture
  session through libfprint, recorded from the reader with umockdev
  (`sudo driver/tests/umockdev/record.sh`), is replayed without it, and the image must come out
  byte for byte. The driver runs in libfprint's emulation mode (`FP_DEVICE_EMULATION=1`), where
  its random values (handshake randoms, RSA padding, image key) come from a fixed sequence, so
  the replayed session matches the recording. The recordings hold a fingerprint and stay in
  `captures/umockdev/`; re-record after changing the command data or what the driver sends.
- **fuzz-corpus** replays of the fuzz corpus (see "Hardening").

The simulator also showed a limit of the stitcher: it finds the finger from ridge energy
against the last quarter of the stream, which is finger-free in real swipes (the sensor
streams on for 1,000-3,000 lines after the finger leaves). A stream where the finger is still
on the sensor in its last quarter gets a shortened print; one of the 57 recorded swipes is like
that.

## Hardening

The driver runs inside fprintd, as root, and parses bytes from the USB device (which could be
something pretending to be the reader) and the command file. The parsers are fuzzed and the
tests run under AddressSanitizer and UndefinedBehaviorSanitizer:

- Sanitizer runs found two faults, both in the command file loader: its descramble table was
  used unchecked as column indices by the swipe decoder (a malformed file could write past a
  line buffer), and it read numbers through misaligned pointers (undefined behaviour). The
  loader now reads byte by byte and accepts only a permutation of the 264 columns and known
  phases.
- First fuzzing run, 10 minutes per target: 45 million command files, 9.9 million record-layer
  inputs, 5.5 million frame streams and 3,565 stitcher inputs (up to 400 lines) without a
  fault. The inputs that added coverage joined the corpus (329 inputs), which
  `hardening-check.sh` replays.
- Under libFuzzer, UndefinedBehaviorSanitizer slows the stitcher about tenfold (2.8 s against
  0.26 s with AddressSanitizer alone, for 150 lines), so the stitcher is fuzzed with
  AddressSanitizer and its corpus replayed under both.

## Configuration programs

The 17 distinct configuration programs (`02`) HP sends before and during finger capture are TLV
lists. Checked against HP's `validity-sensor` binary and across 12 recorded HP sessions:

- **Stored verbatim in HP's binary:** every type `0x0002` table (1408 bytes each, 24 KB in
  total), 1269 of 1294 register writes (type `0x0003`, 9 bytes each), and all fields of types
  `0x0007`, `0x000a`, `0x000c`–`0x0015`, `0x0017`, `0x001b`, `0x001d`. A driver can extract
  these from HP's package at install time, like the patch bodies.
- **Computed by HP, identical in all 12 sessions (35 fields):** 25 register writes, the type
  `0x0005` register masks and the 338-byte type `0x0018` finger-detection parameters. Whether
  they differ between sensors is unknown without a second VFS495.
- **Computed per session (1 value):** the low byte of register `0x2014` in a type `0x0005`
  field repeated in 7 commands (`80`, `82`, `83`… across sessions), evidently a calibration
  result. Open captures that reuse one recorded value work.
- **Chosen by the host:** the type `0x0006` field (image key).

Where the programs come from (live trace of HP's command senders,
`research/programs/trace_senders.py`): every `02` program is sent by
`scsSensorSendGetFingerprint_V4` from a "print configuration" (configuration lists
`falconPrintConfigList`, `falconCalConfigList`, `falconWoeConfigList` in HP's binary). A
finger-capture session runs:

| Commands | HP function | Role |
|---|---|---|
| #3 | `scsDetermineFlexId` | identify the sensor variant |
| #6–#12 | `scsSensorFalconCalibrate` | 7 calibration captures, then `scsFalconCalWoe` computes finger-detection settings |
| `12` | `scsSensorFalconWOESetup` | finger-detection (wake on event) setup |
| #16, #21 | `scsSesnorGetBaselineData` | baseline captures (2402-byte replies) |
| #22 | `idsWITSensorGetFalconFingerprint` | arm finger detection, then poll `17`, then abort `04` |

The computed fields are calibration results. Apart from the three type `0x0005` masks per
program and the type `0x0018` detection parameters in the arming command, they are three
register writes: `0x300420c8 = 0x83` (from calibration pass 2 on), `0x30042120 = 0x06` and
`0x30042160 = 0x06` (from pass 7 on). `scsSensorFalconCalibrate` is a state machine with seven capture stages (`scsFalconCalCommDet`,
`PgaOffset`, `Adc`, `AspLna1`, `AspPga1`, `PgaGain`, `Woe`), about 3,000 decompiled lines.

**Calibration can be switched off.** HP reads a `calibrationEnable` setting (default 1; the
persistent store is empty) and without it uses `scsFalconCalSetDefaults`. With the default
forced to 0 (`research/programs/nocal.py`) the session shrinks to 12 commands before arming, and
every field of every program is verbatim from HP's binary except the 338-byte type `0x0018`
detection parameters, which are identical with and without calibration and across all 13
recorded sessions. `scsSensorSendGetFingerprint_V4` builds that field in code: a type `0x18`,
length `0x152` TLV holding about ten 16-bit motion parameters (values such as 10, 10, 150,
30, 400, and `0x80c7` from the sensor-variant table), zero-padded to 338 bytes. HP's related
settings are named `motionParam*`. A driver can build it from named constants. The open client runs this sequence with setup in 0.95 s.

Uncalibrated captures match well (right index, 5 uncalibrated swipes vs each other and vs
calibrated swipes, batch-scored):

| Comparison | Pairs matching | Median score |
|---|---|---|
| uncalibrated vs uncalibrated | 100% (20/20) | 69 |
| calibrated vs calibrated | 100% (90/90) | 79 |
| uncalibrated vs calibrated | 88% (88/100) | 59 |
| uncalibrated vs other fingers | 0% (0/100) | 6.5, max 15 |

Decision for the first driver version: run uncalibrated, with the session designed so a
calibration stage can be added before arming later. Caveat: 5 swipes on one sensor; calibration
may matter across temperature or sensor units.

## Layout

- `research/handshake/record_hp_session.sh NAME [getprint|getprintwait]` records one HP
  session under gdb: USB traffic to `captures/wire.NAME.log`, session secrets to
  `captures/session.NAME.jsonl`.
- `research/handshake/dump_session.py` is the gdb script it uses (HP 4.5-136 addresses).
- `research/handshake/verify.py` recomputes a recorded handshake offline with the upstream code.
- `research/handshake/live_test.py` runs the upstream handshake live against the sensor.
- `research/session/decrypt.py` decrypts all in-session traffic of a recording, MAC-checked.
- `research/session/vfs495.py` is the open client library.
- `research/session/replay.py` replays a decrypted recording through the open client.
- `research/session/capture.py` captures swipes with the open client only.
- `research/image/decode.py` turns a decrypted swipe stream into descrambled scan lines.
- `research/reference/record_reference.sh` records HP reference swipes (lines + HP's image);
  `process.py` turns them into pairs in `captures/refset/`.
- `research/programs/trace_senders.py` is a gdb script that logs every command HP sends with
  its call chain.
- `research/quality/assemble.py` is the two-line stitcher; `score.py` scores one image set;
  `score_blocks.py` scores large sets in batches.
- `research/patches/dump_hmac.py` is a gdb script that logs HP's patch-signature handling.
- `research/tools/usblog.c` is the upstream libusb-0.1 logger with a thread-safety fix.
- `research/hpdata/` maps the command data onto HP's package and derives the recipe;
  `live-test.sh` and `nopoll-test.sh` are the sensor tests behind findings 22 and 23.
- `driver/recipe/` builds the driver's command file from HP's download: the recipe,
  `build-commands.py` and `hp_package.py` (reads SoftPaq sp84530, finds HP's patch table).
- `driver/` is the C code for the libfprint driver, built with meson (`meson setup build/driver
  driver && ninja -C build/driver`; `-Dnative=true` tunes for the build machine, which makes no
  measurable difference). `driver/tools/make-commands.py` writes the command file the
  driver loads from a decrypted recording (it stays in `captures/`). `vfs495-tool capture
  captures/vfs495-commands.bin OUT 5 45` captures five swipes; `vfs495-tool assemble` stitches
  saved scan lines. The C stitcher matches `assemble.py` to within one grey level.
- `driver/src/vfs495.c` is the libfprint driver, built as `build/driver/libfprint-tod-vfs495.so`.
  It reads the command file from `/usr/lib/vfs495-driver/commands.bin` (`$VFS495_COMMANDS`
  overrides). `driver/tools/fp-test.py` runs it through libfprint without installing it
  (`list`, `open`, `capture`, `enroll`, `verify`). Driver design notes:
  - it resets the USB port on open (finding 16) and on recovery;
  - four data reads stay pending from arming until after the abort (finding 19); a swipe ends
    after a silence (finding 20, "Swipe feedback"); decoding and stitching run in a worker
    thread;
  - an error before a finger is reported triggers one silent reset and setup; an error
    during a swipe asks for a retry; suspend stops while waiting for a finger, and resume
    sets up again;
  - the module marks itself resident: its GType cannot be unregistered, and libfprint
    unloads TOD modules when its context is freed.
- `driver/packaging/build-deb.sh` builds the `vfs495-driver` package into `build/deb/`, with
  command data built from HP's download (it is HP-derived, so the package must not be
  redistributed); `driver/tools/install-driver.sh`
  builds and installs it. The package has fprintd log match results, which `vfs495-scores
  [SINCE]` (`driver/tools/scores.sh`) summarises; `vfs495-check` (`driver/tools/check.py`)
  reports whether libfprint loads the driver.
- `driver/tests/vfs495-unit.c` and `vfs495-sim.c` are the tests without recorded data
  ("Tests"); `driver/tests/umockdev/` records and replays capture sessions.
- `driver/tests/vfs495-test.c` holds the regression tests (`meson test -C build/driver`). They
  check the driver's code against private data in `captures/` and skip without it: the SSLv3
  code against five recorded HP sessions (keys, Finished, and all 2525 client records
  re-encrypted byte for byte, all server replies MAC-checked), the command file's structure,
  decoding of a swipe HP's tool received, the command file built from HP's package against the
  recorded one, and the stitcher's verdict and image for 57 saved scans.
  `driver/tests/golden.txt` holds the expected verdicts, sizes and hashes; after an intended
  change, `build/driver/vfs495-test --update driver/tests/golden.txt captures` updates it.
  `driver/tests/make-vectors.py` extracts the session vectors from recordings.
- `driver/fuzz/` holds fuzz targets for every parser of untrusted bytes (the command file, the
  record layer and handshake reply, signed patches against a flash block, swipe frames, the
  stitcher), built as libFuzzer fuzzers with clang or as replayers of the private corpus in
  `captures/fuzz/`. `driver/tools/hardening-check.sh` runs the regression tests and the
  corpus replay with AddressSanitizer and UndefinedBehaviorSanitizer (see "Hardening").
- `captures/` holds recordings. It is git-ignored: recordings contain the sensor serial,
  per-device keys and raw sensor data.

## Running

Requires the `vfs495-fprint` package (it installs HP's binary to `/var/lib/vfs495-fprint` and a
udev rule giving the logged-in user access to the sensor), `gdb`, and a virtualenv:

```bash
python3 -m venv .venv && .venv/bin/pip install pyusb cryptography
research/handshake/record_hp_session.sh run4
PYTHONPATH=research/handshake/stubs python3 research/handshake/verify.py captures/session.run4.jsonl captures/wire.run4.log
.venv/bin/python research/session/decrypt.py captures/session.run4.jsonl captures/wire.run4.log
cd research/session && ../../.venv/bin/python replay.py ../../captures/wire.run4.decrypted.json test
```

The open client only replays commands recorded from HP's `getprint` and `getprintwait`.
Upstream analysis found that this command path writes nothing permanent to the sensor: patches
go to sensor RAM. Nothing here issues HP's flash-write or provisioning commands.
