# vfs495-driver

Work towards a native Linux driver for the Validity VFS495 swipe fingerprint reader
(USB `138a:003f`), found in 2013–2015 HP EliteBook, ProBook and ZBook laptops.

Builds on the reverse engineering in
[saifulmd0/vfs495-linux](https://github.com/saifulmd0/vfs495-linux) (MIT), expected as a
sibling clone at `../vfs495-linux`.

## Status

**Open code captures from the sensor end to end, with no HP code involved.** The open client
(`research/session/vfs495.py`) reads the sensor's key from its flash, completes the secure
session, configures the sensor, arms finger detection with an image key it chooses itself,
polls for the finger, decrypts and decodes the swipe, and aborts cleanly
(`research/session/capture.py`). Five consecutive swipes in one session all produced full,
clear prints of the same finger. Setup takes 6.7 s once; re-arming between swipes 0.65 s.

What still comes from HP: the firmware patch bodies and the configuration command payloads,
taken from recordings of HP's tool. Open question for the driver: how to obtain those
payloads at install time without redistributing them, and whether they differ between sensors.

Current work: stitching swipes into undistorted prints (Phase 2, see "Image quality" below).

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
16. **The sensor needs recovery handling on open.** Starting the init sequence immediately after
    HP's tool exited once failed with a USB I/O error on the first patch upload; 20 seconds
    later it succeeded. A client that exits while the sensor is armed and holding data leaves
    it to reset itself. A driver needs a reset or abort step before init.

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
