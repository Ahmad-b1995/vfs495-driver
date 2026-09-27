"""Decrypt the application traffic of a recorded HP session.

Uses the key block HP derived (from the gdb events) to decrypt every SSL record after the
handshake in both directions, checking each record's MAC. Prints one line per transfer and
writes the full transcript as JSON next to the wire log.

Usage: python3 decrypt.py captures/session.NAME.jsonl captures/wire.NAME.log
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Direction:
    """One direction of the Validity SSLv3 record layer (AES-256-CBC, SHA-1 MAC without length)."""

    def __init__(self, mac_key, key, iv):
        self.mac_key, self.key, self.iv, self.seq = mac_key, key, iv, 0

    def open(self, rtype, ct):
        dec = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        self.iv = ct[-16:]
        pad = pt[-1] + 1
        body, mac = pt[:-pad][:-20], pt[:-pad][-20:]
        hdr = struct.pack(">Q", self.seq) + bytes([rtype])
        inner = hashlib.sha1(self.mac_key + b"\x36" * 40 + hdr + body).digest()
        ok = hashlib.sha1(self.mac_key + b"\x5c" * 40 + inner).digest() == mac
        self.seq += 1
        return body, ok


def records(buf):
    """Split a buffer of SSL records into (type, payload) pairs."""
    out = []
    while len(buf) >= 5:
        n = int.from_bytes(buf[3:5], "big")
        out.append((buf[0], buf[5:5 + n]))
        buf = buf[5 + n:]
    return out


def load_wire(path):
    xfers = []
    for line in open(path):
        w = line.split()
        if len(w) > 5 and w[1] in ("OUT", "IN") and w[5].startswith("data="):
            xfers.append((w[1], w[2].split("=")[1], bytes.fromhex(w[5][5:])))
    return xfers


def main():
    events = [json.loads(l) for l in open(sys.argv[1])]
    kb = bytes.fromhex(next(e for e in events if e["kind"] == "keys")["keyblock"])
    client = Direction(kb[0:20], kb[40:72], kb[104:120])
    server = Direction(kb[20:40], kb[72:104], kb[120:136])
    xfers = load_wire(sys.argv[2])

    transcript, in_session, bad = [], False, 0
    for i, (d, ep, data) in enumerate(xfers):
        entry = {"i": i, "dir": d, "ep": ep, "len": len(data)}
        if d == "OUT" and data[:3] == b"\x11\x54\x01":  # client flight: CKE, CCS, Finished
            recs = records(data[3:])
            body, ok = client.open(0x16, recs[2][1])
            entry.update(kind="client Finished", mac_ok=ok)
            in_session = True
        elif in_session and d == "IN" and ep == "01" and data[:1] == b"\x14":
            # server CCS + Finished, followed by one unsolicited app-data record (seq 1)
            recs = records(data)
            body, ok = server.open(0x16, recs[1][1])
            plain = []
            for rtype, ct in recs[2:]:
                extra, extra_ok = server.open(rtype, ct)
                plain.append(extra.hex())
                ok = ok and extra_ok
            entry.update(kind="server Finished", mac_ok=ok, plain="".join(plain))
        elif in_session and ep == "01" and data[:1] in (b"\x17", b"\x15"):
            side = client if d == "OUT" else server
            plain = []
            for rtype, ct in records(data):
                body, ok = side.open(rtype, ct)
                plain.append(body.hex())
                bad += not ok
                entry.update(kind="alert" if rtype == 0x15 else "appdata", mac_ok=ok)
            entry["plain"] = "".join(plain)
        else:
            entry.update(kind="plain", head=data[:24].hex())
            if d == "OUT":
                entry["plain"] = data.hex()
        transcript.append(entry)

    for e in transcript:
        p = bytes.fromhex(e.get("plain", ""))
        if e["kind"] == "appdata" and e["dir"] == "OUT":
            desc = f"CMD {p[0]:02x} +{len(p) - 1}B  {p[1:25].hex()}"
        elif e["kind"] == "appdata":
            desc = f"REPLY status {p[:2][::-1].hex()} +{len(p) - 2}B  {p[2:26].hex()}"
        elif e["kind"] == "alert":
            desc = f"ALERT {p.hex()}"
        elif e["kind"].endswith("Finished"):
            desc = e["kind"] + (f" + unsolicited {p.hex()}" if p else "")
        elif e["dir"] == "OUT":
            desc = f"plain CMD {p[0]:02x} +{len(p) - 1}B"
        else:
            desc = f"plain {e['head']}"
        mac = "" if "mac_ok" not in e else ("  mac ok" if e["mac_ok"] else "  MAC FAIL")
        print(f"{e['i']:3d} {e['dir']:3s} ep{e['ep']} {e['len']:6d}  {desc}{mac}")

    out = Path(sys.argv[2]).with_suffix(".decrypted.json")
    json.dump(transcript, open(out, "w"), indent=1)
    print(f"\n{bad} MAC failures; transcript: {out}")


if __name__ == "__main__":
    main()
