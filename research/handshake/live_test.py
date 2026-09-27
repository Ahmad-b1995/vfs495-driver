"""Live handshake test: the project's own SSL client code (tools/ssl_session.py), fed with this
sensor's key 2 and the init commands recorded from HP's session (wire.run3.log)."""
import json
import secrets
import struct
import sys

import usb.core
import usb.util

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAPTURES = ROOT / "captures"
sys.path.insert(0, str(ROOT.parent / "vfs495-linux" / "tools"))  # sibling clone of saifulmd0/vfs495-linux
from ssl_session import SSLState, rsa_encrypt_reversed, ssl3_finished, ssl3_prf, tunnel

VID, PID, EP_OUT, EP_IN, EP_DATA = 0x138A, 0x003F, 0x01, 0x81, 0x82

outs = []
for line in open(CAPTURES / "wire.run3.log"):
    w = line.split()
    if len(w) > 5 and w[1] == "OUT" and w[5].startswith("data="):
        outs.append(bytes.fromhex(w[5][5:]))
ch_idx = next(i for i, o in enumerate(outs) if o[:1] == b"\x11")
init, ch_template = outs[:ch_idx], outs[ch_idx]
keys = [json.loads(l) for l in open(CAPTURES / "session.run2.jsonl") if '"rsakey"' in l]
modulus = bytes.fromhex(keys[1]["modulus"])  # key 2: the one HP encrypts the premaster with

dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None:
    sys.exit("sensor not found")
dev.set_configuration(1)
usb.util.claim_interface(dev, 0)


def send(p):
    dev.write(EP_OUT, p, 3000)


def recv(n=0x400, to=3000):
    return bytes(dev.read(EP_IN, n, to))


try:
    for c in init:
        send(c)
        r = recv()
        if c[0] == 0x1F:
            try:
                while len(bytes(dev.read(EP_DATA, 16384, 400))) == 16384:
                    pass
            except usb.core.USBError:
                pass
        print(f"init cmd {c[0]:02x} len {len(c)} -> status {r[:2].hex()}")

    rec_ch = bytearray(ch_template[3:])
    client_random = secrets.token_bytes(32)
    rec_ch[11:43] = client_random
    ch_hs = bytes(rec_ch[5:])
    premaster = b"\x03\x00" + secrets.token_bytes(46)
    cke_hs = b"\x10\x00\x01\x00" + rsa_encrypt_reversed(modulus, 0x10001, premaster)
    cke_rec = b"\x16\x03\x00" + struct.pack(">H", len(cke_hs)) + cke_hs

    send(tunnel(bytes(rec_ch)))
    sh = recv()
    sh_hs = sh[5:5 + int.from_bytes(sh[3:5], "big")]
    server_random = sh[11:43]
    print("ServerHello:", sh[:12].hex(), "len", len(sh))

    master = ssl3_prf(premaster, client_random, server_random, 48)
    st = SSLState(ssl3_prf(master, server_random, client_random, 136))
    fin_hs = b"\x14\x00\x00\x24" + ssl3_finished(master, ch_hs + sh_hs + cke_hs, struct.pack("<I", 0x434C4E54))
    send(tunnel(cke_rec + b"\x14\x03\x00\x00\x01\x01" + st.encrypt_record(0x16, fin_hs)))
    resp = recv()
    print("response:", resp.hex())
    if resp[:1] == b"\x14":
        print("RESULT: HANDSHAKE ACCEPTED (server sent ChangeCipherSpec + Finished)")
    elif resp[:1] == b"\x15":
        print(f"RESULT: ALERT level {resp[5]} desc 0x{resp[6]:02x}")
finally:
    usb.util.release_interface(dev, 0)
    usb.util.dispose_resources(dev)
