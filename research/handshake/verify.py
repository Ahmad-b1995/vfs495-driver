"""Recompute a recorded HP handshake with the project's SSL code and compare byte for byte.
Usage: python3 verify.py [session.jsonl] [wire.log]   (defaults: captures/session.run2.jsonl, captures/wire.run2.log)"""
import json, struct, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAPTURES = ROOT / "captures"
sys.path.insert(0, str(ROOT.parent / "vfs495-linux" / "tools"))  # sibling clone of saifulmd0/vfs495-linux
from ssl_session import ssl3_prf, ssl3_finished, SSLState   # the project's own implementation

ev = [json.loads(l) for l in open(sys.argv[1] if len(sys.argv) > 1 else CAPTURES / "session.run2.jsonl")]
get = lambda k: [e for e in ev if e["kind"] == k]
wire = [l.split() for l in open(sys.argv[2] if len(sys.argv) > 2 else CAPTURES / "wire.run2.log")]
outs = [bytes.fromhex(w[5].split("=")[1]) for w in wire if w[1] == "OUT" and w[5].startswith("data=")]
ins = [bytes.fromhex(w[5].split("=")[1]) for w in wire if w[1] == "IN" and w[2] == "ep=01" and len(w) > 5]

ch_tun = next(o for o in outs if o[:3] == b"\x11\x3c\x00")
fl_tun = next(o for o in outs if o[:3] == b"\x11\x54\x01")
sh = next(i for i in ins if i[:3] == b"\x16\x03\x00")
ch_rec = ch_tun[3:]; ch_hs = ch_rec[5:]
sh_body = sh[5:5 + int.from_bytes(sh[3:5], "big")]
fl = fl_tun[3:]
cke_rec = fl[:5 + int.from_bytes(fl[3:5], "big")]; cke_hs = cke_rec[5:]
rest = fl[len(cke_rec):]; ccs = rest[:6]; fin_rec = rest[6:]
cR, sR = ch_rec[11:43], sh[11:43]

hs = [bytes.fromhex(e["data"]) for e in get("hs_update")]
print("1. hashed msgs == wire (CH, SH, SHD, CKE):", hs == [ch_hs, sh_body[:49], sh_body[49:], cke_hs])

pm = get("premaster")[0]; keys = get("keys")[0]
premaster = bytes.fromhex(pm["premaster"])
print("2. randoms: ctx+0x38==client, ctx+0x40==server:", pm["rand_0x38"] == cR.hex(), pm["rand_0x40"] == sR.hex())
master = ssl3_prf(premaster, cR, sR, 48)
kb = ssl3_prf(master, sR, cR, 136)
print("3. KDF master / keyblock match HP:", master.hex() == keys["master"], kb.hex() == keys["keyblock"])

fin = ssl3_finished(master, ch_hs + sh_body + cke_hs, struct.pack("<I", 0x434C4E54))
hp_fin = bytes.fromhex(get("finished")[0]["out"])
print("4. Finished body matches HP:", b"\x14\x00\x00\x24" + fin == hp_fin)
st = SSLState(kb)
print("5. encrypted Finished record == wire bytes:", st.encrypt_record(0x16, b"\x14\x00\x00\x24" + fin) == fin_rec, "| CCS:", ccs.hex())

k1, k2 = [bytes.fromhex(e["modulus"]) for e in get("rsakey")]
ops = get("rsa_op")
cke_ct = cke_hs[4:]
em = bytes.fromhex(ops[-1]["em"])
print("6. premaster-encryption EM ends with premaster:", em[:2].hex(), em[-48:] == premaster)
for name, key in (("key1", k1), ("key2", k2)):
    for order in ("little", "big"):
        n = int.from_bytes(key, order)
        c = pow(int.from_bytes(em, "big"), 65537, n).to_bytes(256, "big")
        if c in (cke_ct, cke_ct[::-1]):
            print(f"   CKE ciphertext produced by {name} read {order}-endian", "(wire reversed)" if c != cke_ct else "")
em1 = bytes.fromhex(ops[0]["em"])
for order in ("little", "big"):
    n = int.from_bytes(k1, order)
    for eo in ("big", "little"):
        m = pow(int.from_bytes(em1, eo), 65537, n).to_bytes(256, "big")
        if m[:2] in (b"\x00\x01", b"\x01\x00") or m[-2:] in (b"\x01\x00",):
            print(f"7. first RSA op with key1 ({order}, input {eo}) decodes to signature padding:", m[:12].hex(), "...", m[-40:].hex())
