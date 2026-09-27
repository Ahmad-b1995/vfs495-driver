"""Minimal open-source client for the Validity VFS495 (138a:003f).

Covers the plaintext pre-session commands, the Validity SSLv3 handshake, encrypted commands and
replies (with MAC checks), and bulk reads from the image endpoint. Protocol details are in the
project README; crypto primitives come from saifulmd0/vfs495-linux tools/ssl_session.py.
"""
import hashlib
import secrets
import struct
import sys
from pathlib import Path

import usb.core
import usb.util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT.parent / "vfs495-linux" / "tools"))
from ssl_session import SSLState, rsa_encrypt_reversed, ssl3_finished, ssl3_prf  # noqa: E402

VID, PID = 0x138A, 0x003F
EP_OUT, EP_CMD_IN, EP_DATA_IN = 0x01, 0x81, 0x82
DATA_CHUNK = 16384

# Where the sensor keeps its RSA key in the 4096-byte flash block returned by the
# second pre-session 0x1f read.
FLASH_KEY_OFFSET = 1718
LABEL_CLIENT = struct.pack("<I", 0x434C4E54)


class ProtocolError(Exception):
    pass


class _ServerState:
    """Server-to-host direction of the record layer: decrypt and verify."""

    def __init__(self, mac_key, key, iv):
        self.mac_key, self.key, self.iv, self.seq = mac_key, key, iv, 0

    def open(self, rtype, ct):
        pt = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)).decryptor().update(ct)
        self.iv = ct[-16:]
        pad = pt[-1] + 1
        body, mac = pt[:-pad][:-20], pt[:-pad][-20:]
        hdr = struct.pack(">Q", self.seq) + bytes([rtype])
        inner = hashlib.sha1(self.mac_key + b"\x36" * 40 + hdr + body).digest()
        if hashlib.sha1(self.mac_key + b"\x5c" * 40 + inner).digest() != mac:
            raise ProtocolError(f"bad MAC on server record seq {self.seq}")
        self.seq += 1
        return body


def split_records(buf):
    out = []
    while len(buf) >= 5:
        n = int.from_bytes(buf[3:5], "big")
        out.append((buf[0], buf[5:5 + n]))
        buf = buf[5 + n:]
    return out


class Vfs495:
    def __init__(self, log=print):
        self.log = log
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise ProtocolError("sensor not found")
        self.dev.set_configuration(1)
        usb.util.claim_interface(self.dev, 0)
        self.client = None
        self.server = None

    def close(self):
        usb.util.release_interface(self.dev, 0)
        usb.util.dispose_resources(self.dev)

    # --- raw transport -----------------------------------------------------------------
    def _write(self, data, timeout=3000):
        self.dev.write(EP_OUT, data, timeout)

    def _read_cmd(self, size=0x4000, timeout=3000):
        return bytes(self.dev.read(EP_CMD_IN, size, timeout))

    def read_data(self, timeout=1000):
        """Read the image/data endpoint until a short transfer or a timeout."""
        chunks = []
        while True:
            try:
                chunk = bytes(self.dev.read(EP_DATA_IN, DATA_CHUNK, timeout))
            except usb.core.USBTimeoutError:
                break
            chunks.append(chunk)
            if len(chunk) < DATA_CHUNK:
                break
        return b"".join(chunks)

    # --- plaintext phase ---------------------------------------------------------------
    def cmd_plain(self, payload):
        self._write(payload)
        return self._read_cmd()

    # --- SSL session -------------------------------------------------------------------
    def handshake(self, modulus, client_hello_template):
        rec_ch = bytearray(client_hello_template[3:])
        client_random = secrets.token_bytes(32)
        rec_ch[11:43] = client_random
        ch_hs = bytes(rec_ch[5:])
        premaster = b"\x03\x00" + secrets.token_bytes(46)
        cke_hs = b"\x10\x00\x01\x00" + rsa_encrypt_reversed(modulus, 0x10001, premaster)
        cke_rec = b"\x16\x03\x00" + struct.pack(">H", len(cke_hs)) + cke_hs

        self._write(bytes([0x11]) + struct.pack("<H", len(rec_ch)) + bytes(rec_ch))
        sh = self._read_cmd()
        if sh[:1] != b"\x16":
            raise ProtocolError(f"unexpected ServerHello: {sh[:16].hex()}")
        sh_hs = sh[5:5 + int.from_bytes(sh[3:5], "big")]
        server_random = sh[11:43]

        master = ssl3_prf(premaster, client_random, server_random, 48)
        kb = ssl3_prf(master, server_random, client_random, 136)
        self.client = SSLState(kb)
        self.server = _ServerState(kb[20:40], kb[72:104], kb[120:136])

        fin_hs = b"\x14\x00\x00\x24" + ssl3_finished(master, ch_hs + sh_hs + cke_hs, LABEL_CLIENT)
        flight = cke_rec + b"\x14\x03\x00\x00\x01\x01" + self.client.encrypt_record(0x16, fin_hs)
        self._write(bytes([0x11]) + struct.pack("<H", len(flight)) + flight)

        resp = self._read_cmd()
        recs = split_records(resp)
        if not recs or recs[0][0] != 0x14:
            raise ProtocolError(f"handshake rejected: {resp.hex()}")
        self.server.open(0x16, recs[1][1])  # server Finished (MAC-checked)
        extra = [self.server.open(t, ct) for t, ct in recs[2:]]
        return b"".join(extra)

    def cmd(self, payload, timeout=3000):
        """Send one encrypted command; return the decrypted reply (status u16 LE + data)."""
        self._write(self.client.encrypt_record(0x17, payload))
        resp = self._read_cmd(timeout=timeout)
        return b"".join(self.server.open(t, ct) for t, ct in split_records(resp))

    def cmd_draining(self, payload, data_timeout=500):
        """Send a command that may make the sensor push data before it replies (e.g. abort).

        The sensor does not deliver the reply while data is waiting on the data endpoint, so
        drain that first. Returns (decrypted reply, drained data)."""
        self._write(self.client.encrypt_record(0x17, payload))
        data = self.read_data(timeout=data_timeout)
        resp = self._read_cmd()
        return b"".join(self.server.open(t, ct) for t, ct in split_records(resp)), data

    def goodbye(self):
        """Send the close_notify alert HP sends at the end of a session."""
        self._write(self.client.encrypt_record(0x15, b"\x01\x00"))
        try:
            resp = self._read_cmd(timeout=1000)
            return b"".join(self.server.open(t, ct) for t, ct in split_records(resp))
        except usb.core.USBError:
            return b""
