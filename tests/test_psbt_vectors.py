"""Independent (hashlib/struct) recomputation of the BIP 143 example digest
for the PSBT fixture used by tests/psbt_validation.soma, and a structural
check of its BIP 174 framing. No network; published BIP 143 values.
Source: BIP 143 'Native P2WPKH' example and BIP 174 PSBT v0 framing.
"""
import hashlib, pathlib, struct

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def varint(n):
    return bytes([n]) if n < 253 else b"\xfd" + struct.pack("<H", n)

ROOT = pathlib.Path(__file__).resolve().parents[1]
src = (ROOT / "tests/psbt_validation.soma").read_text()
def hexof(name):
    line = next(l for l in src.splitlines() if l.startswith(name))
    return bytes.fromhex(line.split('"')[1])

unsigned = hexof("unsigned_hex")
fixture_hex = ("70736274ff0100a0" + unsigned.hex() +
               "000001011f0046c323000000001600141d0f172a0ecb48aee1be1f2687d2963ae33f71a1000000")
fixture = bytes.fromhex(fixture_hex)
assert fixture[:5] == b"psbt\xff"
# BIP 174 global map: one key-value (unsigned tx), separator, then input/output maps.
assert fixture[5] == 1 and fixture[6] == 0 and fixture[7] == len(unsigned) if len(unsigned) < 253 else True

# Parse the unsigned tx (legacy serialization).
def read_tx(b):
    ver, = struct.unpack_from("<I", b, 0); off = 4
    nin = b[off]; off += 1; ins = []
    for _ in range(nin):
        ins.append((b[off:off+36], b[off+37:off+41])); off += 41
    nout = b[off]; off += 1; outs = []
    for _ in range(nout):
        amt, = struct.unpack_from("<Q", b, off); off += 8
        slen = b[off]; off += 1; outs.append((amt, b[off:off+slen])); off += slen
    lock, = struct.unpack_from("<I", b, off)
    return ver, ins, outs, lock

ver, ins, outs, lock = read_tx(unsigned)
assert ver == 1 and len(ins) == 2 and [o[0] for o in outs] == [112340000, 223450000]
assert sum(o[0] for o in outs) <= 2100000000000000

# BIP 143 digest for input 1 with its witness UTXO (6 BTC, P2WPKH script).
wu_amount = 600000000
script = bytes.fromhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
assert len(script) == 22 and script[:2] == b"\x00\x14"
script_code = bytes.fromhex("1976a914") + script[2:] + bytes.fromhex("88ac")
preimage = (struct.pack("<I", ver) + dsha(b"".join(i[0] for i in ins)) +
            dsha(b"".join(i[1] for i in ins)) + ins[1][0] + script_code +
            struct.pack("<Q", wu_amount) + ins[1][1] +
            dsha(b"".join(struct.pack("<Q", a) + varint(len(s)) + s for a, s in outs)) +
            struct.pack("<I", lock) + struct.pack("<I", 1))
digest = dsha(preimage)
assert digest.hex() == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", digest.hex()
print("PASS: independent BIP143 digest and BIP174 framing check (hashlib)")
