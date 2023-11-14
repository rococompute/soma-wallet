"""Independent Base64 check: the ASCII list embedded in
tests/psbt_base64.soma must be the canonical Base64 (BIP 174 text form) of
the BIP 143 PSBT fixture bytes from tests/psbt.soma. No network.
"""
import base64, pathlib, re

root = pathlib.Path(__file__).resolve().parents[1]
psbt_src = (root / "tests/psbt.soma").read_text()
unsigned_hex = next(l for l in psbt_src.splitlines()
                    if l.startswith("unsigned_hex")).split('"')[1]
fixture = bytes.fromhex("70736274ff0100a0" + unsigned_hex +
    "000001011f0046c323000000001600141d0f172a0ecb48aee1be1f2687d2963ae33f71a1000000")
assert fixture[:5] == b"psbt\xff"

b64_src = (root / "tests/psbt_base64.soma").read_text()
line = next(l for l in b64_src.splitlines() if l.startswith("fixture_b64"))
embedded = bytes(int(x) for x in re.findall(r"\d+", line.split(":=", 1)[1]))
assert embedded == base64.b64encode(fixture), "embedded Base64 must be canonical"
assert base64.b64decode(embedded) == fixture
# Canonical-padding aliases rejected by the Soma decoder.
assert base64.b64decode("TQ==") == base64.b64decode("TR==") == b"M"
assert base64.b64decode("TWE=") == base64.b64decode("TWF=") == b"Ma"
print("PASS: independent Base64 fixture encoding check")
