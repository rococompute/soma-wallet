"""Independent struct-based check of the public production framing fixture.

No KDF, AEAD, keys, randomness or persistence. The .exp expectations prove that
the Soma parser and serializer use these same independently encoded bytes.
"""
import json
import pathlib
import re
import struct

root = pathlib.Path(__file__).resolve().parent
v = json.loads((root / 'vault_format_fixture.json').read_text())
source = (root / 'vault_format.soma').read_text()
fixture = bytes.fromhex(re.search(r'fixture_hex : string := "([0-9a-f]+)"', source)[1])
prefix = struct.Struct('<4s6BHIIHBB')
salt = bytes(range(16))
nonce = bytes(range(16, 40))
ciphertext = b'\xa5' * 32
tag = b'\x5a' * 16
expected = (b'SWVP', 1, 1, 19, 1, 0, 4, 64, 65536, 3, 32, 16, 24)
header = prefix.pack(*expected) + salt + nonce
assert prefix.size == 24 and len(header) == 64
assert prefix.unpack(fixture[:24]) == expected
assert fixture == header + ciphertext + tag
assert len(fixture) == v['envelope_bytes'] == 112
assert header.hex() == v['header_hex'] and fixture.hex() == v['envelope_hex']
assert fixture[24:40].hex() == v['salt_hex'] == salt.hex()
assert fixture[40:64].hex() == v['nonce_hex'] == nonce.hex()
assert fixture[64:96].hex() == v['ciphertext_hex'] == ciphertext.hex()
assert fixture[96:].hex() == v['tag_hex'] == tag.hex()
assert int.from_bytes(fixture[12:16], 'little') == v['memory_kib'] == 65536
assert int.from_bytes(fixture[16:20], 'little') == v['passes'] == 3
assert fixture[9] == v['lanes'] == 4
assert v['kdf_version'] == 19 and v['derived_key_bytes'] == 32
# This profile costs 64 MiB, not the legacy test format's 64 KiB. The wire
# encodes KiB in a full LE32 field (65536 cannot fit the test format's LE16).
assert int.from_bytes(fixture[12:16], 'little') * 1024 == 64 * 1024 * 1024
assert not fixture.startswith(b'SWVT') and len(fixture) != 100
expectations = (root / 'vault_format.exp').read_text()
assert 'parse_production fixture = FormatOk model' in expectations
assert 'serialize_production model = FormatOk fixture' in expectations
assert 'production_aad model = FormatOk (firstn 64 fixture)' in expectations
print('PASS: independent production-vault framing, fixed RFC9106 profile, '
      'LE32 costs, complete header/AAD and public fixture bytes (no crypto or persistence)')
