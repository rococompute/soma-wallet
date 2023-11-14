"""Independent public serialization fixture; synthetic DER is not a signature."""
import base64, hashlib, json, pathlib, struct
root=pathlib.Path(__file__).resolve().parent
v=json.loads((root/'signing_export_fixture.json').read_text())
raw=bytes.fromhex(v['psbt']);candidate=bytes.fromhex(v['candidate'])
der=bytes.fromhex(v['synthetic_der'])
assert der==bytes.fromhex('3006020101020101') # r=1,s=1, encoding-only public data
assert base64.b64decode(v['base64'],validate=True)==candidate
assert base64.b64encode(candidate).decode()==v['base64']
pub=bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
entry=bytes([34,2])+pub+bytes([len(der)+1])+der+b'\x01'
assert candidate==raw[:-2]+entry+raw[-2:] # selected input only, existing order preserved
h=bytes.fromhex('751e76e8199196d454941c45d1b3a323f1433bd6')
outpoint=bytes([1])*36;sequence=bytes([255])*4
output=struct.pack('<Q',1)+b'\0'
dsha=lambda b: hashlib.sha256(hashlib.sha256(b).digest()).digest()
preimage=struct.pack('<I',2)+dsha(outpoint)+dsha(sequence)+outpoint+b'\x19\x76\xa9\x14'+h+b'\x88\xac'+struct.pack('<Q',2)+sequence+dsha(output)+struct.pack('<I',0)+struct.pack('<I',1)
assert dsha(preimage).hex()==v['sighash']
assert v['candidate'] in (root/'signing_prepare.exp').read_text()
assert v['base64'] in (root/'signing_prepare.exp').read_text()
print('PASS: independent public PSBT candidate encoding, Base64 and digest fixtures')
