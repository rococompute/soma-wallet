"""Boot handle-only PSBT signing over the retained key slot; verify independently.

The public scalar-one WIF is imported once and every signature uses its handle.
Only public signed data is emitted; WIF/scalar text in logs is forbidden.
"""
import base64
import hashlib
import json
import os
import pathlib
import struct
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
v = json.loads((root/'tests/sign_driver_fixture.json').read_text())
assert v['psbt'] in (root/'tests/sign_driver_fixture.soma').read_text()
env=os.environ.copy();env['SOMA_MIRAGE_SWITCH']='hvf'
run=subprocess.run(['timeout','120','opam','exec','--switch=hvf','--','solo5-hvt',
    '--mem=256','--',str(root/'tests/runtime_slot_sign.hvt'),'--arg=public-one'],
    cwd=root,env=env,capture_output=True,text=True)
logs=run.stdout+run.stderr
alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def wif(scalar):
    b=b'\xef'+scalar.to_bytes(32,'big')+b'\x01'
    b+=hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    n=int.from_bytes(b,'big');text=''
    while n:
        n,d=divmod(n,58);text=alphabet[d]+text
    return text
for scalar in (1,2):
    assert wif(scalar) not in logs, 'WIF disclosed in boot logs'
    assert scalar.to_bytes(32,'big').hex() not in logs, 'scalar hex disclosed in boot logs'
assert run.returncode==0, 'handle signing image failed'
assert 'PASS: handle-only approved PSBT signing, approval/key/content/identity negatives, lock and replacement' in run.stdout
assert run.stdout.splitlines().count('PENDING_HOOK_BEFORE_SLOT')==3, 'pending hook ordering/count'
def field(prefix):
    found=[line[len(prefix):] for line in run.stdout.splitlines() if line.startswith(prefix)]
    assert len(found)==1, 'missing/duplicate public export'
    return found[0]
raw=bytes.fromhex(field('SIGNED_PSBT_HEX='));b64=field('SIGNED_PSBT_BASE64=')
assert base64.b64decode(b64,validate=True)==raw
assert base64.b64encode(raw).decode()==b64
class Reader:
    def __init__(self,b):self.b=b;self.i=0
    def take(self,n):
        assert n>=0 and self.i+n<=len(self.b)
        out=self.b[self.i:self.i+n];self.i+=n;return out
    def compact(self):
        n=self.take(1)[0];assert n<253 # this bounded public fixture
        return n
    def variable(self):return self.take(self.compact())
    def mapping(self):
        entries=[]
        while True:
            n=self.compact()
            if not n:return entries
            entries.append((self.take(n),self.variable()))
    def end(self):assert self.i==len(self.b)
def parse(b):
    r=Reader(b);assert r.take(5)==b'psbt\xff'
    maps=[r.mapping() for _ in range(3)];r.end();return maps
before=parse(bytes.fromhex(v['psbt']));after=parse(raw)
assert after[0]==before[0] and after[2]==before[2]
assert after[1][:-1]==before[1] and len(after[1])==len(before[1])+1
pub=bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
key,sig=after[1][-1];assert key==b'\x02'+pub and sig[-1]==1
der=sig[:-1]
unsigned=dict(before[0])[b'\x00'];assert unsigned.hex()==v['unsigned']
t=Reader(unsigned);version=t.take(4);assert version==struct.pack('<I',2)
assert t.compact()==1;outpoint=t.take(36);assert t.variable()==b''
sequence=t.take(4);assert t.compact()==1;start=t.i
amount=t.take(8);destination=t.variable();outputs=unsigned[start:t.i]
locktime=t.take(4);t.end()
assert destination.hex()=='001406afd46bcdfd22ef94ac122aa11f241244a37ecc'
assert int.from_bytes(amount,'little')==v['output_satoshis']
dsha=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
funding=bytes.fromhex(v['funding_tx'])
assert outpoint==dsha(funding)+bytes(4)
f=Reader(funding);assert f.take(4)==version;assert f.compact()==1
f.take(36);f.variable();f.take(4);assert f.compact()==1
funding_amount=f.take(8);funding_script=f.variable();f.take(4);f.end()
u=Reader(dict(before[1])[b'\x01']);input_amount=u.take(8);script=u.variable();u.end()
assert input_amount==funding_amount and script==funding_script
assert int.from_bytes(input_amount,'little')==v['input_satoshis']
assert v['input_satoshis']-v['output_satoshis']==v['fee_satoshis']==1000
h=hashlib.new('ripemd160',hashlib.sha256(pub).digest()).digest()
assert script==b'\0\x14'+h
preimage=(version+dsha(outpoint)+dsha(sequence)+outpoint+b'\x19\x76\xa9\x14'+h+
    b'\x88\xac'+input_amount+sequence+dsha(outputs)+locktime+struct.pack('<I',1))
assert dsha(preimage).hex()==v['sighash']
# Scalar comparison is a framing/low-S check, never an EC implementation.
rlen=der[3];slen=der[5+rlen];sstart=6+rlen
assert sstart+slen==len(der)
order=int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16)
assert 0<int.from_bytes(der[sstart:],'big')<=order//2
# Node/OpenSSL performs the second SHA256 of BIP143 and all EC verification.
js='''
const {ECDH,createPublicKey,verify}=require('node:crypto');
const fs=require('node:fs'),assert=require('node:assert/strict');
const v=JSON.parse(fs.readFileSync(0,'utf8'));
const pub=ECDH.convertKey(Buffer.from(v.pub,'hex'),'secp256k1',undefined,undefined,'uncompressed');
const key=createPublicKey({key:Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200','hex'),pub]),format:'der',type:'spki'});
const msg=Buffer.from(v.message,'hex'),sig=Buffer.from(v.der,'hex');
assert.equal(verify('sha256',msg,key,sig),true);
const altered=Buffer.from(msg);altered[0]^=1;
assert.equal(verify('sha256',altered,key,sig),false);
const corrupt=Buffer.from(sig);corrupt[corrupt.length-1]^=1;
assert.equal(verify('sha256',msg,key,corrupt),false);
'''
checked=subprocess.run(['node','-e',js],input=json.dumps(dict(pub=pub.hex(),
    message=hashlib.sha256(preimage).hexdigest(),der=der.hex())),capture_output=True,text=True)
assert checked.returncode==0, 'independent OpenSSL verification failed'
print('PASS: booted handle-only signing: pending hook before slot IO, approval/key-ref/content/store/out-of-range-identity negatives, lock and replacement invalidation, log hygiene')
print('PASS: handle signature independently verified: OpenSSL signature/low-S, BIP143 digest, ownership/funding, outputs/fee and exact PSBT preservation')
