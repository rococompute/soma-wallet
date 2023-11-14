"""Boot real handle-based signing with PUBLIC fixtures; verify via OpenSSL."""
import json, os, pathlib, subprocess
root=pathlib.Path(__file__).resolve().parents[1]
env=os.environ.copy();env['SOMA_MIRAGE_SWITCH']='hvf'
run=subprocess.run(['timeout','120','opam','exec','--switch=hvf','--','solo5-hvt',
    '--mem=256','--',str(root/'tests/key_slot_runtime.hvt'),'--arg=public-one'],
    cwd=root,env=env,capture_output=True,text=True)
logs=run.stdout+run.stderr
assert ('00'*31+'01') not in logs, 'private scalar hex disclosed'
# Public fixture WIFs must also stay out of output, including failed imports.
source=(root/'tests/keys.soma').read_text()
import re
for name in ('wif_testnet','wif_mainnet','wif_bad_checksum','wif_zero_scalar'):
    match=re.search(r'^'+name+r' : kbytes := \[([^\]]+)\]',source,re.M)
    fixture=bytes(int(n) for n in re.findall(r'\d+',match[1])).decode()
    assert fixture not in logs, 'WIF disclosed'
assert run.returncode==0, 'key-slot runtime image failed'
assert 'PASS: runtime slot custody, stale handles, invalid imports and lock' in run.stdout
fields={}
for prefix in ('SLOT_PUBLIC=','SLOT_DER='):
    values=[line[len(prefix):] for line in run.stdout.splitlines() if line.startswith(prefix)]
    assert len(values)==1, 'missing/duplicate public output'
    fields[prefix[:-1]]=values[0]
js='''
const fs=require('node:fs'),assert=require('node:assert/strict');
const {ECDH,createPublicKey,verify}=require('node:crypto');
const v=JSON.parse(fs.readFileSync(0,'utf8'));
assert.equal(v.SLOT_PUBLIC,'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
const raw=ECDH.convertKey(Buffer.from(v.SLOT_PUBLIC,'hex'),'secp256k1',undefined,undefined,'uncompressed');
const key=createPublicKey({key:Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200','hex'),raw]),format:'der',type:'spki'});
const der=Buffer.from(v.SLOT_DER,'hex');
assert.equal(verify('sha256',Buffer.from('retained slot runtime fixture'),key,der),true);
assert.equal(verify('sha256',Buffer.from('changed retained slot runtime fixture'),key,der),false);
const corrupt=Buffer.from(der);corrupt[corrupt.length-1]^=1;
assert.equal(verify('sha256',Buffer.from('retained slot runtime fixture'),key,corrupt),false);
'''
result=subprocess.run(['node','-e',js],input=json.dumps(fields),capture_output=True,text=True)
assert result.returncode==0, 'independent runtime slot signature verification failed'
print('PASS: booted key-slot signing independently verified; replacement/lock/stale/WIF failures and log hygiene')
