import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash,createECDH,ECDH,createPublicKey,verify} from 'node:crypto';
const module = new WebAssembly.Module(await readFile(new URL('../crypto/signer.wasm',import.meta.url)));
assert.deepEqual(WebAssembly.Module.imports(module),[], 'No WASI/host imports');
const w = new WebAssembly.Instance(module,{}).exports;
const OK=1, INDEX=2, BYTE=3, KEY_SHORT=4, DIGEST_SHORT=5, INVALID=6, NOT_BEGUN=8, LENGTH=9;
const n=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const scalar = x => Buffer.from(x.toString(16).padStart(64,'0'),'hex');
const sha = m => createHash('sha256').update(m).digest();
function feed(k,d=Buffer.alloc(32)) {
  assert.equal(w.bridge_begin(k.length,d.length),OK);
  k.forEach((v,i)=>assert.equal(w.bridge_key_byte(i,v),OK));
  d.forEach((v,i)=>assert.equal(w.bridge_digest_byte(i,v),OK));
}
function bytes(reader,count) {
  return Buffer.from(Array.from({length:count},(_,i)=>{
    const b=reader(i); assert.ok(b>=0 && b<=255); return b;
  }));
}
function publicObject(pub) {
  const raw=ECDH.convertKey(pub,'secp256k1',undefined,undefined,'uncompressed');
  return createPublicKey({key:Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200','hex'),raw]),format:'der',type:'spki'});
}
function signed(k,message) {
  feed(k,sha(message)); assert.equal(w.bridge_sign(0),OK);
  assert.equal(w.bridge_inputs_cleared(0),1);
  const pub=bytes(w.bridge_public_byte,33), compact=bytes(w.bridge_compact_byte,64);
  const der=bytes(w.bridge_der_byte,w.bridge_der_size(0));
  const independent=publicObject(pub);
  assert.equal(verify('sha256',message,independent,der),true,'OpenSSL verifies DER');
  assert.equal(verify('sha256',message,{key:independent,dsaEncoding:'ieee-p1363'},compact),true,'OpenSSL verifies compact');
  assert.ok(BigInt('0x'+compact.subarray(32).toString('hex'))<=n/2n,'low-S');
  const corrupt=Buffer.from(compact); corrupt[10]^=1;
  assert.equal(verify('sha256',message,{key:independent,dsaEncoding:'ieee-p1363'},corrupt),false);
  assert.equal(verify('sha256',Buffer.concat([message,Buffer.from([1])]),independent,der),false,'different digest rejected');
  return {pub,compact,der};
}
// Public scalar multiples of SEC2's secp256k1 generator; OpenSSL ECDH is an
// independent derivation. SEC2 v2 section 2.4.1: https://www.secg.org/sec2-v2.pdf
const pubkeys=[
 [1n,'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
 [2n,'02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'],
 [3n,'02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'],
 [n-1n,'0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798']
];
for (const [d,expected] of pubkeys) {
  const k=scalar(d); feed(k); assert.equal(w.bridge_derive(0),OK);
  assert.equal(w.bridge_inputs_cleared(0),1);
  assert.equal(bytes(w.bridge_public_byte,33).toString('hex'),expected);
  const ecdh=createECDH('secp256k1');ecdh.setPrivateKey(k);
  assert.equal(ecdh.getPublicKey('hex','compressed'),expected);
  assert.equal(w.bridge_compact_byte(0),256,'derive does not expose an old signature');
  const msg=Buffer.from('public fixture '+d.toString(16));
  const a=signed(k,msg),b=signed(k,msg);
  assert.deepEqual(a,b,'RFC6979 repeatability');
}
// Published independent RFC6979 vectors, pinned to bitcoinjs-lib v3.3.2;
// full source URL and public-test-key provenance are in signer-vectors.json.
const fixtures=JSON.parse(await readFile(new URL('./signer-vectors.json',import.meta.url)));
for (const v of fixtures.vectors) {
  const got=signed(Buffer.from(v.d.padStart(64,'0'),'hex'),Buffer.from(v.message));
  assert.equal(got.der.toString('hex'),v.signature,'Published deterministic DER vector');
}
for (const d of [0n,n,n+1n,(1n<<256n)-1n]) {
  feed(scalar(d));assert.equal(w.bridge_sign(0),INVALID);
  assert.equal(w.bridge_inputs_cleared(0),1);
  assert.equal(w.bridge_public_byte(0),256);assert.equal(w.bridge_compact_byte(0),256);
  feed(scalar(d));assert.equal(w.bridge_derive(0),INVALID);
}
for (const size of [0,1,31,33,64]) {
  assert.equal(w.bridge_begin(size,32),LENGTH);
  assert.equal(w.bridge_inputs_cleared(0),1);
  assert.equal(w.bridge_begin(32,size),LENGTH);
}
assert.equal(w.bridge_begin(32,32),OK);
for (let i=0;i<31;i++) assert.equal(w.bridge_key_byte(i,0),OK);
assert.equal(w.bridge_sign(0),KEY_SHORT); assert.equal(w.bridge_inputs_cleared(0),1);
assert.equal(w.bridge_begin(32,32),OK);
for (let i=0;i<32;i++) assert.equal(w.bridge_key_byte(i,i===31?1:0),OK);
assert.equal(w.bridge_sign(0),DIGEST_SHORT); assert.equal(w.bridge_inputs_cleared(0),1);
assert.equal(w.bridge_begin(32,32),OK);assert.equal(w.bridge_key_byte(32,1),INDEX);
assert.equal(w.bridge_inputs_cleared(0),1);
assert.equal(w.bridge_begin(32,32),OK);assert.equal(w.bridge_digest_byte(0,256),BYTE);
assert.equal(w.bridge_inputs_cleared(0),1);
assert.equal(w.bridge_sign(0),NOT_BEGUN);
feed(scalar(1n));assert.equal(w.bridge_sign(0),OK);
assert.equal(w.bridge_public_byte(33),257);assert.equal(w.bridge_compact_byte(64),257);
assert.equal(w.bridge_der_byte(w.bridge_der_size(0)),257);
assert.equal(w.bridge_clear(0),OK);assert.equal(w.bridge_inputs_cleared(0),1);
assert.equal(w.bridge_public_byte(0),256);assert.equal(w.bridge_der_size(0),256);
assert.equal(w.bridge_sign(0),NOT_BEGUN,'one-shot input staging');
console.log('PASS: runtime signer vectors, independent OpenSSL verification, malformed inputs, clearing');
