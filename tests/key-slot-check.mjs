// PUBLIC scalar fixtures only. No private values are logged; OpenSSL verifies.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash,ECDH,createPublicKey,verify} from 'node:crypto';
const module=new WebAssembly.Module(await readFile(new URL('../crypto/key_slot.wasm',import.meta.url)));
assert.deepEqual(WebAssembly.Module.imports(module),[]);
const make=()=>new WebAssembly.Instance(module,{}).exports;
const w=make();
const key=n=>Buffer.from(n.toString(16).padStart(64,'0'),'hex');
const pub1=Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798','hex');
const pub2=Buffer.from('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5','hex');
const sha=b=>createHash('sha256').update(b).digest();
const bytes=(reader,n)=>Buffer.from(Array.from({length:n},(_,i)=>{const b=reader(i);assert.ok(b<256);return b;}));
function emptyOutputs(v) {
  assert.equal(v.slot_inputs_cleared(0),1);
  assert.equal(v.slot_public_byte(0),256);assert.equal(v.slot_der_byte(0),256);assert.equal(v.slot_der_size(0),256);
}
function locked(v) {assert.equal(v.slot_locked(0),1);assert.equal(v.slot_handle(0),0);emptyOutputs(v);}
function imported(v,scalar,expected) {
  assert.equal(v.slot_begin_import(32),1);
  key(scalar).forEach((b,i)=>assert.equal(v.slot_key_byte(i,b),1));
  assert.equal(v.slot_commit_import(0),1);
  const h=v.slot_handle(0);assert.ok(h>0 && h<=65535);
  assert.deepEqual(bytes(v.slot_public_byte,33),expected);
  assert.equal(v.slot_inputs_cleared(0),1);assert.equal(v.slot_der_byte(0),256);
  return h;
}
function signed(v,h,expected,message) {
  assert.equal(v.slot_begin_digest(h,32),1);
  sha(message).forEach((b,i)=>assert.equal(v.slot_digest_byte(i,b),1));
  assert.equal(v.slot_sign(h),1);assert.equal(v.slot_inputs_cleared(0),1);
  const pub=bytes(v.slot_public_byte,33),der=bytes(v.slot_der_byte,v.slot_der_size(0));
  assert.deepEqual(pub,expected);
  const raw=ECDH.convertKey(pub,'secp256k1',undefined,undefined,'uncompressed');
  const pk=createPublicKey({key:Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200','hex'),raw]),format:'der',type:'spki'});
  assert.equal(verify('sha256',message,pk,der),true);
  assert.equal(verify('sha256',Buffer.concat([message,Buffer.from([1])]),pk,der),false);
  const bad=Buffer.from(der);bad[bad.length-1]^=1;assert.equal(verify('sha256',message,pk,bad),false);
  const rlen=der[3],slen=der[5+rlen];assert.equal(6+rlen+slen,der.length);
  assert.ok(BigInt('0x'+der.subarray(6+rlen).toString('hex'))<=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')/2n);
  assert.equal(v.slot_sign(h),8,'digest staging is consumed');emptyOutputs(v);
  assert.equal(v.slot_handle(0),h,'valid scalar remains until explicit lock/replacement');
}
locked(w);
const first=imported(w,1n,pub1);
signed(w,first,pub1,Buffer.from('public retained slot fixture'));
assert.equal(w.slot_clear_transient(0),1);assert.equal(w.slot_handle(0),first);emptyOutputs(w);
signed(w,first,pub1,Buffer.from('second public digest; new approval belongs to future owner'));
const second=imported(w,2n,pub2);assert.ok(second>first);
assert.equal(w.slot_begin_digest(first,32),10);emptyOutputs(w);
assert.equal(w.slot_sign(first),10);emptyOutputs(w);
signed(w,second,pub2,Buffer.from('replacement public fixture'));
assert.equal(w.slot_lock(0),1);locked(w);
assert.equal(w.slot_begin_digest(second,32),10);locked(w);
assert.equal(w.slot_sign(second),10);locked(w);
for(const scalar of [0n,BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')]) {
  const old=imported(w,1n,pub1);
  assert.equal(w.slot_begin_import(32),1);
  key(scalar).forEach((b,i)=>assert.equal(w.slot_key_byte(i,b),1));
  assert.equal(w.slot_commit_import(0),6);locked(w);
  assert.equal(w.slot_begin_digest(old,32),10);locked(w);
}
for(const n of [0,1,31,33,128]) {
  const old=imported(w,1n,pub1);
  assert.equal(w.slot_begin_import(n),9);locked(w);
  assert.equal(w.slot_sign(old),10);locked(w);
}
assert.equal(w.slot_begin_import(32),1);assert.equal(w.slot_commit_import(0),4);locked(w);
for(const [index,byte,code] of [[32,1,2],[0,256,3]]) {
  assert.equal(w.slot_begin_import(32),1);assert.equal(w.slot_key_byte(index,byte),code);locked(w);
}
const current=imported(w,1n,pub1);
assert.equal(w.slot_begin_digest(current,31),9);emptyOutputs(w);
assert.equal(w.slot_begin_digest(current,32),1);assert.equal(w.slot_sign(current),5);emptyOutputs(w);
assert.equal(w.slot_begin_digest(current,32),1);assert.equal(w.slot_digest_byte(32,1),2);emptyOutputs(w);
assert.equal(w.slot_begin_digest(current,32),1);assert.equal(w.slot_digest_byte(0,256),3);emptyOutputs(w);
assert.equal(w.slot_begin_digest(0,32),10);emptyOutputs(w);
assert.equal(w.slot_public_byte(33),256);
assert.equal(w.slot_lock(0),1);locked(w);
// No testing backdoor or mutable counter export: exhaust the real 16-bit space.
const exhausted=make();
for(let i=1;i<=65535;i++) assert.equal(exhausted.slot_begin_import(32),1);
key(1n).forEach((b,i)=>assert.equal(exhausted.slot_key_byte(i,b),1));
assert.equal(exhausted.slot_commit_import(0),1);assert.equal(exhausted.slot_handle(0),65535);
assert.equal(exhausted.slot_begin_import(32),11);locked(exhausted);
assert.equal(exhausted.slot_sign(65535),10);locked(exhausted);
assert.equal(exhausted.slot_lock(0),1);
assert.equal(exhausted.slot_begin_import(32),11,'lock must never reset or wrap generation');locked(exhausted);
console.log('PASS: retained slot identity, independent signatures/low-S, stale handles, import failures, staging, lock erasure and actual generation exhaustion');
