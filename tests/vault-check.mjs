// Host WASM checks, with an independent libsodium Argon2id+AEAD reference.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const ref = spawnSync('python3', [fileURLToPath(new URL('./vault_reference.py', import.meta.url))], {encoding:'utf8'});
assert.equal(ref.status, 0, 'independent libsodium reference failed: '+ref.stderr);
const expected = Buffer.from(JSON.parse(ref.stdout).envelope, 'hex');
const module = new WebAssembly.Module(await readFile(new URL('../crypto/vault.wasm',import.meta.url)));
assert.deepEqual(WebAssembly.Module.imports(module), [], 'vault has no entropy/filesystem/host imports');
const instance = () => new WebAssembly.Instance(module, {}).exports;
const w = instance();
const key = Buffer.concat([Buffer.alloc(31),Buffer.from([1])]); // PUBLIC scalar one
const pass = Buffer.from('pub'), salt = Buffer.alloc(16,17), nonce = Buffer.alloc(24,34);
const put = (v, slot, raw, offset=0) => raw.forEach((b,i)=>assert.equal(v.vault_put(slot,i+offset,b),1));
const read = (reader,n) => Buffer.from(Array.from({length:n},(_,i)=>{const b=reader(i);assert.ok(b<256);return b;}));
function inputsCleared(v) {assert.equal(v.vault_inputs_cleared(0),1);}
function locked(v) {
  inputsCleared(v);assert.equal(v.vault_locked(0),1);
  assert.equal(v.vault_opened_byte(0),256);assert.equal(v.vault_envelope_byte(0),256);
}
function seal(v) {
  assert.equal(v.vault_begin(pass.length),1);put(v,0,pass);put(v,1,key);
  put(v,2,salt,12);put(v,2,nonce,28);
  assert.equal(v.vault_test_seal(0),1);inputsCleared(v);
  assert.equal(v.vault_opened_byte(0),256);
  return read(v.vault_envelope_byte,100);
}
function open(v,raw,password=pass) {
  assert.equal(v.vault_begin(password.length),1);put(v,0,password);put(v,2,raw);
  return v.vault_open(raw.length);
}
const envelope=seal(w);
assert.deepEqual(envelope,expected,'independent Argon2id13 + XChaCha20-Poly1305 byte vector');
assert.equal(w.vault_envelope_byte(100),257);
assert.equal(open(w,envelope),1);inputsCleared(w);
assert.deepEqual(read(w.vault_opened_byte,32),key);
assert.equal(w.vault_opened_byte(32),257);
assert.equal(w.vault_envelope_byte(0),256);
assert.equal(w.vault_locked(0),0);
assert.equal(w.vault_lock(0),1);locked(w);
assert.equal(open(w,envelope,Buffer.from('wrong')),8);locked(w);
// Every byte of header, salt, nonce, ciphertext and tag is bound or rejected.
for (let i=0;i<100;i++) {
  const changed=Buffer.from(envelope);changed[i]^=1;
  assert.equal(open(w,changed),i<12?7:8,'tampered envelope byte '+i);locked(w);
}
for (const n of [0,1,51,52,84,99]) {
  assert.equal(open(w,envelope.subarray(0,n)),2);locked(w);
}
for (const n of [0,129,256]) {assert.equal(w.vault_begin(n),2);locked(w);}
assert.equal(w.vault_open(100),3);locked(w);
assert.equal(w.vault_begin(3),1);assert.equal(w.vault_test_seal(0),6);locked(w);
assert.equal(w.vault_begin(3),1);assert.equal(w.vault_open(100),6);locked(w);
for (const [slot,index,byte,code] of [[0,3,1,5],[1,32,1,5],[2,100,1,5],[3,0,1,5],[0,0,256,4]]) {
  assert.equal(w.vault_begin(3),1);assert.equal(w.vault_put(slot,index,byte),code);locked(w);
}
assert.equal(open(w,envelope),1);
assert.equal(w.vault_seal(0),9,'production sealing fails without entropy');locked(w);
// A new instance has no retained state; public envelope may be reopened only
// with the correct passphrase. This tests module reset, not disk persistence.
const restarted=instance();locked(restarted);
assert.equal(open(restarted,envelope),1);
assert.deepEqual(read(restarted.vault_opened_byte,32),key);
assert.equal(restarted.vault_lock(0),1);locked(restarted);
console.log('PASS: vault independent KDF/AEAD vector, roundtrip, byte tampering, wrong passphrase, bounds, wipe/lock and instance reset; persistence disabled');
