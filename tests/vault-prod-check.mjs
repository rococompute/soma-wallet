// Host checks for the SWVP v1 production primitives in crypto/vault.wasm.
// Public fixtures only: scalar-one key, passphrase "public test passphrase",
// salt 16 x 0x5a, nonce 24 x 0xa5 (caller-supplied; no entropy is generated).
// Independent reference: Argon2id via Node's crypto.argon2Sync (OpenSSL) and
// XChaCha20-Poly1305 via libsodium (vault_prod_reference.py).
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {argon2Sync} from 'node:crypto';
const module = new WebAssembly.Module(await readFile(new URL('../crypto/vault.wasm', import.meta.url)));
assert.deepEqual(WebAssembly.Module.imports(module), [], 'vault has no host imports');
const w = new WebAssembly.Instance(module, {}).exports;
const pass = Buffer.from('public test passphrase');
const key = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const salt = Buffer.alloc(16, 0x5a), nonce = Buffer.alloc(24, 0xa5);
const header = Buffer.concat([Buffer.from('SWVP'), Buffer.from([1, 1, 19, 1, 0, 4, 64, 0,
  0, 0, 1, 0, 3, 0, 0, 0, 32, 0, 16, 24]), salt, nonce]);
assert.equal(header.length, 64);

// Independent expected envelope.
let t = Date.now();
const derived = argon2Sync('argon2id', {message: pass, nonce: salt, parallelism: 4,
  tagLength: 32, memory: 65536, passes: 3});
const nodeKdfMs = Date.now() - t;
const ref = spawnSync('python3', [fileURLToPath(new URL('./vault_prod_reference.py', import.meta.url))],
  {input: JSON.stringify({key: derived.toString('hex'), nonce: nonce.toString('hex'),
    header: header.toString('hex'), plain: key.toString('hex')}), encoding: 'utf8'});
assert.equal(ref.status, 0, 'libsodium reference failed: ' + ref.stderr);
const r = JSON.parse(ref.stdout);
const expected = Buffer.concat([header, Buffer.from(r.ciphertext, 'hex'), Buffer.from(r.tag, 'hex')]);
assert.equal(expected.length, 112);

const put = (slot, raw, offset = 0) => raw.forEach((b, i) => assert.equal(w.vault_prod_put(slot, i + offset, b), 1));
const read = (reader, n) => Buffer.from(Array.from({length: n}, (_, i) => {
  const b = reader(i); assert.ok(b < 256); return b; }));
const cleared = () => assert.equal(w.vault_prod_cleared(0), 1, 'production state wiped');
function seal() {
  assert.equal(w.vault_prod_begin(pass.length), 1); put(0, pass); put(1, key);
  put(2, salt, 24); put(2, nonce, 40);
  const status = w.vault_prod_seal(0); return status;
}
function open(raw, password = pass) {
  assert.equal(w.vault_prod_begin(password.length), 1); put(0, password); put(2, raw);
  return w.vault_prod_open(raw.length);
}

t = Date.now();
assert.equal(seal(), 1);
const wasmSealMs = Date.now() - t;
assert.equal(w.vault_prod_opened_byte(0), 256);
const envelope = read(w.vault_prod_envelope_byte, 112);
assert.equal(w.vault_prod_envelope_byte(112), 257);
assert.deepEqual(envelope, expected, 'byte-exact SWVP envelope vs independent Argon2id + XChaCha20-Poly1305');
assert.equal(w.vault_lock(0), 1); cleared();

assert.equal(open(envelope), 1);
assert.deepEqual(read(w.vault_prod_opened_byte, 32), key, 'round trip');
assert.equal(w.vault_prod_opened_byte(32), 257); assert.equal(w.vault_prod_envelope_byte(0), 256);
assert.equal(w.vault_prod_cleared(0), 0, 'opened key present until lock');
assert.equal(w.vault_lock(0), 1); cleared();

// Wrong passphrase, and sampled flips of salt, nonce, ciphertext and tag: auth failure, no plaintext.
assert.equal(open(envelope, Buffer.from('wrong passphrase')), 8); cleared();
for (const i of [24, 39, 40, 63, 64, 95, 96, 111]) {
  const changed = Buffer.from(envelope); changed[i] ^= 1;
  assert.equal(open(changed), 8, 'tampered byte ' + i); cleared();
  assert.equal(w.vault_prod_opened_byte(0), 256);
}
// Every header framing/profile byte (0..23) is rejected before the KDF runs.
for (let i = 0; i < 24; i++) {
  const changed = Buffer.from(envelope); changed[i] ^= 1;
  t = Date.now();
  assert.equal(open(changed), 7, 'header byte ' + i); cleared();
  assert.ok(Date.now() - t < nodeKdfMs + wasmSealMs, 'header rejection does not run the KDF');
}
// SWVT bytes, weak/excess costs and wrong lanes are policy-rejected before the KDF.
const swvt = Buffer.from(envelope); swvt.write('SWVT', 0); assert.equal(open(swvt), 7); cleared();
for (const [offset, value] of [[12, 64], [14, 2], [16, 2], [16, 4], [9, 1]]) {
  const changed = Buffer.from(envelope); changed[offset] = value;
  assert.equal(open(changed), 7, 'policy byte ' + offset); cleared();
}
for (const n of [0, 63, 64, 111]) { assert.equal(open(envelope.subarray(0, n)), 2); cleared(); }
assert.equal(w.vault_prod_begin(3), 1); assert.equal(w.vault_prod_put(2, 112, 0), 5); cleared();
// Incomplete staging and caller-written header bytes are refused.
assert.equal(w.vault_prod_begin(pass.length), 1); put(0, pass); put(2, salt, 24); put(2, nonce, 40);
assert.equal(w.vault_prod_seal(0), 6); cleared();
assert.equal(w.vault_prod_begin(pass.length), 1); put(0, pass); put(1, key); put(2, salt, 24);
put(2, nonce, 40); assert.equal(w.vault_prod_put(2, 0, 0), 1);
assert.equal(w.vault_prod_seal(0), 6); cleared();
assert.equal(w.vault_prod_seal(0), 3); assert.equal(w.vault_prod_open(112), 3); cleared();
for (const n of [0, 129]) { assert.equal(w.vault_prod_begin(n), 2); cleared(); }
// The SWVT entry points are unaffected and still fail closed for production sealing.
assert.equal(w.vault_seal(0), 9); cleared();
console.log(`PASS: SWVP v1 production seal/open byte-exact vs OpenSSL Argon2id + libsodium XChaCha20-Poly1305; tamper, header/policy before KDF, wipe/lock (host KDF: node ${nodeKdfMs} ms, wasm seal ${wasmSealMs} ms)`);
