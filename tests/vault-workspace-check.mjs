// Independently inspects the SWVP Argon2 workspace bytes in crypto/vault.wasm
// memory (not the vault_prod_cleared flag) after seal/open success and after
// wrong-passphrase, tamper, invalid-input and lock cleanup paths. The region is
// located from real memory growth: the first production KDF grows memory by
// exactly 64 MiB and p_work is the start of the grown pages. Public fixtures
// only (scalar-one key, "public test passphrase", fixed caller salt/nonce).
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const module = new WebAssembly.Module(await readFile(new URL('../crypto/vault.wasm', import.meta.url)));
const w = new WebAssembly.Instance(module, {}).exports;
const memory = w.memory;
assert.ok(memory instanceof WebAssembly.Memory, 'vault exports its linear memory');
const SIZE = 65536 * 1024;
const before = memory.buffer.byteLength;
const pass = Buffer.from('public test passphrase');
const key = Buffer.concat([Buffer.alloc(31), Buffer.from([1])]);
const salt = Buffer.alloc(16, 0x5a), nonce = Buffer.alloc(24, 0xa5);
const put = (slot, raw, offset = 0) => raw.forEach((b, i) => assert.equal(w.vault_prod_put(slot, i + offset, b), 1));
function workspaceZero(label) {
  assert.equal(memory.buffer.byteLength, before + SIZE, label + ': workspace grown exactly once');
  const words = new BigUint64Array(memory.buffer, before, SIZE / 8);
  let residue = 0n;
  for (let i = 0; i < words.length; i++) residue |= words[i];
  assert.equal(residue, 0n, label + ': Argon2 workspace bytes are zero');
}
function seal() {
  assert.equal(w.vault_prod_begin(pass.length), 1); put(0, pass); put(1, key);
  put(2, salt, 24); put(2, nonce, 40); return w.vault_prod_seal(0);
}
function open(raw, password = pass) {
  assert.equal(w.vault_prod_begin(password.length), 1); put(0, password); put(2, raw);
  return w.vault_prod_open(raw.length);
}
// Invalid input before any KDF never grows or touches the workspace.
assert.equal(w.vault_prod_begin(0), 2);
assert.equal(memory.buffer.byteLength, before, 'no workspace before a production KDF');

assert.equal(seal(), 1); workspaceZero('after successful seal');
const envelope = Buffer.from(Array.from({length: 112}, (_, i) => w.vault_prod_envelope_byte(i)));
assert.ok(envelope.every(b => b < 256));
assert.equal(w.vault_lock(0), 1); workspaceZero('after lock'); assert.equal(w.vault_prod_cleared(0), 1);

assert.equal(open(envelope), 1); workspaceZero('after successful open');
assert.equal(w.vault_prod_opened_byte(31), 1, 'round trip of public fixture key');
assert.equal(w.vault_lock(0), 1); workspaceZero('after lock of opened key');

assert.equal(open(envelope, Buffer.from('wrong passphrase')), 8); workspaceZero('after wrong passphrase');
assert.equal(w.vault_prod_opened_byte(0), 256, 'no plaintext on failure');
const tampered = Buffer.from(envelope); tampered[100] ^= 1;
assert.equal(open(tampered), 8); workspaceZero('after tamper');
assert.equal(w.vault_prod_opened_byte(0), 256, 'no plaintext on tamper');
// Policy/framing and staging failures after the workspace exists.
const header = Buffer.from(envelope); header[0] ^= 1;
assert.equal(open(header), 7); workspaceZero('after header rejection');
assert.equal(open(envelope.subarray(0, 64)), 2); workspaceZero('after short envelope');
assert.equal(w.vault_prod_begin(3), 1); assert.equal(w.vault_prod_put(2, 112, 0), 5); workspaceZero('after bad slot index');
assert.equal(w.vault_prod_seal(0), 3); workspaceZero('after seal without begin');
assert.equal(w.vault_lock(0), 1); workspaceZero('after final lock'); assert.equal(w.vault_prod_cleared(0), 1);
console.log('PASS: SWVP Argon2 workspace bytes independently zero after seal/open, wrong passphrase, tamper, invalid input and lock');
