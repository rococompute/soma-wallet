import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const module=new WebAssembly.Module(await readFile(new URL('../crypto/crypto_probe.wasm',import.meta.url)));
assert.deepEqual(WebAssembly.Module.imports(module),[],'Cryptography has no host/WASI imports');
const instance=new WebAssembly.Instance(module,{});
assert.equal(instance.exports.probe(1,0),31,'Known key, public point, ECDSA verification, tamper rejection');
assert.equal(instance.exports.probe(0,0),0,'Zero private key is rejected');
console.log('PASS: import-free secp256k1 WASM known-key and negative tests');
