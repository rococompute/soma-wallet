"""Independent libsodium XChaCha20-Poly1305 for the PUBLIC SWVP v1 test vector.

Reads JSON {key, nonce, header, plain} (hex) on stdin: key is the Argon2id output
that tests/vault-prod-check.mjs derives independently with Node's OpenSSL-backed
crypto.argon2Sync. Prints {ciphertext, tag}. Public fixture data only."""
import ctypes as c, ctypes.util, json, sys
library = ctypes.util.find_library('sodium')
assert library, 'libsodium host reference library is required for vault checks'
s = c.CDLL(library)
assert s.sodium_init() >= 0
ptr = c.c_void_p; ull = c.c_ulonglong
f = s.crypto_aead_xchacha20poly1305_ietf_encrypt_detached
f.argtypes = [ptr, ptr, ptr, ptr, ull, ptr, ull, ptr, ptr, ptr]; f.restype = c.c_int
v = {k: bytes.fromhex(x) for k, x in json.load(sys.stdin).items()}
assert len(v['key']) == 32 and len(v['nonce']) == 24 and len(v['header']) == 64
cipher = c.create_string_buffer(len(v['plain'])); tag = c.create_string_buffer(16); n = ull()
assert f(cipher, tag, c.byref(n), v['plain'], len(v['plain']), v['header'], len(v['header']),
         None, v['nonce'], v['key']) == 0 and n.value == 16
print(json.dumps({'ciphertext': cipher.raw.hex(), 'tag': tag.raw.hex()}))
