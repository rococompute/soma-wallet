"""Independent libsodium reference for a PUBLIC combined Argon2id/AEAD vector.

No key/KDF output is printed, only public ciphertext/tag/header. libsodium is a
host test dependency, never linked into the app. Parameters match the documented
TEST-ONLY envelope, not a production password policy.
"""
import ctypes as c
import ctypes.util
import json
library = ctypes.util.find_library('sodium')
assert library, 'libsodium host reference library is required for vault checks'
s = c.CDLL(library)
assert s.sodium_init() >= 0
ptr=c.c_void_p; ull=c.c_ulonglong
s.crypto_pwhash.argtypes=[ptr,ull,ptr,ull,ptr,ull,c.c_size_t,c.c_int]
s.crypto_pwhash.restype=c.c_int
s.crypto_aead_xchacha20poly1305_ietf_encrypt_detached.argtypes=[ptr,ptr,ptr,ptr,ull,ptr,ull,ptr,ptr,ptr]
s.crypto_aead_xchacha20poly1305_ietf_encrypt_detached.restype=c.c_int
password=b'pub'; salt=bytes([17])*16; nonce=bytes([34])*24
key=bytes(31)+b'\x01' # PUBLIC scalar-one test key
header=b'SWVT'+bytes([1,1,1,1,64,0,3,0])+salt+nonce
assert len(header)==52
derived=c.create_string_buffer(32)
assert s.crypto_pwhash(derived,32,password,len(password),salt,3,64*1024,2)==0
cipher=c.create_string_buffer(32);tag=c.create_string_buffer(16);taglen=ull()
assert s.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
    cipher,tag,c.byref(taglen),key,32,header,len(header),None,nonce,derived)==0
assert taglen.value==16
print(json.dumps({'envelope':(header+cipher.raw+tag.raw).hex()}))
