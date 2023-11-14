"""Independent hashlib/Bech32 recomputation of the public fixtures used by
tests/keys.soma. Provenance: documented scalar-one test key; its testnet WIF
(cMahea...), mainnet WIF (KwDiB...), generator HASH160 and BIP 173 testnet /
regtest Bech32 examples. No network, no real keys.
"""
import hashlib

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58check(payload):
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + chk; n = int.from_bytes(data, 'big'); s = ''
    while n: n, r = divmod(n, 58); s = ALPHABET[r] + s
    return s
def hash160(b): return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def polymod(vals):
    chk = 1
    for v in vals:
        top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1: chk ^= GEN[i]
    return chk
def bech32(hrp, h):
    data = [0]
    acc = bits = 0
    for v in h:
        acc = (acc << 8) | v; bits += 8
        while bits >= 5: bits -= 5; data.append((acc >> bits) & 31)
    pm = polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data + [0] * 6) ^ 1
    return hrp + '1' + ''.join(CHARSET[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])

key1 = (1).to_bytes(32, 'big')
assert b58check(b'\xef' + key1 + b'\x01') == 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA'
assert b58check(b'\x80' + key1 + b'\x01') == 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
pub = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
h = hash160(pub)
assert h.hex() == '751e76e8199196d454941c45d1b3a323f1433bd6'
assert bech32('tb', h) == 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'
assert bech32('bcrt', h) == 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
assert hashlib.new('ripemd160', b'').hexdigest() == '9c1185a5c5e9fc54612808977ee8f548b2258d31'
print('PASS: independent WIF, HASH160 and Bech32 fixture recomputation')
