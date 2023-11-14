"""Booted evidence about the signer image's entropy source (no secrets).

Boots tests/entropy_probe.hvt three times with the normal tender and once
with `solo5-hvt --no-random` as a negative control. The probe bytes are
throwaway draws from Sandbox.random, never used as key, salt or nonce.

What this establishes: in the normal boots, mirage-crypto-rng-mirage seeds
Fortuna with host bytes from the solo5_random hypercall (the fallback
message is absent, and it does appear when the tender withholds host
random), and draws differ within and across restarts with no constant or
counter-like pattern. What it cannot establish: statistical quality, or the
host CSPRNG's own seeding. Those rest on the tender's source review in README.
"""
import os
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy()
env['SOMA_MIRAGE_SWITCH'] = 'hvf'
FALLBACK = 'no host entropy (solo5_random unavailable)'


def boot(*tender_flags):
    result = subprocess.run(
        ['timeout', '60', 'opam', 'exec', '--switch=hvf', '--', 'solo5-hvt',
         '--mem=256', *tender_flags, '--', str(root / 'tests/entropy_probe.hvt'),
         '--arg=draw'], cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode == 0, 'entropy probe image failed to boot'
    logs = result.stdout + result.stderr
    blocks = [line.split('=', 1)[1] for line in result.stdout.splitlines()
              if line.startswith('ENTROPY_BLOCK=')]
    assert len(blocks) == 2, 'probe must print exactly two blocks'
    for block in blocks:
        assert len(block) == 64 and all(c in '0123456789abcdef' for c in block)
    return logs, [bytes.fromhex(b) for b in blocks]


def patterned(block):
    steps = {(block[i + 1] - block[i]) % 256 for i in range(len(block) - 1)}
    return len(set(block)) < 16 or len(steps) == 1


draws = []
for _ in range(3):
    logs, blocks = boot()
    assert FALLBACK not in logs, 'normal tender boot fell back to timing-only seeding'
    draws += blocks

# Negative control: the marker is visible when host random is withheld, so its
# absence above means Fortuna was seeded from solo5_random host bytes.
control_logs, control = boot('--no-random')
assert FALLBACK in control_logs, 'negative control did not report missing host entropy'

assert len(set(draws + control)) == len(draws + control), 'repeated block within or across boots'
for block in draws + control:
    assert not patterned(block), 'constant or counter-like probe block'
counts = [b''.join(draws).count(bytes([v])) for v in range(256)]
assert max(counts) <= 12, 'implausibly skewed byte distribution'
print('PASS: booted Sandbox.random is host-seeded (solo5_random), varies within/across '
      'restarts, no patterns; --no-random control falls back; probe bytes unused')
