"""Host-only packaging cross-checks (no boot, no keys, no network).

README is the operator documentation; this checks that what it names is real:
dependency pins match the vendored UPSTREAM records (tag, commit and file
hashes), every repository path README names in backticks exists, the documented
commands exist and are executable, scripts/run boots the actual UI image on an
isolated host-only network, the scope and development-only statements are
present, and the served UI is still documented and built as locked. The actual
host-only HTTP boot of main.hvt is tests/test_ui_http.py."""
import hashlib, os, pathlib, re
root = pathlib.Path(__file__).resolve().parents[1]
readme = (root/'README.md').read_text()

def upstream(name):
    fields = {}
    hashes = {}
    for line in (root/'vendor'/name/'UPSTREAM').read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == 'sha256':
            hashes[parts[2]] = parts[1]
        elif len(parts) >= 2:
            fields[parts[0]] = parts[1]
    return fields, hashes

# Dependency pins: README names the same tag and commit as the vendored record.
for name, label in (('monocypher', 'Monocypher'), ('secp256k1', 'libsecp256k1')):
    fields, hashes = upstream(name)
    assert re.fullmatch(r'[0-9a-f]{40}', fields['commit']), name + ' UPSTREAM commit malformed'
    assert fields['commit'] in readme, name + ' commit in UPSTREAM is not the one README documents'
    assert (label + ' ' + fields['tag']) in readme, name + ' tag in UPSTREAM is not the one README documents'
    assert fields['repository'] in readme or name == 'secp256k1', name + ' upstream repository not documented'
    for file, digest in hashes.items():
        actual = hashlib.sha256((root/'vendor'/name/file).read_bytes()).hexdigest()
        assert actual == digest, 'vendor/%s/%s differs from its recorded sha256' % (name, file)
assert 'Bitcoin Core libsecp256k1 v0.6.0' in readme

# Every repository path README names exists (bare test_*.py names live in tests/).
external = ('tenders/',)  # Solo5 tender sources, outside this repository
named = set(re.findall(r'`([A-Za-z0-9_./-]+\.(?:soma|exp|py|mjs|c|h|definition))`', readme))
named |= set(re.findall(r'`(scripts/[a-z-]+)`', readme))
missing = []
for path in sorted(named):
    if path.startswith(external):
        continue
    # README's `name.soma/.exp` shorthand names both files of a pair.
    parts = [path[:-len('/.exp')], path[:-len('.soma/.exp')] + '.exp'] if path.endswith('.soma/.exp') else [path]
    for part in parts:
        if not any(c.exists() for c in (root/part, root/'tests'/part)):
            missing.append(part)
assert not missing, 'README names files that do not exist: %s' % missing

# Documented commands exist, are executable, and run boots the actual UI host-only.
for command in ('./scripts/check', './scripts/build-crypto', './scripts/run'):
    assert command in readme, command + ' is not documented'
    assert os.access(root/command, os.X_OK), command + ' is not executable'
run = (root/'scripts/run').read_text()
assert 'solo5-vmnet --mode=host --isolate' in run, 'scripts/run is not host-only and isolated'
assert run.rstrip().endswith('"$PWD/main.hvt"') and './scripts/check' in run, 'scripts/run must check, then boot main.hvt'
assert 'SOMA=/absolute/path/to/soma' in readme and "env.get('SOMA','soma')" in (root/'scripts/check').read_text(), \
    'documented pinned-SOMA selection does not match scripts/check'

# Scope, recovery and development-only statements are present.
for claim in ('testnet/regtest, PSBT v0, native P2WPKH', 'SIGHASH_ALL', 'never broadcasts',
              'Do not use real funds', 'not an audited or production-ready wallet',
              'Encrypted persistence must remain disabled', 'The vault protects and\npersists nothing yet'):
    assert claim in readme, 'README lacks: ' + claim

# The served UI stays locked: main.soma serves wallet_ui's Locked session only.
main = (root/'main.soma').read_text()
assert 'serve 8080' in main and 'always Locked' in main, 'served baseline is no longer documented as locked'
assert 'served UI does not import keys' in readme, 'README must state the served UI imports no keys'
print('PASS: packaging pins, named paths, commands, host-only run and documented limits match the checkout')
