"""Check the recorded hashes of the unmodified pinned crypto dependency."""
import hashlib
import pathlib
root=pathlib.Path(__file__).resolve().parents[1]/'vendor/monocypher'
manifest=(root/'UPSTREAM').read_text()
assert 'commit ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f' in manifest
entries=[line.split() for line in manifest.splitlines() if line.startswith('sha256 ')]
assert {line[2] for line in entries}=={'monocypher.c','monocypher.h','LICENCE.md'}
for _, expected, name in entries:
    assert hashlib.sha256((root/name).read_bytes()).hexdigest()==expected, 'vendored source hash mismatch'
print('PASS: pinned Monocypher source and license hashes')
