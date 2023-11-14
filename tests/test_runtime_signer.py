"""Boot the typed WASM wrapper with a documented public fixture selected at runtime."""
import os
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy()
env['SOMA_MIRAGE_SWITCH'] = 'hvf'
result = subprocess.run(
    ['timeout', '120', 'opam', 'exec', '--switch=hvf', '--',
     'solo5-hvt', '--mem=256', '--', str(root / 'tests/runtime_signer.hvt'), '--arg=public-one'],
    cwd=root, env=env, capture_output=True, text=True)
assert result.returncode == 0, result.stdout + result.stderr
assert 'PASS: runtime typed signer and clear' in result.stdout, result.stdout + result.stderr
print('PASS: typed signer executes with runtime input in the unikernel')
