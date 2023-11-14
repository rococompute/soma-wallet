"""Boot the typed SWVP adapter's rejection paths (public fixtures, no secrets).

Valid inputs must stop at the closed KDF gate (ProdKdfUnavailable) and malformed
ones at their typed format/length errors, with WASM production state wiped.
"""
import os
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy()
env['SOMA_MIRAGE_SWITCH'] = 'hvf'
run = subprocess.run(['timeout', '120', 'opam', 'exec', '--switch=hvf', '--', 'solo5-hvt',
                      '--mem=256', '--', str(root / 'tests/vault_prod_adapter.hvt'), '--arg=adapter'],
                     cwd=root, env=env, capture_output=True, text=True)
logs = run.stdout + run.stderr
assert ('00' * 31 + '01') not in logs, 'secret hex disclosed'
assert run.returncode == 0, 'SWVP adapter boot failed with status %d' % run.returncode
assert 'PASS: booted SWVP typed adapter: format/length/large-N rejections and closed KDF gate, SWVT and SWVP state wiped' in run.stdout
assert 'production_kdf_enabled : bool := false.' in (root / 'wallet_vault_prod.soma').read_text()
print('PASS: booted SWVP typed adapter rejections; KDF gate closed; SWVT and SWVP state wiped on every exit')
