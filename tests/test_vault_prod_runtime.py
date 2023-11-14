"""Boot the SWVP v1 production rejection checks (public fixtures, no secrets).

The full 64-MiB Argon2id seal is not run here: its booted cost is documented in
README (run tests/vault_prod_runtime.hvt with --arg=measure to reproduce)."""
import os, pathlib, subprocess
root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy(); env['SOMA_MIRAGE_SWITCH'] = 'hvf'
run = subprocess.run(['timeout', '120', 'opam', 'exec', '--switch=hvf', '--', 'solo5-hvt',
    '--mem=256', '--', str(root/'tests/vault_prod_runtime.hvt'), '--arg=reject'],
    cwd=root, env=env, capture_output=True, text=True)
assert run.returncode == 0, 'SWVP booted rejection check failed'
assert 'PASS: booted SWVP header/policy rejection before KDF and wipe' in run.stdout
assert ('00'*31 + '01') not in run.stdout + run.stderr, 'key hex disclosed'
print('PASS: booted SWVP production rejection paths and wipe')
