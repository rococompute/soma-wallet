"""Boot the typed adapter with public fixture selection; never print secrets."""
import os, pathlib, subprocess
root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy(); env['SOMA_MIRAGE_SWITCH'] = 'hvf'
result = subprocess.run(['timeout', '120', 'opam', 'exec', '--switch=hvf', '--',
    'solo5-hvt', '--mem=256', '--', str(root/'tests/vault_runtime.hvt'), '--arg=public-fixture'],
    cwd=root, env=env, capture_output=True, text=True)
assert result.returncode == 0, 'vault runtime boot failed'
assert 'PASS: typed vault public roundtrip, wrong passphrase and cleanup' in result.stdout, 'vault runtime check failed'
assert ('00'*31+'01') not in result.stdout+result.stderr, 'key hex disclosed'
print('PASS: typed vault executes inside the unikernel without secret logs')
