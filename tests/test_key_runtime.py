"""Boot a public fixture selected at runtime; print no WIF or scalar."""
import os, pathlib, subprocess
root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy(); env['SOMA_MIRAGE_SWITCH'] = 'hvf'
result = subprocess.run(['timeout', '120', 'opam', 'exec', '--switch=hvf', '--',
    'solo5-hvt', '--mem=256', '--', str(root/'tests/key_runtime.hvt'), '--arg=public-one'],
    cwd=root, env=env, capture_output=True, text=True)
assert result.returncode == 0, 'runtime key import image failed'
assert 'PASS: runtime WIF identities and failure cleanup' in result.stdout, 'runtime key checks did not pass'
print('PASS: runtime public WIF identities and failure cleanup')
