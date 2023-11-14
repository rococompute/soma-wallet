"""Normal and no-host-RNG boots must both refuse material with clean vaults."""
import os, pathlib, subprocess
root=pathlib.Path(__file__).resolve().parents[1]
env=os.environ.copy();env['SOMA_MIRAGE_SWITCH']='hvf'
marker='PASS: entropy unverified; no salt or nonce; both vault interfaces cleared'
fallback='no host entropy (solo5_random unavailable)'
for disabled in (False,True):
    command=['timeout','90','opam','exec','--switch=hvf','--','solo5-hvt','--mem=256']
    if disabled:command+=['--no-random']
    command+=['--',str(root/'tests/runtime_vault_entropy_gate.hvt'),'--arg=public-refusal']
    run=subprocess.run(command,cwd=root,env=env,capture_output=True,text=True)
    logs=run.stdout+run.stderr
    assert run.returncode==0 and marker in run.stdout,'entropy refusal/cleanup image failed'
    assert (fallback in logs)==disabled,'host RNG negative control is not effective'
    assert [line for line in run.stdout.splitlines() if line.startswith('PASS:')]==[marker]
    assert 'ENTROPY_BLOCK=' not in logs and 'SALT=' not in logs and 'NONCE=' not in logs
    assert ('00'*31+'01') not in logs,'public scalar hex disclosed'
print('PASS: normal and --no-random boots both refuse unverified entropy, emit no material and clear both vaults')
