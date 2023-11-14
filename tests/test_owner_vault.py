"""Drive the real owner and ensure every unlock attempt destroys prior state."""
import os,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
env=os.environ.copy();env['SOMA_MIRAGE_SWITCH']='hvf'
run=subprocess.run(['timeout','120','opam','exec','--switch=hvf','--','solo5-hvt','--mem=256','--',
    str(root/'tests/runtime_owner_vault.hvt'),'--arg=public-lifecycle'],cwd=root,env=env,capture_output=True,text=True)
logs=run.stdout+run.stderr
assert run.returncode==0, logs
assert 'PASS: live owner unlock invalidation, stale handles, dual vault cleanup, lock/reset, canonical unavailable and bounded failures' in run.stdout
actual=[line[6:] for line in run.stdout.splitlines() if line.startswith('LIFE: ')]
prefix=['imported','reviewed','approved-dirty']
no_old=['no-psbt','no-key','no-export','no-key']
expected=['locked']+prefix+['pending','signed','export-before-unlock','malformed']+no_old
for failure in ['kdf-unavailable','pass-rejected','pass-rejected','oversized','byte-rejected','swvt-rejected','policy-rejected']:
    expected+=prefix+[failure]+no_old
for _ in range(2):expected+=prefix+['locked']+no_old
expected+=['locked']
assert actual==expected, repr(actual)
for secret in ['cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA',
               'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87K7XCyj5v',
               (bytes(31)+b'\x01').hex(),(bytes(31)+b'\x02').hex()]:
    assert secret not in logs,'fixture key disclosure'
assert 'SIGNED_PSBT_HEX=' not in logs and 'OPENED_KEY=' not in logs
print('PASS: owner lifecycle command order, previous export invalidation, no prior key/approval reuse, stale handles, dual cleanup and log hygiene')
