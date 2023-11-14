"""Boot the fixture-only owner UI and verify the public signed download independently."""
import base64, hashlib, json, os, pathlib, re, queue, threading, signal, socket, struct, subprocess, time, urllib.parse
root=pathlib.Path(__file__).resolve().parents[1]
v=json.loads((root/'tests/sign_driver_fixture.json').read_text())
env=os.environ.copy();env['SOMA_MIRAGE_SWITCH']='hvf'
responses=[];logs=[]
class App:
    def __init__(self,enabled):
        args=['opam','exec','--switch=hvf','--','solo5-vmnet','--mode=host','--isolate','--',
              'solo5-hvt','--mem=256','--',str(root/'tests/owner_app_build.hvt')]
        if enabled:args+=['--arg=public-fixture']
        self.proc=subprocess.Popen(args,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                   text=True,start_new_session=True)
        self.address=None
        self.lines=queue.Queue()
        def collect():
            for line in self.proc.stdout:
                logs.append(line);self.lines.put(line)
        self.reader=threading.Thread(target=collect,daemon=True);self.reader.start()
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            try:line=self.lines.get(timeout=1)
            except queue.Empty:
                assert self.proc.poll() is None,'owner app exited before ready'
                continue
            found=re.search(r'Lease obtained! IP: (\d+\.\d+\.\d+\.\d+)',line)
            if found:self.address=found[1]
            if 'OWNER_UI_READY' in line and self.address:return
        self.close();raise AssertionError('owner app readiness timeout')
    def exchange(self,raw,late=None):
        c=socket.create_connection((self.address,8081),timeout=15)
        c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        with c:
            c.sendall(raw)
            if late is not None:
                time.sleep(.25)
                try:c.sendall(late)
                except OSError:pass
            answer=b''
            while True:
                try:part=c.recv(65536)
                except ConnectionResetError:break
                if not part:break
                answer+=part
        head,sep,body=answer.partition(b'\r\n\r\n');assert sep,'no complete HTTP response'
        headers={}
        for line in head.decode('ascii').split('\r\n')[1:]:
            k,_,value=line.partition(':');headers[k.lower()]=value.strip()
        assert int(headers['content-length'])==len(body)
        assert headers.get('cache-control')=='no-store'
        responses.append(answer)
        return headers,body
    def request(self,path='/',body=None,extra='',declared=None,split=False):
        method='GET' if body is None else 'POST'
        payload=b'' if body is None else body.encode()
        head=f'{method} {path} HTTP/1.1\r\nHost: wallet\r\nConnection: close\r\n'
        if body is not None:
            head+='Content-Type: application/x-www-form-urlencoded\r\n'
            head+=f'Content-Length: {len(payload) if declared is None else declared}\r\n'
        head+=extra+'\r\n'
        return self.exchange(head.encode()+(b'' if split else payload),payload if split else None)
    def page(self,path='/',body=None,**kwargs):
        headers,body=self.request(path,body,**kwargs)
        assert headers['content-type'].startswith('text/html')
        assert 'default-src' in headers['content-security-policy']
        assert headers['x-content-type-options']=='nosniff'
        return body.decode()
    def close(self):
        if self.proc.poll() is None:os.killpg(self.proc.pid,signal.SIGTERM)
        try:self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait(timeout=5)
        self.reader.join(timeout=2)
def revision(page):
    found=re.search(r'name="revision" value="(\d+)"',page)
    assert found,'no current review revision';return found[1]
def rejected(page):assert 'Request rejected' in page
fixture='psbt='+urllib.parse.quote(base64.b64encode(bytes.fromhex(v['psbt'])).decode(),safe='')
app=App(False)
try:
    page=app.page();assert 'Wallet locked' in page
    assert '<button disabled="disabled">Import public test fixture</button>' in page
    rejected(app.page('/fixture',''))
    assert 'Wallet locked' in app.page()
finally:app.close()
app=App(True)
try:
    assert 'Wallet locked' in app.page()
    page=app.page('/fixture','');assert 'Public test key imported' in page and 'bcrt1' in page
    page=app.page('/review',fixture)
    assert all(s in page for s in ['Transaction review','99000 sat','1000 sat','Inputs','Outputs','claims in the PSBT'])
    rev=revision(page)
    rejected(app.page('/approve','revision='+rev,declared=len('revision='+rev)+10))
    assert revision(app.page())==rev
    rejected(app.page('/lock','',extra='Content-Length: 0\r\n'))
    rejected(app.page('/lock','',extra=' Content-Length: 0\r\n'))
    rejected(app.page('/lock','',extra='Transfer-Encoding : chunked\r\n'))
    rejected(app.page('/lock','',extra='broken-header\r\n'))
    assert revision(app.page())==rev
    rejected(app.page('/approve','revision='+rev,extra='Transfer-Encoding: chunked\r\n'))
    rejected(app.page('/approve','revision='+rev+'&input=0'))
    rejected(app.page('/approve','revision='+rev,split=True))
    assert revision(app.page())==rev
    page=app.page('/approve','revision='+rev);assert 'Approved for one signing attempt' in page
    rejected(app.page('/approve','revision='+rev))
    page=app.page('/review',fixture);newrev=revision(page);assert newrev!=rev
    rejected(app.page('/approve','revision='+rev))
    assert revision(app.page())==newrev
    app.page('/approve','revision='+newrev)
    page=app.page('/sign','input=0');assert 'Signed PSBT ready' in page and 'Download signed PSBT' in page
    rejected(app.page('/sign','input=0'))
    headers,raw=app.request('/export')
    assert headers['content-type']=='application/octet-stream'
    assert 'attachment' in headers['content-disposition']
    page=app.page('/review',fixture);rev=revision(page)
    rejected(app.page('/export'))
    app.page('/approve','revision='+rev)
    app.page('/fixture','')
    rejected(app.page('/sign','input=0'));rejected(app.page('/export'))
    rev=revision(app.page('/review',fixture));app.page('/approve','revision='+rev)
    assert 'Wallet locked' in app.page('/lock','')
    rejected(app.page('/approve','revision='+rev));rejected(app.page('/export'))
    assert 'Wallet locked' in app.page('/reset','')
finally:app.close()
# Only public fixture keys are used. Neither their WIFs nor scalar hex may leak.
def wif(scalar):
    b=b'\xef'+scalar.to_bytes(32,'big')+b'\x01'
    b+=hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    n=int.from_bytes(b,'big');text='';alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while n:n,d=divmod(n,58);text=alphabet[d]+text
    return text
combined=b''.join(responses)+''.join(logs).encode()
for scalar in (1,2):
    assert wif(scalar).encode() not in combined,'WIF disclosed'
    assert scalar.to_bytes(32,'big').hex().encode() not in combined,'scalar hex disclosed'
class Reader:
    def __init__(self,b):self.b=b;self.i=0
    def take(self,n):
        assert n>=0 and self.i+n<=len(self.b)
        out=self.b[self.i:self.i+n];self.i+=n;return out
    def compact(self):
        n=self.take(1)[0];assert n<253 # this bounded public fixture
        return n
    def variable(self):return self.take(self.compact())
    def mapping(self):
        entries=[]
        while True:
            n=self.compact()
            if not n:return entries
            entries.append((self.take(n),self.variable()))
    def end(self):assert self.i==len(self.b)
def parse(b):
    r=Reader(b);assert r.take(5)==b'psbt\xff'
    maps=[r.mapping() for _ in range(3)];r.end();return maps
before=parse(bytes.fromhex(v['psbt']));after=parse(raw)
assert after[0]==before[0] and after[2]==before[2]
assert after[1][:-1]==before[1] and len(after[1])==len(before[1])+1
pub=bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
key,sig=after[1][-1];assert key==b'\x02'+pub and sig[-1]==1
der=sig[:-1]
unsigned=dict(before[0])[b'\x00'];assert unsigned.hex()==v['unsigned']
t=Reader(unsigned);version=t.take(4);assert version==struct.pack('<I',2)
assert t.compact()==1;outpoint=t.take(36);assert t.variable()==b''
sequence=t.take(4);assert t.compact()==1;start=t.i
amount=t.take(8);destination=t.variable();outputs=unsigned[start:t.i]
locktime=t.take(4);t.end()
assert destination.hex()=='001406afd46bcdfd22ef94ac122aa11f241244a37ecc'
assert int.from_bytes(amount,'little')==v['output_satoshis']
dsha=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
funding=bytes.fromhex(v['funding_tx'])
assert outpoint==dsha(funding)+bytes(4)
f=Reader(funding);assert f.take(4)==version;assert f.compact()==1
f.take(36);f.variable();f.take(4);assert f.compact()==1
funding_amount=f.take(8);funding_script=f.variable();f.take(4);f.end()
u=Reader(dict(before[1])[b'\x01']);input_amount=u.take(8);script=u.variable();u.end()
assert input_amount==funding_amount and script==funding_script
assert int.from_bytes(input_amount,'little')==v['input_satoshis']
assert v['input_satoshis']-v['output_satoshis']==v['fee_satoshis']==1000
h=hashlib.new('ripemd160',hashlib.sha256(pub).digest()).digest()
assert script==b'\0\x14'+h
preimage=(version+dsha(outpoint)+dsha(sequence)+outpoint+b'\x19\x76\xa9\x14'+h+
    b'\x88\xac'+input_amount+sequence+dsha(outputs)+locktime+struct.pack('<I',1))
assert dsha(preimage).hex()==v['sighash']
# Scalar comparison is a framing/low-S check, never an EC implementation.
rlen=der[3];slen=der[5+rlen];sstart=6+rlen
assert sstart+slen==len(der)
order=int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',16)
assert 0<int.from_bytes(der[sstart:],'big')<=order//2
# Node/OpenSSL performs the second SHA256 of BIP143 and all EC verification.
js='''
const {ECDH,createPublicKey,verify}=require('node:crypto');
const fs=require('node:fs'),assert=require('node:assert/strict');
const v=JSON.parse(fs.readFileSync(0,'utf8'));
const pub=ECDH.convertKey(Buffer.from(v.pub,'hex'),'secp256k1',undefined,undefined,'uncompressed');
const key=createPublicKey({key:Buffer.concat([Buffer.from('3056301006072a8648ce3d020106052b8104000a034200','hex'),pub]),format:'der',type:'spki'});
const msg=Buffer.from(v.message,'hex'),sig=Buffer.from(v.der,'hex');
assert.equal(verify('sha256',msg,key,sig),true);
const altered=Buffer.from(msg);altered[0]^=1;
assert.equal(verify('sha256',altered,key,sig),false);
const corrupt=Buffer.from(sig);corrupt[corrupt.length-1]^=1;
assert.equal(verify('sha256',msg,key,corrupt),false);
'''
checked=subprocess.run(['node','-e',js],input=json.dumps(dict(pub=pub.hex(),
    message=hashlib.sha256(preimage).hexdigest(),der=der.hex())),capture_output=True,text=True)
assert checked.returncode==0, 'independent OpenSSL verification failed'
print('PASS: host-only fixture owner HTTP/JSX flow, exact revisions, malformed/fragmented framing, one-shot signing, independent PSBT verification and no key disclosure')
