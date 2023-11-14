"""Boot the host-only owner UI; cross-site browser POSTs must change nothing."""
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
SAME='Origin: http://wallet\r\nSec-Fetch-Site: same-origin\r\n'
FORGED=['Origin: http://evil.example\r\n','Origin: null\r\n','Origin: http://wallet:8082\r\n',
        'Origin: https://wallet\r\n','Sec-Fetch-Site: cross-site\r\n','Sec-Fetch-Site: same-site\r\n',
        'Origin: http://wallet\r\nOrigin: http://wallet\r\n',
        'Sec-Fetch-Site: same-origin\r\nSec-Fetch-Site: same-origin\r\n']
def state(app):
    page=app.page();found=re.search(r'name="revision" value="(\d+)"',page)
    return page,(found[1] if found else None)
app=App(True)
try:
    for extra in FORGED:rejected(app.page('/fixture','',extra=extra))
    assert 'Wallet locked' in app.page()
    assert 'Public test key imported' in app.page('/fixture','',extra=SAME)
    rev=revision(app.page('/review',fixture,extra=SAME))
    for extra in FORGED:
        for path,body in (('/approve','revision='+rev),('/sign','input=0'),('/lock',''),('/reset',''),('/review',fixture)):
            rejected(app.page(path,body,extra=extra))
        page,now=state(app)
        assert now==rev and 'Review every output and fee' in page and 'Approved for one signing attempt' not in page
    rejected(app.page('/export'))
    assert 'Approved for one signing attempt' in app.page('/approve','revision='+rev,extra=SAME)
    for extra in FORGED:
        rejected(app.page('/sign','input=0',extra=extra))
        page,_=state(app)
        assert 'Approved for one signing attempt' in page and 'Signed PSBT ready' not in page
    rejected(app.page('/export'))
    assert 'Signed PSBT ready' in app.page('/sign','input=0',extra='Sec-Fetch-Site: same-origin\r\n')
    headers,_=app.request('/export');assert headers['content-type']=='application/octet-stream'
    for extra in FORGED:rejected(app.page('/lock','',extra=extra))
    assert 'Signed PSBT ready' in app.page()
    assert 'Wallet locked' in app.page('/lock','',extra=SAME)
finally:app.close()
text=''.join(logs)
for scalar in (1,2):assert (('00'*31)+'%02x'%scalar) not in text,'scalar hex logged'
print('PASS: cross-site, null, wrong-port, same-site and duplicate-header POSTs change nothing; same-origin flow signs')
