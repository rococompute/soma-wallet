"""Boot the wallet UI image (main.hvt, built by scripts/check) host-only and
isolated, as scripts/run does, then fetch it over HTTP: GET / must be served
as text/html with the import form and disabled signing; POST /review with the
public BIP 143 PSBT fixture (tests/psbt_base64.soma) must render its review;
a malformed PSBT must render a typed rejection. No key is involved."""
import os, socket, pathlib, re, signal, subprocess, sys, time, urllib.parse
root = pathlib.Path(__file__).resolve().parents[1]
env = os.environ.copy(); env['SOMA_MIRAGE_SWITCH'] = 'hvf'
src = (root / 'tests/psbt_base64.soma').read_text()
line = next(l for l in src.splitlines() if l.startswith('fixture_b64'))
fixture = bytes(int(x) for x in re.findall(r'\d+', line.split(':=', 1)[1])).decode()

proc = subprocess.Popen(['opam', 'exec', '--switch=hvf', '--', 'solo5-vmnet', '--mode=host', '--isolate', '--',
                         'solo5-hvt', '--mem=256', '--', str(root / 'main.hvt')],
                        cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        start_new_session=True)
def fail(msg):
    print('FAIL:', msg, file=sys.stderr); sys.exit(1)
try:
    address, deadline = None, time.time() + 60
    while time.time() < deadline:
        out = proc.stdout.readline()
        if not out:
            fail('UI image exited before serving')
        m = re.search(r'Lease obtained! IP: (\d+\.\d+\.\d+\.\d+)', out)
        if m: address = m.group(1)
        if address and '"event":"serving"' in out: break
    else:
        fail('UI image did not start serving')

    def exchange(chunks):
        """send [chunks] as separate writes; return (head, body) of the answer"""
        for attempt in range(10):
            try:
                c = socket.create_connection((address, 8080), timeout=20)
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                for i, chunk in enumerate(chunks):
                    if i: time.sleep(0.3)
                    c.sendall(chunk)
                data = b''
                while True:
                    d = c.recv(65536)
                    if not d: break
                    data += d
                head, _, body = data.decode().partition('\r\n\r\n')
                return head, body
            except OSError:
                time.sleep(1)
        fail(f'no answer from {address}:8080')

    def request(method, path, body=None, split=False):
        head = f'{method} {path} HTTP/1.1\r\nHost: wallet\r\nConnection: close\r\n'
        if body is None:
            return exchange([(head + '\r\n').encode()])
        head += f'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n'
        return exchange([head.encode(), body.encode()] if split else [(head + body).encode()])

    def header(head, name):
        for l in head.split('\r\n')[1:]:
            k, _, v = l.partition(':')
            if k.strip().lower() == name.lower(): return v.strip()
        return ''

    r, page = request('GET', '/')
    if not r.startswith('HTTP/1.1 200') or not header(r, 'Content-Type').startswith('text/html'):
        fail(f'GET / served {r!r}')
    if int(header(r, 'Content-Length')) != len(page.encode()):
        fail('Content-Length does not match the body')
    if header(r, 'Cache-Control') != 'no-store' or 'default-src' not in header(r, 'Content-Security-Policy'):
        fail('missing no-store or CSP')
    if header(r, 'X-Content-Type-Options') != 'nosniff':
        fail('missing nosniff')
    for needle in ['<form method="post" action="/review">', 'name="psbt"',
                   '<button disabled="disabled">Sign transaction</button>', 'Import a key first.']:
        if needle not in page: fail(f'GET / lacks {needle!r}')

    r, page = request('POST', '/review', 'psbt=' + urllib.parse.quote(fixture, safe=''))
    if not header(r, 'Content-Type').startswith('text/html'):
        fail('POST /review is not HTML')
    for needle in ['Transaction review', '112340000 sat', '1.12340000 BTC', '2.23450000 BTC',
                   '600000000 sat', 'fee are unavailable', 'claimed by the PSBT', 'No inputs are selected', '<button disabled="disabled">Sign transaction</button>']:
        if needle not in page: fail(f'review lacks {needle!r}')

    r, page = request('POST', '/review', 'psbt=abc')
    if 'PSBT rejected' not in page or 'the Base64 padding is not canonical' not in page:
        fail('malformed PSBT was not rejected with its typed error')

    # a VALID fixture body shorter than its declared length is not reviewed
    body = 'psbt=' + urllib.parse.quote(fixture, safe='')
    head = ('POST /review HTTP/1.1\r\nHost: wallet\r\nContent-Type: application/x-www-form-urlencoded\r\n'
            f'Content-Length: {len(body) + 20}\r\n\r\n')
    r, page = exchange([(head + body).encode()])
    if 'did not arrive whole' not in page or 'Transaction review' in page:
        fail('a short body with a valid PSBT prefix was reviewed')
    r, page = request('POST', '/review', 'psbt=' + urllib.parse.quote(fixture[:40] + ' ' + fixture[40:], safe=''))
    if 'the text is not Base64' not in page:
        fail('whitespace inside the Base64 was not rejected')

    # a body sent after the headers, in a later packet, is reported honestly
    r, page = request('POST', '/review', 'psbt=abc', split=True)
    if 'did not arrive whole' not in page:
        fail('a late body was not reported as missing')
finally:
    os.killpg(proc.pid, signal.SIGTERM)
    try: proc.wait(10)
    except subprocess.TimeoutExpired: os.killpg(proc.pid, signal.SIGKILL)
print('PASS: booted UI serves HTML form, PSBT review and typed rejection over HTTP')
