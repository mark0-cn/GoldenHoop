"""Disposable upstream only. Generated canaries/private keys never reach guests."""
import base64
import hashlib
import http.server
import ipaddress
import json
import os
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path

os.umask(0o077)
root = Path('/tmp/credential-fixture')
root.mkdir(mode=0o700)
v4 = socket.gethostbyname(socket.gethostname())
v6s = [str(ipaddress.IPv6Address(int(line.split()[0], 16)))
       for line in Path('/proc/net/if_inet6').read_text().splitlines()
       if line.split()[-1] != 'lo' and not ipaddress.IPv6Address(int(line.split()[0], 16)).is_link_local]
assert len(v6s) == 1
v6 = v6s[0]
tokens = {name: secrets.token_urlsafe(32) for name in ('alpha', 'beta', 'rotated', 'exchange', 'delayed', 'exchange-auth')}
def openssl(*args):
    subprocess.run(['openssl', *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=GoldenHoop credential fixture root', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', str(root / 'ca.key'), '-out', str(root / 'ca.pem'))
openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=GoldenHoop credential fixture',
        '-keyout', str(root / 'server.key'), '-out', str(root / 'server.csr'))
(root / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
    + f'subjectAltName=IP:{v4},IP:{v6},DNS:api.credential.test,DNS:other.credential.test\n')
openssl('x509', '-req', '-in', str(root / 'server.csr'), '-CA', str(root / 'ca.pem'), '-CAkey', str(root / 'ca.key'),
        '-CAcreateserial', '-out', str(root / 'server.pem'), '-days', '1', '-extfile', str(root / 'server.ext'))
public = (root / 'ca.pem').read_text()
control = dict(ipv4=v4, ipv6=v6, tokens=tokens, public_ca=public, expected_body='goldenhoop_receiver_accepted')
(root / 'control.json').write_text(json.dumps(control))
lock = threading.Lock()


def emit(**fields):
    with lock:
        print(json.dumps(fields), flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body, reflected=None):
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        if reflected:
            self.send_header('X-Reflected-Credential', reflected)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def handle_request(self):
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 <= length <= 2 * 1024 * 1024:
            return self.reply(413, b'bounded')
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            chunks = []
            total = 0
            while True:
                line = self.rfile.readline(65)
                size = int(line.strip(), 16)
                total += size
                if len(line) > 64 or total > 2 * 1024 * 1024:
                    return self.reply(413, b'bounded')
                if size == 0:
                    assert self.rfile.readline(3) == b'\r\n'
                    break
                chunks.append(self.rfile.read(size))
                assert self.rfile.read(2) == b'\r\n'
            body = b''.join(chunks)
        else:
            body = self.rfile.read(length)
        path = urllib.parse.urlsplit(self.path)
        if path.path in ('/exchange', '/exchange-delayed'):
            if self.command != 'POST' or self.headers.get('X-Exchange-Auth') != tokens['exchange-auth']:
                return self.reply(401, b'denied')
            delayed = path.path == '/exchange-delayed'
            emit(event='exchange_received', delayed=delayed, authenticated=True)
            if delayed:
                time.sleep(3)
            value = tokens['delayed' if delayed else 'exchange']
            try:
                self.reply(200, json.dumps(dict(value=value)).encode())
            except (OSError, ssl.SSLError):
                emit(event='exchange_connection_collected', delayed=delayed)
            return
        authorization = self.headers.get('Authorization', '')
        values = [self.headers.get('X-Provider-Key', ''), self.headers.get('X-Placeholder', '')]
        if authorization.startswith('Bearer '):
            values.append(authorization[7:])
        elif authorization.startswith('Basic '):
            try:
                raw = base64.b64decode(authorization[6:], validate=True).decode()
                if raw.startswith('goldenhoop:'):
                    values.append(raw[len('goldenhoop:'):])
            except (ValueError, UnicodeError):
                pass
        values.extend(v for _, v in urllib.parse.parse_qsl(path.query))
        selected = next((name for name, token in tokens.items() if name != 'exchange-auth' and token in values), None)
        if path.path.startswith('/v1/substitute/'):
            selected = next((name for name, token in tokens.items()
                             if name != 'exchange-auth' and token in urllib.parse.unquote(path.path)
                             and token in values and token.encode() in body), None)
        if selected is None:
            emit(event='uncredentialed_request', tls=isinstance(self.connection, ssl.SSLSocket))
            return self.reply(401, b'denied')
        token = tokens[selected]
        digest = hashlib.sha256(token.encode()).hexdigest()
        emit(event='accepted', tls=isinstance(self.connection, ssl.SSLSocket), secret_sha256=digest,
             basic=authorization.startswith('Basic '), substituted=path.path.startswith('/v1/substitute/'))
        if path.path == '/v1/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            try:
                for count in range(60):
                    self.wfile.write(f'data: {count}\n\n'.encode())
                    self.wfile.flush()
                    time.sleep(1)
            except (OSError, ssl.SSLError):
                pass
            finally:
                emit(event='stream_collected', secret_sha256=digest)
            self.close_connection = True
            return
        self.reply(200, control['expected_body'].encode(), reflected=token)

    do_GET = handle_request
    do_POST = handle_request


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


plain = Server(('::', 18080), Handler)
secure = Server(('::', 18443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(root / 'server.pem'), str(root / 'server.key'))
secure.socket = context.wrap_socket(secure.socket, server_side=True)
for server in (plain, secure):
    threading.Thread(target=server.serve_forever, daemon=True).start()
emit(ready=True, http_port=18080, https_port=18443)
threading.Event().wait()
