"""Trusted, owner-scoped fault fixture for the real local Docker API.

Never mounted in a source/converter. Holds actual request/response boundaries;
does not emulate Docker or edit GoldenHoop's database.
"""
import http.client
import http.server
import json
import select
import socket
import socketserver
import threading
import time
from urllib.parse import parse_qs, urlsplit


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.fault = None
        self.requests = []

    def snapshot(self):
        with self.lock:
            fault = None if self.fault is None else {k: v for k, v in self.fault.items() if k != 'release'}
            return dict(fault=fault, requests=list(self.requests))

    def arm(self, value):
        assert value['mode'] in ['create_before', 'create_after', 'export_mid', 'disk_mid', 'remove_after', 'inspect404_after']
        with self.lock:
            assert self.fault is None or self.fault['released']
            self.fault = dict(mode=value['mode'], skip=value.get('skip', 0), seen=0,
                              claimed=False, hit=False, released=False, backend_completed=False,
                              release=threading.Event())

    def claim(self, mode):
        with self.lock:
            fault = self.fault
            if fault is None or fault['mode'] != mode or fault['claimed']:
                return None
            fault['seen'] += 1
            if fault['seen'] <= fault['skip']:
                return None
            fault['claimed'] = True
            return fault

    def hold(self, fault, **observed):
        with self.lock:
            fault.update(observed, hit=True)
        # The fixture owner always releases or stops this process on failure.
        if not fault['release'].wait(900):
            raise TimeoutError('fault boundary was not released')

    def release(self):
        with self.lock:
            assert self.fault is not None
            self.fault['released'] = True
            self.fault['release'].set()


STATE = State()


class Backend(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('localhost', timeout=900)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(900)
        self.sock.connect('/backend.sock')


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def control(self):
        if self.path == '/_fault/arm':
            size = int(self.headers.get('Content-Length', '0'))
            assert 0 < size <= 4096
            STATE.arm(json.loads(self.rfile.read(size)))
        elif self.path == '/_fault/release':
            STATE.release()
        else:
            assert self.path == '/_fault/state'
        data = json.dumps(STATE.snapshot()).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def request_body(self, backend):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            while True:
                line = self.rfile.readline(128)
                assert line.endswith(b'\r\n')
                size = int(line.split(b';', 1)[0], 16)
                assert 0 <= size <= 16 * 1024**2
                if size == 0:
                    assert self.rfile.readline(2) == b'\r\n'
                    backend.send(b'0\r\n\r\n')
                    return
                data = self.rfile.read(size)
                assert len(data) == size and self.rfile.read(2) == b'\r\n'
                backend.send(f'{size:x}\r\n'.encode() + data + b'\r\n')
        else:
            remaining = int(self.headers.get('Content-Length', '0'))
            while remaining:
                data = self.rfile.read(min(65536, remaining))
                assert data
                backend.send(data)
                remaining -= len(data)

    def tunnel(self, backend):
        sockets = [self.connection, backend.sock]
        deadline = time.monotonic() + 900
        while sockets and time.monotonic() < deadline:
            readable, _, _ = select.select(sockets, [], [], 1)
            for source in readable:
                target = backend.sock if source is self.connection else self.connection
                data = source.recv(65536)
                if not data:
                    sockets.remove(source)
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                else:
                    target.sendall(data)

    def forward(self):
        self.close_connection = True
        if self.path.startswith('/_fault/'):
            return self.control()
        parsed = urlsplit(self.path)
        path = parsed.path
        create = self.command == 'POST' and path.endswith('/containers/create')
        event = dict(method=self.command, path=self.path, backend_dispatched=False)
        with STATE.lock:
            assert len(STATE.requests) < 1024
            STATE.requests.append(event)
        before = STATE.claim('create_before') if create else None
        if before:
            STATE.hold(before, request=self.path, backend_completed=False)
        backend = Backend()
        response = None
        try:
            backend.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            upgrade = self.headers.get('Connection', '').lower() == 'upgrade'
            for key, value in self.headers.items():
                if key.lower() not in ['connection', 'expect']:
                    backend.putheader(key, value)
            backend.putheader('Connection', 'Upgrade' if upgrade else 'close')
            backend.endheaders()
            self.request_body(backend)
            event['backend_dispatched'] = True
            response = backend.getresponse()
            event['status'] = response.status
            if before:
                before['backend_completed'] = True
            after = STATE.claim('create_after') if create else None
            if self.command == 'DELETE' and '/containers/' in path:
                after = STATE.claim('remove_after') or after
            if self.command == 'GET' and '/containers/' in path and path.endswith('/json') and response.status == 404:
                after = STATE.claim('inspect404_after') or after
            buffered = None
            if create or after:
                buffered = response.read(1024**2 + 1)
                assert len(buffered) <= 1024**2
                if create and response.status == 201:
                    event['container_id'] = json.loads(buffered)['Id']
                if after:
                    STATE.hold(after, request=self.path, status=response.status,
                               container_id=event.get('container_id'), backend_completed=True)
            if response.status == 101:
                self.send_response_only(response.status, response.reason)
                for key, value in response.getheaders():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.flush()
                return self.tunnel(backend)
            self.send_response_only(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in ['connection', 'transfer-encoding', 'content-length']:
                    self.send_header(key, value)
            chunked = buffered is None and response.status not in [204, 304] and self.command != 'HEAD'
            if chunked:
                self.send_header('Transfer-Encoding', 'chunked')
            else:
                self.send_header('Content-Length', str(len(buffered or b'')))
            self.send_header('Connection', 'close')
            self.end_headers()
            if buffered is not None:
                self.wfile.write(buffered)
                return
            if not chunked:
                return
            middle = None
            if self.command == 'GET' and path.endswith('/export'):
                middle = STATE.claim('export_mid')
            archive = parse_qs(parsed.query).get('path', [''])[0]
            if self.command == 'GET' and path.endswith('/archive') and archive.endswith('/rootfs.ext4'):
                middle = STATE.claim('disk_mid')
            count = 0
            boundary = 8 * 1024**2 + 1024
            if middle and middle['mode'] == 'export_mid':
                boundary = 4 * 1024**2 + 262144
            while True:
                size = min(65536, boundary - count) if middle else 65536
                data = response.read(size)
                if not data:
                    self.wfile.write(b'0\r\n\r\n')
                    break
                self.wfile.write(f'{len(data):x}\r\n'.encode() + data + b'\r\n')
                self.wfile.flush()
                count += len(data)
                if middle and count == boundary:
                    STATE.hold(middle, request=self.path, status=response.status,
                               forwarded_body_bytes=count, backend_completed=False)
                    # Close the real read stream after the killed producer; no
                    # remaining response bytes are delivered by this fixture.
                    return
        except (BrokenPipeError, ConnectionResetError, OSError) as error:
            event['transport_error'] = type(error).__name__
        finally:
            if response is not None:
                response.close()
            backend.close()
            event['handler_finished'] = True

    do_GET = forward
    do_POST = forward
    do_PUT = forward
    do_DELETE = forward
    do_HEAD = forward


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


with Server('/proxy/docker.sock', Handler) as server:
    print('trusted Docker fault proxy ready', flush=True)
    server.serve_forever()
