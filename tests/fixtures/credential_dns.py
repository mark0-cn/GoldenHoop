"""Disposable loopback DNS upstream for the two credential fixture names only."""
import ipaddress
import json
import socket
import struct
import threading

MAPPING = {}  # Filled with owned receiver addresses by the native harness.
tcp = socket.socket()
tcp.bind(('127.0.0.1', 0))
port = tcp.getsockname()[1]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(('127.0.0.1', port))
tcp.listen(8)


def answer(data, transport):
    if len(data) < 17 or struct.unpack('!H', data[4:6])[0] != 1:
        raise ValueError('invalid fixture DNS question')
    offset, labels = 12, []
    while data[offset]:
        size = data[offset]
        assert size <= 63 and offset + size + 1 < len(data)
        labels.append(data[offset + 1:offset + 1 + size].decode('ascii').lower())
        offset += size + 1
    offset += 1
    kind, family = struct.unpack('!HH', data[offset:offset + 4])
    question = data[12:offset + 4]
    name = '.'.join(labels)
    permitted = name in ('api.credential.test', 'other.credential.test') and kind in (1, 28) and family == 1
    print(json.dumps(dict(query=name if permitted else 'unapproved', transport=transport, unexpected_query=not permitted)), flush=True)
    if not permitted:
        return data[:2] + struct.pack('!HHHHH', 0x8185, 1, 0, 0, 0) + question
    address = ipaddress.ip_address(MAPPING['ipv4' if kind == 1 else 'ipv6']).packed
    record = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 30, len(address)) + address
    return data[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question + record


def datagrams():
    while True:
        data, peer = udp.recvfrom(4096)
        udp.sendto(answer(data, 'udp'), peer)


def exact(stream, size):
    data = b''
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise OSError('truncated fixture question')
        data += part
    return data


def streams():
    while True:
        stream, _ = tcp.accept()
        with stream:
            stream.settimeout(3)
            size = int.from_bytes(exact(stream, 2), 'big')
            assert 0 < size <= 4096
            response = answer(exact(stream, size), 'tcp')
            stream.sendall(len(response).to_bytes(2, 'big') + response)


threading.Thread(target=datagrams, daemon=True).start()
threading.Thread(target=streams, daemon=True).start()
print(json.dumps(dict(ready=True, endpoint='127.0.0.1:' + str(port))), flush=True)
threading.Event().wait()
