"""Owned dual-stack nonce service and allocation-wide DNS pressure client."""
TARGET = r'''
import json,selectors,socket,sys
expected=sys.argv[1].encode()+b'\n';answer=b'ok:'+expected
selector=selectors.DefaultSelector();datagrams=set();clients=set()
for family,address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
 for port in [19001,19003,19002]:
  udp=port==19002;sock=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  sock.bind((address,port));sock.setblocking(False)
  if udp:datagrams.add(sock)
  else:sock.listen(16)
  selector.register(sock,selectors.EVENT_READ,bytearray())
print(json.dumps({'ready':True,'ipv6_ready':True}),flush=True)
while True:
 for key,_ in selector.select(1):
  sock=key.fileobj
  if sock in datagrams:
   data,peer=sock.recvfrom(256)
   if data==expected:sock.sendto(answer,peer)
  elif sock not in clients:
   client,_=sock.accept()
   if len(clients)>=16:client.close();continue
   client.setblocking(False);clients.add(client);selector.register(client,selectors.EVENT_READ,bytearray())
  else:
   try:
    data=sock.recv(256)
    if not data:raise EOFError()
    key.data.extend(data)
    if len(key.data)>256:raise ValueError('fixture input bound')
    while b'\n' in key.data:
     end=key.data.index(10)+1;line=bytes(key.data[:end]);del key.data[:end]
     if line!=expected:raise ValueError('fixture challenge differs')
     sock.sendall(answer)
   except (OSError,EOFError,ValueError):selector.unregister(sock);clients.remove(sock);sock.close()
'''

PRESSURE = r'''
import concurrent.futures,json,socket,struct,sys,time
v4,p4,v6,p6=sys.argv[1:5];query=bytes(json.loads(sys.argv[5]));streams=[]
try:
 def connect(index):return socket.create_connection((v4,int(p4)) if index%2==0 else (v6,int(p6)),timeout=2)
 with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:streams=list(pool.map(connect,range(16)))
 time.sleep(.15)
 with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as datagram:
  datagram.settimeout(1);datagram.connect((v6,int(p6)));datagram.send(query);response=datagram.recv(65535)
 identifier,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',response[:12])
 print(json.dumps({'connections':len(streams),'id':identifier,'rcode':flags&15,'answers':an,'authority':ns,'additional':ar}))
finally:
 for stream in streams:stream.close()
'''
