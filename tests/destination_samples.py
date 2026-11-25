"""Bounded diagnostic listeners on exact task-owned host addresses only."""

LOCAL_HOST = r'''
import errno,ipaddress,json,os,selectors,socket,sys,time
address4,address6,token=sys.argv[1:]
assert ipaddress.ip_address(address4).version==4 and ipaddress.ip_address(address4).is_private
assert ipaddress.ip_address(address6).version==6 and ipaddress.ip_address(address6).is_private
assert all(not ipaddress.ip_address(a).is_unspecified and not ipaddress.ip_address(a).is_multicast for a in (address4,address6))
status={line.split(":",1)[0]:line.split(":",1)[1].strip() for line in open("/proc/self/status") if line.startswith(("CapEff:","NoNewPrivs:"))}
assert os.getuid()==os.getgid()==1000 and int(status["CapEff"],16)==0 and status["NoNewPrivs"]=="1"
expected=token.encode()+b"\n";answer=b"ok:"+expected
assert len(expected)<=128
selector=selectors.DefaultSelector();ports=[];clients={}
for family,address in ((socket.AF_INET,address4),(socket.AF_INET6,address6)):
 server=socket.socket(family,socket.SOCK_STREAM)
 if family==socket.AF_INET6:server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 deadline=time.monotonic()+4
 while True:
  try:server.bind((address,0));break
  except OSError as error:
   if error.errno!=errno.EADDRNOTAVAIL or time.monotonic()>=deadline:raise
   time.sleep(.05)
 assert server.getsockname()[0]==address and server.getsockname()[1]>=1024
 ports.append(server.getsockname()[1]);server.listen(16);server.setblocking(False);selector.register(server,selectors.EVENT_READ)
print(json.dumps({"ready":True,"address4":address4,"address6":address6,"port4":ports[0],"port6":ports[1],"uid":os.getuid(),"gid":os.getgid(),"cap_effective":int(status["CapEff"],16),"no_new_privileges":True}),flush=True)
def close(client):
 selector.unregister(client);clients.pop(client,None);client.close()
while True:
 for key,_ in selector.select(.1):
  sock=key.fileobj
  if sock not in clients:
   client,_=sock.accept()
   if len(clients)>=16:client.close();continue
   client.setblocking(False);clients[client]=[bytearray(),time.monotonic()];selector.register(client,selectors.EVENT_READ)
  else:
   try:
    part=sock.recv(129-len(clients[sock][0]))
    if not part:close(sock);continue
    clients[sock][0].extend(part)
    if len(clients[sock][0])>128:close(sock);continue
    if b"\n" in clients[sock][0]:
     if bytes(clients[sock][0])==expected:sock.sendall(answer)
     close(sock)
   except OSError:close(sock)
 for client,(_,started) in list(clients.items()):
  if time.monotonic()-started>1.5:close(client)
'''
