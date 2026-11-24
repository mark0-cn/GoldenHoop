"""Public fixture programs; these are not GoldenHoop's production data plane."""

TARGET = r'''
import json,selectors,socket,sys
token=sys.argv[1].encode(); expected=token+b"\n"; answer=b"ok:"+expected
selector=selectors.DefaultSelector()
for port in [19001,19003]:
 sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 sock.bind(("0.0.0.0",port)); sock.listen(16); sock.setblocking(False)
 selector.register(sock,selectors.EVENT_READ,bytearray())
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind(("0.0.0.0",19002)); udp.setblocking(False)
selector.register(udp,selectors.EVENT_READ,None)
print(json.dumps({"ready":True,"tcp_ports":[19001,19003],"udp_port":19002}),flush=True)
clients=set()
while True:
 for key,_ in selector.select(1):
  sock=key.fileobj
  if sock is udp:
   data,address=sock.recvfrom(256)
   if data==expected: sock.sendto(answer,address)
  elif sock not in clients:
   client,_=sock.accept()
   if len(clients)>=16: client.close(); continue
   client.setblocking(False); clients.add(client); selector.register(client,selectors.EVENT_READ,bytearray())
  else:
   try:
    data=sock.recv(256)
    if not data: raise EOFError()
    key.data.extend(data)
    if len(key.data)>256: raise ValueError("fixture input bound")
    while b"\n" in key.data:
     position=key.data.index(10)+1; line=bytes(key.data[:position]); del key.data[:position]
     if line!=expected: raise ValueError("unexpected fixture challenge")
     sock.sendall(answer)
   except (OSError,EOFError,ValueError):
    selector.unregister(sock); clients.remove(sock); sock.close()
'''

HOST = r'''
import json,socket,time
from pathlib import Path
config=Path("/run/probe-config.json")
while not config.exists(): time.sleep(0.05)
config=json.loads(config.read_text()); expected=config["token"].encode()+b"\n"
server=socket.create_server((config["gateway"],0),backlog=16)
Path("/run/probe-ready.json").write_text(json.dumps({"port":server.getsockname()[1]}))
while True:
 client,_=server.accept()
 with client:
  client.settimeout(1)
  try:
   data=b""
   while not data.endswith(b"\n") and len(data)<256:
    part=client.recv(256-len(data))
    if not part: break
    data+=part
   if data==expected: client.sendall(b"ok:"+expected)
  except OSError: pass
'''

CLIENT = r'''
import json,os,socket,sys
mode,ip,port,token=sys.argv[1:]; port=int(port)
request=token.encode()+b"\n"; expected=b"ok:"+request
def exchange(sock):
 try:
  sock.sendall(request); reply=b""
  while len(reply)<len(expected):
   part=sock.recv(128)
   if not part: break
   reply+=part
  return {"ok":reply==expected,"reply_hex":reply.hex()}
 except OSError as error: return {"ok":False,"error":type(error).__name__}
def connect():
 return socket.create_connection((ip,port),timeout=1.2)
if mode=="tcp":
 try:
  with connect() as sock: result=exchange(sock)
 except OSError as error: result={"ok":False,"error":type(error).__name__}
 print(json.dumps(result),flush=True)
elif mode=="udp":
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
  sock.settimeout(1.2)
  try:
   sock.sendto(request,(ip,port)); reply,_=sock.recvfrom(128)
   result={"ok":reply==expected,"reply_hex":reply.hex()}
  except OSError as error: result={"ok":False,"error":type(error).__name__}
  print(json.dumps(result),flush=True)
elif mode=="persistent":
 with connect() as sock:
  print(json.dumps({"connected":True}),flush=True)
  for line in sys.stdin:
   item=json.loads(line)
   if item["action"]=="close": break
   assert item["action"]=="exchange"
   print(json.dumps(exchange(sock)),flush=True)
else: raise ValueError("unknown fixture mode")
'''

IDENTITY = r'''
import json,os,subprocess
status=open("/proc/self/status").read().splitlines()
credentials={line.split(":",1)[0]:line.split(":",1)[1].strip() for line in status if line.startswith(("CapEff:","NoNewPrivs:"))}
attempt=subprocess.run(["nft","-j","list","tables"],capture_output=True,text=True,timeout=5)
print(json.dumps({"uid":os.getuid(),"gid":os.getgid(),"groups":os.getgroups(),"credentials":credentials,"nft_exit_code":attempt.returncode}))
'''
