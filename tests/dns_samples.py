"""Public controlled DNS upstream fixture; never used by production services."""
DNS = r'''
import json,socket,struct,sys,threading
target=sys.argv[1]
udp_ready=threading.Event();tcp_ready=threading.Event()
def answer(data):
 if len(data)<12 or data[4:6]!=b'\x00\x01': raise ValueError('bad fixture query')
 cursor=12;labels=[]
 while True:
  size=data[cursor];cursor+=1
  if size==0: break
  if size>63 or cursor+size>len(data): raise ValueError('bad fixture label')
  labels.append(data[cursor:cursor+size].decode('ascii'));cursor+=size
 kind,cls=struct.unpack('!HH',data[cursor:cursor+4]);cursor+=4
 name='.'.join(labels).lower();print(json.dumps({'query':name,'kind':kind}),flush=True)
 question=data[12:cursor];header=struct.pack('!HHHHHH',int.from_bytes(data[:2],'big'),0x8180,1,int(kind==1),0,0)
 ttl={'short.test':4,'long.test':30}.get(name,10)
 record=b'\xc0\x0c'+struct.pack('!HHIH',1,1,ttl,4)+socket.inet_aton(target) if kind==1 else b''
 return header+question+record
def udp():
 server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('0.0.0.0',19004))
 udp_ready.set()
 while True:
  data,peer=server.recvfrom(4096)
  try: server.sendto(answer(data),peer)
  except (ValueError,IndexError,struct.error): pass
def exact(stream,count):
 result=b''
 while len(result)<count:
  data=stream.recv(count-len(result))
  if not data: raise EOFError()
  result+=data
 return result
def tcp():
 server=socket.socket();server.bind(('0.0.0.0',19004));server.listen(8)
 tcp_ready.set()
 while True:
  stream,_=server.accept()
  with stream:
   stream.settimeout(3)
   try:
    count=int.from_bytes(exact(stream,2),'big')
    if not 12<=count<=4096: continue
    response=answer(exact(stream,count));stream.sendall(len(response).to_bytes(2,'big')+response)
   except (OSError,EOFError,ValueError,IndexError,struct.error): pass
threading.Thread(target=udp,daemon=True).start()
threading.Thread(target=tcp,daemon=True).start()
if not udp_ready.wait(5) or not tcp_ready.wait(5): raise RuntimeError('fixture listeners not ready')
print(json.dumps({'ready':True}),flush=True)
threading.Event().wait()
'''
