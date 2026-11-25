"""Owned DNS spy for the protected bootstrap contract, never production code."""
UPSTREAM = r'''
import json,socket,struct,threading
for _ in range(16):
 tcp=socket.socket();tcp.bind(('127.0.0.1',0));port=tcp.getsockname()[1]
 udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 try:udp.bind(('127.0.0.1',port));break
 except OSError:tcp.close();udp.close()
else:raise RuntimeError('no paired fixture port')
tcp.listen(8)
def answer(data,transport):
 print(json.dumps({'unexpected_query':True,'transport':transport,'bytes':len(data)}),flush=True)
 if len(data)<12:return b''
 return data[:2]+struct.pack('!HHHHH',0x8182,0,0,0,0)
def datagrams():
 while True:
  data,peer=udp.recvfrom(4096);udp.sendto(answer(data,'udp'),peer)
def streams():
 while True:
  stream,_=tcp.accept()
  with stream:
   stream.settimeout(2)
   try:
    data=stream.recv(4096);response=answer(data,'tcp');stream.sendall(len(response).to_bytes(2,'big')+response)
   except OSError:pass
threading.Thread(target=datagrams,daemon=True).start();threading.Thread(target=streams,daemon=True).start()
print(json.dumps({'ready':True,'endpoint':'127.0.0.1:'+str(port)}),flush=True)
threading.Event().wait()
'''
