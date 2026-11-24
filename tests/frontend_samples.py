"""Unprivileged wire client for actual workload DNS boundary tests."""
CLIENT = r'''
import json,socket,struct,sys
mode,address,port=sys.argv[1:4];wire=bytes(json.loads(sys.argv[4]))
def exact(stream,count):
 value=b''
 while len(value)<count:
  data=stream.recv(count-len(value))
  if not data: raise EOFError()
  value+=data
 return value
def skip_name(data,cursor):
 for _ in range(128):
  size=data[cursor];cursor+=1
  if size==0:return cursor
  if size&192==192:return cursor+1
  if size>63:raise ValueError('bad fixture response label')
  cursor+=size
 raise ValueError('too many labels')
try:
 if mode=='tcp':
  with socket.create_connection((address,int(port)),timeout=3) as stream:
   stream.sendall(len(wire).to_bytes(2,'big')+wire);size=int.from_bytes(exact(stream,2),'big')
   if not 12<=size<=65535:raise ValueError('bad fixture DNS length')
   response=exact(stream,size)
 else:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
   stream.settimeout(3);stream.connect((address,int(port)));stream.send(wire);response=stream.recv(65535)
 identifier,flags,questions,answers,_,_=struct.unpack('!HHHHHH',response[:12]);cursor=12
 for _ in range(questions):cursor=skip_name(response,cursor)+4
 addresses=[]
 for _ in range(answers):
  cursor=skip_name(response,cursor);kind,cls,ttl,size=struct.unpack('!HHIH',response[cursor:cursor+10]);cursor+=10
  if kind==1 and cls==1 and size==4:addresses.append(socket.inet_ntoa(response[cursor:cursor+size]))
  cursor+=size
 assert identifier==71
 print(json.dumps({'ok':True,'rcode':flags&15,'answers':answers,'addresses':addresses}))
except (OSError,EOFError,ValueError,IndexError,struct.error) as error:
 print(json.dumps({'ok':False,'error':type(error).__name__}))
'''

MALFORMED_CLIENT = r'''
import json,socket,struct,sys
mode,address,port=sys.argv[1:4];wire=bytes(json.loads(sys.argv[4]))
try:
 if mode=='udp':
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
   stream.settimeout(3);stream.connect((address,int(port)));stream.send(wire);response=stream.recv(65535)
  identifier,flags,questions,answers,authority,additional=struct.unpack('!HHHHHH',response[:12])
  assert identifier==71
  print(json.dumps({'ok':True,'rcode':flags&15,'counts':[questions,answers,authority,additional],'length':len(response)}))
 else:
  with socket.create_connection((address,int(port)),timeout=3) as stream:
   if mode=='partial':stream.sendall(len(wire).to_bytes(2,'big')+wire[:8])
   elif mode=='oversized':stream.sendall((4097).to_bytes(2,'big'))
   elif mode=='short':stream.sendall((11).to_bytes(2,'big'))
   else:raise ValueError('unknown fixture mode')
   stream.shutdown(socket.SHUT_WR)
   print(json.dumps({'ok':True,'closed_without_answer':stream.recv(1)==b''}))
except (OSError,EOFError,ValueError,IndexError,struct.error) as error:
 print(json.dumps({'ok':False,'error':type(error).__name__}))
'''
