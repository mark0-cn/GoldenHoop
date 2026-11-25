"""Trusted namespace inspector and bounded source-integrity packet fixtures."""
INSPECT = r'''
import json,os
from pathlib import Path
status=dict(line.split(':',1) for line in open('/proc/self/status') if line.startswith(('CapEff:','NoNewPrivs:')))
assert int(status['CapEff'],16)==0 and status['NoNewPrivs'].strip()=='1'
links=[]
for p in Path('/sys/class/net').iterdir():
 if p.name!='lo':links.append({'name':p.name,'ifindex':int((p/'ifindex').read_text()),'iflink':int((p/'iflink').read_text()),'mac':(p/'address').read_text().strip()})
print(json.dumps({'uid':os.getuid(),'cap_effective':0,'no_new_privileges':True,'links':links}))
'''

RECEIVER = r'''
import json,selectors,socket,sys
token=sys.argv[1];selector=selectors.DefaultSelector()
for family,address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
 sock=socket.socket(family,socket.SOCK_DGRAM)
 if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 sock.bind((address,19101));selector.register(sock,selectors.EVENT_READ)
print(json.dumps({'ready':True}),flush=True)
while True:
 for key,_ in selector.select(1):
  data,peer=key.fileobj.recvfrom(256)
  try:nonce=data.decode('ascii')
  except UnicodeDecodeError:continue
  if nonce.startswith(token+':') and len(nonce)<=128:
   print(json.dumps({'nonce':nonce,'source':peer[0],'family':key.fileobj.family}),flush=True)
   key.fileobj.sendto(b'ok:'+data,peer)
'''

PACKET = r'''
import ipaddress,json,os,socket,struct,sys,time,zlib
mode,nonce=sys.argv[1:3];config=json.loads(sys.argv[3]);status=dict(line.split(':',1) for line in open('/proc/self/status') if line.startswith(('CapEff:','NoNewPrivs:')))
assert int(status['CapEff'],16)==1<<13 and status['NoNewPrivs'].strip()=='1'
mac=lambda s:bytes.fromhex(s.replace(':',''))
own=mac(config['mac']);gateway=mac(config['gateway_mac']);fake=own[:-1]+bytes([own[-1]^1]);payload=nonce.encode()
def checksum(data):
 if len(data)%2:data+=b'\0'
 value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
 while value>>16:value=(value&65535)+(value>>16)
 return (~value)&65535
def ipv4(source,dest,body,identity=71,fragment=0):
 header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),identity,fragment,64,17,0,socket.inet_aton(source),socket.inet_aton(dest))
 return header[:10]+struct.pack('!H',checksum(header))+header[12:]+body
def ipv6(source,dest,body,protocol=17,hop=64):
 return struct.pack('!IHBB16s16s',6<<28,len(body),protocol,hop,socket.inet_pton(socket.AF_INET6,source),socket.inet_pton(socket.AF_INET6,dest))+body
source_mac=own;kind=0x800;expect_reply=False;bodies=None
if mode in ('normal4','mac4','spoof4','vlan4','normal4-frag','spoof4-frag'):
 source=config['fake4'] if mode.startswith('spoof4') else config['ipv4'];dest=config['target4']
 udp=struct.pack('!HHHH',40123,19101,8+len(payload),0)+payload
 body=ipv4(source,dest,udp)
 if mode=='mac4':source_mac=fake
 if mode=='vlan4':kind=0x8100;body=struct.pack('!HH',1,0x800)+body
 if mode.endswith('-frag'):
  identity=zlib.crc32(payload)&65535;bodies=[]
  for index in range(3):bodies.extend([ipv4(source,dest,udp[:24],(identity+index)&65535,0x2000),ipv4(source,dest,udp[24:],(identity+index)&65535,3)])
 expect_reply=mode.startswith('normal4')
elif mode in ('normal6','spoof6','normal6-frag','spoof6-frag','normal6-hbh','spoof6-hbh','normal6-dest','spoof6-dest'):
 kind=0x86dd;source=config['fake6'] if mode.startswith('spoof6') else config['ipv6'];dest=config['target6']
 udp=struct.pack('!HHHH',40123,19101,8+len(payload),0)+payload
 pseudo=socket.inet_pton(socket.AF_INET6,source)+socket.inet_pton(socket.AF_INET6,dest)+struct.pack('!I3xB',len(udp),17)
 udp=udp[:6]+struct.pack('!H',checksum(pseudo+udp) or 65535)+udp[8:]
 body=ipv6(source,dest,udp);expect_reply=mode.startswith('normal6')
 if mode.endswith(('-hbh','-dest')):body=ipv6(source,dest,bytes([17,0])+b'\0'*6+udp,0 if mode.endswith('-hbh') else 60)
 if mode.endswith('-frag'):
  identity=zlib.crc32(payload);bodies=[]
  for index in range(3):
   bodies.extend([ipv6(source,dest,struct.pack('!BBHI',17,0,1,(identity+index)&0xffffffff)+udp[:24],44),ipv6(source,dest,struct.pack('!BBHI',17,0,24,(identity+index)&0xffffffff)+udp[24:],44)])
elif mode in ('arp-good','arp-sha','arp-spa'):
 kind=0x806;sender=fake if mode=='arp-sha' else own;source=config['fake4'] if mode=='arp-spa' else config['ipv4']
 body=struct.pack('!HHBBH',1,0x800,6,4,1)+sender+socket.inet_aton(source)+b'\0'*6+socket.inet_aton(config['gateway4'])
 expect_reply=mode=='arp-good'
elif mode in ('ns-good','ns-target','na-option','na-target','na-router','ns-extension','na-extension','na-fragment','ns-hop','ns-code'):
 kind=0x86dd;source=config['ipv6'];dest=config['gateway6'];is_ns=mode.startswith('ns-')
 target=(config['fake6'] if mode in ('ns-target','na-target') else config['gateway6'] if is_ns else config['ipv6'])
 flags=0 if is_ns else 0xe0000000 if mode=='na-router' else 0x60000000
 option=struct.pack('!BB',1 if is_ns else 2,1)+(fake if mode=='na-option' else own)
 icmp=struct.pack('!BBHI',135 if is_ns else 136,1 if mode=='ns-code' else 0,0,flags)+socket.inet_pton(socket.AF_INET6,target)+option
 pseudo=socket.inet_pton(socket.AF_INET6,source)+socket.inet_pton(socket.AF_INET6,dest)+struct.pack('!I3xB',len(icmp),58)
 icmp=icmp[:2]+struct.pack('!H',checksum(pseudo+icmp))+icmp[4:]
 body=ipv6(source,dest,icmp,58,254 if mode=='ns-hop' else 255);expect_reply=mode=='ns-good'
 if mode.endswith('-extension'):body=ipv6(source,dest,bytes([58,0])+b'\0'*6+icmp,0,255)
 if mode=='na-fragment':
  identity=zlib.crc32(payload);bodies=[]
  for index in range(3):
   bodies.extend([ipv6(source,dest,struct.pack('!BBHI',58,0,1,(identity+index)&0xffffffff)+icmp[:24],44,255),ipv6(source,dest,struct.pack('!BBHI',58,0,24,(identity+index)&0xffffffff)+icmp[24:],44,255)])
else:raise ValueError('unknown trusted source diagnostic')
frames=[gateway+source_mac+struct.pack('!H',kind)+part for part in (bodies if bodies is not None else [body]*3)]
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as wire:
 wire.bind(('eth0',0));wire.settimeout(.15)
 for frame in frames:assert wire.send(frame)==len(frame)
 observed=False;deadline=time.monotonic()+(.8 if expect_reply else .25)
 while time.monotonic()<deadline:
  try:data=wire.recv(2048)
  except socket.timeout:continue
  if len(data)<14 or data[:6]!=own:continue
  if mode.startswith('normal') and b'ok:'+payload in data:observed=True;break
  if mode=='arp-good' and len(data)>=42 and data[12:14]==b'\x08\x06' and data[20:22]==b'\x00\x02' and data[28:32]==socket.inet_aton(config['gateway4']):observed=True;break
  if mode=='ns-good' and len(data)>=78 and data[12:14]==b'\x86\xdd' and data[54]==136 and data[62:78]==socket.inet_pton(socket.AF_INET6,config['gateway6']):observed=True;break
print(json.dumps({'mode':mode,'sent_frames':len(frames),'frame_bytes':[len(frame) for frame in frames],'reply':observed,'cap_effective':1<<13,'no_new_privileges':True}))
'''
