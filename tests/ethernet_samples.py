"""Narrow trusted NET_RAW diagnostics, separate from the cap-zero workload."""
RAW = r'''
import json,os,socket,sys,time
mode,token,peer=sys.argv[1:4]
status=dict(line.split(':',1) for line in open('/proc/self/status') if line.startswith(('CapEff:','CapPrm:','NoNewPrivs:')))
assert int(status['CapEff'],16)==int(status['CapPrm'],16)==1<<13 and status['NoNewPrivs'].strip()=='1'
request=(token+'\n').encode().ljust(64,b'\0');reply=(b'ok:'+token.encode()+b'\n').ljust(64,b'\0')
protocol=b'\x88\xb5'
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88b5)) as wire:
 wire.bind(('eth0',0));wire.settimeout(.2);own=wire.getsockname()[4]
 identity={'uid':os.getuid(),'cap_effective':int(status['CapEff'],16),'no_new_privileges':status['NoNewPrivs'].strip()=='1','mac':own.hex(':')}
 if mode=='server':
  print(json.dumps({'ready':True,**identity}),flush=True)
  while True:
   try:frame=wire.recv(512)
   except socket.timeout:continue
   if len(frame)>=78 and frame[:6]==own and frame[12:14]==protocol and frame[14:78]==request:
    wire.send(frame[6:12]+own+protocol+reply)
 elif mode=='client':
  target=bytes.fromhex(peer.replace(':',''));frame=target+own+protocol+request
  for _ in range(3):assert wire.send(frame)==len(frame)
  deadline=time.monotonic()+1.2;received=False
  while time.monotonic()<deadline:
   try:frame=wire.recv(512)
   except socket.timeout:continue
   if len(frame)>=78 and frame[:6]==own and frame[6:12]==target and frame[12:14]==protocol and frame[14:78]==reply:
    received=True;break
  print(json.dumps({'ok':received,'sent_frames':3,'ether_type':0x88b5,**identity}),flush=True)
 else:raise ValueError('unknown trusted diagnostic mode')
'''
