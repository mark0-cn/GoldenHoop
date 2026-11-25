"""Zero-capability blocker for an exact owned high TCP DNS port."""
PIN_SOCKET = r'''
import json,socket,sys,threading
endpoint=json.loads(sys.argv[1]);family=socket.AF_INET6 if ':' in endpoint['address'] else socket.AF_INET
listener=socket.socket(family,socket.SOCK_STREAM)
if family==socket.AF_INET6:listener.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
listener.bind((endpoint['address'],endpoint['port']));listener.listen(1)
print(json.dumps({'ready':True,'address':endpoint['address'],'port':listener.getsockname()[1]}),flush=True)
threading.Event().wait()
'''
