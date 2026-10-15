"""Owned Linux acceptance: real gateway/core/ingress; no installed client or live account."""
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(os.environ['UPSTREAM_REVIEW_ROOT']).resolve()
RUNTIME = Path(os.environ.get('UPSTREAM_REVIEW_RUNTIME', str(ROOT/'runtime'))).resolve()
RUNTIME.mkdir(parents=True,exist_ok=True)
MIHOMO = Path(os.environ.get('MIHOMO_BINARY',str(RUNTIME/'mihomo'))).resolve()
AGENT = Path(os.environ.get('UPSTREAM_BINARY',str(RUNTIME/'upstream-agent'))).resolve()
V2BX = Path(os.environ.get('V2BX_BINARY',str(ROOT/'v2bx-test'))).resolve()
if not all(p.is_file() for p in [MIHOMO,AGENT,V2BX]):
    raise RuntimeError('Supply the pinned Mihomo, gateway and V2bX/Xray binaries')
processes = []
servers = []
state = {'revision':1, 'enabled':True, 'source':'', 'selector':'', 'report':{}, 'fail_panel':False,'revoked':False,
         'users':[{'id':101,'uuid':'11111111-2222-4333-8444-555555555555','speed_limit':0,'device_limit':0},
                  {'id':102,'uuid':'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee','speed_limit':0,'device_limit':0}],
         'traffic':{}, 'subscription':b'', 'source_requests':0}
result = {}

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def wait(condition, timeout=35):
    deadline = time.monotonic()+timeout
    while time.monotonic()<deadline:
        if condition(): return
        time.sleep(.2)
    raise AssertionError('Timed out waiting for acceptance condition; report='+json.dumps(state['report']))

def reachable(p):
    try:
        with socket.create_connection(('127.0.0.1',p),timeout=.3): return True
    except OSError: return False

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def send(self,data,code=200):
        if isinstance(data,(dict,list)): data=json.dumps(data).encode();content='application/json'
        else: content='application/octet-stream'
        self.send_response(code);self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(data)));self.end_headers()
        if data:
            try:self.wfile.write(data)
            except (BrokenPipeError,ConnectionResetError):pass
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path).path
        if path=='/sub': state['source_requests']+=1;return self.send(state['subscription'])
        if path.endswith('/Upstream/config'):
            if state['revoked']:return self.send({},403)
            if state['fail_panel']:return self.send({},503)
            return self.send({'data':{'id':1,'revision':state['revision'],'enabled':state['enabled'],'source':state['source'],'selector':state['selector'],'refresh_interval':300}})
        if path.endswith('/UniProxy/config'):
            return self.send({'server_port':entry_port,'host':'127.0.0.1','network':'tcp','network_settings':{},'tls':0,'routes':[],
                              'base_config':{'push_interval':1,'pull_interval':1}})
        if path.endswith('/UniProxy/user'):return self.send({'users':state['users']})
        if path.endswith('/UniProxy/alivelist'):return self.send({'alive':{}})
        if path=='/204':return self.send(b'',204)
        if path.startswith('/bytes/'):
            return self.send(b'x'*int(path.rsplit('/',1)[1]))
        return self.send(b'',404)
    def do_POST(self):
        data=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))) or b'{}')
        if '/Upstream/report' in self.path:state['report']=data
        if '/UniProxy/push' in self.path:
            for uid,pair in data.items():
                old=state['traffic'].setdefault(uid,[0,0]);old[0]+=pair[0];old[1]+=pair[1]
        self.send({'data':True})

def http_server(cert=None,key=None):
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    if cert:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert,key);context.set_alpn_protocols(['http/1.1'])
        server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
    return server.server_port

def start(args,logfile,env=None):
    log=open(logfile,'wb')
    proc=subprocess.Popen([str(a) for a in args],stdout=log,stderr=log,env=env);log.close();processes.append(proc)
    return proc

def core(name,config):
    directory=work/name;directory.mkdir();file=directory/'config.json';file.write_text(json.dumps(config))
    return start([MIHOMO,'-d',directory,'-f',file],work/(name+'.log'))

def request(p,path='/204',timeout=6):
    return subprocess.run(['curl','--silent','--show-error','--noproxy','','--proxy',f'http://127.0.0.1:{p}',
        '--max-time',str(timeout),'-o','/dev/null','-w','%{http_code}:%{size_download}',f'http://127.0.0.1:{target_port}{path}'],capture_output=True,text=True,timeout=timeout+2)

def ready(revision):
    return state['report'].get('status')=='ready' and state['report'].get('applied_revision')==revision

def receive(sock,n):
    data=b''
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part:raise AssertionError('SOCKS control connection closed')
        data+=part
    return data

def udp_request(proxy_port):
    with socket.create_connection(('127.0.0.1',proxy_port),timeout=4) as control:
        control.sendall(b'\x05\x01\x00');assert receive(control,2)==b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01'+b'\x00'*6)
        reply=receive(control,4);assert reply[:2]==b'\x05\x00'
        if reply[3]==1:address=socket.inet_ntoa(receive(control,4))
        elif reply[3]==3:address=receive(control,receive(control,1)[0]).decode()
        else:address=socket.inet_ntop(socket.AF_INET6,receive(control,16))
        destination=struct.unpack('!H',receive(control,2))[0]
        if address=='0.0.0.0':address='127.0.0.1'
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            payload=b'gateway-udp-acceptance'
            packet=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',echo.getsockname()[1])+payload
            udp.sendto(packet,(address,destination));reply,_=udp.recvfrom(4096)
            assert reply.endswith(payload)

def echo_loop():
    while True:
        try:
            data,address=echo.recvfrom(4096);echo.sendto(data,address)
        except OSError:return

try:
    work=Path(tempfile.mkdtemp(prefix='chain-',dir=RUNTIME))
    echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind(('127.0.0.1',0))
    threading.Thread(target=echo_loop,daemon=True).start()
    cert,key=work/'cert.pem',work/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
                    '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    target_port=http_server();tls_port=http_server(cert,key);panel_port=http_server();entry_port=port();relay_port=port()
    mieru_port=port();vless_port=port()
    keys=subprocess.check_output([str(MIHOMO),'generate','reality-keypair'],text=True)
    pairs={line.split(':',1)[0].strip().lower():line.split(':',1)[1].strip() for line in keys.splitlines() if ':' in line}
    private=next(v for k,v in pairs.items() if 'private' in k);public=next(v for k,v in pairs.items() if 'public' in k)
    upstream=core('upstream',{'log-level':'warning','listeners':[
        {'name':'mieru','type':'mieru','listen':'127.0.0.1','port':mieru_port,'transport':'TCP','users':{'fixture':'fixture-password'}},
        {'name':'reality','type':'vless','listen':'127.0.0.1','port':vless_port,'users':[{'username':'fixture','uuid':state['users'][0]['uuid'],'flow':'xtls-rprx-vision'}],
         'reality-config':{'dest':f'127.0.0.1:{tls_port}','private-key':private,'short-id':['0123456789abcdef'],'server-names':['localhost']}}],
        'rules':['MATCH,DIRECT']})
    wait(lambda:reachable(mieru_port) and reachable(vless_port))
    mieru={'name':'trial','type':'mieru','server':'127.0.0.1','port':mieru_port,'transport':'TCP','username':'fixture','password':'fixture-password','udp':True}
    state['subscription']=json.dumps({'proxies':[mieru],'rules':['MATCH,DIRECT']}).encode()
    state['source']=f'https://localhost:{tls_port}/sub'
    config={'panel_url':f'http://127.0.0.1:{panel_port}','upstream_id':1,'token':'a'*64,'mihomo':str(MIHOMO),
            'listen':f'127.0.0.1:{relay_port}','state_dir':str(work/'agent-state'),'probe_url':f'http://127.0.0.1:{target_port}/204','allow_private_sources':True}
    cfg=work/'agent.json';cfg.write_text(json.dumps(config));cfg.chmod(0o600)
    agent=start([AGENT,'-config',cfg],work/'agent.log',dict(os.environ,SSL_CERT_FILE=str(cert)))
    wait(lambda:ready(1));assert request(relay_port,'/bytes/65536').stdout=='200:65536'
    result['https_subscription_mieru_tcp']=True;print('Mieru HTTPS subscription and forwarding passed',flush=True)
    udp_request(relay_port);result['mieru_udp']=True
    old_pid=list((work/'agent-state').glob('core-*'))
    state['revision']=2;wait(lambda:ready(2));assert old_pid==list((work/'agent-state').glob('core-*'))
    result['unchanged_update_keeps_core']=True
    state['subscription']=b'proxies: [broken';state['revision']=3
    wait(lambda:state['report'].get('revision')==3 and state['report'].get('status')=='error')
    assert request(relay_port).stdout=='204:0';result['invalid_update_retains_last_good']=True
    reality=f"vless://{state['users'][0]['uuid']}@127.0.0.1:{vless_port}?security=reality&type=tcp&flow=xtls-rprx-vision&sni=localhost&fp=chrome&pbk={public}&sid=0123456789abcdef#reality"
    state['subscription']=base64.b64encode(reality.encode());state['revision']=4
    wait(lambda:ready(4));assert request(relay_port,'/bytes/131072').stdout=='200:131072'
    result['base64_vless_reality_tcp']=True;print('VLESS Reality subscription switch passed',flush=True)
    udp_request(relay_port);result['vless_reality_udp']=True
    state['enabled']=False;state['revision']=5
    wait(lambda:state['report'].get('status')=='disabled')
    assert request(relay_port).returncode!=0;result['disabled_fails_closed']=True
    state['enabled']=True;state['revision']=6;wait(lambda:ready(6))
    agent.kill();agent.wait(timeout=5)
    agent=start([AGENT,'-config',cfg],work/'agent-restart.log',dict(os.environ,SSL_CERT_FILE=str(cert)))
    state['report']={};wait(lambda:ready(6));assert request(relay_port).stdout=='204:0'
    result['forced_restart_recovers']=True
    duplicate=start([AGENT,'-config',cfg],work/'duplicate.log')
    assert duplicate.wait(timeout=5)!=0;result['duplicate_instance_rejected']=True
    started=time.monotonic();state['fail_panel']=True;time.sleep(6)
    assert request(relay_port).stdout=='204:0'
    wait(lambda:request(relay_port).stdout!='204:0',timeout=75)
    result['panel_outage_revoked_seconds']=round(time.monotonic()-started,2)
    state['report']={};state['fail_panel']=False
    wait(lambda:ready(6) and request(relay_port).stdout=='204:0')
    result['panel_recovery_reauthorizes']=True
    state['revoked']=True
    wait(lambda:request(relay_port).stdout!='204:0',timeout=15)
    state['report']={};state['revoked']=False
    wait(lambda:ready(6) and request(relay_port).stdout=='204:0')
    result['token_revocation_and_recovery']=True
    print('Authorization lease, recovery and instance lock passed',flush=True)
    if V2BX.exists():
        shutil.copyfile(V2BX,work/'v2bx');(work/'v2bx').chmod(0o700)
        out=work/'outbound.json';out.write_text(json.dumps([{'tag':'upstream','protocol':'socks','settings':{'servers':[{'address':'127.0.0.1','port':relay_port}]}}]))
        route=work/'route.json';route.write_text(json.dumps({'domainStrategy':'AsIs','rules':[{'type':'field','network':'tcp,udp','outboundTag':'upstream'}]}))
        vc=work/'v2bx.json';vc.write_text(json.dumps({'Log':{'Level':'warning'},'Cores':[{'Type':'xray','OutboundConfigPath':str(out),'RouteConfigPath':str(route)}],
            'Nodes':[{'ApiHost':f'http://127.0.0.1:{panel_port}','ApiKey':'fixture','NodeID':7,'NodeType':'vless','Core':'xray','ListenIP':'127.0.0.1','ReportMinTraffic':0,'CertConfig':{'CertMode':'none'}}]}))
        ingress=start([work/'v2bx','server','-c',vc],work/'v2bx.log');wait(lambda:reachable(entry_port))
        clients=[]
        for n,user in enumerate(state['users']):
            p=port();clients.append(p)
            core('client'+str(n),{'mixed-port':p,'bind-address':'127.0.0.1','allow-lan':False,'log-level':'warning',
                'proxies':[{'name':'entry','type':'vless','server':'127.0.0.1','port':entry_port,'uuid':user['uuid'],'udp':True}], 'rules':['MATCH,entry']})
            wait(lambda:reachable(p))
        assert request(clients[0],'/bytes/65536').stdout=='200:65536'
        assert request(clients[1],'/bytes/131072').stdout=='200:131072'
        udp_request(clients[1]);result['v2bx_ingress_udp']=True
        wait(lambda:state['traffic'].get('101',[0,0])[1]>=65536 and state['traffic'].get('102',[0,0])[1]>=131072)
        result['two_users_separate_counters']=True
        state['users']=[state['users'][1]];time.sleep(3)
        assert request(clients[0]).stdout!='204:0' and request(clients[1]).stdout=='204:0'
        result['single_user_revocation']=True
        state['users'][0]['speed_limit']=1;time.sleep(3)
        started=time.monotonic();r=request(clients[1],'/bytes/524288',timeout=12);elapsed=time.monotonic()-started
        assert r.stdout=='200:524288' and elapsed>=2.5,(r.stdout,elapsed)
        result['per_user_speed_limit_seconds']=round(elapsed,2)
        print('Real V2bX users, accounting, revocation and speed limit passed',flush=True)
    else:result['v2bx_ingress']='not-run: binary unavailable'
    upstream.terminate();upstream.wait(timeout=5)
    assert request(relay_port).stdout!='204:0';result['no_direct_fallback']=True
    result['source_https_requests']=state['source_requests'];result['passed']=True
finally:
    for proc in reversed(processes):
        if proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    for server in servers:server.shutdown();server.server_close()
    if 'echo' in globals():echo.close()
    result['owned_processes_stopped']=all(p.poll() is not None for p in processes)
    result['private_artifacts']=str(work)
    (ROOT/'chain-result.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result),flush=True)
