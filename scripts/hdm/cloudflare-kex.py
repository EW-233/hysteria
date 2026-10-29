"""创建独立的 KEX 实验 DNS/Worker；管理凭据始终保留在本机，不复用旧 WSS 资源。"""
import argparse,json,secrets
from pathlib import Path
import requests

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser()
p.add_argument('action',choices=['dns','prepare','deploy','status'])
p.add_argument('--proxy')
p.add_argument('--origin',default='kex-origin.kkbk.info')
p.add_argument('--secrets',type=Path,default=Path.home()/'.codex/secrets/hdm-cloudflare')
a=p.parse_args()
c=json.loads((a.secrets/'credentials.json').read_text(encoding='utf-8'))
s=requests.Session()
s.headers['Authorization']='Bearer '+c['apiToken']
if a.proxy:s.proxies={'https':a.proxy}
statefile=a.secrets/'kex-state.json'
state=json.loads(statefile.read_text(encoding='utf-8')) if statefile.exists() else {}
base='https://api.cloudflare.com/client/v4'
def api(method,path,**kw):
    r=s.request(method,base+path,timeout=40,**kw)
    try:b=r.json()
    except ValueError:raise SystemExit('Cloudflare returned non-JSON HTTP '+str(r.status_code))
    if not r.ok or not b.get('success'):
        raise SystemExit('Cloudflare HTTP '+str(r.status_code)+' error codes '+str([x.get('code') for x in b.get('errors',[])]))
    return b.get('result')
def save():
    statefile.write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8')
zone=api('GET','/zones',params={'name':'kkbk.info'})
if len(zone)!=1:raise SystemExit('Expected one authorized zone')
zid=zone[0]['id'];account=c['accountId']
origin=state.get('origin',a.origin) if a.action!='prepare' else a.origin;host='kex.kkbk.info';name='hy2-kex-poc'
if a.action=='prepare':
    if origin not in ['kex-origin.kkbk.info','186-241-106-13.sslip.io']:raise SystemExit('Unexpected experiment origin')
    state.update(origin=origin,workerHost=host,workerName=name,zoneId=zid)
    for key in ['clientToken','upstreamToken']:
        if key not in state:state[key]=secrets.token_hex(32)
    save();print('Prepared private experiment state for:',origin)
elif a.action=='dns':
    records=api('GET','/zones/'+zid+'/dns_records',params={'name':origin})
    if records:
        if len(records)!=1 or records[0]['type']!='A' or records[0]['content']!='186.241.106.13' or records[0].get('proxied'):
            raise SystemExit('Existing origin DNS differs; refusing overwrite')
        record=records[0]
    else:record=api('POST','/zones/'+zid+'/dns_records',json={'type':'A','name':origin,'content':'186.241.106.13','ttl':120,'proxied':False,'comment':'HY2 external-handshake experiment'})
    state.update(origin=origin,originRecordId=record['id'],workerHost=host,workerName=name,zoneId=zid)
    for key in ['clientToken','upstreamToken']:
        if key not in state:state[key]=secrets.token_hex(32)
    save();print('Prepared DNS-only origin:',origin)
elif a.action=='deploy':
    if state.get('origin')!=origin:raise SystemExit('Prepare DNS first')
    metadata={'main_module':'worker.mjs','compatibility_date':'2026-10-28','bindings':[
        {'type':'plain_text','name':'UPSTREAM_HOST','text':origin},
        {'type':'plain_text','name':'UPSTREAM_PORT','text':'18443'},
        {'type':'plain_text','name':'TIMEOUT_MS','text':'8000'},
        {'type':'secret_text','name':'CLIENT_TOKEN','text':state['clientToken']},
        {'type':'secret_text','name':'UPSTREAM_TOKEN','text':state['upstreamToken']}]}
    files={'metadata':(None,json.dumps(metadata),'application/json')}
    for module in ['worker.mjs','relay.mjs']:
        files[module]=(module,(ROOT/'extras/worker-kex'/module).read_bytes(),'application/javascript+module')
    api('PUT','/accounts/'+account+'/workers/scripts/'+name,files=files)
    domains=api('GET','/accounts/'+account+'/workers/domains')
    match=[d for d in domains if d.get('hostname')==host]
    if match and any(d.get('service')!=name for d in match):raise SystemExit('Existing Worker hostname belongs to another service')
    if not match:api('PUT','/accounts/'+account+'/workers/domains',json={'hostname':host,'service':name,'environment':'production','zone_id':zid})
    state['endpoint']='https://'+host+'/k';save();print('Deployed isolated KEX Worker:',state['endpoint'])
else:
    print('Origin:',state.get('origin','not prepared'))
    print('Endpoint:',state.get('endpoint','not deployed'))
