#!/usr/bin/env python3
"""Independent local validation; NOT Splunk/Elastic execution."""
import csv,json,collections
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name):
    with (ROOT/'data'/name).open(newline='') as f:return list(csv.DictReader(f))
dns=load('dns.csv');proxy=load('proxy.csv')
known={'asterpay.example','cityparcel.example'}
def official(d):return any(d==x or d.endswith('.'+x) for x in known)
def keyword(d):return any(k in d for k in ['asterpay','cityparcel'])
leads=[r for r in dns if keyword(r['domain']) and not official(r['domain'])]
bydomain=collections.defaultdict(list)
for r in leads:bydomain[r['domain']].append(r)
result={'dataset':{'dns_events':len(dns),'proxy_events':len(proxy),'unique_dns_ids':len({r['event_id'] for r in dns}),'unique_proxy_ids':len({r['event_id'] for r in proxy}),'distinct_dns_hosts':len({r['hostname'] for r in dns})},'h1_candidates':[{'domain':d,'dns_requests':len(a),'hosts':sorted({x['hostname'] for x in a}),'answer_ips':sorted({x['answer_ip'] for x in a})} for d,a in sorted(bydomain.items())],'h2_post_candidates':[{'domain':p['domain'],'hostname':p['hostname'],'url_path':p['url_path'],'bytes_out':int(p['bytes_out'])} for p in proxy if p['method']=='POST' and p['domain'] in bydomain], 'h3_shared_ips':[]}
byip=collections.defaultdict(set)
for x in result['h1_candidates']:
    for ip in x['answer_ips']:byip[ip].add(x['domain'])
result['h3_shared_ips']=[{'ip':ip,'domains':sorted(ds)} for ip,ds in sorted(byip.items()) if len(ds)>1]
(ROOT/'results').mkdir(exist_ok=True)
(ROOT/'results'/'hunt_results.json').write_text(json.dumps(result,indent=2)+'\n')
for k,v in result.items():print(k,':',v)
