#!/usr/bin/env python3
"""Generate deterministic, entirely synthetic DNS and proxy teaching logs (offline)."""
import csv, random
from datetime import datetime, timedelta, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; (ROOT/'data').mkdir(exist_ok=True)
rng=random.Random(202605)
start=datetime(2026,10,5,8,0,tzinfo=timezone.utc)
normal=['asterpay.example','login.asterpay.example','cityparcel.example','portal.cityparcel.example','docs.example','mail.example','updates.example','news.example']
benign=['asterpay-help.example','cityparcel-archive.example']
suspicious=['asterpay-verify-login.example','cityparcel-track-secure.example','asterpay-account-review.example','cityparcel-delivery-confirm.example']
ips={d:f'192.0.2.{10+i}' for i,d in enumerate(normal)}
ips.update({'asterpay-help.example':'198.51.100.10','cityparcel-archive.example':'198.51.100.11'})
ips.update({'asterpay-verify-login.example':'203.0.113.50','cityparcel-track-secure.example':'203.0.113.50','asterpay-account-review.example':'203.0.113.60','cityparcel-delivery-confirm.example':'203.0.113.60'})
rows=[]
for i in range(900):
    domain=rng.choices(normal+benign,weights=[16,9,11,5,12,13,10,8,2,2])[0]
    rows.append([f'DNS-{i+1:04}',(start+timedelta(seconds=35*i)).isoformat(),'WS-%02d'%(1+rng.randrange(12)),domain,ips[domain], 'NOERROR','baseline', 'true'])
for j,(domain,host,n) in enumerate([(suspicious[0],'WS-03',14),(suspicious[1],'WS-03',9),(suspicious[2],'WS-07',12),(suspicious[3],'WS-09',8)]):
    for k in range(n):
        i=len(rows)+1
        rows.append([f'DNS-{i:04}',(start+timedelta(hours=2+j,seconds=60*k)).isoformat(),host,domain,ips[domain],'NOERROR','planted-candidate','true'])
rows.sort(key=lambda x:x[1]);
with (ROOT/'data'/'dns.csv').open('w',newline='') as f:
    w=csv.writer(f);w.writerow(['event_id','timestamp','hostname','domain','answer_ip','rcode','scenario_label','synthetic']);w.writerows(rows)
proxy=[]
for j,(domain,host,path,method) in enumerate([(suspicious[0],'WS-03','/signin','GET'),(suspicious[0],'WS-03','/session','POST'),(suspicious[1],'WS-03','/track','GET'),(suspicious[2],'WS-07','/review','GET'),(suspicious[3],'WS-09','/track','GET')]):
    proxy.append([f'PROXY-{j+1:03}',(start+timedelta(hours=2+j//2,minutes=j*3)).isoformat(),host,domain,method,path, 420 if method=='POST' else 0,'true'])
for j in range(55):
    d=rng.choice(normal)
    proxy.append([f'PROXY-{j+6:03}',(start+timedelta(seconds=480*j)).isoformat(),'WS-%02d'%(1+rng.randrange(12)),d,'GET','/',0,'true'])
with (ROOT/'data'/'proxy.csv').open('w',newline='') as f:
    w=csv.writer(f);w.writerow(['event_id','timestamp','hostname','domain','method','url_path','bytes_out','synthetic']);w.writerows(proxy)
print(f'Generated {len(rows)} DNS and {len(proxy)} proxy synthetic events')
