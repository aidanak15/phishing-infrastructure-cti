import csv,json
from pathlib import Path
r=Path(__file__).resolve().parents[1]
with (r/'data/dns.csv').open() as f:dns=list(csv.DictReader(f))
with (r/'data/proxy.csv').open() as f:proxy=list(csv.DictReader(f))
a=json.loads((r/'results/hunt_results.json').read_text())
assert len(dns)==943 and len(proxy)==60
assert len({x['event_id'] for x in dns})==943
assert a['dataset']['distinct_dns_hosts']==12
assert len(a['h1_candidates'])==6
assert sum(x['dns_requests'] for x in a['h1_candidates'])==86
assert len(a['h2_post_candidates'])==1
assert len(a['h3_shared_ips'])==2
assert all(x['synthetic']=='true' for x in dns+proxy)
print('PASS: 943 DNS, 60 proxy, 12 hosts, 6 candidates, 1 POST, 2 shared IP clusters; all synthetic')
