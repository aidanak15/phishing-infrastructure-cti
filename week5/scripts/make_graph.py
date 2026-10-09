from pathlib import Path
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
root=Path(__file__).resolve().parents[1]
d=json.loads((root/'results/hunt_results.json').read_text())
fig,ax=plt.subplots(figsize=(12,5))
clusters=d['h3_shared_ips']
for idx,group in enumerate(clusters):
    x=idx*5
    ax.scatter([x+2],[1.0],s=1450,marker='s')
    ax.text(x+2,1,group['ip'],ha='center',va='center',fontsize=10,color='white')
    for off,name in enumerate(group['domains']):
        xx=x+0.4+off*3.2
        ax.scatter([xx],[3],s=950)
        ax.plot([xx,x+2],[2.85,1.2],linestyle='-',alpha=.7)
        ax.text(xx,3.42,name,fontsize=9,ha='center',rotation=0)
ax.set_xlim(-1,9.5);ax.set_ylim(.3,4);ax.axis('off')
ax.set_title('Synthetic shared-IP phishing infrastructure leads (not real threats)',fontsize=13)
fig.tight_layout();fig.savefig(root/'images/infrastructure_graph.png',dpi=150,bbox_inches='tight');plt.close(fig)
print('Saved synthetic infrastructure graph')
