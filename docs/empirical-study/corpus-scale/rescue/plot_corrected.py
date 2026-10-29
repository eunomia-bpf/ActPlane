#!/usr/bin/env python3
"""Plot explicitly corrected estimates, retaining exploratory/undefined status."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,read_csv,write_csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
OUT=HERE/'rescue'

def main():
 rows={r['metric']:r for r in read_csv(OUT/'corrected_summary.csv') if r['group_type']=='overall'}
 plt.rcParams.update({'pdf.fonttype':42,'ps.fonttype':42,'font.size':8})
 fig,axes=plt.subplots(2,2,figsize=(6.5,3.6));data=[]
 for ax,(metric,title) in zip(axes.flat,[('system_state_fraction','System-observable / policies'),('context_required_fraction','Context needed / system-observable'),('cross_event_project_share','Projects with cross-event policies'),('os_enforceable_count','OS-tier candidates (count)')]):
  r=rows[metric];ax.set_title(title,fontsize=8);ax.set_yticks([])
  if not r['value'] or not r['ci_low']:
   ax.text(.5,.5,'Correction not identifiable\nor interval unavailable',ha='center',va='center',transform=ax.transAxes);data.append(r);continue
  scale=1 if metric.endswith('_count') else 100
  point,low,high=[float(r[k])*scale for k in ['value','ci_low','ci_high']]
  # A percentile interval need not contain the point estimate.
  ax.plot([low,high],[0,0],color='#2166ac',lw=2);ax.scatter([point],[0],color='#2166ac',s=22,zorder=3)
  ax.set_ylim(-.6,.6)
  if scale==100:ax.set_xlim(0,100);ax.set_xlabel('Corrected prevalence (%)')
  else:ax.set_xlabel('Corrected count')
  label='Exploratory correction' if r['status'].startswith('exploratory') else 'Test-confusion correction'
  if 'simplex_boundary' in r['point_flag']:label+=' (boundary fit)'
  ax.text(.5,.88,label,ha='center',transform=ax.transAxes,fontsize=7,color='#8c2d04' if r['status'].startswith('exploratory') else '#444444')
  data.append(r)
 fig.suptitle('Misclassification-corrected estimates; transfer assumptions unverified\n95% repository-bootstrap intervals',fontsize=9)
 fig.tight_layout(rect=(0,0,1,.94));(OUT/'figures').mkdir(exist_ok=True)
 fig.savefig(OUT/'figures/corrected-prevalence.pdf',bbox_inches='tight');plt.close(fig)
 write_csv(OUT/'corrected_figure_data.csv',data)
if __name__=='__main__':main()
