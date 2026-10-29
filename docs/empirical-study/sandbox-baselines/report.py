#!/usr/bin/env python3
"""Generate the headline table, manuscript paragraph and embedded-font figure."""
import csv
import json
from pathlib import Path
import subprocess
from study import LANE, RAW

OUT=LANE/'results'
def rows(name):
    with (OUT/name).open() as f:return list(csv.DictReader(f))
def main():
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    matplotlib.rcParams.update({'pdf.fonttype':42,'ps.fonttype':42,'font.size':9})
    comparison=rows('comparison.csv')
    tag=Path(rows('per-trace.csv')[0]['raw_dir']).parents[3].name
    if any(r['completed']!=r['planned'] for r in comparison):
        raise RuntimeError('cannot report a partial matrix as complete')
    baseline=[r for r in comparison if not r['system'].startswith('AgPlane') and r['system']!='control']
    agplane=[r for r in comparison if r['system'].startswith('AgPlane')]
    names={'codex':'Codex workspace-write','srt':'SRT standalone defaults',
           'srt-cwd':'SRT cwd-write analogue','docker':'Docker default security'}
    labels=[names[r['system']] for r in baseline]
    figuredata=[]
    for r in baseline:
        figuredata.append(dict(system=r['system'],metric='prevented',numerator=r['prevented'],denominator=r['eligible_effect_pairs']))
        figuredata.append(dict(system=r['system'],metric='new_compliant_denial',numerator=r['false_trigger'],denominator=r['compliant']))
    for r in agplane:
        figuredata.append(dict(system=r['system'],metric='imported_detection',numerator=r['detected'],denominator=r['violations']))
    with (OUT/'figure-data.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(figuredata[0]));w.writeheader();w.writerows(figuredata)
    fig,axs=plt.subplots(1,3,figsize=(11.6,3.15),gridspec_kw={'width_ratios':[1,1,0.8]},layout='constrained')
    for ax,metric,denom,title,color in [
        (axs[0],'prevented','eligible_effect_pairs','Persistent effect / invocation prevented','#2563a3'),
        (axs[1],'false_trigger','compliant','New denial on compliant traces','#c56a27')]:
        vals=[int(r[metric])/int(r[denom])*100 for r in baseline]
        ax.barh(range(len(labels)),vals,color=color)
        ax.set_yticks(range(len(labels)),labels if ax==axs[0] else ['']*len(labels))
        ax.invert_yaxis();ax.set_xlim(0,125);ax.set_xticks([0,50,100],['0%','50%','100%'])
        ax.set_title(title,fontsize=9)
        for i,r in enumerate(baseline):ax.text(vals[i]+2,i,f"{r[metric]}/{r[denom]}",va='center',fontsize=8)
        ax.spines[['top','right']].set_visible(False)
    ax=axs[2]
    vals=[float(r['detection_rate'])*100 for r in agplane]
    ax.barh(range(len(agplane)),vals,color='#549365')
    ax.set_yticks(range(len(agplane)),['Reference','Best translation'])
    ax.invert_yaxis();ax.set_xlim(0,125);ax.set_xticks([0,50,100],['0%','50%','100%'])
    ax.set_title('AgPlane: imported detection only',fontsize=9)
    for i,r in enumerate(agplane):ax.text(vals[i]+2,i,f"{r['detected']}/{r['violations']}",va='center',fontsize=8)
    ax.spines[['top','right']].set_visible(False)
    fig.savefig(OUT/'comparison.pdf',bbox_inches='tight')
    fig.savefig(RAW/'comparison-preview.png',dpi=90,bbox_inches='tight')
    plt.close(fig)
    table=['| System | Metric | Direct | Script | Hidden | Total | Compliant trigger |',
           '| --- | --- | --- | --- | --- | --- | --- |']
    for r in comparison:
        if r['system']=='control':continue
        detection=r['system'].startswith('AgPlane')
        metric='detection (imported)' if detection else 'effect prevention'
        field='detected' if detection else 'prevented'
        cells=[f"{r[fam+'_'+field]}/{r[fam+'_n']}" for fam in ('direct','script','hidden')]
        total=f"{r['detected']}/{r['violations']}" if detection else f"{r['prevented']}/{r['eligible_effect_pairs']}"
        table.append('| '+' | '.join([names.get(r['system'],r['system']),metric,*cells,total,f"{r['false_trigger']}/{r['compliant']}"])+' |')
    table='\n'.join(table)
    control=next(r for r in comparison if r['system']=='control')
    versions={r['component']:r['version'] for r in rows('versions.csv')}
    fidelity=rows('fidelity.csv')
    equal=sum(int(r['tool_inputs_returns_bytes_equal']) for r in fidelity)
    notexact=sum(not int(r['stdout_stderr_equal']) for r in fidelity)
    best=agplane[1]['system'].replace('AgPlane ','')
    codex=next(r for r in baseline if r['system']=='codex')
    srt=next(r for r in baseline if r['system']=='srt')
    docker=next(r for r in baseline if r['system']=='docker')
    paragraph=(f"We evaluate shipping OS sandbox configurations on {control['planned']} frozen RQ2 traces, using the same tool-effect replayer and repository fixtures as the translation study. "
        f"Against {control['eligible_effect_pairs']} violations with an observable unrestricted-control effect, Codex workspace-write prevents {codex['prevented']}, standalone Anthropic SRT prevents {srt['prevented']}, and default Docker prevents {docker['prevented']}. "
        f"They introduce access-denial errors on {codex['false_trigger']}, {srt['false_trigger']}, and {docker['false_trigger']} of {control['compliant']} compliant traces, respectively. "
        "Standalone SRT's read-only workspace differs from the cwd-write policy of an enabled Claude Code sandbox, which we report separately. "
        f"AgPlane's reference and best translated rules detect {agplane[0]['detected']} and {agplane[1]['detected']} of {agplane[0]['violations']} labeled violations in the prior notification-mode replay. "
        "Detection and prevention are distinct measurements. These author-generated traces measure persistent file effects and prohibited invocations, not agent recovery or general prompt-injection resistance.")
    if len(paragraph.split())>150:raise ValueError('paper paragraph exceeds requested word limit')
    readme=f'''# Official-default sandbox baselines

{table}

Source: [comparison.csv](results/comparison.csv), generated by `analyze.py`.
All planned traces completed for every configuration. Prevention denominators
condition on a prohibited persistent file effect or invocation actually observed
in the matched unrestricted control. Of the labeled violation traces,
{control['control_effect_absent']} have no control effect and
{control['control_effect_unknown']} have an unknown effect. They remain in
[exclusions.csv](results/exclusions.csv), not in prevention denominators.
The imported AgPlane rows use all labeled traces and measure notification
detection, not prevented effects. The best translation is `{best}`, selected
by full-trace F1 from the frozen upstream summary. This is a retrospective
best-of-models row, not held-out model selection.

## Configuration and provenance

- Codex: `{versions['codex']}`. Empty experiment-specific CODEX_HOME,
  `codex sandbox -c 'sandbox_mode="workspace-write"' -- ...` with default
  network off. Its actual Linux implementation uses bubblewrap and seccomp,
  rather than the historical Landlock implementation mentioned in the request.
  The site wrapper is bypassed to avoid changing shared authentication/config.
- Anthropic standalone SRT: `{versions['srt']}`. No settings file, no network
  allowlist, no added workspace-write grant. This is not Claude Code's default:
  Claude Code sandboxing is off by default, and its enabled harness supplies
  cwd-write grants. `srt-cwd.json` is a separate documented-mechanism analogue,
  not the exact interactive Claude policy or a per-rule tuned upper bound.
  Its fixed `/tmp/repo` grant leaves the trace's outside-workspace temporary
  log paths restricted. This can suppress script preparation.
- Docker: `{versions['docker']}` with a digest-pinned Debian userspace image.
  No privilege, capability, network, seccomp or AppArmor overrides during runs.
  Bind mounts supply the checkout and read-only replay inputs plus audit output.
  The image installs workload tools, not policy. Build-time host networking was
  needed because nested default-bridge DNS failed; runtime bridge remains default.
  No claim about network-access coverage follows from these offline traces.

See [versions.csv](results/versions.csv), [configurations.csv](results/configurations.csv),
[docker-image.json](results/docker-image.json), and [replayer-hashes.csv](results/replayer-hashes.csv).
Official sources: [Codex permissions](https://learn.chatgpt.com/docs/permissions),
[Codex security](https://learn.chatgpt.com/docs/agent-approvals-security),
[SRT source and defaults](https://github.com/anthropics/sandbox-runtime),
[Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing),
[Docker default seccomp](https://docs.docker.com/engine/security/seccomp/).
The installed package/source snapshots, rather than moving web pages, define the run.

## Replayer and outcome semantics

The vendor files are copied byte-for-byte from the translation-models lane.
`study.py` executes the original worker's environment/tool/output AST nodes
without changing them. Namespace setup, fixture installation and synchronization
are outside the sandbox. This is an explicit execution adapter, not a claim
that the original coordinator runs inside every sandbox unchanged. The original
worker is also replayed on every trace as a fidelity control. Tool inputs,
return codes and Read byte counts match on {equal} of {len(fidelity)} traces.
Full JSON outputs differ on {notexact} traces; inspect [fidelity.csv](results/fidelity.csv)
and the raw tool logs for timing, commit identifiers and other output differences.
All code runs inside actplane-dev, never on Windows.

Every trace starts from a fresh selected fixture archive at `/tmp/repo`.
The new sandbox runs use the Workspace filesystem, while the imported AgPlane
run used guest-local tmpfs and a guest kernel. Both share trace bytes, fixture
archive hashes and tool-effect implementation; kernel/filesystem environments
are not identical. No BPF engine is loaded in the new sandbox measurements.

The original corpus has labels but no independent executable effect checker.
[effect_oracle.py](effect_oracle.py) therefore maps frozen trace targets to
filesystem hashes/existence, Git refs/index, or successful prohibited execve
invocations. [ORACLE.md](ORACLE.md) defines this unavoidable task-specific
observation. It is not a general semantic verifier. Public disclosure is
unknown because the original harness uses safety shims. Final hashes miss
transient writes that are later reverted. A prohibited invocation is observed
at exec, not inferred to have finished successfully.

False triggers for new sandboxes mean **new tool-visible access-denial errors**
on compliant traces relative to control. AgPlane false triggers mean policy
notifications. These are related collateral-restriction measurements, not
identical internal decisions. The full exact returned errors appear in
[errors.csv](results/errors.csv). Return status alone never establishes effect
prevention. These results do not test whether agents become confused by errors.

## Reproduce and files

From PowerShell, use the supplied wrapper:

```powershell
& "C:\\Program Files\\Git\\bin\\bash.exe" C:/Users/10678/actplane-tools/ws.sh run sandbox-baselines --bg -- bash setup.sh
& "C:\\Program Files\\Git\\bin\\bash.exe" C:/Users/10678/actplane-tools/ws.sh run sandbox-baselines --bg -- bash run.sh
& "C:\\Program Files\\Git\\bin\\bash.exe" C:/Users/10678/actplane-tools/ws.sh run sandbox-baselines -- python3 report.py
```

`setup.sh` installs the version-pinned SRT package and builds the image.
`run.sh` runs all cells and regenerates the CSVs, resuming completed cells.
Raw outputs: `/workspaces/exp/sandbox-baselines/raw/{tag}/`.
Each cell retains payload, exact command, before/after manifests, tool results,
syscall log and execution status. Docker syscall observation runs inside its
default security boundary without extra privileges. `attempts.csv` preserves
failed preflight attempts and the final run. Preflight adapter failures and the
initial Docker build DNS failure are not policy successes.

Committed result files include per-trace outcomes, exclusions, original-replayer
fidelity, exact access errors, imported AgPlane records, versions/configuration,
aggregate data and [comparison.pdf](results/comparison.pdf). The figure uses
Matplotlib with embedded TrueType fonts (`pdf.fonttype=42`), and separates
effect prevention from imported detection.

## Paper paragraph

{paragraph}
'''
    (LANE/'README.md').write_text(readme)
    summary=f'''# Lane summary

Measured official default Codex workspace-write, standalone Anthropic SRT,
and Docker security configurations, plus a separately labeled SRT cwd-write
analogue. Reused the translation lane's traces, fixtures and unchanged tool
replay code. All baseline configurations reached terminal replay outcomes.

{table}

These are different metric types: baseline rows measure control-validated
persistent effect/prohibited-invocation prevention, AgPlane rows are imported
notification detections. Read conditional denominators and compliant collateral
denials together. The result supports resource-boundary versus action-policy
coverage on this corpus, not general sandbox failure or measured agent confusion.

Main files: README.md, results/comparison.csv, results/per-trace.csv,
results/errors.csv, results/exclusions.csv, results/fidelity.csv,
results/agplane-import.csv, results/comparison.pdf. Scripts and source/config
snapshots are in this lane. Large raw outputs remain under
`/workspaces/exp/sandbox-baselines/raw/`.

Open caveats: author-generated corpus, safe shims instead of real public
disclosure, persistent-effect oracle scope, imported guest kernel/filesystem
differences, SRT standalone versus Claude enabled-policy distinction, and nested
Docker bridge DNS. Optional gVisor and injection-bench availability are recorded
in results/optional-lanes.csv; neither blocks this matrix. No paper changes,
pushes, model scaling or tuned per-rule policies were performed.
'''
    (LANE/'SUMMARY.md').write_text(summary)
    print(table)
    print('paper paragraph words',len(paragraph.split()))

if __name__=='__main__':main()
