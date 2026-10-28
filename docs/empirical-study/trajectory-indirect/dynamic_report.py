#!/usr/bin/env python3
"""Render the dynamic section and figure strictly from committed CSV inputs."""
import csv
from pathlib import Path
import statistics

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from analyze import HERE,write_csv
from dynamic_effects import PROFILE_HELPER_BASENAMES


def read(name):return list(csv.DictReader((HERE/name).open()))
def number(value):return float(value) if value!='' else 0.
def pct(value):
    if value=='':return 'n/a'
    value=number(value)
    if 99.99<value<100:return '>99.99%'
    if 0<value<.01:return '<0.01%'
    return f'{value:.2f}%'


def render():
    if not (HERE/'dynamic_summary.csv').exists():return '',None
    summaries=read('dynamic_summary.csv');replays=read('dynamic_replays.csv');plans=read('dynamic_plan.csv')
    overall=next(r for r in summaries if (r['framework'],r['model'],r['classification'])==('ALL','ALL','ALL'))
    overall.setdefault('any_unnamed_effect_calls_pct',100*int(overall['any_unnamed_effect_calls'])/int(overall['recorded_calls']))
    overall.setdefault('any_unnamed_effect_trajectories','pending')
    model_rows=[r for r in summaries if r['framework']!='ALL' and r['classification']=='ALL']
    sensitivities=read('dynamic_sensitivity.csv')
    filtered=next(r for r in sensitivities if (r['framework'],r['model'],r['classification'])==('ALL','ALL','ALL'))
    n=len(replays);planned=len(plans);interim=n<planned
    observer_errors=sum(int(r['observer_errors']) for r in replays)
    metrics=[dict(metric='completed_replay_receipts',value=n),dict(metric='planned_replays',value=planned),
             dict(metric='distinct_replayed_tasks',value=len(set(r['instance_id'] for r in replays))),
             dict(metric='total_recorded_calls',value=overall['recorded_calls']),dict(metric='total_executed_calls',value=overall['executed_calls']),
             dict(metric='setup_failed_steps',value=sum(int(r['setup_failed_steps']) for r in replays)),
             dict(metric='fatal_replays',value=sum(bool(r['fatal']) for r in replays)),
             dict(metric='observer_errors',value=sum(int(r['observer_errors']) for r in replays)),
             dict(metric='call_success_pct',value=100*int(overall['successful_calls'])/int(overall['recorded_calls'])),
             dict(metric='call_executed_pct',value=100*int(overall['executed_calls'])/int(overall['recorded_calls'])),
             dict(metric='strict_path_unnamed_write_pct',value=100*int(overall['strict_unnamed_write_events'])/int(overall['write_events']) if int(overall['write_events']) else ''),
             dict(metric='strict_path_unnamed_exec_pct',value=100*int(overall['strict_unnamed_exec_events'])/int(overall['exec_events']) if int(overall['exec_events']) else '')]
    metrics.extend([dict(metric='profile_helper_basename_count',value=len(PROFILE_HELPER_BASENAMES)),
                    dict(metric='profile_helper_excluded_exec_events',value=filtered['excluded_exec_events']),
                    dict(metric='without_profile_helpers_unnamed_exec_pct',value=filtered['unnamed_exec_events_pct'])])
    call_rows=read('dynamic_calls.csv')
    metrics.extend([dict(metric='excluded_dispatcher_execs',value=sum(int(r['dispatcher_execs']) for r in call_rows)),
                    dict(metric='excluded_patch_helper_execs',value=sum(int(r.get('shim_helper_execs',0)) for r in call_rows)),
                    dict(metric='failed_exec_attempts',value=sum(int(r['failed_exec_attempts']) for r in call_rows))])
    if (HERE/'dynamic_resource_samples.csv').exists():
        resource=read('dynamic_resource_samples.csv')
        measured=[int(r['raw_bytes']) for r in resource if r['raw_bytes']]
        metrics.extend([dict(metric='sampled_raw_bytes_max',value=max(measured) if measured else ''),
                        dict(metric='sampled_workspace_used_pct_max',value=max(number(r['workspace_used_pct']) for r in resource)),
                        dict(metric='resource_snapshots',value=len(resource))])
    write_csv(HERE/'dynamic_report_metrics.csv',metrics)
    vals={r['metric']:r['value'] for r in metrics}
    scopes=read('dynamic_scope_summary.csv')
    project=[r for r in scopes if r['framework']=='ALL' and r['effect']=='write' and r['path_scope'] in ('project_other','project_generated')]
    project_objects=sum(int(r['call_object_pairs']) for r in project)
    project_unnamed=sum(int(r['unnamed_call_object_pairs']) for r in project)
    project_pct=100*project_unnamed/project_objects if project_objects else 0
    nongenerated=[r for r in project if r['path_scope']=='project_other']
    nongenerated_objects=sum(int(r['call_object_pairs']) for r in nongenerated)
    nongenerated_unnamed=sum(int(r['unnamed_call_object_pairs']) for r in nongenerated)
    nongenerated_pct=100*nongenerated_unnamed/nongenerated_objects if nongenerated_objects else ''
    metrics.extend([dict(metric='project_write_call_object_pairs',value=project_objects),
                    dict(metric='project_unnamed_write_call_object_pairs',value=project_unnamed),
                    dict(metric='project_unnamed_write_call_object_pct',value=project_pct),
                    dict(metric='nongenerated_project_write_call_object_pairs',value=nongenerated_objects),
                    dict(metric='nongenerated_project_unnamed_write_call_object_pairs',value=nongenerated_unnamed),
                    dict(metric='nongenerated_project_unnamed_write_call_object_pct',value=nongenerated_pct)])
    balanced=[]
    if (HERE/'dynamic_trajectory_summary.csv').exists():
        per_trajectory=read('dynamic_trajectory_summary.csv')
        for effect in ('write','exec'):
            for unit in ('events','objects'):
                values=[number(r[f'unnamed_{effect}_{unit}_pct']) for r in per_trajectory if r[f'unnamed_{effect}_{unit}_pct']!='']
                median=statistics.median(values) if values else ''
                metrics.extend([dict(metric=f'trajectory_median_unnamed_{effect}_{unit}_pct',value=median),
                                dict(metric=f'trajectories_with_{effect}_{unit}',value=len(values))])
                balanced.append((effect,unit,median,len(values)))
    write_csv(HERE/'dynamic_report_metrics.csv',metrics)

    plt.rcParams.update({'pdf.fonttype':42,'ps.fonttype':42,'font.size':9,'font.family':'DejaVu Sans'})
    fig,(ax,bx)=plt.subplots(1,2,figsize=(10.8,4.2),gridspec_kw={'width_ratios':[1.2,1]})
    labels=[r['framework']+' / '+r['model'] for r in model_rows]
    y=np.arange(len(model_rows))
    ax.barh(y-.16,[number(r['unnamed_write_object_pct']) for r in model_rows],height=.30,color='#7658A5',label='Writes')
    ax.barh(y+.16,[number(r['unnamed_exec_object_pct']) for r in model_rows],height=.30,color='#4C78A8',label='Execs')
    ax.set_yticks(y,labels);ax.invert_yaxis();ax.set_xlim(0,100)
    ax.set_xlabel('Unnamed distinct (call, object) pairs (%)')
    ax.legend(loc='lower center',bbox_to_anchor=(.5,1.02),frameon=False,ncol=2)
    classes=[r for r in summaries if r['framework']=='ALL' and r['classification']!='ALL']
    yc=np.arange(len(classes))
    bx.barh(yc-.16,[number(r['unnamed_write_object_pct']) for r in classes],height=.30,color='#7658A5')
    bx.barh(yc+.16,[number(r['unnamed_exec_object_pct']) for r in classes],height=.30,color='#4C78A8')
    bx.set_yticks(yc,[r['classification'].replace('_',' ') for r in classes]);bx.invert_yaxis();bx.set_xlim(0,100)
    bx.set_xlabel('Unnamed distinct (call, object) pairs (%)')
    for axis,rows in ((ax,model_rows),(bx,classes)):
        for i,row in enumerate(rows):
            for offset,effect in ((-.16,'write'),(.16,'exec')):
                if row['unnamed_'+effect+'_object_pct']=='':
                    axis.text(1,i+offset,'n/a',va='center',fontsize=7,color='#666666')
    for axis in (ax,bx):
        axis.spines[['top','right']].set_visible(False);axis.grid(axis='x',alpha=.18);axis.set_axisbelow(True)
    fig.subplots_adjust(left=.28,right=.98,bottom=.18,top=.84,wspace=.42)
    if interim or observer_errors:
        fig.suptitle('INTERIM: incomplete sample or instrumentation retry pending',fontsize=9,y=1.01)
    fig.savefig(HERE/'dynamic_effects.pdf',metadata={'CreationDate':None,'ModDate':None},bbox_inches='tight')
    fig.savefig(HERE/'dynamic_effects.png',dpi=180,bbox_inches='tight');plt.close(fig)

    table='| Replayed framework / recorded model | Traj. | Recorded calls | Executed | Exit zero | Unnamed write events | Unnamed exec events |\n|---|---:|---:|---:|---:|---:|---:|\n'
    for r in model_rows:
        table+=f"| {r['framework']} / {r['model']} | {r['trajectories']} | {r['recorded_calls']} | {r['executed_calls']} | {r['successful_calls']} | {pct(r['unnamed_write_pct'])} | {pct(r['unnamed_exec_pct'])} |\n"
    sensitivity_table='| Cohort | Excluded execs | Remaining execs | Remaining unnamed execs | Unnamed exec fraction | Call-level precision | Call-level recall |\n|---|---:|---:|---:|---:|---:|---:|\n'
    for r in sensitivities:
        if r['classification']!='ALL':continue
        label='Overall' if r['framework']=='ALL' else r['framework']+' / '+r['model']
        sensitivity_table+=f"| {label} | {r['excluded_exec_events']} | {r['exec_events']} | {r['unnamed_exec_events']} | {pct(r['unnamed_exec_events_pct'])} | {100*number(r['precision']):.1f}% | {100*number(r['recall']):.1f}% |\n"
    class_table='| Static primary class | Calls | Write events | Unnamed writes | Exec events | Unnamed execs |\n|---|---:|---:|---:|---:|---:|\n'
    for r in summaries:
        if r['framework']!='ALL' or r['classification']=='ALL':continue
        class_table+=f"| {r['classification']} | {r['recorded_calls']} | {int(r['write_events']):,} | {pct(r['unnamed_write_pct'])} | {int(r['exec_events']):,} | {pct(r['unnamed_exec_pct'])} |\n"
    scope_table='| Observed file-write location | Write operations | Unnamed operations | Distinct (call, file) pairs | Unnamed pairs |\n|---|---:|---:|---:|---:|\n'
    for r in scopes:
        if r['framework']!='ALL' or r['effect']!='write':continue
        scope_table+=f"| {r['path_scope']} | {int(r['events']):,} | {pct(r['unnamed_pct'])} | {int(r['call_object_pairs']):,} | {pct(r['unnamed_call_object_pct'])} |\n"
    confusions=read('dynamic_confusion.csv')
    confusion_table='| Call denominator | Calls | TP | FP | FN | TN | Precision | Recall |\n|---|---:|---:|---:|---:|---:|---:|---:|\n'
    for r in confusions:
        confusion_table+=f"| {r['scope']} | {r['calls']} | {r['true_positive']} | {r['false_positive']} | {r['false_negative']} | {r['true_negative']} | {100*number(r['precision']):.1f}% | {100*number(r['recall']):.1f}% |\n"
    model_confusion_table='| Replayed framework / model | Calls | TP | FP | FN | Precision | Recall |\n|---|---:|---:|---:|---:|---:|---:|\n'
    for r in read('dynamic_model_confusion.csv'):
        model_confusion_table+=f"| {r['framework']} / {r['model']} | {r['calls']} | {r['true_positive']} | {r['false_positive']} | {r['false_negative']} | {100*number(r['precision']):.1f}% | {100*number(r['recall']):.1f}% |\n"
    balanced_table='| Effect | Weighting within trajectory | Trajectories with effects | Median unnamed fraction |\n|---|---|---:|---:|\n'
    for effect,unit,median,count in balanced:
        balanced_table+=f'| {effect} | {unit} | {count} | {pct(median)} |\n'
    status=f'**Interim: {n} of {planned} planned replay receipts are available.**' if interim else f'**Final fixed sample: {n} replayed trajectories across {len(model_rows)} recorded model groups and {len(set(r["framework"] for r in model_rows))} frameworks.**'
    if observer_errors:status+=' **Observer errors remain. Effect tables are diagnostics pending instrumentation retries.**'
    paragraph=(f"Tool-call arguments do not enumerate every effect of coding-agent execution. We analyzed {sum(int(r['calls']) for r in read('summary.csv')):,} public tool calls "
               f"and replayed {n} trajectories under eBPF observation. In these best-effort replays, {pct(overall['unnamed_write_pct'])} of captured regular-file write operations "
               f"and {pct(overall['unnamed_exec_pct'])} of successful execs lacked a matching literal basename or explicit glob in the initiating arguments. "
               f"Excluding known replay shell-profile helper names leaves {pct(filtered['unnamed_exec_events_pct'])} unnamed execs. "
               f"Outside conventional generated/build/cache paths, {pct(nongenerated_pct)} of distinct project call-file pairs were unnamed. "
               f"The replay attempted {int(overall['executed_calls']):,} calls, with {100*int(overall['successful_calls'])/int(overall['recorded_calls']):.1f}% exiting zero. "
               "These observations motivate enforcement where effects occur. Minimal environments and substitute edit tools limit transfer to original deployments, and unnamed effects do not imply policy violations.")
    if interim:paragraph='Preliminary results. '+paragraph
    if observer_errors:
        paragraph=(f'Dynamic validation is in progress. The current {n} replay receipts contain {observer_errors} observer errors. '
                   'Paper-ready quantitative replay claims are withheld until the same affected trajectories have been replayed with corrected instrumentation. '
                   'All earlier attempts remain recorded, and no sampled task is replaced based on command or setup success.')
    assert len(paragraph.split())<=150
    text=f"""## Dynamic replay validation

{status} The [fixed plan](dynamic_plan.csv) was selected by a committed hash ranking, paired by task within each source. It includes exact base commits recovered from pinned task metadata. No task was replaced based on replay success. Recorded calls are replayed in order against a fresh checkout in a private local PID/mount namespace. Shell command strings remain as recorded. Dedicated edits are implemented as direct file writes by the committed adapter. The coordinator, environment setup, and injected dispatchers are excluded from observed effects. No oracle or verifier patches are applied. [dynamic_metadata_manifest.csv](dynamic_metadata_manifest.csv) records pinned metadata versions, task-archive hashes, and license caveats. The pinned SWE-bench Verified card does not state a dataset license, and no separate native task-data license was verified. Derived tables, brief call previews, and source locators are committed, while full task archives and transcripts stay external and third-party source terms remain applicable.

Across the available receipts, the observer recorded **{int(overall['write_events']):,} successful regular-file write operations**, of which **{pct(overall['unnamed_write_pct'])} were unnamed**, and **{int(overall['exec_events']):,} successful execs**, of which **{pct(overall['unnamed_exec_pct'])} were unnamed**. At least one unnamed write or exec was observed for **{overall["any_unnamed_effect_calls"]} of {overall["recorded_calls"]} recorded calls ({pct(overall["any_unnamed_effect_calls_pct"])})**. The count of trajectories with an observed unnamed effect is **{overall["any_unnamed_effect_trajectories"]}**. These pooled event totals are affected by large installations. Counting each distinct `(call, object)` pair once gives **{pct(overall['unnamed_write_object_pct'])} unnamed write pairs** and **{pct(overall['unnamed_exec_object_pct'])} unnamed exec pairs**. Unresolved/truncated object paths are kept in the denominator and separately counted: {overall['unknown_write_events']} write events and {overall['unknown_exec_events']} exec events. The reported unnamed fractions therefore use the lower endpoint for unresolved names.

An object in these tables is a kernel-resolved regular-file path for writes or the requested executable pathname of a successful exec syscall. It is not an inode or a unique process. Executable aliases, symlinks, and interpreter loading are not expanded into additional exec effects. To avoid weighting trajectories by installation volume, the following medians give each trajectory with the relevant captured effects equal weight. Trajectories with no captured effect of that kind have an undefined fraction and remain in the call/fidelity denominators. [dynamic_trajectory_summary.csv](dynamic_trajectory_summary.csv) contains every replay receipt.

{balanced_table}

{table}
These are effects observed during replays of recorded trajectories, not original OS telemetry. {overall['failed_calls']} calls exited nonzero and {overall['timed_out_calls']} timed out. All recorded calls in completed receipts remain in denominators, including unexecuted calls after a fatal replay error. There are {vals['fatal_replays']} fatal replay receipts and {vals['setup_failed_steps']} failed setup steps, including failed initial steps later recovered by a fallback. Nonzero commands can still produce effects, which are counted. Exit zero means command completion, not agreement with original test outcomes or task resolution. [dynamic_fidelity.csv](dynamic_fidelity.csv) cross-tabulates source-reported status and replay outcome, retaining unavailable source statuses. The source of each failure and original/replayed call statuses are retained in [dynamic_calls.csv](dynamic_calls.csv), [dynamic_replays.csv](dynamic_replays.csv), and external command logs. The observer error count is {vals['observer_errors']}. A nonzero observer error count invalidates complete-census claims and must be resolved before treating a final sample as complete.

### Visibility definition and measured operations

A write targets a named object if its literal basename occurs as a standalone token anywhere in the original argument values, or if a visible shell-style glob matches it. Executable basenames permit PATH resolution. Inline source and editor content count as argument values. This deliberately liberal rule can match a same-named object in another directory, so it is conservative about declaring effects unnamed. A directory name alone does not enumerate descendants. [dynamic_effects.py](dynamic_effects.py) also retains strict full/relative-path matching as a sensitivity result. String truncation is classified as unresolved, rather than unnamed. An `exec` is a successful execve/execveat, not a fork. The injected dispatcher is tracked separately, and the supplied patch shim's injected Python exec is removed one-for-one from its observed helper exec count.

The eBPF observer follows tagged thread lineages using initial-namespace kernel thread IDs and resolves regular-file paths at `security_file_permission`. It counts successful VFS scalar, vectored, positioned, copied, sendfile, and clone writes. It separately records explicit VFS truncations. It excludes pipes/sockets and does not claim a census of every filesystem mutation: empty-file creation, namespace operations, memory-mapped dirtying, and some asynchronous/offloaded paths can be missed. The primary percentages concern the captured positive-byte regular-file write operations and successful execs. The first harness exec is excluded. [dynamic_calibration.csv](dynamic_calibration.csv) checks observed scalar/vector/positioned/copy/truncate/descendant behavior inside an isolated namespace. [dynamic_preflight.csv](dynamic_preflight.csv) and the `dynamic_pilot_*` CSVs retain development failures, including map overflow and a shared-cache pilot. Those pilot observations are excluded from the fixed private-cache sample. A later negative preallocation/stdout check exposed stale path attribution. File-identity guards corrected it. All earlier private-cache attempts are retained in `dynamic_diagnostic_v1_*` and excluded, and the unchanged fixed cohort was restarted with the corrected observer. [dynamic_verification.csv](dynamic_verification.csv) checks that published replay receipts share the corrected observer hash, cover the planned calls, and reconcile with raw map counts.

### Calls labeled indirect versus direct

{class_table}
The physical validation target is a call with at least one observed unnamed write or exec. `indirect` is the positive prediction. All other primary classes are negative, including the separately reported inline-code class. The tables distinguish all recorded calls, executed calls, exit-zero calls, effects-producing calls, and the subset labeled indirect or a direct mutation. Thus command failures are visible in the main denominator, rather than being silently discarded. Precision and recall are descriptive for this replay and visibility definition.

{confusion_table}

{model_confusion_table}

### Shell-profile sensitivity

The preserved recorded login-shell wrappers source this replay host's profile. Its `/etc/profile` executes `id` and `run-parts` ([dynamic_profile_audit.csv](dynamic_profile_audit.csv) records source hashes and matching line locations), which explains observed unnamed execs even for some read-only command bodies. These are real effects of the replayed wrapper, while the original deployment's profile is unavailable. The post-hoc filename-filter sensitivity below removes every exec whose basename is `id` or `run-parts`, whether named or unnamed. It can therefore also remove genuine project/helper executions and is not a causal origin classifier. Primary write counts are unchanged, primary exec counts retain these effects, and primary static predictions are never retuned. [dynamic_sensitivity.csv](dynamic_sensitivity.csv) and per-call helper counters retain the filter accounting.

{sensitivity_table}
[dynamic_confusion.csv](dynamic_confusion.csv) also reports unresolved truth counts and corresponding precision/recall bounds. A failed or unexecuted call is not evidence that the original deployment had no indirect effect. Unsupported tool substitution, dependency failures, malformed normalized commands, different runtime versions, SCM-derived version labels from shallow history, time limits, and initial environment differences limit transfer to original executions.

### Working-tree and cache effects

{scope_table}
`project_generated` identifies conventional generated/build/cache components, including Git metadata, bytecode, virtual environments, node_modules, target, build, and dist. `project_other` covers remaining files below the project root. These are path conventions, not an intent or security judgment. Both rows are included in the project-tree fraction. Package-cache and environment writes are genuine replay effects but can dominate pooled counts. Private per-trajectory caches prevent a preceding model's replay from warming a later one. Instrumentation failures, including long-path buffer errors, trigger a retained full-sequence retry of the same task with a larger buffer. Command or setup failures alone do not trigger this instrumentation procedure. Separately, initial Astropy environment trials exposed isolated-build setuptools incompatibility and GCC 14 rejecting legacy C signatures. The primary mini cohort uses the same recorded legacy build dependencies, a no-build-isolation fallback, and GCC/G++ 12. Earlier completed or interrupted environment trials remain in `environment-attempts/` and the attempt ledger. Setup changes never apply oracle patches. [dynamic_attempts.csv](dynamic_attempts.csv) accounts for primary and excluded attempts, while [dynamic_replays.csv](dynamic_replays.csv) records the actual path-buffer size of each primary attempt. Setup effects are excluded. Disposable runtime trees are removed after source commits, command receipts, freeze records, final diffs, and observer data are saved. Full per-call object records are in the external `dynamic/effects.jsonl.gz`; [dynamic_effect_sample.csv](dynamic_effect_sample.csv) gives hash-ranked examples balanced across static class, effect kind, and path scope.

[dynamic_effects.pdf](dynamic_effects.pdf) compares distinct call-object fractions by model group and static class, with embedded TrueType fonts. [dynamic_report_metrics.csv](dynamic_report_metrics.csv) records report totals. The cohort is a paired, descriptive sample with best-effort environments, not a causal comparison of models or frameworks. [dynamic_evidence_manifest.csv](dynamic_evidence_manifest.csv) hashes retained metadata, call receipts, command logs, and observer evidence. [dynamic_host_environment.csv](dynamic_host_environment.csv) records local tool versions and analysis-source hashes.

"""
    return text,paragraph


if __name__=='__main__':
    section,paragraph=render()
    if section:(HERE/'dynamic_section.md').write_text(section)
    if paragraph:(HERE/'dynamic_paper_paragraph.txt').write_text(paragraph+'\n')
