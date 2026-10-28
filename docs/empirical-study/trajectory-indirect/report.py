#!/usr/bin/env python3
"""Generate the figure, headline CSV, and README from committed analysis CSVs."""
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from analyze import HERE, CLASSES, write_csv
from dynamic_report import render as render_dynamic


def read(name):
    return list(csv.DictReader((HERE/name).open()))


def main():
    summaries=read('summary.csv')
    trajectories=read('trajectories.csv')
    resources=read('resources.csv')[0]
    frameworks=sorted(set(r['framework'] for r in summaries))
    total_calls=sum(int(r['calls']) for r in summaries)
    total_traj=sum(int(r['trajectories']) for r in summaries)
    per_framework=defaultdict(list)
    for row in trajectories:
        per_framework[row['framework']].append(row)
    headline=[]
    for framework,rows in sorted(per_framework.items()):
        n=len(rows)
        calls=sum(int(r['calls']) for r in rows)
        headline.append(dict(framework=framework,trajectories=n,calls=calls,
                             indirect_calls=sum(int(r['indirect']) for r in rows),
                             indirect_calls_pct=100*sum(int(r['indirect']) for r in rows)/calls,
                             any_indirect_pct=100*sum(int(r['any_indirect']) for r in rows)/n,
                             any_author_then_execute_pct=100*sum(int(r['any_author_then_execute']) for r in rows)/n,
                             any_create_then_execute_pct=100*sum(int(r['any_create_then_execute']) for r in rows)/n))
    write_csv(HERE/'headline.csv',headline)
    indirect=sum(int(r['indirect']) for r in summaries)
    zero=sum(int(r['calls'])==0 for r in trajectories)
    unknown=sum(int(r['unknown']) for r in summaries)
    parser_errors=sum(int(r['parser_errors']) for r in summaries)
    failures=sum(int(r['failed_calls']) for r in summaries)
    missing_status=sum(int(r['unknown_status_calls']) for r in summaries)
    nebius_pool=sum(int(r['population_rows']) for r in read('dataset_manifest.csv') if r['source']=='nebius')
    native_rows=sum(int(r['sampled_rows']) for r in read('dataset_manifest.csv') if r['source']=='native')
    sample_rows=len(read('sample_calls.csv'))
    methods=[dict(metric=k,value=v) for k,v in dict(total_trajectories=total_traj,total_calls=total_calls,
             frameworks=len(frameworks),model_groups=len(summaries),indirect_calls=indirect,
             unknown_calls=unknown,shell_parser_errors=parser_errors,zero_call_trajectories=zero,
             failed_calls=failures,unknown_status_calls=missing_status,nebius_sample_pool=nebius_pool,
             nebius_shards=2,nebius_per_model_cap=1000,mini_per_model=200,native_sample_rows=native_rows,
             native_run=0,classification_sample_rows=sample_rows,classes=len(CLASSES),
             validation_framework_strata=len(frameworks),validation_per_framework_prediction_stratum=10,
             validation_target_calls=100,request_concurrency=4,annotation_attempt_limit=3,
             figure_pdf_fonttype=42,paragraph_limit_words=150,validation_confidence_pct=95).items()]
    write_csv(HERE/'method_metrics.csv',methods)
    labels=[]
    for row in summaries:
        model=row['model'].replace('swe-agent-','').replace('unattributed GPT-4o / Claude-3.5-Sonnet mixture','unattributed expert mixture')
        labels.append(row['framework']+' / '+model)
    colors={'direct_edit':'#4C78A8','context_edit':'#9EC1DF','direct_shell':'#59A14F','indirect':'#7658A5',
            'inline_code':'#F2B447','read_only':'#D9D9D9','unknown':'#D96D6D'}
    names={'direct_edit':'Explicit-path editor','context_edit':'Context editor','direct_shell':'Named shell mutation',
           'indirect':'Indirect execution','inline_code':'Inline code (separate)','read_only':'Read/control','unknown':'Unclassified'}
    plt.rcParams.update({'pdf.fonttype':42,'ps.fonttype':42,'font.size':9,'font.family':'DejaVu Sans'})
    fig,(ax,bx)=plt.subplots(1,2,figsize=(12.5,4.8),gridspec_kw={'width_ratios':[1.25,1]},sharey=True)
    y=np.arange(len(summaries))
    left=np.zeros(len(summaries))
    for category in CLASSES:
        values=np.array([float(r[category+'_pct']) for r in summaries])
        ax.barh(y,values,left=left,color=colors[category],label=names[category],height=.65)
        left+=values
    ax.set_yticks(y,labels)
    ax.invert_yaxis()
    ax.set_xlabel('Share of recorded calls / action slots (%)')
    ax.set_xlim(0,100)
    bx.scatter([float(r['any_indirect_pct']) for r in summaries],y,color=colors['indirect'],marker='o',label='Any indirect execution',s=34)
    bx.scatter([float(r['any_author_then_execute_pct']) for r in summaries],y,color='#222222',marker='x',label='Observed write then execute',s=34)
    bx.set_xlim(-3,103)
    bx.set_xlabel('Share of sampled trajectories (%)')
    bx.legend(loc='lower center',bbox_to_anchor=(.5,1.01),fontsize=8,frameon=False)
    for axis in (ax,bx):
        axis.spines[['top','right']].set_visible(False)
        axis.grid(axis='x',alpha=.18)
        axis.set_axisbelow(True)
    handles,legend_labels=ax.get_legend_handles_labels()
    fig.legend(handles,legend_labels,ncol=4,loc='lower center',bbox_to_anchor=(.55,.01),frameon=False,fontsize=8)
    fig.subplots_adjust(left=.34,right=.98,top=.90,bottom=.24,wspace=.12)
    fig.savefig(HERE/'indirect_execution.pdf',metadata={'CreationDate':None,'ModDate':None},bbox_inches='tight')
    fig.savefig(HERE/'indirect_execution.png',dpi=180,bbox_inches='tight')
    plt.close(fig)

    def table(rows):
        text='| Framework / recorded model | Traj. | Calls | Indirect calls | Any indirect | Write then execute | Explicit create then execute |\n|---|---:|---:|---:|---:|---:|---:|\n'
        for r in rows:
            text+=f"| {r['framework']} / {r['model']} | {int(r['trajectories']):,} | {int(r['calls']):,} | {float(r['indirect_pct']):.1f}% | {float(r['any_indirect_pct']):.1f}% | {float(r['any_author_then_execute_pct']):.1f}% | {float(r['any_create_then_execute_pct']):.1f}% |\n"
        return text
    lowest_call=min(float(r['indirect_pct']) for r in summaries)
    highest_call=max(float(r['indirect_pct']) for r in summaries)
    lowest_traj=min(float(r['any_indirect_pct']) for r in summaries)
    highest_traj=max(float(r['any_indirect_pct']) for r in summaries)
    paragraph=(f"Indirect execution is common in public coding-agent trajectories. In a reproducible sample of {total_traj:,} trajectories from {len(frameworks)} frameworks "
               f"covering {len(summaries)} recorded model groups, static analysis identified script, module, build, test, or package execution in {lowest_traj:.1f}% to {highest_traj:.1f}% of trajectories per group. "
               f"These calls account for {lowest_call:.1f}% to {highest_call:.1f}% of recorded calls within a group, excluding inline programs from the indirect category. "
               "We also observed agents executing files they had written earlier, including within a combined shell call. "
               "Such calls expose an entrypoint without enumerating the objects that its execution may affect, motivating enforcement at the operating-system boundary. "
               "These measurements characterize recorded execution patterns, rather than the fraction of actual file writes or process creations whose targets are absent from tool arguments.")
    assert len(paragraph.split())<=150
    methods.append(dict(metric='paper_paragraph_words',value=len(paragraph.split())))
    write_csv(HERE/'method_metrics.csv',methods)
    validation='The blinded annotation run is pending. Treat the static classifications as preliminary until `validation_summary.csv` is present.\n'
    if (HERE/'validation_summary.csv').exists():
        vals={r['metric']:float(r['value']) for r in read('validation_summary.csv')}
        attempts=read('annotation_attempts.csv')
        failed_attempts=sum(r['status']=='failed' for r in attempts)
        methods.extend([dict(metric='annotation_attempts',value=len(attempts)),dict(metric='annotation_failed_attempts',value=failed_attempts)])
        write_csv(HERE/'method_metrics.csv',methods)
        lo=vals['predicted_indirect_weighted_both_indirect']
        hi=vals['predicted_indirect_weighted_either_indirect']
        radius=vals['predicted_indirect_hoeffding_95_radius']
        validation=f"""[validation_labels.csv](validation_labels.csv) contains independent labels from `qwen3.8-27b-nvfp4` and `zai/glm-5.3-flash`, using the exact prompt in [validation_prompt.txt](validation_prompt.txt). Model identities were verified by model listing and response fields. Each rater saw the full tool arguments and working-directory/editor context, without heuristic labels, heuristic reasons, feedback, or the other rater's output. We froze a deterministic sample of {int(vals['calls'])} calls: equal samples of {int(vals['predicted_indirect_sample_calls'])} predicted-indirect calls and {int(vals['other_sample_calls'])} other calls, with {10} calls in each framework-by-prediction stratum. The classifier's primary labels were frozen before annotations, and subsequent author-history changes did not alter that sample or its class predictions.

The raters agreed on the full label for {100*vals['seven_way_agreement']:.1f}% of calls (Cohen's kappa {vals['seven_way_kappa']:.3f}) and on indirect versus other for {100*vals['binary_agreement']:.1f}% (kappa {vals['binary_kappa']:.3f}). For predicted-indirect calls, population-stratum-weighted agreement with each rater was {100*vals['predicted_indirect_weighted_rater_a_indirect']:.1f}% and {100*vals['predicted_indirect_weighted_rater_b_indirect']:.1f}%. The two-rater consensus envelope for this operational precision is {100*lo:.1f}% to {100*hi:.1f}%. Allowing stratified sampling uncertainty gives a conservative simultaneous confidence envelope of {100*max(0,lo-radius):.1f}% to {100*min(1,hi+radius):.1f}% at the {95}% level using stratified Hoeffding bounds. This is agreement with model judgments, not a bound on physical side-effect visibility or shared model errors. [validation_confusion.csv](validation_confusion.csv) retains all disagreements. The run used {len(attempts)} attempts, including {failed_attempts} unsuccessful attempts, all retained in [annotation_attempts.csv](annotation_attempts.csv). No majority adjudication or heuristic tuning to these answers was performed.
"""
    validation+='The reviewed disagreements include read-only grep pipelines dispatched by xargs and a malformed nested-shell command whose intended Java compilation/execution was recognizable to both raters. The conservative xargs rule can therefore count read-only dispatch as indirect, while strict shell parsing can miss intended project execution. The spot check does not validate the separate write-history/authorship metric.\n'
    dynamic_section,dynamic_paragraph=render_dynamic()
    if dynamic_paragraph:
        paragraph=dynamic_paragraph
        for metric in methods:
            if metric['metric']=='paper_paragraph_words':metric['value']=len(paragraph.split())
        write_csv(HERE/'method_metrics.csv',methods)
    origin_table='| Framework / recorded model | Any project/module/runner entrypoint | Any script with no recovered earlier write |\n|---|---:|---:|\n'
    for r in summaries:
        origin_table+=f"| {r['framework']} / {r['model']} | {float(r['any_project_runner_pct']):.1f}% | {float(r['any_no_prior_write_script_pct']):.1f}% |\n"
    quality_text=''
    if (HERE/'trajectory_quality.csv').exists():
        quality=read('trajectory_quality.csv')
        quality_text='For comparison, the following shares require success evidence for an indirect call or for the execution after a recovered earlier write. They still do not establish OS side effects. SWE-agent shell feedback often lacks an exit code, so its success-conditioned rates can be lower through missing status alone. Explicit tool statuses and recorded exit codes take precedence over text heuristics.\n\n'
        quality_text+='| Framework / recorded model | Distinct known task IDs | Any indirect call with success evidence | Any execution with success evidence after recovered write |\n|---|---:|---:|---:|\n'
        for r in quality:
            no_success=int(r['successful_indirect_calls'])==0 and int(r['unknown_status_indirect_calls'])>0
            success='not recorded' if no_success else f"{float(r['any_successful_indirect_pct']):.1f}%"
            author='not recorded' if no_success else f"{float(r['any_successful_author_pct']):.1f}%"
            known=r['distinct_known_instance_ids'] if int(r['distinct_known_instance_ids']) else 'unavailable'
            quality_text+=f"| {r['framework']} / {r['model']} | {known} | {success} | {author} |\n"
        quality_text+='\n[trajectory_quality.csv](trajectory_quality.csv) also records unavailable instance identities, repeated known instance IDs, and repeated recovered action sequences. These rows are retained. Identical recovered actions do not necessarily imply identical source trajectories, especially where ambiguous source actions yielded unknown arguments. Because shard sampling can concentrate repeated attempts on a small set of tasks, [task_balanced_summary.csv](task_balanced_summary.csv) provides a sensitivity analysis that gives each known task equal weight. Call shares are averaged across per-task call shares, while trajectory flags are averaged within task before averaging across tasks. Task identity is unavailable for the SFT mixture, so its task-balanced fields are blank. [verification.csv](verification.csv) records successful cross-checks of source file hashes, adapter coverage, per-call locators, trajectory and group totals, and the frozen validation predictions.\n'
    text=f"""# Indirect execution in public coding-agent trajectories

**Measured:** static execution patterns in {total_traj:,} trajectories and {total_calls:,} recorded tool calls/action slots from {len(frameworks)} frameworks and {len(summaries)} recorded model groups. **Not measured:** the fraction of actual file mutations or process executions whose targets are missing from tool arguments. There was no dynamic replay, so this study cannot supply that OS-event denominator.

## Results

{table(summaries)}
Every call percentage uses all recorded calls/action slots in its group. The remaining columns use all sampled trajectories, including the {zero} trajectory with no extracted calls. `Write then execute` includes a statically recovered earlier write to the exact normalized execution path, including ordered commands in the same call. It includes modifications of existing scripts, so it must not be described as the rate of newly authored scripts. The narrower creation column requires a dedicated create or add-file editor operation in an earlier call. Generic write tools, redirects, and `open(..., 'w')` can overwrite files and do not establish that a file was new. The column therefore undercounts new scripts and is a source-specific proxy.

The complete class shares and counts are in [summary.csv](summary.csv), with all trajectory counts in [trajectories.csv](trajectories.csv), framework aggregates in [headline.csv](headline.csv), and a stratified per-call sample of {sample_rows} rows in [sample_calls.csv](sample_calls.csv). [indirect_execution.pdf](indirect_execution.pdf) uses embedded TrueType fonts (`pdf.fonttype={42}`), and [indirect_execution.png](indirect_execution.png) provides a preview.

## Sources, licenses, and sampling

The pinned releases, file hashes, compressed bytes, declared licenses, and sample sizes are in [dataset_manifest.csv](dataset_manifest.csv). [sources.json](sources.json) is the sampling configuration. Pins are content revisions, and every downloaded data file has a SHA-256 checksum. S3 objects are not version-addressed, so reproduction must check their recorded hashes rather than assume that the experiment-repository pin freezes them.

- [Nebius SWE-agent](https://huggingface.co/datasets/nebius/SWE-agent-trajectories/tree/68195a1450865274106246d0d0296a1d6807b88e): rank the published parquet filenames by SHA-256 of the committed seed and filename, take {2} shards, then take up to {1000:,} trajectories per recorded model by a second hash ranking within the resulting {nebius_pool:,}-row pool. All action slots in selected trajectories are parsed. Smaller model groups retain every available row in the chosen shards. This is a shard sample followed by a capped model sample, not a uniform sample of the full release. The card declares CC BY 4.0 and explicitly retains repository-specific licenses and Llama model terms. We preserve the recorded model names rather than infer checkpoints beyond the release's metadata.
- [SWE-Gym OpenHands SFT](https://huggingface.co/datasets/SWE-Gym/OpenHands-SFT-Trajectories/tree/4aaa5a4a4b5861f4799d2336908760c190ac3b17): use the complete released successful-trajectory split. The card declares MIT. The [SWE-Gym paper](https://arxiv.org/abs/2412.21139) describes GPT-4o and Claude-3.5-Sonnet collection, but the released SFT rows contain messages only, so individual model and task identity are unavailable. We retain a single unattributed expert-mixture group. This release is explicitly selected for success.
- [SWE-bench experiments](https://github.com/SWE-bench/experiments/tree/40f164d5b8f1d249bf95a6df8b74b577fd8e519d): follow pinned mini-SWE-agent metadata to public S3 trajectory objects for the Opus and GPT runs in the manifest. Uniformly hash-rank instance filenames and take {200} per model. The matched instance-name ranking also pairs these samples across models. S3 access was successful. No explicit dataset license was located for these trajectory objects. The scaffold's software license is not a license for the trajectory data. We publish derived aggregates, hashes, and short command previews, and make no claim of permissive relicensing.
- [SWE-rebench native-agent release](https://huggingface.co/datasets/ibragim-bad/swe_rebench_07_2026_trajectories/tree/cdae27cdd16673f0c682871ad55d325f24cc7020): use the complete run-{0} shards for Claude Code and Codex, totaling {native_rows} trajectories. The card declares `other` and explicitly retains repository and provider terms without relicensing. This is a third-party normalized release. Framework and model identities are recorded publisher fields, not independently verified vendor provenance. Original patches are omitted by the publisher. Only derived metrics, locators, and short previews are committed here.

[availability.csv](availability.csv) records other considered sources and exclusions, including SWE-smith, MoatlessTools, and the raw OpenHands archive. No result-dependent trajectory filtering, success filtering beyond a source's published selection, or truncation of selected trajectories was applied. The seed was fixed before classification and is not an inference about representativeness.

## Operational method

[collect.py](collect.py) retrieves pinned metadata and selected shards/objects into an external raw directory. [analyze.py](analyze.py) extracts source-native calls, parses shell ASTs with bashlex, and maintains a per-trajectory path history. Recorded mini-SWE-agent harness actions take precedence over duplicate provider messages. OpenHands function XML and native structured calls are parsed separately. Nebius assistant messages contain action proposals, so they are treated as action slots. Ambiguous fenced blocks are retained as unknown, rather than choosing a convenient command. [normalization_audit.csv](normalization_audit.csv) and [extraction_audit.csv](extraction_audit.csv) expose counts by adapter and trajectory.

The mutually exclusive classes are:

| Class | Operational meaning |
|---|---|
| `direct_edit` | A dedicated editor/create/patch operation explicitly names a path. |
| `context_edit` | SWE-agent line-range editing relies on an open-file path from prior feedback. |
| `direct_shell` | Shell syntax names a mutation, such as a redirect, shell mutator, or Git operation. |
| `indirect` | Executes a file/script/module, project executable, build/test/package/lint tool, or dynamic shell dispatch. Its entrypoint is named, while additional effects require runtime/code reasoning. |
| `inline_code` | Inline interpreter code requires code analysis. It stays separate even if it names a literal write path. |
| `read_only` | Reads, searches, editor views, shell control, and polling. |
| `unknown` | Unrecognized tools/commands, parser failures, or ambiguous extraction. |

For combined shell calls the primary priority is indirect, inline code, unknown, named shell mutation, then read/control. A call can therefore have both explicit write paths and an indirect primary label. Read-only pipelines do not become indirect merely because they contain a pipe. Shell wrappers with inline shell bodies are parsed recursively. Heredoc source bodies passed to writers are data, rather than executed shell commands. The parser normalizes simple quoted heredoc delimiters to work around bashlex's delimiter handling. Unknown options, shell expansion, aliases, generic project CLIs, and unsupported syntax can cause unknowns or misses. A runner's presence is potential execution, including syntactically present branches, rather than proof that it ran successfully.

Writes are recovered from dedicated editor paths, SWE-agent feedback state, literal redirects, selected shell writers, and literal Python `open`/Path write expressions with limited string propagation. No source is executed. The Python analysis skips function/class bodies. We resolve exact paths using observed `cd`, tool working directories, or source-reported cwd. Missing cwd gets a separate unknown-root namespace. `Write then execute` requires an interpreter/script execution path matching that history, or a writer command preceding an execution command in the same shell AST. Failed writes identified from feedback do not enter cross-call history. A successful combined-call return code is imperfect evidence for every constituent command. We separately publish earlier-call, same-call, and feedback-confirmed counts. We do not trace imported modules, test-discovered files, symlinks, environment-derived paths, or generated script contents through arbitrary transformations.

For existing project code, `any_project_runner` and `any_no_prior_write_script` in [summary.csv](summary.csv) provide separate trajectory proxies. The former observes build/test/package/module entrypoints. The latter observes an explicit script execution with no recovered earlier write. These percentages use sampled trajectories:

{origin_table}
Missing a prior write does not prove pre-existence, and neither metric measures side effects attributable to existing code. The flags can overlap within a trajectory. Package tools may run downloaded code, and project runners also execute dependencies.

The parser retained {unknown:,} unknown calls/action slots, including {parser_errors:,} shell parse failures. There were {failures:,} calls with failure evidence and {missing_status:,} with unavailable/uncertain success status. These are retained in call denominators. The source feedback is not a complete success oracle. [download_failures.csv](download_failures.csv) records download failures/retries, including an explicit no-failures marker when applicable.

{quality_text}

## Validation and dynamic-replay feasibility

[probe.py](probe.py) records that the installed Docker client cannot reach a daemon, and that bpftrace is unavailable. No replay environment was provisioned and no service or deployment was changed. Without task images and a replay sandbox, an OS-effect fraction cannot be measured here. The ActPlane policy engine's match-only event stream would also require extra instrumentation for an all-writes/all-execs denominator. We used the requested model-annotation fallback instead.

{validation}
## Limitations and permitted interpretation

This is a descriptive sample of public benchmark and training trajectories. Models, harness versions, languages, prompts, budgets, and success selection differ, so the rows do not identify causal framework/model effects. The OpenHands and SWE-agent prompts encourage reproduction scripts, which can increase write-then-execute frequency. Native transcripts are publisher-normalized, and the older text-action format can contain proposals that the environment rejected. Multiple calls may be retries of the same action. No call weighting reconstructs real-world deployment prevalence.

The indirect class is a **potential execution surface**, not a finding that a mutation occurred, that a specific object was unnamed, or that a real guardrail missed it. Inline programs are excluded from the headline indirect fraction because their literal arguments can contain target names. Unknown calls and indirect effects hidden behind apparently direct operations, such as Git hooks or editor internals, mean the class shares do not bound actual OS effects. The model spot check evaluates the stated static categories and can share systematic errors. The write-history analysis is incomplete and does not establish authorship of an entire script.

## Reproduction and outputs

From this directory, with a dedicated virtual environment and an external writable raw directory:

```bash
python3 -m pip install -r requirements.txt
python3 collect.py --raw "$RAW"
python3 analyze.py --raw "$RAW"
python3 probe.py --raw "$RAW"
python3 validate.py --raw "$RAW"
python3 verify.py --raw "$RAW"
python3 report.py
python3 -m pytest -q test_analyze.py
```

The annotation command requires `LITELLM_BASE_URL` and `LITELLM_API_KEY` for the named GLM model, plus access to the named direct Qwen endpoint. It keeps at most {4} requests concurrent and never writes credentials. Completed annotations are cached. Transport/format failures get up to {3} attempts and are retained. Full arguments, feedback excerpts, model responses, normalized sampled trajectories, and logs remain under the external raw directory. The committed call sample contains source locators and hashes to recover full arguments without redistributing whole trajectories.

At the last [resource measurement](resources.csv), raw files occupied {int(resources['raw_bytes'])/1e9:.3f} GB, under the {int(resources['raw_limit_bytes'])/1e9:g} GB limit, and workspace disk use was {float(resources['workspace_used_pct']):.1f}%, below {resources['workspace_limit_pct']}%. [method_metrics.csv](method_metrics.csv) records report constants and derived totals. All quantitative claims in this README are generated by this script from committed CSVs. Source versions, licensing statements, and sampling decisions are recorded in the manifest, configuration, and availability audit.

The requested `oss-change-workflow` skill was absent from the available catalog and filesystem search. We followed the scope, validation, synchronized docs/results, and branch workflow stated in AGENTS.md and the operator update. Results are handed off on the experiment branch. This study changes only this output directory and does not edit the paper.

## Paper-ready motivation paragraph

{paragraph}
"""
    if dynamic_section:
        text=text.replace('**Not measured:** the fraction of actual file mutations or process executions whose targets are missing from tool arguments. There was no dynamic replay, so this study cannot supply that OS-event denominator.',
                          '**Dynamic follow-up:** the replay section below measures captured OS write/exec effects against the initiating call arguments. These are best-effort replays, rather than original deployment telemetry.')
        text=text.replace('## Results\n',''+dynamic_section+'## Static results\n',1)
        text=text.replace('[probe.py](probe.py) records that the installed Docker client cannot reach a daemon, and that bpftrace is unavailable. No replay environment was provisioned and no service or deployment was changed. Without task images and a replay sandbox, an OS-effect fraction cannot be measured here. The ActPlane policy engine\'s match-only event stream would also require extra instrumentation for an all-writes/all-execs denominator. We used the requested model-annotation fallback instead.',
                          'The initial static pass used the model-annotation fallback while replay infrastructure was unavailable. The follow-up installed bpftrace and local toolchains and used isolated local namespaces, without Docker or changes to cluster services, the gateway, Coder, or model deployments. An all-match ActPlane notify policy is another observer option. This study uses successful-operation eBPF probes for its dynamic denominator.')
        text=text.replace('The indirect class is a **potential execution surface**, not a finding that a mutation occurred, that a specific object was unnamed, or that a real guardrail missed it.',
                          'The static indirect class is a **potential execution surface**. The dynamic section separately identifies captured unnamed effects. Neither identifies a real deployed guardrail miss or a policy violation.')
        text=text.replace('python3 report.py\npython3 -m pytest -q test_analyze.py',
                          'python3 report.py\npython3 -m pytest -q test_analyze.py test_dynamic.py')
        text=text.replace('## Paper-ready motivation paragraph\n',
                          '''## Dynamic replay reproduction

The replay requires Linux tracing privileges, BTF, bpftrace, bubblewrap, a C compiler, Git, and relevant language toolchains. This run installed bpftrace, OpenJDK, Maven, Go, pnpm, and yarn locally. Host/package versions and per-trajectory setup receipts are retained. Python interpreter versions are pinned in [dynamic_config.json](dynamic_config.json).

```bash
python3 dynamic_prepare.py --raw "$RAW"
UV_PYTHON_INSTALL_DIR="$RAW/dynamic/toolchains" UV_PYTHON_BIN_DIR="$RAW/dynamic/toolbin" uv python install 3.9.25 3.12.16
python3 dynamic_run.py --raw "$RAW"
python3 dynamic_effects.py --raw "$RAW"
python3 report.py
```

The committed sample plan and task metadata hashes identify exact repository base commits. Environment setup runs outside the observed lineage and its failures are recorded. Shell calls use their recorded text, with only a coordinator exit trap to recover cwd and status. Dedicated read/search tools use bounded in-process substitutes. Edit-tool behavior is the committed substitute implementation, so proprietary tool internals are not reconstructed. Recreated source checkouts, dependency trees, and caches are disposable after final diffs, version/freeze receipts, source commits, logs, and observer maps are retained. Raw evidence stays in the external raw directory. Resource snapshots are in [dynamic_resource_samples.csv](dynamic_resource_samples.csv), which samples disk use rather than claiming a continuous maximum.

## Paper-ready motivation paragraph
''')
    (HERE/'README.md').write_text(text)
    (HERE/'paper_paragraph.txt').write_text(paragraph+'\n')
    print(f"Generated report for {total_traj} trajectories, {total_calls} calls")


if __name__=='__main__':
    main()
