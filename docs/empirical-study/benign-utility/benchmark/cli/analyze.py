"""Export native installed-CLI outcomes without copying transcripts or credentials."""
import csv
import json
import re
from pathlib import Path

RAW = Path('/workspaces/exp/benign-utility/raw/benchmark-cli')
OUT = RAW.parent.parent / 'benchmark/cli/results'


def main():
    rows, activity, interventions, scopes, lineages = [], [], [], [], []
    for path in sorted((RAW / 'jobs').glob('*/*/result.json')):
        result = json.loads(path.read_text())
        trial = path.parent
        native = trial / 'verifier/ctrf.json'
        ctrf = json.loads(native.read_text()) if native.exists() else {}
        summary = ctrf.get('results', {}).get('summary', {})
        verifier = result.get('verifier_result') or {}
        trajectory_path = trial / 'agent/trajectory.json'
        trajectory = json.loads(trajectory_path.read_text()) if trajectory_path.exists() else {}
        scope_path = trial / 'agent/scope.json'
        if scope_path.exists():
            scope = json.loads(scope_path.read_text())
            observer_path = trial / 'agent/observer.jsonl'
            observer_text = observer_path.read_text()
            for line in observer_text.splitlines():
                try:
                    payload = json.loads(line)
                except ValueError:
                    continue
                for event in str(payload.get('data', '')).splitlines():
                    fields = event.split('|', 4)
                    if len(fields) == 5 and fields[0] in ('READ', 'CONNECT', 'EXEC', 'FORK'):
                        activity.append(dict(job=trial.parent.name, event=fields[0],
                            timestamp_ns=fields[1], owner=fields[2], pid=fields[3], target=fields[4]))
            events = []
            for line in (trial / 'agent/engine.log').read_text().splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get('event') == 'TAINT_VIOLATION':
                    events.append(event)
                    provenance = event.get('provenance') or {}
                    tools = sum(len(step.get('tool_calls', [])) for step in trajectory.get('steps', []))
                    interventions.append(dict(job=trial.parent.name,
                        call_index=0 if tools == 0 else 'unknown',
                        phase='pre-tool/bootstrap' if tools == 0 else 'requires timeline audit',
                        timestamp_ns=event.get('timestamp'), pid=event.get('pid'),
                        session_root=event.get('session_root'), comm=event.get('comm'),
                        target=event.get('target'), killed=event.get('killed'),
                        blocked=event.get('blocked'), effect=event.get('effect'),
                        source_path=provenance.get('target'), source_pid=provenance.get('pid'),
                        source_timestamp_ns=provenance.get('timestamp_ns'),
                        adjudication='true strict-policy violation' if provenance.get('target') in
                            ('/tmp/codex-secrets/auth.json', '/installed-agent/codex-home/auth.json')
                            else 'unknown'))
            relevant = [row for row in activity if row['job'] == trial.parent.name]
            parents = {int(row['target']): int(row['pid']) for row in relevant if row['event'] == 'FORK'}
            actors = {(row['event'], int(row['pid'])) for row in relevant if row['event'] in ('READ', 'CONNECT')}
            actors.update(('INTERVENED_PROCESS', int(event['pid'])) for event in events)
            for role, pid in sorted(actors):
                chain = [pid]
                while chain[-1] != scope['kernel_root_pid'] and chain[-1] in parents:
                    parent = parents[chain[-1]]
                    if parent in chain:
                        raise RuntimeError('Cycle in observed CLI lineage')
                    chain.append(parent)
                lineages.append(dict(job=trial.parent.name, role=role, pid=pid,
                    root_reachable=chain[-1] == scope['kernel_root_pid'],
                    root_to_actor=' > '.join(map(str, reversed(chain)))))
            scopes.append(dict(job=trial.parent.name, kernel_root_pid=scope['kernel_root_pid'],
                namespace_root_pid=scope['namespace_root_pid'],
                instrumentation_alive_at_end=scope.get('instrumentation_alive_at_end'),
                root_fork_observed=scope.get('root_fork_observed'),
                exec_events=sum(row['event'] == 'EXEC' for row in relevant),
                source_read_events=sum(row['event'] == 'READ' for row in relevant),
                connect_events=sum(row['event'] == 'CONNECT' for row in relevant),
                violation_events=len(events), killed_events=sum(bool(event.get('killed')) for event in events),
                blocked_events=sum(bool(event.get('blocked')) for event in events),
                network_effect=scope.get('network_effect', 'kill'),
                native_enforce_mode=scope.get('native_enforce_mode', 'not separately exported'),
                all_event_roots_match=all(event.get('session_root') == scope['kernel_root_pid'] for event in events),
                helper_errors=observer_text.count('helper_error'),
                lost_events=observer_text.count('lost_events'),
                hook_environment=json.dumps(scope['hook_environment'], sort_keys=True),
                engine_sha256=scope['engine_sha256'], observer_sha256=scope['observer_sha256']))
        agent = result.get('agent_info') or {}
        exception = result.get('exception_info') or {}
        exit_match = re.search(r'Command failed \(exit (-?\d+)\)', exception.get('exception_message', ''))
        tests = summary.get('tests', 0)
        passed, failed = summary.get('passed', 0), summary.get('failed', 0)
        stage = next((name for name in ('verifier', 'agent_execution', 'agent_setup', 'environment_setup')
                      if result.get(name)), 'unknown')
        rows.append(dict(job=trial.parent.name, trial=trial.name, native_result=str(path),
            finished_at=result.get('finished_at'), stage=stage,
            exception_type=exception.get('exception_type', ''),
            native_exit_code=int(exit_match[1]) if exit_match else '',
            official_reward=(verifier.get('rewards') or {}).get('reward', ''),
            ctrf_exists=int(native.exists()), tests=tests, passed=passed, failed=failed,
            skipped=summary.get('skipped', 0),
            verifier_executed=int(tests > 0 and passed + failed > 0),
            agent_steps=sum(step.get('source') == 'agent' for step in trajectory.get('steps', [])),
            cli_version=agent.get('version', ''), model=(agent.get('model_info') or {}).get('name', '')))
    OUT.mkdir(parents=True, exist_ok=True)
    if rows:
        with (OUT / 'attempts.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)
    for name, evidence in (('activity', activity), ('interventions', interventions), ('scope', scopes), ('lineage', lineages)):
        if evidence:
            with (OUT / f'{name}.csv').open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(evidence[0]), lineterminator="\n")
                writer.writeheader(); writer.writerows(evidence)
    print(f'Exported {len(rows)} terminal native CLI attempts; transcripts stay remote.')


if __name__ == '__main__':
    main()