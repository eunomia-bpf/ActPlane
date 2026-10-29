"""Export native installed-CLI outcomes without copying transcripts or credentials."""
import csv
import json
from pathlib import Path

RAW = Path('/workspaces/exp/benign-utility/raw/benchmark-cli')
OUT = RAW.parent.parent / 'benchmark/cli/results'


def main():
    rows = []
    for path in sorted((RAW / 'jobs').glob('*/*/result.json')):
        result = json.loads(path.read_text())
        trial = path.parent
        native = trial / 'verifier/ctrf.json'
        ctrf = json.loads(native.read_text()) if native.exists() else {}
        summary = ctrf.get('results', {}).get('summary', {})
        verifier = result.get('verifier_result') or {}
        trajectory_path = trial / 'agent/trajectory.json'
        trajectory = json.loads(trajectory_path.read_text()) if trajectory_path.exists() else {}
        agent = result.get('agent_info') or {}
        exception = result.get('exception_info') or {}
        tests = summary.get('tests', 0)
        passed, failed = summary.get('passed', 0), summary.get('failed', 0)
        stage = next((name for name in ('verifier', 'agent_execution', 'agent_setup', 'environment_setup')
                      if result.get(name)), 'unknown')
        rows.append(dict(job=trial.parent.name, trial=trial.name, native_result=str(path),
            finished_at=result.get('finished_at'), stage=stage,
            exception_type=exception.get('exception_type', ''),
            official_reward=(verifier.get('rewards') or {}).get('reward', ''),
            ctrf_exists=int(native.exists()), tests=tests, passed=passed, failed=failed,
            skipped=summary.get('skipped', 0),
            verifier_executed=int(tests > 0 and passed + failed > 0),
            agent_steps=sum(step.get('source') == 'agent' for step in trajectory.get('steps', [])),
            cli_version=agent.get('version', ''), model=(agent.get('model_info') or {}).get('name', '')))
    OUT.mkdir(parents=True, exist_ok=True)
    if rows:
        with (OUT / 'attempts.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
    print(f'Exported {len(rows)} terminal native CLI attempts; transcripts stay remote.')


if __name__ == '__main__':
    main()