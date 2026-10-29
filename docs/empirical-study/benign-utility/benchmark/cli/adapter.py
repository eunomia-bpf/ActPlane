"""Controller-root measurement around Harbor's unchanged native Codex command."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid

from harbor.agents.installed.codex import Codex

BASE = Path('/workspaces/exp/benign-utility/raw/benchmark')
HOOKS = ('ACTPLANE_HOOK_PROFILE', 'ACTPLANE_ENABLE_ADVANCED_HOOKS', 'ACTPLANE_ADVANCED_TRACEPOINTS')
AUTH_PATHS = ('/installed-agent/codex-home/auth.json', '/tmp/codex-secrets/auth.json')


class ControllerCodex(Codex):
    CONNECT_EFFECT = 'kill'
    CONTROL_CONDITION = 'c-cli'

    async def exec_as_agent(self, environment, command, **kwargs):
        if 'codex exec ' not in command:
            return await super().exec_as_agent(environment, command, **kwargs)
        folder = self.logs_dir
        marker = 'bucli' + uuid.uuid4().hex[:8]
        pidfile = f'/tmp/{marker}.pid'
        mapping = folder / 'pid-mapping.bt'
        mapped = folder / 'pid-mapping.jsonl'
        mapping.write_text('BEGIN { printf("PID_MAPPER_READY\\n"); }\n'
            'tracepoint:syscalls:sys_enter_openat /comm == "' + marker + '"/ '
            '{ printf("HOST_PID|%d\\n", curtask->tgid); exit(); }\n')
        processes = []
        streams = []
        native = None
        scope = dict(scope='native codex controller shell, API client and descendants',
            hook_environment={key: os.environ.get(key, 'unset') for key in HOOKS},
            observer_string_bytes=1024, call_index=0, condition=self.CONTROL_CONDITION,
            network_effect=self.CONNECT_EFFECT,
            engine_sha256=hashlib.sha256((BASE / 'engine/process').read_bytes()).hexdigest(),
            command_sha256=hashlib.sha256(command.encode()).hexdigest(),
            added_auth_source_paths=AUTH_PATHS)

        def spawn(args, logfile, env=None):
            stream = logfile.open('w'); streams.append(stream)
            proc = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT, env=env)
            processes.append((proc, logfile))
            return proc

        async def ready(proc, logfile, receipt):
            while receipt not in logfile.read_text():
                if proc.poll() is not None:
                    raise RuntimeError(f'CLI instrumentation failed before {receipt}: {logfile}')
                await asyncio.sleep(.1)

        try:
            mapper = spawn(['bpftrace', '-f', 'json', str(mapping)], mapped)
            await ready(mapper, mapped, 'PID_MAPPER_READY')
            # Pause the actual native exec shell before its controller or API starts.
            prefix = (f"printf '%s' $$ >{pidfile}; printf '%s' {marker} >/proc/self/comm; "
                      ': >/dev/null; kill -STOP $$; printf bash >/proc/self/comm; /bin/true; ')
            native = asyncio.create_task(super().exec_as_agent(environment, prefix + command, **kwargs))
            await ready(mapper, mapped, 'HOST_PID|')
            root = int(re.search(r'HOST_PID\|(\d+)', mapped.read_text())[1])
            pid = await environment.exec(command=f'cat {pidfile}')
            namespace_root = int(pid.stdout.strip())
            if root <= 0 or namespace_root <= 0 or 'helper_error' in mapped.read_text():
                raise RuntimeError('CLI kernel root mapping is invalid')
            scope.update(kernel_root_pid=root, namespace_root_pid=namespace_root,
                         mapped_monotonic_ns=time.monotonic_ns())
            source = Path(__file__).parents[2] / 'replay/source_observer.bt'
            observer = folder / 'observer.bt'
            original = source.read_text()
            needle = '$name == "oauth_creds.json"'
            if original.count(needle) != 1:
                raise RuntimeError('Frozen observer source changed unexpectedly')
            observer.write_text(original.replace(needle, needle +
                ' || $p == "/tmp/codex-secrets/auth.json" || $p == "/installed-agent/codex-home/auth.json"'))
            scope['observer_sha256'] = hashlib.sha256(observer.read_bytes()).hexdigest()
            scope['shared_observer_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
            observation = folder / 'observer.jsonl'
            watcher = spawn(['bpftrace', '-f', 'json', str(observer), str(root)], observation,
                {**os.environ, 'BPFTRACE_MAX_STRLEN': '1024', 'BPFTRACE_MAX_MAP_KEYS': '262144'})
            await ready(watcher, observation, 'SOURCE_OBSERVER_READY')
            policy = (Path(__file__).parents[1] / 'policies/c.dsl').read_text()
            policy = policy.replace('rule secret-no-network:', ''.join(
                f'source SECRET = file "{path}"\n' for path in AUTH_PATHS) + 'rule secret-no-network:')
            policy = policy.replace('kill connect endpoint', self.CONNECT_EFFECT + ' connect endpoint')
            (folder / 'policy.dsl').write_text(policy)
            subprocess.run(['/workspaces/lanes/translation-models/target/release/actplane',
                '--rule', policy, 'compile', '--out', str(folder / 'policy.bin'), '--force'],
                check=True, capture_output=True)
            engine_log = folder / 'engine.log'
            engine = spawn([str(BASE / 'engine/process'), '--config', str(folder / 'policy.bin'),
                            '--seed-pid', str(root)], engine_log)
            await ready(engine, engine_log, 'ActPlane: ready')
            scope['native_enforce_mode'] = 'enforce mode' in engine_log.read_text()
            if self.CONNECT_EFFECT == 'block' and not scope['native_enforce_mode']:
                raise RuntimeError('Native block requires the retained engine enforce-mode receipt')
            scope['continued_monotonic_ns'] = time.monotonic_ns()
            (folder / 'scope.json').write_text(json.dumps(scope, indent=2))
            await environment.exec(command=f'kill -CONT {namespace_root}')
            try:
                return await native
            finally:
                scope['finished_monotonic_ns'] = time.monotonic_ns()
                scope['instrumentation_alive_at_end'] = watcher.poll() is None and engine.poll() is None
                scope['root_fork_observed'] = f'|benchmark|{root}|' in observation.read_text()
                (folder / 'scope.json').write_text(json.dumps(scope, indent=2))
        finally:
            if native is not None and not native.done():
                native.cancel()
                await asyncio.gather(native, return_exceptions=True)
            statuses = []
            for proc, logfile in processes:
                before = proc.poll()
                if before is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        await asyncio.to_thread(proc.wait, timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.terminate(); await asyncio.to_thread(proc.wait, timeout=5)
                statuses.append(dict(log=logfile.name, pre_stop_returncode=before,
                                     final_returncode=proc.returncode))
            for stream in streams:
                stream.close()
            (folder / 'observer-status.json').write_text(json.dumps(statuses, indent=2))

class ControllerBlockCodex(ControllerCodex):
    CONNECT_EFFECT = 'block'
    CONTROL_CONDITION = 'c-cli-native-block'
