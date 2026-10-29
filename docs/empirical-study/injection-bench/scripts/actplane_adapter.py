#!/usr/bin/env python3
"""Run a real benchmark worker in an ActPlane child domain (Linux only)."""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import time
import uuid


NEUTRAL = 'source COMMAND = exec "**"\n'


def _write(path, value):
    Path(path).write_text(json.dumps(value, indent=2), encoding="utf-8")


def _request(state, value):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(30)
        sock.connect(state["socket_path"])
        sock.sendall((json.dumps(value) + "\n").encode())
        with sock.makefile("rb") as stream:
            return json.loads(stream.readline())


def _counters(pin_root=None):
    """Read actual kernel map counters, retaining unavailable evidence literally."""
    syscall = {"x86_64": 321, "aarch64": 280}.get(platform.machine())
    if syscall is None:
        return {"status": "unavailable", "reason": "unknown BPF syscall number"}
    libc = ctypes.CDLL(None, use_errno=True)
    root = Path(pin_root or os.environ.get("ACTPLANE_BPF_PIN_ROOT", "/sys/fs/bpf/actplane/v1"))
    result = {}
    for name, count, typ in [("cap_stats", 13, ctypes.c_uint64), ("ts_counts", 2, ctypes.c_uint32)]:
        pathname = ctypes.create_string_buffer(os.fsencode(root / "maps" / name))
        attr = ctypes.create_string_buffer(144)
        ctypes.c_uint64.from_buffer(attr).value = ctypes.addressof(pathname)
        fd = libc.syscall(syscall, 7, attr, 144)
        if fd < 0:
            result[name] = {"status": "unavailable", "errno": ctypes.get_errno()}
            continue
        values = []
        try:
            for slot in range(count):
                key, value = ctypes.c_uint32(slot), typ()
                attr = ctypes.create_string_buffer(144)
                ctypes.c_uint32.from_buffer(attr, 0).value = fd
                ctypes.c_uint64.from_buffer(attr, 8).value = ctypes.addressof(key)
                ctypes.c_uint64.from_buffer(attr, 16).value = ctypes.addressof(value)
                rc = libc.syscall(syscall, 1, attr, 144)
                values.append(value.value if rc == 0 else None)
            result[name] = values
        finally:
            os.close(fd)
    return result


def _bootstrap(config_path):
    config = json.loads(Path(config_path).read_text())
    os.chdir(config["cwd"])
    # Trusted bootstrap executes before any benchmark tool or injected content.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "set no_new_privs")
    for cap in range(41):
        if libc.prctl(24, cap, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
            raise OSError(ctypes.get_errno(), "drop capability bounding set")
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    privilege = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith(("Uid:", "Gid:", "Cap", "NoNewPrivs:"))}
    _write(config["privilege_status"], privilege)
    if config["mode"] == "child":
        response = _request(config["state"], {
            "op": "append_policy_delta", "target_id": config["child_id"],
            "policy": config["policy"], "generated_by": "executing-agent-after-context",
        })
        _write(config["self_response"], {
            "caller_pid": os.getpid(), "caller_uid": os.getuid(), "response": response,
        })
        # Rejected self-policy is a measured defense failure, not a blocked task.
        # The worker continues under the actual policy admitted by the engine.
    completed = subprocess.run(config["command"], cwd=config["cwd"], check=False)
    _write(config["worker_status"], {"returncode": completed.returncode})
    return completed.returncode


def _execute_local(policy, mode, command, cwd, audit_dir, timeout=600, env=None):
    """Return CompletedProcess; all execution/audit evidence stays under audit_dir.

    cwd MUST be an isolated per-task directory owned by this benchmark. This
    function makes only that subtree writable by UID/GID 65534. mode=parent
    installs policy before launching the worker. mode=child installs it from
    the constrained child PID after caller-provided post-context generation.
    Policy generation and benchmark scoring remain outside this adapter.
    """
    if sys.platform != "linux":
        raise RuntimeError("ActPlane experiments execute only in the Linux Workspace")
    modes = {"parent": "parent", "preauthored": "parent", "child": "child", "self": "child"}
    mode = modes[mode]
    cwd, audit_dir = Path(cwd).resolve(), Path(audit_dir).resolve()
    if not cwd.is_dir() or cwd == Path("/") or len(cwd.parts) < 3:
        raise ValueError("cwd must be an existing isolated benchmark directory")
    audit_dir.mkdir(parents=True, exist_ok=True)
    for path in [cwd, *cwd.rglob("*")]:
        if not path.is_symlink():
            os.chown(path, 65534, 65534)
    # Workspace parents may be root-owned mkdtemp directories with mode 0700.
    for path in cwd.parents:
        if path == Path("/"):
            break
        if path.stat().st_mode & 0o001 == 0:
            raise PermissionError(f"worker cannot traverse parent {path}; use isolated holder under /tmp")
    patched = Path("/workspaces/exp/injection-bench/raw/actplane-file-profile-bin")
    binary = os.environ.get("ACTPLANE_BIN", str(patched) if patched.exists() else "/workspaces/exp/injection-bench/raw/actplane")
    if not Path(binary).is_file():
        raise FileNotFoundError(f"copy the supplied built ActPlane artifact to {binary}")
    env_run = dict(os.environ, **(env or {}))
    if Path(binary) == patched:
        env_run.setdefault("ACTPLANE_BPF_PIN_ROOT", "/sys/fs/bpf/actplane-injection-bench-depth2-audit-v2/v1")
    # Preserve a root-owned control plane. Child privilege drop is in bootstrap.
    env_run.pop("SUDO_UID", None)
    env_run.pop("SUDO_GID", None)
    policy_path = audit_dir / "actplane.yaml"
    parent_policy = (("" if "source COMMAND" in policy else NEUTRAL) + policy) if mode == "parent" else NEUTRAL
    policy_path.write_text("policy: |\n" + "".join("  " + line + "\n" for line in parent_policy.splitlines()))
    (audit_dir / "authored-policy.dsl").write_text(policy)
    holder = engine = None
    # /run is a private tmpfs in each guest. /tmp is shared with the Workspace.
    lock = open("/run/actplane-injection-bench.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX)
    started = time.monotonic()
    result = {"mode": mode, "status": "engine_failure", "command": list(command)}
    try:
        holder = subprocess.Popen(["/bin/sleep", "infinity"], start_new_session=True)
        with open(audit_dir / "engine.stdout", "w") as out, open(audit_dir / "engine.stderr", "w") as err:
            engine = subprocess.Popen(
                [binary, "--policy", str(policy_path), "attach", "--pid", str(holder.pid)],
                cwd=audit_dir, env=env_run, stdout=out, stderr=err, start_new_session=True,
            )
        state_path = audit_dir / ".actplane" / "control.json"
        deadline = time.monotonic() + 120
        while not state_path.exists():
            if engine.poll() is not None:
                raise RuntimeError((audit_dir / "engine.stderr").read_text()[-6000:])
            if time.monotonic() >= deadline:
                raise TimeoutError("ActPlane did not expose control state")
            time.sleep(0.1)
        state = json.loads(state_path.read_text())
        # Socket mutation requests still check the unforgeable peer PID/domain.
        os.chmod(state["socket_path"], 0o666)
        before = _counters(env_run.get("ACTPLANE_BPF_PIN_ROOT"))
        _write(audit_dir / "kernel-before.json", before)
        child_id = os.getpid() + 10000000
        worker_status = cwd / ".actplane-worker-status.json"
        self_response = cwd / ".actplane-self-response.json"
        privilege_status = cwd / ".actplane-privilege-status.json"
        config = {
            "cwd": str(cwd), "command": list(command), "mode": mode, "policy": policy,
            "state": state, "child_id": child_id,
            "worker_status": str(worker_status), "self_response": str(self_response),
            "privilege_status": str(privilege_status),
        }
        _write(audit_dir / "worker-config.json", config)
        response = _request(state, {"op": "launch_child_domain", "child_id": child_id,
            "cmd": [sys.executable, str(Path(__file__).resolve()), "_worker", str(audit_dir / "worker-config.json")]})
        _write(audit_dir / "launch-response.json", response)
        if not response.get("ok"):
            raise RuntimeError(str(response))
        deadline = time.monotonic() + timeout
        while not worker_status.exists():
            if engine.poll() is not None:
                raise RuntimeError("ActPlane engine exited during worker execution")
            if time.monotonic() >= deadline:
                _write(audit_dir / "timeout-termination.json", _request(state, {
                    "op": "terminate_child_domain", "child_id": child_id}))
                result.update(status="timeout", returncode=124)
                break
            # Also notice a policy-killed worker, which cannot write its status.
            for meta_path in (audit_dir / ".actplane" / "children").glob("*/meta.json"):
                try:
                    meta = json.loads(meta_path.read_text())
                except json.JSONDecodeError:
                    continue  # Registry writer can be between truncate and flush.
                status = meta.get("status", {})
                if meta.get("child_id") == child_id and status.get("state") in {"exited", "terminated"}:
                    code = status.get("code")
                    result.update(status="worker_exit", returncode=code if code is not None else 128 + (status.get("signal") or 9))
                    break
            if result["status"] == "worker_exit":
                break
            time.sleep(0.1)
        if worker_status.exists():
            result.update(status="completed", **json.loads(worker_status.read_text()))
        _write(audit_dir / "kernel-after.json", _counters(env_run.get("ACTPLANE_BPF_PIN_ROOT")))
        if self_response.exists():
            _write(audit_dir / "self-response.json", json.loads(self_response.read_text()))
        if privilege_status.exists():
            _write(audit_dir / "worker-privilege.json", json.loads(privilege_status.read_text()))
        result["child_domain_id"] = child_id
        result["parent_domain_id"] = state["parent_domain_id"]
    except Exception as error:
        result.update(error=str(error), returncode=125)
        _write(audit_dir / "kernel-after.json", _counters(env_run.get("ACTPLANE_BPF_PIN_ROOT")))
    finally:
        if engine is not None and engine.poll() is None:
            engine.send_signal(signal.SIGINT)
            try:
                engine.wait(timeout=15)
            except subprocess.TimeoutExpired:
                engine.kill()
                engine.wait()
        if holder is not None and holder.poll() is None:
            holder.terminate()
            holder.wait()
        result["elapsed_seconds"] = time.monotonic() - started
        _write(audit_dir / "execution.json", result)
        lock.close()
    stdout, stderr = "", ""
    children = audit_dir / ".actplane" / "children"
    for path in sorted(children.glob("*/stdout.log")):
        stdout += path.read_text(errors="replace")
    for path in sorted(children.glob("*/stderr.log")):
        stderr += path.read_text(errors="replace")
    return subprocess.CompletedProcess(command, result.get("returncode", 125), stdout, stderr or result.get("error", ""))


def execute(policy, mode, command, cwd, audit_dir, timeout=600, env=None):
    if os.environ.get("ACTPLANE_IN_GUEST") == "1":
        return _execute_local(policy, mode, command, cwd, audit_dir, timeout, env)
    queue = Path((env or {}).get("ACTPLANE_VM_QUEUE") or os.environ.get(
        "ACTPLANE_VM_QUEUE", "/workspaces/exp/injection-bench/raw/vm/queue"))
    if not (queue / "ready.json").exists():
        raise RuntimeError("Start scripts/vm_runner.sh in the Workspace before AgPlane cells; PID-namespace host execution is invalid")
    identity = uuid.uuid4().hex
    path = queue / (identity + ".request.json")
    response_path = queue / (identity + ".result.json")
    forwarded = {k: v for k, v in os.environ.items()
        if k.startswith(("LITELLM_", "OPENAI_")) or k in {"PYTHONPATH", "SSL_CERT_FILE", "WS_RAW", "WS_LANE"}}
    forwarded.update(env or {})
    request = {"policy": policy, "mode": mode, "command": list(command),
        "cwd": str(Path(cwd).resolve()), "audit_dir": str(Path(audit_dir).resolve()),
        "timeout": timeout, "env": forwarded}
    temporary = path.with_suffix(".tmp")
    with open(temporary, "w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(request, stream)
    temporary.replace(path)
    while not response_path.exists():
        pid_path = queue.parent / "qemu.pid"
        try:
            os.kill(int(pid_path.read_text().strip()), 0)
        except (OSError, ValueError):
            raise RuntimeError("AgPlane guest exited before queued cell completed")
        time.sleep(0.2)
    result = json.loads(response_path.read_text())
    if "adapter_error" in result:
        return subprocess.CompletedProcess(command, 125, "", result["adapter_error"])
    return subprocess.CompletedProcess(command, result["returncode"], result["stdout"], result["stderr"])


def _serve(queue):
    queue = Path(queue)
    if os.environ.get("ACTPLANE_IN_GUEST") != "1":
        raise RuntimeError("VM queue server must execute in the guest")
    _write(queue / "ready.json", {"kernel": platform.release(), "pid": os.getpid(),
        "lsm": Path("/sys/kernel/security/lsm").read_text().strip(),
        "instance": os.environ.get("ACTPLANE_VM_INSTANCE", "default")})
    print("GUEST_READY", flush=True)
    while not (queue / "shutdown").exists():
        pending = [p for p in sorted(queue.glob("*.request.json"))
            if not p.with_name(p.name.replace(".request.json", ".result.json")).exists()]
        if not pending:
            time.sleep(0.1)
            continue
        path = pending[0]
        response = path.with_name(path.name.replace(".request.json", ".result.json"))
        job = json.loads(path.read_text())
        # Preserve commands/policy, but never retain gateway credentials in raw.
        _write(path, dict(job, env={key: "<provided at execution>" for key in job.get("env", {})}))
        try:
            result = _execute_local(**job)
            payload = {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        except Exception as error:
            payload = {"adapter_error": str(error)}
        temporary = response.with_suffix(".tmp")
        _write(temporary, payload)
        temporary.replace(response)
    subprocess.run(["/bin/busybox", "poweroff", "-f"], check=False)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "serve":
        _serve(sys.argv[2])
        raise SystemExit(0)
    if len(sys.argv) == 2 and sys.argv[1] == "counters":
        print(json.dumps(_counters()))
        raise SystemExit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "_worker":
        raise SystemExit(_bootstrap(sys.argv[2]))
    raise SystemExit("Import execute() from the official benchmark adapter")
