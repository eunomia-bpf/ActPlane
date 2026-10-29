#!/usr/bin/env python3
"""Export small, measured mechanism-preflight evidence, never benchmark metrics."""
import csv
import hashlib
import json
import os
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_text())


def records(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


raw = Path(os.environ["WS_RAW"])
out = raw.parent / "results" / "kernel-preflight"
out.mkdir(parents=True, exist_ok=True)
rows = []
evidence = {"kind": "inert mechanism preflight, not benchmark results",
    "source_commit": "fe23a1e730f330768a7a884bd75850dc6852f299",
    "guest": read(raw / "vm/queue/ready.json"), "artifacts": {}, "cases": {}}
for relative in ["actplane-file-profile-bin", "actplane-file-profile.patch",
    "actplane-file-profile/bpf/prebuilt/process.bpf.o", "actplane-file-profile/bpf/capability.bpf.h",
    "actplane-file-profile/bpf/process.bpf.c", "actplane-file-profile/bpf/src/lib.rs"]:
    path = raw / relative
    evidence["artifacts"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
for mode in ["parent", "child"]:
    root = raw / "kernel-preflight/guest-depth2" / mode
    execution = read(root / "execution.json")
    before, after = read(root / "kernel-before.json"), read(root / "kernel-after.json")
    privilege = read(root / "worker-privilege.json")
    events = records(root / ".actplane/events.jsonl")
    audit = records(root / ".actplane/audit.jsonl")
    child_logs = list((root / ".actplane/children").glob("*/stdout.log"))
    stdout = "".join(path.read_text() for path in child_logs)
    appends = [r for r in audit if r.get("event") == "append_policy_delta"]
    blocked = [r for r in events if r.get("blocked") is True]
    row = {"mode": mode, "guest_kernel": evidence["guest"]["kernel"],
        "returncode": execution["returncode"],
        "allowed_read_write_succeeded": int("legitimate read/write succeeded" in stdout),
        "protected_read_denied": int("kernel denied inert read" in stdout),
        "blocked_kernel_events": len(blocked),
        "uid": privilege["Uid"].split()[0], "gid": privilege["Gid"].split()[0],
        "cap_eff": privilege["CapEff"], "cap_prm": privilege["CapPrm"],
        "cap_bnd": privilege["CapBnd"], "no_new_privs": privilege["NoNewPrivs"],
        "self_policy_attempts": len(appends),
        "self_policy_accepted": sum(r["status"] == "accepted" for r in appends),
        "kernel_accept_before": before["cap_stats"][0], "kernel_accept_after": after["cap_stats"][0],
        "kernel_reject_before": before["cap_stats"][1], "kernel_reject_after": after["cap_stats"][1],
        "rules_before": before["ts_counts"][0], "rules_after": after["ts_counts"][0],
        "updates_before": before["ts_counts"][1], "updates_after": after["ts_counts"][1],
        "append_caller_uid": appends[0]["caller_identity"]["uid"] if appends else "not_applicable",
        "append_stage": "kernel_count_confirmed" if appends else "parent_policy_installed_before_worker"}
    rows.append(row)
    evidence["cases"][mode] = {"summary": row, "execution": execution,
        "privilege": privilege, "kernel_before": before, "kernel_after": after,
        "native_audit": audit, "native_events": events, "stdout": stdout}
with open(out / "preflight.csv", "w", newline="") as stream:
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
(out / "evidence.json").write_text(json.dumps(evidence, indent=2))
(out / "artifact.patch").write_text((raw / "actplane-file-profile.patch").read_text())
print(out)
