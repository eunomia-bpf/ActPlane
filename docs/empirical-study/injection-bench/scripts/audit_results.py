#!/usr/bin/env python3
"""Export native policy-admission and effect evidence without deriving ASR.

Rejected runtime audit status alone is never called a kernel rejection. Initial
parent installation precedes kernel-before.json, so failed initial loads have
no attributable counter baseline. Syntax flags describe requests, not intent.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import os
from pathlib import Path
import re


STAGES = {4: "caller_domain", 5: "source_or_target_state", 6: "target_authority",
          7: "operation_authority", 8: "label_authority", 9: "scope_widening",
          10: "submitter_identity", 11: "unsupported_feature", 12: "request_or_table"}


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def fnv(text):
    value = 0xcbf29ce484222325
    for byte in text.encode():
        value = ((value ^ byte) * 0x100000001b3) & ((1 << 64) - 1)
    return f"fnv1a64:{value:016x}"


def write_csv(path, rows, fallback):
    fields = list(dict.fromkeys(key for row in rows for key in row)) or fallback
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_json(path, issues, case):
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError("expected a JSON object")
        return value
    except (ValueError, OSError) as error:
        issues.append(dict(case=case, path=str(path), line="", error=str(error)))
        return {}


def read_lines(path, issues, case):
    if not path.exists():
        return []
    result = []
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("expected a JSON audit object")
            result.append((number, value))
        except ValueError as error:
            issues.append(dict(case=case, path=str(path), line=number, error=str(error)))
    return result


def delta(before, after, key, slot):
    a, b = before.get(key), after.get(key)
    if (isinstance(a, list) and isinstance(b, list) and len(a) > slot and len(b) > slot
            and isinstance(a[slot], int) and isinstance(b[slot], int)):
        value = b[slot] - a[slot]
        return value if value >= 0 else None
    return None


def error_stage(error):
    """Only exact source-native error families, not generic keyword guesses."""
    if re.search(r"caller domain \d+ (cannot target runtime domain|lacks runtime authority|lacks label authority)", error):
        return "userspace_authority_precheck", "bpf/src/lib.rs::precheck_append_authority"
    if "requires features not enabled when the eBPF engine was loaded" in error:
        return "userspace_feature_precheck", "bpf/src/lib.rs::validate_supported_features"
    if re.search(r"runtime policy delta has \d+ (updates|rules) but only \d+", error):
        return "userspace_capacity_precheck", "bpf/src/lib.rs::append_policy_delta_with_rule_id_base"
    if "append policy delta requires approval metadata" in error or "is not in runtime.approval.append_delta.allowed_approvers" in error:
        return "userspace_approval_precheck", "crates/actplane-runtime/src/runtime.rs::evaluate_append_delta"
    parser_patterns = [r"expected (?:word|string|declaration|kind in target|node kind in target)",
        r"expected '(?:=|:|notify|by|if|file|exec)", r"unknown (?:kind|op|declaration|unless cond) '",
        r"unterminated string", r"duplicate rule name `", r"the `label` keyword has been removed"]
    if any(re.search(pattern, error) for pattern in parser_patterns):
        return "userspace_dsl_parse", "crates/actplane-ifc-compiler/src/dsl/parse.rs"
    if "was not admitted by the kernel; count remained" in error:
        return "kernel_ack_missing", "bpf/src/lib.rs::submit_expect_count"
    return "unknown", ""


def syntax(text):
    # Top-level request tokens only. A reason/comment mentioning a feature is
    # not a request to use it. Unsupported weakening keywords remain visible.
    if text is None:
        return {name: "unknown" for name in ["declassify_syntax", "endorse_syntax", "source_syntax",
            "weakening_keyword_syntax", "weakening_keywords"]}
    tokens = re.findall(r"(?m)^\s*([A-Za-z_-]+)\b", text)
    weakening = sorted(set(tokens) & {"declassify", "disable", "remove", "delete", "replace",
        "reset", "unload", "allow", "clear", "weaken"})
    return dict(declassify_syntax=int("declassify" in tokens), endorse_syntax=int("endorse" in tokens),
        source_syntax=int("source" in tokens), weakening_keyword_syntax=int(bool(weakening)),
        weakening_keywords="|".join(weakening))


def main():
    raw = Path(os.environ.get("WS_RAW", "/workspaces/exp/injection-bench/raw"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", nargs="+", type=Path,
        default=[raw / "runs/main-v1", raw / "runs/frontier-v1"])
    parser.add_argument("--out", type=Path, default=raw.parent / "results/audit")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    cases, attempts, initial, generated, issues = [], [], [], [], []
    for run in args.runs:
        names = sorted({p.name for root in [run / "cases", run / "kernel"] if root.exists()
                        for p in root.iterdir() if p.is_dir()})
        for name in names:
            case_dir, kernel = run / "cases" / name, run / "kernel" / name
            key = f"{run.name}/{name}"
            scored = read_json(case_dir / "scored.json", issues, key)
            provenance = read_json(case_dir / "policy-provenance.json", issues, key)
            inp = read_json(case_dir / "input.json", issues, key)
            execution = read_json(kernel / "execution.json", issues, key)
            config = read_json(kernel / "worker-config.json", issues, key)
            before = read_json(kernel / "kernel-before.json", issues, key)
            after = read_json(kernel / "kernel-after.json", issues, key)
            response = read_json(kernel / "self-response.json", issues, key)
            if not response:
                response = read_json(case_dir / ".actplane-self-response.json", issues, key)
            base = dict(run=run.name, case=name, task_id=scored.get("task_id", inp.get("workspace", {}).get("task_id", "unknown")),
                model=scored.get("model", provenance.get("model", inp.get("model", "unknown"))),
                system=scored.get("defense", provenance.get("system", "unknown")),
                no_attack=scored.get("no_attack", "unknown"), run_status=scored.get("run_status", "pending"))
            native_path = kernel / ".actplane/audit.jsonl"
            native = read_lines(native_path, issues, key)
            appends = [(line, event) for line, event in native if event.get("event") == "append_policy_delta"]
            accepted = [event for _, event in appends if event.get("status") == "accepted"]
            rejected = [event for _, event in appends if event.get("status") == "rejected"]
            cap_accept = delta(before, after, "cap_stats", 0)
            cap_reject = delta(before, after, "cap_stats", 1)
            rule_delta = delta(before, after, "ts_counts", 0)
            update_delta = delta(before, after, "ts_counts", 1)
            stage_counts = {label: delta(before, after, "cap_stats", slot) for slot, label in STAGES.items()}
            accepted_rules = sum(event.get("rule_count", 0) for event in accepted)
            counts_correlate = (rule_delta == accepted_rules and rule_delta is not None
                and update_delta is not None and cap_accept == rule_delta + update_delta)
            candidates = []
            for path in [kernel / "authored-policy.dsl", case_dir / "generated-policy.dsl"]:
                if path.exists():
                    text = path.read_text()
                    candidates.append((fnv(text), text, str(path)))
            if "policy" in config:
                candidates.append((fnv(config["policy"]), config["policy"], str(kernel / "worker-config.json") + "#policy"))
            policy_path = case_dir / "generated-policy.dsl"
            if policy_path.exists():
                text = policy_path.read_text()
                generated.append(dict(base, policy_sha256=sha(text), policy_text_ref=str(policy_path),
                    authored_policy="present", submitted_to_adapter=int((kernel / "authored-policy.dsl").exists()),
                    **syntax(text)))
            elif str(base["system"]).startswith("agplane_"):
                generated.append(dict(base, policy_sha256="", policy_text_ref="", authored_policy="absent",
                    submitted_to_adapter=0, **syntax(None)))

            # Initial parent installation is a distinct invocation. The authored
            # self-policy is not part of the neutral initial parent configuration.
            yaml_path = kernel / "actplane.yaml"
            if yaml_path.exists() and any((kernel / p).exists() for p in ["engine.stdout", "engine.stderr", "execution.json"]):
                state = config.get("state", {})
                role = "parent_initial_load" if execution.get("mode", "parent" if base["system"] == "agplane_pre" else "child") == "parent" else "neutral_parent_initial_load"
                error = execution.get("error", "")
                if not error and (kernel / "engine.stderr").exists():
                    error = (kernel / "engine.stderr").read_text(errors="replace")[-6000:]
                stage, source = error_stage(error)
                ready = bool(before)
                status = "accepted" if ready else ("failed" if execution else "pending")
                if ready:
                    stage, source = "kernel_initial_install_ack", "crates/actplane-runtime/src/runtime.rs::watch_policy_for_pid"
                text = yaml_path.read_text()
                # The emitted YAML uses only a literal policy block.
                dsl = "\n".join(line[2:] for line in text.splitlines()[1:] if line.startswith("  ")) + "\n"
                initial.append(dict(base, phase=role, status=status, decision_stage=stage,
                    decision_source=source, caller_pid=state.get("pid", "unknown"),
                    caller_uid=next((event.get("submitter_identity", {}).get("uid") for _, event in native
                        if event.get("submitter_identity", {}).get("pid") == state.get("pid")), "unknown"),
                    target_id=state.get("parent_domain_id", execution.get("parent_domain_id", "unknown")),
                    policy_sha256=sha(dsl), policy_text_ref=str(yaml_path) + "#policy", **syntax(dsl),
                    kernel_acceptance_confirmed=int(ready), kernel_rejection_confirmed=0,
                    counter_baseline_available=int(bool(before)),
                    error=error[:1000] if not ready else "", evidence_ref=str(kernel / "execution.json")))

            response_matched = False
            for index, (line, event) in enumerate(appends):
                text = reference = None
                for native_hash, candidate, candidate_ref in candidates:
                    if native_hash == event.get("policy_hash"):
                        text, reference = candidate, candidate_ref
                        break
                caller = event.get("caller_identity", {})
                same_response = (response and event.get("caller_pid") == response.get("caller_pid")
                    and (text is not None or len(appends) == 1))
                response_matched = response_matched or bool(same_response)
                error = event.get("error", "")
                stage, source = error_stage(error)
                kernel_decision = "unknown"
                if event.get("status") == "accepted":
                    if counts_correlate and cap_accept and len(accepted) == 1:
                        stage, kernel_decision = "kernel_acceptance_counter_correlated", "accepted"
                    elif counts_correlate and cap_accept and len(accepted) > 1:
                        stage, kernel_decision = "kernel_acceptance_group_counter_correlated", "accepted_group_correlated"
                    elif counts_correlate and cap_accept == 0:
                        stage, kernel_decision = "userspace_noop_no_kernel_submission", "not_submitted"
                    else:
                        stage = "native_acceptance_counter_unavailable_or_mismatch"
                    source = "bpf/src/lib.rs::append_policy_delta_with_rule_id_base;submit_expect_count"
                # One rejected native request and no other unknown rejection is
                # necessary for attributing aggregate kernel reject/stage counts.
                if (event.get("status") == "rejected" and stage == "kernel_ack_missing"
                        and len(rejected) == 1 and cap_reject and cap_reject > 0
                        and sum(value or 0 for value in stage_counts.values()) == cap_reject):
                    stage, kernel_decision = "kernel_rejection_counter_correlated", "rejected"
                elif event.get("status") == "rejected" and stage.startswith("userspace_"):
                    kernel_decision = "not_submitted"
                attempts.append(dict(base, phase="runtime_append", attempt_index=index,
                    caller_pid=event.get("caller_pid", "unknown"), caller_uid=caller.get("uid", "unknown"),
                    caller_gid=caller.get("gid", "unknown"), target_id=event.get("target_id", "unknown"),
                    native_policy_hash=event.get("policy_hash", "unknown"),
                    policy_sha256=sha(text) if text is not None else "unknown",
                    policy_text_ref=reference or "unavailable", text_completeness="full" if text is not None else "unavailable",
                    **syntax(text), status=event.get("status", "unknown"), decision_stage=stage,
                    decision_source=source, kernel_decision=kernel_decision,
                    kernel_acceptance_confirmed=int(kernel_decision.startswith("accepted")),
                    kernel_rejection_confirmed=int(kernel_decision == "rejected"),
                    native_rule_count=event.get("rule_count", "unknown"),
                    kernel_rule_delta=rule_delta, kernel_update_delta=update_delta,
                    kernel_accept_delta=cap_accept, kernel_reject_delta=cap_reject,
                    kernel_reject_stage_deltas=json.dumps(stage_counts, separators=(",", ":")),
                    error=error[:1000], evidence_ref=f"{native_path}#L{line}"))
            if response and not response_matched:
                payload = response.get("response", {})
                error = str(payload.get("error", ""))
                stage, source = error_stage(error)
                text = config.get("policy")
                if text is None and (kernel / "authored-policy.dsl").exists():
                    text = (kernel / "authored-policy.dsl").read_text()
                attempts.append(dict(base, phase="child_submission_without_native_audit", attempt_index=len(appends),
                    caller_pid=response.get("caller_pid", "unknown"), caller_uid=response.get("caller_uid", "unknown"),
                    caller_gid="unknown", target_id=config.get("child_id", "unknown"),
                    native_policy_hash="unavailable", policy_sha256=sha(text) if text is not None else "unknown",
                    policy_text_ref=str(kernel / "authored-policy.dsl") if text is not None else "unavailable",
                    text_completeness="full" if text is not None else "unavailable", **syntax(text),
                    status="response_accepted_without_native_audit" if payload.get("ok") else "rejected",
                    decision_stage=stage, decision_source=source,
                    kernel_decision="not_submitted" if stage.startswith("userspace_") else "unknown",
                    kernel_acceptance_confirmed=0, kernel_rejection_confirmed=0,
                    error=error[:1000], evidence_ref=str(kernel / "self-response.json")))

            events_path = kernel / ".actplane/events.jsonl"
            events = read_lines(events_path, issues, key)
            if not events_path.exists():
                events = [(n, event) for n, event in read_lines(kernel / "engine.stdout", [], key)
                    if event.get("event") == "taint_violation"]
            effects = scored.get("actual_effects", [])
            final_state = case_dir / "actual-final-state.json"
            cases.append(dict(base, engine_mode=execution.get("mode", "not_reached"),
                engine_status=execution.get("status", "pending_or_not_reached"),
                engine_returncode=execution.get("returncode", "unknown"),
                kernel_artifacts_present=int(kernel.exists()), authored_policy_present=int(policy_path.exists()),
                native_append_attempts=len(appends), blocked_kernel_events=sum(e.get("blocked") is True for _, e in events),
                kernel_event_evidence="native_event_file" if events_path.exists() else "absent_or_stdout_only",
                killed_kernel_events=sum(e.get("killed") is True for _, e in events),
                kernel_accept_delta=cap_accept, kernel_reject_delta=cap_reject,
                kernel_rule_delta=rule_delta, kernel_update_delta=update_delta,
                failed_structured_writes=sum(e.get("operation") == "write_file" and e.get("success") is False for e in effects),
                denied_structured_writes=sum(e.get("operation") == "write_file" and e.get("success") is False
                    and e.get("errno") in (1, 13) for e in effects),
                successful_structured_writes=sum(e.get("operation") == "write_file" and e.get("success") is True for e in effects),
                scored_attack_completed=scored.get("attack_completed", "unknown"),
                scored_attack_outcome_known=scored.get("attack_outcome_known", "unknown"),
                scored_utility_pass=scored.get("utility_pass", "unknown"),
                final_state_ref=str(final_state) if final_state.exists() else "unavailable",
                final_state_sha256=sha(final_state.read_text()) if final_state.exists() else "unavailable",
                note="ASR/utility remain official scored-state outcomes; denied writes can leave partial state"))
    groups = defaultdict(list)
    for row in cases:
        groups[(row["run"], row["model"], row["system"])].append(row)
    summary = []
    for (run, model, system), group in sorted(groups.items()):
        selected = lambda rows: [r for r in rows if (r["run"], r["model"], r["system"]) == (run, model, system)]
        aa, ii, gg = selected(attempts), selected(initial), selected(generated)
        summary.append(dict(run=run, model=model, system=system, cases_observed=len(group),
            cases_terminal=sum(r["run_status"] != "pending" for r in group),
            generated_policy_present=sum(r["authored_policy"] == "present" for r in gg),
            policy_absent_no_submission=sum(r["authored_policy"] == "absent" for r in gg),
            initial_load_attempts=len(ii), runtime_submission_attempts=len(aa),
            native_accepted=sum(r["status"] == "accepted" for r in aa),
            native_rejected=sum(r["status"] == "rejected" for r in aa),
            kernel_acceptance_correlated=sum(r["kernel_acceptance_confirmed"] for r in aa),
            kernel_rejection_correlated=sum(r["kernel_rejection_confirmed"] for r in aa),
            userspace_rejections=sum(r["status"] == "rejected" and r["decision_stage"].startswith("userspace_") for r in aa),
            unresolved_decision_stage=sum(r["kernel_decision"] == "unknown" for r in aa),
            requested_declassify=sum(r["declassify_syntax"] == 1 for r in gg),
            requested_endorse=sum(r["endorse_syntax"] == 1 for r in gg),
            requested_source=sum(r["source_syntax"] == 1 for r in gg),
            blocked_kernel_events=sum(r["blocked_kernel_events"] for r in group)))
    for name, rows in [("cases", cases), ("append_attempts", attempts), ("initial_loads", initial),
                       ("generated_policies", generated), ("summary", summary), ("read_issues", issues)]:
        write_csv(args.out / (name + ".csv"), rows,
            ["case", "path", "line", "error"] if name == "read_issues" else ["case", "status"])
    print(json.dumps(dict(cases_observed=len(cases), cases_terminal=sum(r["run_status"] != "pending" for r in cases),
        initial_load_attempts=len(initial), runtime_submission_attempts=len(attempts),
        decision_stages=dict(Counter(r["decision_stage"] for r in attempts)),
        genuine_kernel_rejections=sum(r["kernel_rejection_confirmed"] for r in attempts),
        read_issues=len(issues), output=str(args.out)), separators=(",", ":")))


if __name__ == "__main__":
    main()
