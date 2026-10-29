#!/usr/bin/env python3
"""Classify recorded calls, never inferred OS event counts. See README for estimands."""
import argparse
import ast
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
import posixpath
import re
from pathlib import Path

import bashlex

HERE = Path(__file__).resolve().parent
CLASSES = ("direct_edit", "context_edit", "direct_shell", "indirect", "inline_code", "read_only", "unknown")
READ_TOOLS = {"read", "read_file", "glob", "grep", "ls", "list_directory", "search", "web_search", "webfetch", "finish", "task_complete", "think", "todowrite", "todo_write", "exit_plan_mode", "enterplanmode"}
SHELL_TOOLS = {"bash", "execute_bash", "exec_command", "shell_command", "shell", "terminal", "run", "run_command", "functions.exec_command"}
EDIT_TOOLS = {"edit", "write", "write_file", "edit_file", "str_replace_editor", "str_replace_based_edit_tool", "apply_patch", "functions.apply_patch", "file_editor"}
READ_CMDS = set("ls pwd cat head tail less more grep egrep fgrep rg ag find locate which whereis type wc sort uniq cut tr diff cmp file stat du df echo printf true false test [ cd export unset alias unalias set shopt env printenv date sleep basename dirname realpath readlink xxd od hexdump nl tac paste column uname whoami id ps pgrep kill jobs wait fg bg history help man open goto scroll_up scroll_down search_dir search_file find_file submit exit pwd clear tree git_status".split())
RUNNERS = set("pytest py.test nosetests nose tox nox make gmake cmake ninja meson npm npx yarn pnpm pip pip3 pipx uv poetry pdm hatch cargo rustc rustfmt go javac java mvn mvnw gradle gradlew ant sbt dotnet bun deno tsc eslint jest vitest mocha rake rspec bundle composer phpunit mypy pylint flake8 ruff black isort coverage django-admin sphinx-build pre-commit ctest gcc g++ cc c++ clang clang++ cython maturin setup.py".split())
MUTATORS = set("rm rmdir mv cp mkdir touch truncate install ln chmod chown chgrp tee patch apply_patch".split())
INTERPRETER = re.compile(r"^(python[\d.]*|pypy[\d.]*|bash|sh|zsh|dash|ksh|node|ruby|perl|php|lua|Rscript|julia)$")


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def parse_args(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            j = json.loads(value)
            return j if isinstance(j, dict) else {"text": value}
        except ValueError:
            return {"text": value}
    return {}


def feedback_exit_code(feedback):
    match=re.search(r"\[Command finished with exit code (-?\d+)\]",str(feedback))
    return int(match[1]) if match else None


def reported_status(call,feedback):
    code=call.get("exit_code")
    if code is not None:
        return "success" if code==0 else "failed"
    if call.get("result_status")=="success":
        return "success"
    if call.get("result_status") in ("error","failed"):
        return "failed"
    if re.search(r"(?i)(syntax error|error:|does not exist|no such file|command not found|failed to|not found in file)",feedback[:1500]):
        return "failed"
    return "unknown"


def normalize(row):
    """Yield calls with source sequence and feedback. Keep extraction failures visible."""
    source = row["source"]
    if source == "nebius":
        messages = row["trajectory"]
        cwd, active = None, None
        for i, m in enumerate(messages):
            text = m.get("text") or ""
            if m["role"] == "user":
                match = re.findall(r"\(Current directory: ([^\n)]+)\)", text)
                if match:
                    cwd = match[-1]
                match = re.findall(r"\(Open file: ([^\n)]+)\)", text)
                if match:
                    active = match[-1] if match[-1] != "n/a" else None
            if m["role"] != "ai":
                continue
            blocks = re.findall(r"```[^\n]*\n(.*?)```", text, re.S)
            result = messages[i + 1].get("text", "") if i + 1 < len(messages) and messages[i + 1]["role"] == "user" else ""
            if len(blocks) == 1:
                yield dict(seq=i, tool="swe_shell", args={"command": blocks[0].strip()}, feedback=result or "", cwd=cwd, active=active, extraction="fenced_action")
            else:
                # This corpus logs action proposals as assistant text, without a separate tool-call field.
                yield dict(seq=i, tool="extraction_unknown", args={}, feedback=result or "", cwd=cwd, active=active,
                           extraction=f"assistant_action_blocks_{len(blocks)}")
        return
    if source == "native":
        results = {e.get("tool_call_id"): e for e in row["events"] if e["type"] == "tool_result"}
        for event in row["events"]:
            if event["type"] != "tool_call":
                continue
            result = results.get(event.get("tool_call_id"), {})
            yield dict(seq=event["seq"], tool=event.get("tool", "unknown"), args=parse_args(event.get("input")),
                       feedback=dumps(result.get("content", "")), result_status=result.get("status", "unknown"),
                       exit_code=result.get("exit_code"), extraction="native_event")
        return
    messages = row["messages"]
    results = {}
    for m in messages:
        call_id = m.get("tool_call_id", m.get("call_id"))
        if call_id and (m.get("role") == "tool" or m.get("type") == "function_call_output"):
            results[call_id] = m
    for i, m in enumerate(messages):
        if source == "mini" and m.get("extra", {}).get("actions"):
            # Executed action text, as recorded by the harness, avoids provider escaping differences.
            for j, action in enumerate(m["extra"]["actions"]):
                result = results.get(action.get("tool_call_id"), {})
                yield dict(seq=f"{i}.{j}", tool="bash", args={"command": action["command"]},
                           feedback=result.get("extra", {}).get("raw_output", result.get("output", result.get("content", ""))),
                           exit_code=result.get("extra", {}).get("returncode"), extraction="harness_action", cwd="/testbed")
            continue
        if m.get("role") != "assistant":
            continue
        if m.get("tool_calls"):
            for j, call in enumerate(m["tool_calls"]):
                fn = call.get("function", {})
                result = results.get(call.get("id"), {})
                yield dict(seq=f"{i}.{j}", tool=fn.get("name", "unknown"), args=parse_args(fn.get("arguments")),
                           feedback=result.get("content", ""), exit_code=feedback_exit_code(result.get("content", "")), extraction="structured_tool_call")
            continue
        text = m.get("content") or ""
        for j, (tool, body) in enumerate(re.findall(r"<function=([^>]+)>(.*?)</function>", text, re.S)):
            args = dict(re.findall(r"<parameter=([^>]+)>(.*?)</parameter>", body, re.S))
            feedback = messages[i + 1].get("content", "") if i + 1 < len(messages) else ""
            yield dict(seq=f"{i}.{j}", tool=tool, args=args, feedback=feedback or "", exit_code=feedback_exit_code(feedback), extraction="xml_function")


def walk(node):
    yield node
    for key, value in vars(node).items():
        if key == "heredoc":
            continue
        if isinstance(value, bashlex.ast.node):
            yield from walk(value)
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, bashlex.ast.node):
                    yield from walk(child)


def literal_path(value):
    return bool(value and not re.search(r"[\s$`*?{}<>\n]", value) and value not in ("-", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/fd/1", "/dev/fd/2"))


def canonical(path, cwd):
    if not literal_path(path):
        return None
    return posixpath.normpath(path if path.startswith("/") else posixpath.join(cwd or "/__unknown_cwd__", path))


def python_literal_writes(code, cwd):
    """Recover literal Python write paths, without executing or importing any code.

    This does not change the inline_code class. It only supplies write-history
    evidence for later script executions. Dynamic strings and aliases are skipped.
    """
    try:
        tree=ast.parse(code)
    except (SyntaxError, ValueError):
        return []
    strings={}
    def value(node):
        if isinstance(node,ast.Constant) and isinstance(node.value,str):
            return node.value
        if isinstance(node,ast.Name):
            return strings.get(node.id)
        if isinstance(node,ast.Call) and isinstance(node.func,(ast.Name,ast.Attribute)) and node.args:
            name=node.func.id if isinstance(node.func,ast.Name) else node.func.attr
            if name in ("Path","PurePath","PurePosixPath"):
                parts=[value(a) for a in node.args]
                if all(p is not None for p in parts):
                    return posixpath.join(*parts)
        if isinstance(node,ast.BinOp):
            left,right=value(node.left),value(node.right)
            if left is not None and right is not None:
                if isinstance(node.op,ast.Add):
                    return left+right
                if isinstance(node.op,ast.Div):
                    return posixpath.join(left,right)
        return None
    writes=[]
    # Only process module-level statements and their literal expressions in order.
    # Branches are syntactic evidence, not a claim that the statement succeeded.
    def visit(node):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
            return
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            val=value(node.value)
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target,ast.Name):
                    strings.pop(target.id,None)
                    if val is not None:
                        strings[target.id]=val
        if isinstance(node,ast.Call):
            fn=node.func
            path=None
            if isinstance(fn,ast.Name) and fn.id=="open" and node.args:
                mode=value(node.args[1]) if len(node.args)>1 else next((value(k.value) for k in node.keywords if k.arg=="mode"),"r")
                if mode and any(c in mode for c in "wax+"):
                    path=value(node.args[0])
            elif isinstance(fn,ast.Attribute) and fn.attr in ("write_text","write_bytes","touch"):
                path=value(fn.value)
            if path:
                resolved=canonical(path,cwd)
                if resolved:
                    writes.append(resolved)
        for child in ast.iter_child_nodes(node):
            visit(child)
    visit(tree)
    return sorted(set(writes))


def shell_analysis(command, cwd=None, active=None):
    result = dict(classification="unknown", reason="unrecognized_command", writes=[], creates=[], executions=[],
                  runner=False, parser_error=False, inline=False, cwd=cwd, active=active)
    # SWE-agent special editor bodies are not shell syntax.
    special = re.match(r"^\s*(create|open|edit)\s+([^\n]+)", command)
    if special:
        op, arg = special.groups()
        if op in ("create", "open"):
            try:
                import shlex
                path = shlex.split(arg)[0]
            except (ValueError, IndexError):
                return result
            target = canonical(path, cwd)
            result["active"] = target
            result.update(classification="direct_edit" if op == "create" else "read_only", reason=f"swe_{op}")
            if op == "create" and target:
                result["writes"].append(target)
                result["creates"].append(target)
        else:
            result.update(classification="context_edit", reason="swe_edit_uses_open_file")
            if active:
                result["writes"].append(active)
        return result
    if not command.strip():
        result.update(classification="read_only", reason="poll_or_empty")
        return result
    try:
        # bashlex 0.18 does not remove delimiter quotes when matching heredocs.
        # Remove only quotes around simple delimiter identifiers for AST parsing.
        parse_command = re.sub(r"<<(\-?)\s*(['\"])([A-Za-z_]\w*)\2", r"<<\1\3", command)
        roots = bashlex.parse(parse_command + "\n")
        nodes = [node for root in roots for node in walk(root)]
    except (Exception, RecursionError):
        result.update(parser_error=True, reason="shell_parse_failure")
        return result
    classes, reasons = set(), set()
    write_order, execution_order = {}, []
    ordered_same_call = False
    cmd_nodes = sorted([n for n in nodes if n.kind == "command"], key=lambda x: x.pos[0])
    local_cwd = cwd
    for n in cmd_nodes:
        words = [p.word for p in n.parts if p.kind == "word"]
        redirects = [p for p in n.parts if p.kind == "redirect"]
        for redir in redirects:
            output = getattr(redir, "output", None)
            if redir.type in (">", ">>", ">|", "&>", "&>>", "<>") and isinstance(output, bashlex.ast.node):
                target = canonical(getattr(output, "word", ""), local_cwd)
                if target:
                    result["writes"].append(target)
                    write_order.setdefault(target,n.pos[0])
                    # A redirect could replace an existing file, so do not assert creation.
                    classes.add("direct_shell")
                    reasons.add("literal_redirect")
        if not words:
            continue
        exe = posixpath.basename(words[0])
        # Unwrap common process launchers, without interpreting arbitrary option payloads.
        while exe in ("env", "timeout", "time", "command", "sudo", "nice", "nohup") and len(words) > 1:
            words = words[1:]
            while words and (words[0].startswith("-") or "=" in words[0] or (exe in ("timeout", "nice") and re.fullmatch(r"\d+[smhd]?", words[0]))):
                words = words[1:]
            if not words:
                break
            exe = posixpath.basename(words[0])
        if not words:
            classes.add("read_only")
            continue
        args = words[1:]
        if exe == "cd" and args:
            local_cwd = canonical(args[0], local_cwd) or local_cwd
        if INTERPRETER.fullmatch(exe):
            shell_c = next((i for i,a in enumerate(args) if a.startswith("-") and not a.startswith("--") and "c" in a[1:]), None) if exe in ("bash", "sh", "zsh", "dash", "ksh") else None
            if shell_c is not None and shell_c + 1 < len(args):
                nested = shell_analysis(args[shell_c + 1], local_cwd, active)
                classes.add(nested["classification"])
                reasons.add("shell_c:" + nested["reason"])
                for key in ("writes", "creates", "executions"):
                    result[key].extend(nested[key])
                for key in ("runner", "inline", "parser_error"):
                    result[key] |= nested[key]
                ordered_same_call |= nested.get("same_call_author_then_execute",False)
                continue
            if "-c" in args or "-e" in args or "-" in args or any(r.type in ("<<", "<<-") for r in redirects) or not args:
                classes.add("inline_code")
                reasons.add("inline_interpreter")
                result["inline"] = True
                if exe.startswith(("python", "pypy")):
                    code = ""
                    if "-c" in args and args.index("-c")+1<len(args):
                        code = args[args.index("-c")+1]
                    for redirect in redirects:
                        heredoc=getattr(redirect,"heredoc",None)
                        if heredoc is not None:
                            # bashlex includes the closing delimiter in its heredoc value.
                            code="\n".join(heredoc.value.splitlines()[:-1])
                    paths=python_literal_writes(code,local_cwd)
                    result["writes"].extend(paths)
                    for path in paths:
                        write_order.setdefault(path,n.pos[0])
                continue
            if "-m" in args:
                classes.add("indirect")
                reasons.add("interpreter_module")
                result["runner"] = True
                continue
            file = next((a for a in args if not a.startswith("-")), None)
            if file and literal_path(file):
                target = canonical(file, local_cwd)
                result["executions"].append(target)
                execution_order.append((target,n.pos[0]))
                classes.add("indirect")
                reasons.add("interpreter_file")
            else:
                classes.add("unknown")
        elif exe in RUNNERS:
            classes.add("indirect")
            reasons.add("build_test_package_or_project_tool")
            result["runner"] = True
        elif exe in ("source", ".") and args:
            classes.add("indirect")
            reasons.add("sourced_file")
            result["executions"].append(canonical(args[0], local_cwd))
            execution_order.append((canonical(args[0],local_cwd),n.pos[0]))
        elif words[0].startswith(("./", "../", "/")) or re.search(r"\.(sh|py|pl|rb|js)$", words[0]):
            # Known system commands specified by absolute path retain normal semantics.
            if exe not in READ_CMDS | MUTATORS | {"git", "sed", "awk"}:
                classes.add("indirect")
                reasons.add("executable_path")
                result["executions"].append(canonical(words[0], local_cwd))
                execution_order.append((canonical(words[0],local_cwd),n.pos[0]))
            else:
                classes.add("direct_shell" if exe in MUTATORS else "read_only")
        elif exe in MUTATORS or (exe == "sed" and any(a == "--in-place" or a.startswith("--in-place=") or (a.startswith("-") and not a.startswith("--") and "i" in a[1:]) for a in args)):
            classes.add("direct_shell")
            reasons.add("named_shell_mutator")
            # Targets for these writers are recoverable without parsing option values.
            if exe in ("touch", "tee", "mkdir", "truncate"):
                candidates = [a for a in args if not a.startswith("-")]
            elif exe in ("cp", "mv", "install", "ln"):
                candidates = [a for a in args if not a.startswith("-")][-1:]
            elif exe == "sed":
                candidates = args[-1:] if args else []
            else:
                candidates = []
            for path in candidates:
                target = canonical(path, local_cwd)
                if target:
                    result["writes"].append(target)
                    write_order.setdefault(target,n.pos[0])
        elif exe == "git":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub in ("status", "diff", "log", "show", "grep", "ls-files", "rev-parse", "describe", "blame", "help", "ls-tree", "cat-file", "check-ignore"):
                classes.add("read_only")
            elif sub in ("checkout", "restore", "reset", "clean", "rm", "mv", "add", "commit", "apply", "switch", "branch", "init", "clone", "fetch", "pull", "merge", "rebase", "stash", "config", "update-index", "tag"):
                classes.add("direct_shell")
                reasons.add("git_operation")
            else:
                classes.add("unknown")
        elif exe == "sed":
            classes.add("read_only")
        elif exe in ("awk", "gawk", "xargs", "eval", "exec") or (exe == "find" and any(a in ("-exec", "-execdir", "-delete") for a in args)):
            classes.add("inline_code" if exe in ("awk", "gawk", "eval") else "indirect")
            reasons.add("dynamic_shell_dispatch")
        elif exe in READ_CMDS:
            classes.add("read_only")
        else:
            classes.add("unknown")
            reasons.add("unrecognized_command")
    # A call may both mutate an explicitly named file and launch project code.
    # Preserve component flags, then assign one mutually exclusive primary class.
    priority = ("indirect", "inline_code", "unknown", "direct_shell", "read_only")
    result["classification"] = next((c for c in priority if c in classes), "read_only")
    result["reason"] = "+".join(sorted(reasons)) or "read_or_shell_control"
    result["cwd"] = local_cwd
    result["components"] = sorted(classes)
    result["executions"] = [p for p in result["executions"] if p]
    result["writes"] = sorted(set(result["writes"]))
    # This flag only records a same-call co-occurrence. It does not establish ordering.
    result["same_call_write_exec_candidate"] = bool(set(result["writes"]) & set(result["executions"]))
    result["same_call_author_then_execute"] = ordered_same_call or any(p in write_order and write_order[p]<position for p,position in execution_order)
    return result


def classify(call, cwd, active):
    tool = call["tool"].lower()
    args = call["args"]
    path = args.get("path", args.get("file_path", args.get("file", "")))
    if tool in SHELL_TOOLS or tool == "swe_shell":
        return shell_analysis(str(args.get("command", args.get("cmd", args.get("text", "")))), cwd, active)
    result = dict(classification="unknown", reason="unrecognized_tool", writes=[], creates=[], executions=[],
                  runner=False, parser_error=False, inline=False, cwd=cwd, active=active)
    if tool in EDIT_TOOLS:
        operation = args.get("command", "")
        if operation == "view":
            result.update(classification="read_only", reason="editor_view")
        elif tool.endswith("apply_patch"):
            patch = args.get("patch", args.get("input", args.get("text", "")))
            paths = re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", str(patch), re.M)
            if paths:
                result.update(classification="direct_edit", reason="patch_paths")
                result["writes"] = [p for p in (canonical(x, cwd) for x in paths) if p]
                result["creates"] = [p for p in (canonical(x, cwd) for x in re.findall(r"^\*\*\* Add File: (.+)$", str(patch), re.M)) if p]
        elif path:
            result.update(classification="direct_edit", reason="editor_explicit_path")
            target = canonical(str(path).strip(), cwd)
            if target:
                result["writes"] = [target]
                if operation == "create":
                    result["creates"] = [target]
    elif tool in READ_TOOLS or tool.startswith(("web.", "web_", "todo")):
        result.update(classification="read_only", reason="read_or_control_tool")
    elif tool == "extraction_unknown":
        result["reason"] = call["extraction"]
    return result


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def analyze(raw):
    all_calls, trajectories, normalization_audit, extraction = [], [], [], Counter()
    with gzip.open(raw / "sampled_trajectories.jsonl.gz", "rt") as f:
        for line in f:
            row = json.loads(line)
            calls = list(normalize(row))
            messages=row.get("messages",row.get("trajectory",[]))
            normalization_audit.append(dict(trajectory_id=row["trajectory_id"],source=row["source"],framework=row["framework"],model=row["model"],
                                            source_messages=len(messages),
                                            nebius_action_slots=sum(m.get("role")=="ai" for m in messages) if row["source"]=="nebius" else 0,
                                            native_tool_events=sum(e["type"]=="tool_call" for e in row.get("events",[])),
                                            mini_harness_actions=sum(len(m.get("extra",{}).get("actions",[])) for m in messages),
                                            openhands_function_markers=sum(len(re.findall(r"<function=",m.get("content") or "")) for m in messages if m.get("role")=="assistant") if row["source"]=="openhands" else 0,
                                            extracted_calls=len(calls),zero_call_trajectory=int(not calls)))
            cwd, active = None, None
            written, created = {}, {}
            tcalls = []
            for index, call in enumerate(calls):
                cwd = call.get("cwd") or cwd
                active = call.get("active", active)
                args = call["args"]
                call_cwd = args.get("workdir", args.get("cwd", cwd))
                # A path on an editor call gives no evidence about the shell's cwd.
                result = classify(call, call_cwd, active)
                feedback = str(call.get("feedback") or "")
                status=reported_status(call,feedback)
                if call["tool"] == "swe_shell" and result["classification"] in ("direct_edit", "context_edit") and status != "failed" and "(Open file:" in feedback:
                    status = "success"
                if call["tool"] == "str_replace_editor" and re.search(r"(?i)(created successfully|has been edited|has been updated|successfully)", feedback[:500]):
                    status = "success"
                prior = [p for p in result["executions"] if p in written]
                prior_created = [p for p in result["executions"] if p in created]
                same_call=result.get("same_call_author_then_execute",False)
                identity = f"{row['trajectory_id']}:{call['seq']}"
                record = dict(call_id=identity, source=row["source"], framework=row["framework"], model=row["model"],
                              trajectory_id=row["trajectory_id"], instance_id=row.get("instance_id", "unavailable"),
                              call_index=index, source_seq=call["seq"], tool=call["tool"], classification=result["classification"],
                              reason=result["reason"], status=status, parser_error=int(result["parser_error"]),
                              explicit_write_paths=dumps(result["writes"]), executed_paths=dumps(result["executions"]),
                              author_then_execute=int(bool(prior) or same_call), earlier_call_author_then_execute=int(bool(prior)),
                              create_then_execute=int(bool(prior_created)),
                              confirmed_author_then_execute=int(any(written[p]["status"] == "success" for p in prior) or (same_call and status=="success")),
                              no_prior_write_script=int(bool(result["executions"]) and not prior and not same_call),
                              project_runner=int(result["runner"]), inline_component=int(result["inline"]),
                              same_call_write_exec_candidate=int(result.get("same_call_write_exec_candidate", False)),
                              same_call_author_then_execute=int(same_call),
                              author_call_ids=dumps([written[p]["id"] for p in prior]),
                              raw_file=row["raw_file"], raw_row=row["raw_row"],
                              argument_sha256=hashlib.sha256(dumps(args).encode()).hexdigest())
                record_full = dict(record, args=args, feedback=feedback[:2000], cwd=call_cwd, active=active)
                all_calls.append(record_full)
                tcalls.append(record)
                extraction[(row["source"], call["extraction"])]+=1
                if status != "failed":
                    for p in result["writes"]:
                        written[p] = {"id": identity, "status": status}
                    for p in result["creates"]:
                        created[p] = {"id": identity, "status": status}
                if row["source"] != "mini":
                    cwd = result["cwd"]
                    active = result["active"]
            count = Counter(c["classification"] for c in tcalls)
            trajectories.append(dict(trajectory_id=row["trajectory_id"], source=row["source"], framework=row["framework"],
                                     model=row["model"], instance_id=row.get("instance_id", "unavailable"), calls=len(tcalls),
                                     **{c:count[c] for c in CLASSES},
                                     any_indirect=int(count["indirect"]>0),
                                     any_author_then_execute=int(any(c["author_then_execute"] for c in tcalls)),
                                     any_earlier_call_author_then_execute=int(any(c["earlier_call_author_then_execute"] for c in tcalls)),
                                     any_same_call_author_then_execute=int(any(c["same_call_author_then_execute"] for c in tcalls)),
                                     any_confirmed_author_then_execute=int(any(c["confirmed_author_then_execute"] for c in tcalls)),
                                     any_create_then_execute=int(any(c["create_then_execute"] for c in tcalls)),
                                     any_no_prior_write_script=int(any(c["no_prior_write_script"] for c in tcalls)),
                                     any_project_runner=int(any(c["project_runner"] for c in tcalls)),
                                     parser_errors=sum(c["parser_error"] for c in tcalls)))
    with gzip.open(raw / "classified_calls.jsonl.gz", "wt") as f:
        for row in all_calls:
            f.write(dumps(row) + "\n")
    write_csv(HERE / "trajectories.csv", trajectories)
    write_csv(HERE / "normalization_audit.csv", normalization_audit)
    write_csv(HERE / "extraction_audit.csv", [dict(source=k[0], extraction=k[1], calls=v) for k,v in sorted(extraction.items())])
    # Sample across every framework/model/class, with deterministic selection.
    strata = defaultdict(list)
    for row in all_calls:
        strata[(row["framework"], row["model"], row["classification"])].append(row)
    sample=[]
    for key, rows in sorted(strata.items()):
        for row in sorted(rows, key=lambda r: hashlib.sha256(r["call_id"].encode()).hexdigest())[:4]:
            item={k:v for k,v in row.items() if k not in ("args", "feedback", "cwd", "active")}
            command=row["args"].get("command", row["args"].get("cmd", ""))
            item["argument_preview"] = (command.splitlines()[0][:160] if isinstance(command, str) and command else str(row["args"].get("path", row["args"].get("file_path", "")))[:160])
            sample.append(item)
    write_csv(HERE / "sample_calls.csv", sample)
    summaries=[]
    groups=defaultdict(list)
    for trajectory in trajectories:
        groups[(trajectory["framework"],trajectory["model"])].append(trajectory)
    for (framework, model), rows in sorted(groups.items()):
        totals={c:sum(r[c] for r in rows) for c in CLASSES}
        n, calls=len(rows),sum(r["calls"] for r in rows)
        summary=dict(framework=framework,model=model,trajectories=n,calls=calls,**totals)
        summary.update({c+"_pct":round(100*totals[c]/calls,4) if calls else "" for c in CLASSES})
        for metric in ("any_indirect", "any_author_then_execute", "any_earlier_call_author_then_execute", "any_same_call_author_then_execute", "any_confirmed_author_then_execute", "any_create_then_execute", "any_no_prior_write_script", "any_project_runner"):
            summary[metric]=sum(r[metric] for r in rows)
            summary[metric+"_pct"]=round(100*summary[metric]/n,4)
        summary["parser_errors"]=sum(r["parser_errors"] for r in rows)
        calls_in_group=[c for c in all_calls if c["framework"]==framework and c["model"]==model]
        for metric in ("author_then_execute","earlier_call_author_then_execute","same_call_author_then_execute","confirmed_author_then_execute","create_then_execute","no_prior_write_script","project_runner","inline_component"):
            summary[metric+"_calls"]=sum(c[metric] for c in calls_in_group)
        summary["failed_calls"]=sum(c["status"]=="failed" for c in calls_in_group)
        summary["unknown_status_calls"]=sum(c["status"]=="unknown" for c in calls_in_group)
        summaries.append(summary)
    write_csv(HERE / "summary.csv", summaries)
    print(dumps(summaries))


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--raw", type=Path, required=True)
    analyze(p.parse_args().raw)
