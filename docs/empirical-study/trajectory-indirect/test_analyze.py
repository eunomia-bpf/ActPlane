"""Regression cases for false visibility and trajectory extraction errors."""
import json
import pytest
from analyze import shell_analysis, classify, normalize, python_literal_writes, feedback_exit_code, reported_status


@pytest.mark.parametrize("command,category", [
    ("cat src/a.py | head -20", "read_only"),
    ("rg 'python helper.py' src", "read_only"),
    ("cat > helper.py <<'PY'\nprint('pytest')\nPY", "direct_shell"),
    ("python helper.py", "indirect"),
    ("python3 -u /tmp/helper.py", "indirect"),
    ("bash helper.sh", "indirect"),
    ("./helper.sh", "indirect"),
    ("make test", "indirect"),
    ("python -m pytest tests/test_a.py", "indirect"),
    ("npm install", "indirect"),
    ("cd /repo && pytest -q", "indirect"),
    ("timeout 60s env A=x python helper.py", "indirect"),
    ("python -c 'print(1)'", "inline_code"),
    ("python - <<'PY'\nfrom pathlib import Path\nPath('a').write_text('x')\nPY", "inline_code"),
    ("bash -lc 'cat a.py | head'", "read_only"),
    ("bash -lc 'cd /repo && make test'", "indirect"),
    ("rm -f a.py", "direct_shell"),
    ("sed -i 's/a/b/' a.py", "direct_shell"),
    ("sed -n '1,20p' a.py", "read_only"),
    ("git diff -- a.py", "read_only"),
    ("git checkout -- a.py", "direct_shell"),
    ("find . -name '*.py' -exec python {} \\;", "indirect"),
    ("cat a | xargs sh", "indirect"),
    ("unknown_command a.py", "unknown"),
    ("create helper.py", "direct_edit"),
    ("edit 1:3\nprint('x')\nend_of_edit", "context_edit"),
])
def test_categories(command, category):
    assert shell_analysis(command, "/repo", "/repo/a.py")["classification"] == category


def test_script_paths_and_heredoc_not_executed():
    r = shell_analysis("cat > helper.py <<'PY'\npython not_really_executed.py\nPY\npython helper.py", "/repo")
    assert r["writes"] == ["/repo/helper.py"]
    assert r["executions"] == ["/repo/helper.py"]
    assert r["same_call_write_exec_candidate"]
    assert r["same_call_author_then_execute"]


def test_same_call_order_matters():
    r=shell_analysis("python helper.py; echo x > helper.py",'/repo')
    assert r['same_call_write_exec_candidate']
    assert not r['same_call_author_then_execute']
    r=shell_analysis("python helper.py > helper.py",'/repo')
    assert not r['same_call_author_then_execute']


def test_feedback_context():
    row = {"source":"nebius", "trajectory":[
        {"role":"user", "text":"(Open file: /repo/h.py)\n(Current directory: /repo)"},
        {"role":"ai", "text":"Edit.\n```\nedit 1:2\nx=1\nend_of_edit\n```"},
        {"role":"user", "text":"ok"}]}
    c=list(normalize(row))[0]
    assert c["cwd"] == "/repo"
    assert c["active"] == "/repo/h.py"
    assert classify(c,c["cwd"],c["active"])["writes"] == ["/repo/h.py"]


def test_mini_actions_are_not_double_counted():
    row={"source":"mini", "messages":[{"role":"assistant", "extra":{"actions":[{"command":"pytest", "tool_call_id":"a"}]},
         "tool_calls":[{"id":"a", "function":{"name":"bash","arguments":json.dumps({"command":"pytest"})}}]},
         {"role":"tool","tool_call_id":"a","extra":{"returncode":0,"raw_output":"ok"}}]}
    calls=list(normalize(row))
    assert len(calls)==1
    assert calls[0]["exit_code"] == 0


def test_patch_editor_paths():
    c={"tool":"apply_patch","args":{"text":"*** Begin Patch\n*** Add File: helper.py\n+x=1\n*** End Patch"}}
    r=classify(c,"/repo",None)
    assert r["classification"] == "direct_edit"
    assert r["creates"] == ["/repo/helper.py"]


def test_inline_literal_writes_and_dynamic_exclusions():
    code="""from pathlib import Path
p=Path('/tmp')/'reproduce.py'
p.write_text('print(1)')
with open('other.py','w') as f:
    f.write('x')
open(input(), 'w').write('unknown')
def unused():
    open('not_executed.py','w').write('x')
"""
    assert python_literal_writes(code,'/repo')==['/repo/other.py','/tmp/reproduce.py']
    r=shell_analysis("python - <<'PY'\n"+code+"PY",'/repo')
    assert r['classification']=='inline_code'
    assert r['writes']==['/repo/other.py','/tmp/reproduce.py']


def test_recorded_exit_code_beats_arbitrary_error_text():
    assert feedback_exit_code('Traceback quoted in source\n[Command finished with exit code 0]')==0
    assert feedback_exit_code('[Command finished with exit code 2]')==2
    assert feedback_exit_code('No recorded status') is None
    assert reported_status({'exit_code':0},'quoted error: in a source file')=='success'
    assert reported_status({'exit_code':1,'result_status':'success'},'')=='failed'
    assert reported_status({'result_status':'success'},'quoted error: in a source file')=='success'
    assert reported_status({},'No recorded status')=='unknown'
