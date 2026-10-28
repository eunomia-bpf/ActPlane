"""Visibility and edit-replay semantics, fixed before examining dynamic outcomes."""
from pathlib import Path
from dynamic_effects import visibility
from replay_tools import apply_patch,run


def test_basename_visibility_is_deliberately_liberal():
    assert visibility('/repo/nested/result.json',{'command':'cat result.json'},'/repo','write')['named']==1
    assert visibility('/repo/nested/result.json',{'command':'cat result.json'},'/repo','write')['strict_named']==0
    assert visibility('/repo/a.py',{'command':'cat a.py.bak'},'/repo','write')['named']==0
    assert visibility('/repo/a.py',{'command':'cat a.py.bak'},'/repo','write')['strict_named']==0
    assert visibility('/repo/a.py',{'command':'echo x > ./a.py'},'/repo','write')['strict_named']==1


def test_entrypoint_does_not_name_descendant_effect():
    assert visibility('/tmp/hidden.txt',{'command':'python helper.py'},'/repo','write')['named']==0
    assert visibility('/usr/bin/python',{'command':'python helper.py'},'/repo','exec')['named']==1
    assert visibility('/bin/git',{'command':'python helper.py'},'/repo','exec')['named']==0


def test_inline_literals_count_and_directories_do_not():
    assert visibility('/tmp/hidden.txt',{'command':'python -c "open(\'hidden.txt\',\'w\')"'},'/repo','write')['named']==1
    assert visibility('/repo/tests/cache.txt',{'command':'pytest tests/'},'/repo','write')['named']==0


def test_globs_are_shell_words_not_embedded_program_arithmetic():
    assert visibility('/repo/test_a.py',{'command':'rm test_*.py'},'/repo','write')['named']==1
    assert visibility('/tmp/hidden.txt',{'command':"python - <<'PY'\na * b\nPY"},'/repo','write')['named']==0


def test_truncation_is_unknown():
    assert visibility('/repo/very_long..',{'command':'make'},'/repo','write')['named']==-1
    path='/repo/'+('nested/'*40)+'out.txt'
    assert visibility(path,{'command':'cat out.txt'},'/repo','write')['named']==-1
    assert visibility(path,{'command':'cat out.txt'},'/repo','write',1024)['named']==1


def test_edit_and_patch_apply_bytes_without_oracle(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    run('Write',{'file_path':'src/a.py','content':'x=1\n'})
    run('Edit',{'file_path':'src/a.py','old_string':'x=1','new_string':'x=2'})
    assert Path('src/a.py').read_text()=='x=2\n'
    apply_patch('*** Begin Patch\n*** Update File: src/a.py\n@@\n-x=2\n+x=3\n*** Add File: helper.py\n+print(1)\n*** End Patch')
    assert Path('src/a.py').read_text()=='x=3\n'
    assert Path('helper.py').read_text()=='print(1)\n'
