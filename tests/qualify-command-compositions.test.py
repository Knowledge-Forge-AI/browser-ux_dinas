"""Qualification conditions must survive optimized Python execution."""
import ast
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize('override', [False, True])
@pytest.mark.parametrize('timeout', [False, True])
def test_pinned_acquisition_flags_and_timeout(tmp_path, override, timeout):
    from types import SimpleNamespace
    import json
    source = Path(__file__).with_name('qualify-command-compositions.py').read_text()
    definition = next(ast.get_source_segment(source, n) for n in ast.parse(source).body
                      if isinstance(n, ast.FunctionDef) and n.name == 'run')
    commands = []
    def invoke(command, **kwargs):
        commands.append(command)
        if timeout: raise subprocess.TimeoutExpired(command, kwargs['timeout'])
        return SimpleNamespace(returncode=0, stdout='{}', stderr='')
    namespace = dict(counter=0, args=SimpleNamespace(scratch=tmp_path), root=tmp_path,
                     Path=Path, json=json,
                     subprocess=SimpleNamespace(run=invoke, TimeoutExpired=subprocess.TimeoutExpired))
    exec(definition, namespace)
    command = ['nix', 'build', 'path:/fixture#check']
    if override: command += ['--override-input', 'browser-ux_dinas', 'path:/candidate']
    if timeout:
        with pytest.raises(RuntimeError, match='TIMEOUT'): namespace['run'](command)
    else: namespace['run'](command)
    assert '--offline' not in commands[0]
    assert '--no-write-lock-file' in commands[0]
    assert ('--no-update-lock-file' in commands[0]) is (not override)
    assert commands[0][-4:] == ['--max-jobs', '1', '--cores', '2']
    record = json.loads((tmp_path / 'command-1.json').read_text())
    assert record['status'] == ('TIMEOUT' if timeout else 'PASS')


@pytest.mark.parametrize('optimized', [False, True])
def test_qualification_failure_is_not_optimized_away(optimized):
    source = Path(__file__).with_name('qualify-command-compositions.py').read_text()
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(tree))
    guard = next(node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name == 'require')
    program = ast.get_source_segment(source, guard) + '''
require(True, 'valid input')
require(False, 'synthetic State C drift')
'''
    result = subprocess.run([sys.executable, *(['-O'] if optimized else []), '-c', program],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert 'RuntimeError: synthetic State C drift' in result.stderr


@pytest.mark.parametrize('optimized', [False, True])
def test_private_graph_isolation_and_real_drift(optimized):
    source = Path(__file__).with_name('qualify-command-compositions.py').read_text()
    names = {'require', 'browser_override', 'compare_graph'}
    definitions = '\n'.join(ast.get_source_segment(source, node) for node in ast.parse(source).body
                            if isinstance(node, ast.FunctionDef) and node.name in names)
    program = definitions + '''
lock = {'locks': {'root': 'root', 'nodes': {
 'root': {'inputs': {'composition-nd': 'old-public', 'alias': ['composition-nd','browser-ux_dinas']}},
 'old-public': {'locked': {'rev': 'old'}, 'inputs': {'browser-ux_dinas': 'browser'}},
 'browser': {'locked': {'rev': 'old-browser'}},
 'new-public': {'locked': {'rev': 'new'}, 'inputs': {'vm': 'new-vm'}},
 'new-vm': {'locked': {'rev': 'new-vm'}}}}}
flags, allowed = browser_override(lock, 'private', '/candidate')
require(flags == ['--override-input','composition-nd/browser-ux_dinas','path:/candidate'], 'public substitution')
require(allowed == {'/composition-nd/browser-ux_dinas','/alias'}, 'wrong aliases')
p = {'policyHash': 'same', 'braveWriters': 1, 'videoWriters': 1}
for kind in ('input','descendant','policy','writer','claim','closure'):
 before = {'/composition-nd': 'old', '/composition-nd/browser-ux_dinas': 'old-browser'}
 after = dict(before, **{'/composition-nd/browser-ux_dinas':'new-browser'})
 projections = [[dict(p)], [dict(p)]]; systems = [['same'], ['same']]; claims = [[], []]
 if kind == 'input': after['/composition-nd'] = 'new-public'
 if kind == 'descendant': after['/composition-nd/browser-ux_dinas/nixpkgs'] = 'drift'
 if kind == 'policy': projections[1][0]['policyHash'] = 'changed'
 if kind == 'writer': projections[1][0]['braveWriters'] = 2
 if kind == 'claim': claims[1].append('unexpected')
 if kind == 'closure': systems[1].append('unexpected')
 try: compare_graph('private',before,after,allowed,projections,systems,claims,[p])
 except RuntimeError: pass
 else: raise RuntimeError('drift accepted: '+kind)

# Equal baseline/candidate projections must still match accepted policy and
# independently enforce one writer. Check the specific rejecting guard.
for kind in ('accepted-policy', 'braveWriters', 'videoWriters'):
 candidate = dict(p)
 accepted = dict(p)
 if kind == 'accepted-policy': accepted['policyHash'] = 'accepted-other'
 else: candidate[kind] = 2
 expected = 'accepted baseline policy drift' if kind == 'accepted-policy' else 'writer count drift'
 try:
  compare_graph('private', {}, {}, set(), [[candidate], [candidate]], [[], []], [[], []], [accepted])
 except RuntimeError as error:
  require(expected in str(error), 'wrong isolated failure: '+str(error))
 else: raise RuntimeError('isolated drift accepted: '+kind)
compare_graph('private', {}, {}, set(), [[p], [p]], [[], []], [[], []], [p])

# A second Browser-bearing route may follow the target, but cannot retain a
# distinct old Browser node while the primary route is overridden.
lock['locks']['nodes']['root']['inputs']['browser-ux_dinas'] = ['composition-nd', 'browser-ux_dinas']
browser_override(lock, 'private', '/candidate')
lock['locks']['nodes']['other-browser'] = {'locked': {'rev': 'other'}}
lock['locks']['nodes']['root']['inputs']['browser-ux_dinas'] = 'other-browser'
try: browser_override(lock, 'private', '/candidate')
except RuntimeError as error:
 require('Unexpected Browser topology' in str(error), 'wrong topology failure')
else: raise RuntimeError('multiple Browser nodes accepted')
'''
    result = subprocess.run([sys.executable, *(['-O'] if optimized else []), '-c', program],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
