"""R5-CHROME-C1A own-workload-PID rendezvous: policy, helper, observer and PID-preserving chain.

Portable only: synthetic files, mocked getpid/execv, and one documented departure from mocked
process observation: a real chain of project-authored Python stubs (cnt_pipe_exec -> a loader
for the helper -> a stub standing in for sandbox-exec). No sandbox-exec, browser, Mach call,
codesign, ps scan, network or Nix. Native semantics stay host-pending.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

WS, LS = 'com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd'
# Pre-edit (PREP2 entry = HEAD cnt_confinement.py) templates for the fixed Chrome-shaped
# synthetic configuration below, computed once from the entry export and pinned.
GOLDEN = {(): '2f07a1b57d222245ff7bba5acad4110c1b6e210b7e3d49fc557b06b11445d923',
          (WS,): '0a8065593c9bdebab57c4677c9d6ae43ebe229e9d6d82cbf941d8a82ba21a713',
          (WS, LS): 'be51c2ff0a4054200fb5f404609a7786ad094ea6a711bfa6ce099d3580bcfd34'}
FIREFOX_DEFAULT = 'fab8c31ce797f36a63fc7ae1e4f08f406e363add0a6a7dbc8844cc0f024e048a'
RULE_TEXT = ('(allow mach-register mach-lookup (global-name (string-append '
             '"com.google.Chrome.MachPortRendezvousServer." (param "CHROME_RENDEZVOUS_PID"))))\n')
SB = '/usr/bin/sandbox-exec'


@pytest.fixture
def modules(monkeypatch, repo_root, tmp_path):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_chrome_rendezvous as rv
    import cnt_confinement as boundary
    monkeypatch.setattr(boundary, 'SCRATCH', tmp_path)
    run = tmp_path / 'attempt'
    (run / 'runtime').mkdir(parents=True)
    # Synthetic store: run itself, so run/runtime is both an accepted owned root and a closure root.
    monkeypatch.setattr(rv, 'STORE', str(run))
    executable = run / 'runtime/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    executable.parent.mkdir(parents=True)
    return rv, boundary, run, executable


def chrome(boundary, run, services=(WS, LS), **kw):
    return boundary.policy(run, [run / 'runtime'], services, None, firefox_child_ipc=False, **kw)


def template(boundary, text, run, **kw):
    return boundary.policy_evidence(text, run, None, False, **kw)['policy_template_sha256']


# ---- policy -------------------------------------------------------------------------------

@pytest.mark.parametrize('services', list(GOLDEN))
def test_absent_or_false_option_keeps_pre_edit_chrome_bytes(modules, services):
    rv, boundary, run, _ = modules
    absent = chrome(boundary, run, services)
    assert chrome(boundary, run, services, chrome_rendezvous=False) == absent
    assert template(boundary, absent, run) == GOLDEN[services]
    assert 'MachPortRendezvousServer' not in absent and 'param' not in absent
    assert boundary.policy_evidence(absent, run, None, False, services) == boundary.policy_evidence(
        absent, run, None, False, services, chrome_rendezvous=False)


def test_firefox_default_bytes_unchanged(modules):
    rv, boundary, run, _ = modules
    bundle = run / 'runtime/Firefox.app'
    bundle.mkdir()
    kw = dict(firefox_child_ipc=True, firefox_executable=bundle / 'Contents/MacOS/firefox')
    text = boundary.policy(run, [bundle], (WS, LS), 12345, **kw)
    assert boundary.policy(run, [bundle], (WS, LS), 12345, chrome_rendezvous=False, **kw) == text
    assert boundary.policy_evidence(text, run, 12345, True)['policy_template_sha256'] == FIREFOX_DEFAULT
    assert 'rendezvous' not in json.dumps(boundary.policy_evidence(text, run, 12345, True, (WS, LS)))


@pytest.mark.parametrize('services', list(GOLDEN))
def test_selected_adds_exactly_one_final_rule(modules, services):
    rv, boundary, run, exe = modules
    without = chrome(boundary, run, services)
    text = chrome(boundary, run, services, chrome_rendezvous=True, chrome_executable=exe)
    assert rv.RULE == RULE_TEXT and text == without + RULE_TEXT
    assert text.count('MachPortRendezvousServer') == 1 and text.count('mach-register') == 1
    assert 'global-name-regex' not in text and '*' not in RULE_TEXT and not any(c.isdigit() for c in RULE_TEXT)
    assert len(text.splitlines()) == len(without.splitlines()) + 1


def test_selected_keeps_every_existing_denial(modules):
    rv, boundary, run, exe = modules
    text = chrome(boundary, run, chrome_rendezvous=True, chrome_executable=exe)
    assert '(deny default)' in text and '(allow default)' not in text and '(deny network*)' in text
    assert '(deny mach-lookup ' + ' '.join('(global-name ' + json.dumps(s) + ')'
                                          for s in boundary.CREDENTIAL_SERVICES) + ')' in text
    assert '(deny file-write* (subpath ' + json.dumps(str(run / 'runtime')) + '))' in text
    assert text.count('(allow mach-lookup (global-name ') == 2 and 'SystemConfiguration' not in text
    assert '(allow network-outbound' not in text and 'localhost:' not in text


def test_policy_evidence_selected_and_subtraction(modules):
    rv, boundary, run, exe = modules
    without = chrome(boundary, run)
    text = chrome(boundary, run, chrome_rendezvous=True, chrome_executable=exe)
    plain = boundary.policy_evidence(text, run, None, False, (WS, LS))
    selected = boundary.policy_evidence(text, run, None, False, (WS, LS), chrome_rendezvous=True)
    assert set(selected) - set(plain) == {'chrome_rendezvous', 'rendezvous_parameter', 'rendezvous_rule_sha256',
                                          'policy_template_without_rendezvous_sha256', 'rendezvous_lookup_register',
                                          'rendezvous_residual'}
    assert selected['policy_template_sha256'] != GOLDEN[(WS, LS)]
    assert selected['policy_template_without_rendezvous_sha256'] == GOLDEN[(WS, LS)] == template(boundary, without, run)
    assert selected['chrome_rendezvous'] == 'OWN_WORKLOAD_PID'
    assert selected['rendezvous_parameter'] == 'CHROME_RENDEZVOUS_PID'
    assert selected['rendezvous_rule_sha256'] == hashlib.sha256(RULE_TEXT.encode()).hexdigest()
    assert selected['rendezvous_lookup_register'] == 'POLICY_ALLOWED_NOT_EXERCISED'
    assert 'not the process' in selected['rendezvous_residual'] and 'crashpad' in selected['rendezvous_residual']
    for broken in (without, text + RULE_TEXT, text.replace(RULE_TEXT, '') + RULE_TEXT + '\n',
                   RULE_TEXT + without):
        evidence = boundary.policy_evidence(broken, run, None, False, (WS, LS), chrome_rendezvous=True)
        assert evidence['policy_template_without_rendezvous_sha256'] is None


@pytest.mark.parametrize('case', ['firefox-ipc', 'port', 'configd', 'chromium', 'outside-roots', 'string-path',
                                  'missing-executable', 'too-deep', 'outside-store'])
def test_selected_refuses_outside_the_chrome_lane(modules, case):
    rv, boundary, run, exe = modules
    kw = dict(chrome_rendezvous=True, chrome_executable=exe)
    roots, services, port, ipc = [run / 'runtime'], (WS, LS), None, False
    if case == 'firefox-ipc':
        bundle = run / 'runtime/Firefox.app'
        bundle.mkdir()
        roots, ipc = [bundle], True
        kw['firefox_executable'] = bundle / 'Contents/MacOS/firefox'
    elif case == 'port':
        port = 12345
    elif case == 'configd':
        services = (WS, boundary.CONFIGD)
    elif case == 'chromium':
        kw['chrome_executable'] = run / 'runtime/Applications/Chromium.app/Contents/MacOS/Chromium'
    elif case == 'outside-roots':
        other = run / 'other'
        kw['chrome_executable'] = other / 'Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    elif case == 'string-path':
        kw['chrome_executable'] = str(exe)
    elif case == 'missing-executable':
        kw['chrome_executable'] = None
    elif case == 'too-deep':
        kw['chrome_executable'] = run / 'runtime/x/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    elif case == 'outside-store':
        rv.STORE = str(run / 'elsewhere')
    with pytest.raises(RuntimeError, match='Chrome rendezvous requires the selected Chrome lane|configd'):
        boundary.policy(run, roots, services, port, firefox_child_ipc=ipc, **kw)


@pytest.mark.parametrize('value', [1, 0, 'true', None, 'OWN_WORKLOAD_PID'])
def test_option_must_be_a_literal_bool(modules, value):
    rv, boundary, run, exe = modules
    with pytest.raises(RuntimeError, match='Chrome rendezvous option invalid'):
        chrome(boundary, run, chrome_rendezvous=value, chrome_executable=exe)


def test_executable_without_option_refuses(modules):
    rv, boundary, run, exe = modules
    with pytest.raises(RuntimeError, match='Chrome rendezvous requires the selected Chrome lane'):
        chrome(boundary, run, chrome_executable=exe)


# ---- helper -------------------------------------------------------------------------------

class Execd(BaseException):
    pass


def private_dir(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def sandboxed(run, program=None):
    return [SB, '-f', str(run / 'confinement.sb'), str(program or '/nix/store/p-python/bin/python3'),
            '-B', str(run / 'probe.py'), 'x']


def invoke(rv, evidence, label, command, pid=4242, environ=None, execv=None, getpid=None):
    calls = []
    def fake_execv(path, argv):
        calls.append((path, argv))
        raise Execd
    try:
        code = rv.main([str(evidence), label, '--', *command], environ or {'PATH': '/usr/bin:/bin'},
                       getpid=getpid or (lambda: pid), execv=execv or fake_execv)
    except Execd:
        code = 'EXEC'
    return code, calls


def lines(evidence, label):
    return [json.loads(line) for line in (evidence / ('rendezvous-' + label + '.json')).read_text().splitlines()]


def test_helper_execs_the_exact_argv_with_its_own_pid(modules, tmp_path, monkeypatch):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    monkeypatch.setattr(os, 'getppid', lambda: pytest.fail('getppid is never a PID source'))
    command = sandboxed(run)
    before = set(os.listdir('/dev/fd'))
    seen = {}
    def execv(path, argv):
        seen.update(path=path, argv=argv, fds=set(os.listdir('/dev/fd')),
                    record=(evidence / 'rendezvous-canary.json').read_text())
        raise Execd
    code, _ = invoke(rv, evidence, 'canary', command, execv=execv)
    assert code == 'EXEC' and seen['path'] == SB
    assert seen['argv'] == [SB, '-D', 'CHROME_RENDEZVOUS_PID=4242', *command[1:]]
    assert seen['fds'] == before  # record and directory descriptors closed before exec
    record = json.loads(seen['record'])
    assert set(record) == {'schema', 'label', 'state', 'pid', 'salt', 'argv_template_sha256'}
    assert (record['state'], record['pid'], record['label']) == ('EXEC', 4242, 'canary')
    assert record['argv_template_sha256'] == rv.argv_template_sha256(
        [SB, '-D', 'CHROME_RENDEZVOUS_PID=<RENDEZVOUS_PID>', *command[1:]])
    assert oct((evidence / 'rendezvous-canary.json').stat().st_mode & 0o777) == oct(0o600)


def test_browser_label_runs_only_the_bound_chrome_executable(modules, tmp_path):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    command = [SB, '-f', str(run / 'confinement.sb'), str(exe), '--headless=new', '--remote-debugging-pipe']
    code, calls = invoke(rv, evidence, 'browser', command)
    assert code == 'EXEC' and calls[0][1][:3] == [SB, '-D', 'CHROME_RENDEZVOUS_PID=4242']
    assert calls[0][1][3:] == command[1:]


@pytest.mark.parametrize('pid', [0, 1, -1, True, '4242', 2 ** 31, None, 4242.0])
def test_invalid_own_pid_refuses_without_exec(modules, tmp_path, pid):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    code, calls = invoke(rv, evidence, 'canary', sandboxed(run), pid=pid)
    assert code == 125 and calls == []
    assert lines(evidence, 'canary') == [{'schema': rv.SCHEMA, 'label': 'canary', 'state': 'REFUSED',
                                          'code': 'INVALID_PARAMETER'}]


@pytest.mark.parametrize('case,code', [
    ('dash-D', 'INJECTED_PARAMETER'), ('attached-D', 'INJECTED_PARAMETER'), ('named', 'INJECTED_PARAMETER'),
    ('service', 'INJECTED_PARAMETER'), ('dash-p', 'INJECTED_PARAMETER'), ('dash-n', 'INJECTED_PARAMETER'),
    ('environment', 'INJECTED_PARAMETER'), ('wrong-sandbox', 'ARGV_SHAPE'), ('no-f', 'ARGV_SHAPE'),
    ('relative-policy', 'ARGV_SHAPE'), ('policy-name', 'ARGV_SHAPE'), ('relative-program', 'ARGV_SHAPE'),
    ('short', 'ARGV_SHAPE'), ('canary-runs-chrome', 'PROGRAM'), ('browser-runs-python', 'PROGRAM'),
    ('browser-outside-store', 'PROGRAM')])
def test_injected_or_malformed_commands_refuse(modules, tmp_path, case, code):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    label, command, environ = 'canary', sandboxed(run), None
    if case == 'dash-D':
        command += ['-D', 'CHROME_RENDEZVOUS_PID=1']
    elif case == 'attached-D':
        command.append('-DX=1')
    elif case == 'named':
        command.append('x-CHROME_RENDEZVOUS_PID')
    elif case == 'service':
        command.append('com.google.Chrome.MachPortRendezvousServer.1')
    elif case in ('dash-p', 'dash-n'):
        command.append('-' + case[-1])
    elif case == 'environment':
        environ = {'CHROME_RENDEZVOUS_PID': '1'}
    elif case == 'wrong-sandbox':
        command[0] = '/usr/bin/env'
    elif case == 'no-f':
        command[1] = '-p'
    elif case == 'relative-policy':
        command[2] = 'confinement.sb'
    elif case == 'policy-name':
        command[2] = str(run / 'other.sb')
    elif case == 'relative-program':
        command[3] = 'python3'
    elif case == 'short':
        command = command[:3]
    elif case == 'canary-runs-chrome':
        command[3] = str(exe)
    elif case == 'browser-runs-python':
        label = 'browser'
    elif case == 'browser-outside-store':
        label, command[3] = 'browser', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    result, calls = invoke(rv, evidence, label, command, environ=environ)
    assert result == 125 and calls == []
    assert lines(evidence, label) == [{'schema': rv.SCHEMA, 'label': label, 'state': 'REFUSED', 'code': code}]


@pytest.mark.parametrize('case', ['missing-separator', 'bad-label'])
def test_usage_refusals_write_nothing(modules, tmp_path, case):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    argv = ([str(evidence), 'canary', *sandboxed(run)] if case == 'missing-separator'
            else [str(evidence), 'chrome', '--', *sandboxed(run)])
    assert rv.main(argv, {}, getpid=lambda: 4242, execv=lambda *a: pytest.fail('exec')) == 125
    assert list(evidence.iterdir()) == []


@pytest.mark.parametrize('case', ['relative', 'symlink', 'mode-0755', 'file', 'missing', 'record-present'])
def test_evidence_directory_refusals(modules, tmp_path, monkeypatch, case):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    target = evidence
    if case == 'relative':
        monkeypatch.chdir(tmp_path)
        target = Path('ev')
    elif case == 'symlink':
        target = tmp_path / 'alias'
        target.symlink_to(evidence, target_is_directory=True)
    elif case == 'mode-0755':
        evidence.chmod(0o755)
    elif case == 'file':
        target = tmp_path / 'plain'
        target.write_text('')
    elif case == 'missing':
        target = tmp_path / 'absent'
    elif case == 'record-present':
        (evidence / 'rendezvous-canary.json').write_text('earlier\n')
        (evidence / 'rendezvous-canary.json').chmod(0o600)
    code, calls = invoke(rv, target, 'canary', sandboxed(run))
    assert code == 125 and calls == []
    if case == 'record-present':
        assert (evidence / 'rendezvous-canary.json').read_text() == 'earlier\n'
    else:
        assert list(evidence.iterdir()) == []


def test_exec_failure_is_recorded_and_never_retried(modules, tmp_path):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    calls = []
    def missing(path, argv):
        calls.append(argv)
        raise OSError(errno.ENOENT, 'synthetic')
    code, _ = invoke(rv, evidence, 'canary', sandboxed(run), execv=missing)
    assert code == 127 and len(calls) == 1
    first, second = lines(evidence, 'canary')
    assert first['state'] == 'EXEC' and second == {'schema': rv.SCHEMA, 'label': 'canary',
                                                   'state': 'EXEC_FAILED', 'errno': errno.ENOENT}


# ---- observer -----------------------------------------------------------------------------

def helper_record(rv, evidence, label, command, pid=4242):
    code, _ = invoke(rv, evidence, label, command, pid=pid)
    assert code == 'EXEC'


def canary_pid(path, pid, mode=0o600, raw=None):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.write(descriptor, raw if raw is not None else json.dumps({'pid': pid}).encode())
    os.close(descriptor)
    os.chmod(path, mode)


@pytest.mark.parametrize('case,state', [
    ('match', 'MATCHED_WORKLOAD'), ('other-pid', 'PID_MISMATCH'), ('supervisor-pid', 'PID_MISMATCH'),
    ('argv', 'ARGV_MISMATCH'), ('absent', 'RECORD_ABSENT'), ('garbage', 'RECORD_INVALID'),
    ('oversized', 'RECORD_INVALID'), ('symlink', 'RECORD_INVALID'), ('group-readable', 'RECORD_INVALID'),
    ('wrong-label', 'RECORD_INVALID'), ('three-lines', 'RECORD_INVALID'), ('bool-pid', 'RECORD_INVALID'),
    ('unobserved', 'WORKLOAD_UNOBSERVED'), ('bool-workload', 'WORKLOAD_UNOBSERVED'),
    ('refused', 'HELPER_REFUSED'), ('invalid-parameter', 'INVALID_PARAMETER'), ('exec-failed', 'EXEC_FAILED')])
def test_browser_observation_states(modules, tmp_path, case, state):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    command = [SB, '-f', str(run / 'confinement.sb'), str(exe), '--remote-debugging-pipe']
    record = evidence / 'rendezvous-browser.json'
    workload = 4242
    if case not in ('absent', 'refused', 'invalid-parameter', 'exec-failed', 'symlink'):
        # 'supervisor-pid': the helper ran with the supervisor's number instead of the workload's.
        helper_record(rv, evidence, 'browser', command, pid=4241 if case == 'supervisor-pid' else 4242)
    if case == 'other-pid':
        workload = 4343
    elif case == 'argv':
        command = command + ['--extra']
    elif case == 'garbage':
        record.write_bytes(b'{not json\n')
        record.chmod(0o600)
    elif case == 'oversized':
        record.write_bytes(b' ' * 5000)
        record.chmod(0o600)
    elif case == 'symlink':
        other = tmp_path / 'other.json'
        other.write_text('{}')
        record.symlink_to(other)
    elif case == 'group-readable':
        record.chmod(0o640)
    elif case == 'wrong-label':
        record.write_text(record.read_text().replace('"browser"', '"canary"'))
    elif case == 'three-lines':
        record.write_text(record.read_text() * 3)
    elif case == 'bool-pid':
        record.write_text(record.read_text().replace('"pid": 4242', '"pid": true'))
    elif case == 'unobserved':
        workload = None
    elif case == 'bool-workload':
        workload = True
    elif case == 'refused':
        invoke(rv, evidence, 'browser', command + ['-D'])
    elif case == 'invalid-parameter':
        invoke(rv, evidence, 'browser', command, pid=0)
    elif case == 'exec-failed':
        invoke(rv, evidence, 'browser', command, execv=lambda *a: (_ for _ in ()).throw(OSError(errno.EACCES, 'x')))
    value = rv.observe(evidence, 'browser', workload, command)
    assert value['state'] == state and set(value) == set(rv.observation('X'))
    assert rv.matched(value) is (state == 'MATCHED_WORKLOAD')
    assert value['sandboxed_pid_matches'] is None
    exported = json.dumps(rv.project(value))
    assert '4242' not in exported and '4241' not in exported and str(tmp_path) not in exported
    assert 'MachPortRendezvousServer' not in exported
    if case == 'refused':
        assert value['helper_code'] == 'INJECTED_PARAMETER'
    if case == 'exec-failed':
        assert value['exec_errno'] == errno.EACCES
    if case in ('other-pid', 'supervisor-pid'):
        assert value['workload_pid_matches'] is False and value['argv_template_matches'] is True


@pytest.mark.parametrize('case,state', [
    ('match', 'MATCHED_WORKLOAD'), ('absent', 'SANDBOXED_PID_UNOBSERVED'), ('different', 'PID_MISMATCH'),
    ('garbage', 'SANDBOXED_PID_UNOBSERVED'), ('extra-key', 'SANDBOXED_PID_UNOBSERVED'),
    ('group-writable', 'SANDBOXED_PID_UNOBSERVED'), ('workload-differs', 'PID_MISMATCH')])
def test_canary_observation_requires_the_sandboxed_program_report(modules, tmp_path, case, state):
    rv, boundary, run, exe = modules
    evidence = private_dir(tmp_path / 'ev')
    command = sandboxed(run)
    helper_record(rv, evidence, 'canary', command)
    report = run / 'canary-pid.json'
    if case in ('match', 'workload-differs'):
        canary_pid(report, 4242)
    elif case == 'different':
        canary_pid(report, 4343)
    elif case == 'garbage':
        canary_pid(report, None, raw=b'garbage')
    elif case == 'extra-key':
        canary_pid(report, None, raw=json.dumps({'pid': 4242, 'x': 1}).encode())
    elif case == 'group-writable':
        canary_pid(report, 4242, mode=0o620)
    value = rv.observe(evidence, 'canary', 4343 if case == 'workload-differs' else 4242, command, report)
    assert value['state'] == state
    assert rv.matched(value, canary=True) is (state == 'MATCHED_WORKLOAD')
    assert rv.matched(value) is False  # a canary match is never a browser-shaped match
    if case == 'match':
        assert value['sandboxed_pid_matches'] is True
    if case == 'different':
        assert value['sandboxed_pid_matches'] is False and value['workload_pid_matches'] is True


def test_salted_record_digest_does_not_reveal_the_pid(modules, tmp_path):
    rv, boundary, run, exe = modules
    digests = set()
    canary_pid(run / 'canary-pid.json', 4242)
    for name in ('a', 'b'):
        evidence = private_dir(tmp_path / name)
        helper_record(rv, evidence, 'canary', sandboxed(run))
        digests.add(rv.observe(evidence, 'canary', 4242, sandboxed(run), run / 'canary-pid.json')['record_sha256'])
    assert len(digests) == 2
    brute = {hashlib.sha256(json.dumps({'pid': n}).encode()).hexdigest() for n in range(4200, 4300)}
    assert not digests & brute


def test_observer_label_misuse_raises(modules, tmp_path):
    rv, boundary, run, exe = modules
    with pytest.raises(ValueError):
        rv.observe(tmp_path, 'canary', 1, sandboxed(run))
    with pytest.raises(ValueError):
        rv.observe(tmp_path, 'browser', 1, sandboxed(run), tmp_path / 'x')
    with pytest.raises(ValueError):
        rv.observe(tmp_path, 'other', 1, sandboxed(run))


def test_projection_revalidates(modules):
    rv, *_ = modules
    assert rv.project(None) is None
    assert rv.project({'state': 'SOMETHING', 'workload_pid_matches': 1, 'record_sha256': '/private/x',
                       'helper_code': 'ARBITRARY', 'exec_errno': '2'}) == {
        'state': 'UNCLASSIFIED', 'workload_pid_matches': None, 'argv_template_matches': None,
        'sandboxed_pid_matches': None, 'record_sha256': None, 'helper_code': None, 'exec_errno': None}


# ---- PID-preserving chain (real Python stubs) ---------------------------------------------

LOADER = r'''
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('rendezvous_under_test', sys.argv[1])
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.STORE, module.SANDBOX_EXEC = sys.argv[2], sys.argv[3]
raise SystemExit(module.main(sys.argv[4:], os.environ))
'''

STUB = r'''#!{python} -B
import json, os, stat, sys
report = {{'pid': os.getpid(), 'argv': sys.argv[1:], 'fds': {{}}}}
for fd in (3, 4):
    try:
        info = os.fstat(fd)
        report['fds'][str(fd)] = [info.st_dev, info.st_ino, stat.S_ISFIFO(info.st_mode)]
    except OSError:
        report['fds'][str(fd)] = None
if report['fds']['3'] and report['fds']['4']:
    os.write(4, os.read(3, 16).upper())
if sys.argv[6] == 'canary':
    fd = os.open(os.path.join(os.path.dirname(sys.argv[7]), 'canary-pid.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, json.dumps({{'pid': os.getpid()}}).encode()); os.close(fd)
with open(sys.argv[7], 'w') as stream:
    json.dump(report, stream)
'''

CHAIN = r'''
import fcntl, json, os, select, subprocess, sys
tests, loader, helper, store, stub, evidence, program, report, layout = sys.argv[1:10]
sys.path.insert(0, tests)
import cnt_chrome_rendezvous as rv
rv.STORE = store
for fd in (3, 4):
    try: os.close(fd)
    except OSError: pass
if layout == 'occupied':
    for _ in range(2): os.open(os.devnull, os.O_RDONLY)
a, b = os.pipe(); c, d = os.pipe()
if layout in ('absent', 'reversed'):
    original = (a, b, c, d)
    a, b, c, d = [fcntl.fcntl(fd, fcntl.F_DUPFD, 20) for fd in original]
    for fd in original: os.close(fd)
if layout == 'reversed':
    # The child's read end sits on 4 and its write end on 3: the remapper must swap them.
    os.dup2(d, 3); os.close(d); d = 3
    os.dup2(a, 4); os.close(a); a = 4
label = 'canary' if layout == 'canary' else 'browser'
sandboxed = [stub, '-f', os.path.join(os.path.dirname(report), 'confinement.sb'), program, label, report]
inner = [sys.executable, '-B', loader, helper, store, stub, evidence, label, '--', *sandboxed]
fds = [] if label == 'canary' else [a, d]
argv = ([sys.executable, '-B', os.path.join(tests, 'cnt_pipe_exec.py'), json.dumps(fds), *inner]
        if fds else inner)
process = subprocess.Popen(argv, pass_fds=tuple(fds), close_fds=True, cwd=os.path.dirname(report))
os.close(a); os.close(d)
echoed = None
if fds:
    os.write(b, b'nonce')
    echoed = os.read(c, 16).decode() if select.select([c], [], [], 10)[0] else 'TIMEOUT'
code = process.wait(10)
rv.SANDBOX_EXEC = stub
observed = rv.observe(evidence, label, process.pid, sandboxed,
                      os.path.join(os.path.dirname(report), 'canary-pid.json') if label == 'canary' else None)
print(json.dumps({'popen_pid': process.pid, 'code': code, 'echoed': echoed,
                  'report': json.load(open(report)), 'observed': observed}))
'''


@pytest.mark.parametrize('layout', ['plain', 'absent', 'occupied', 'reversed', 'canary'])
def test_real_chain_preserves_pid_parameter_and_descriptors(repo_root, tmp_path, layout):
    tests = repo_root / 'tests'
    store = tmp_path / 'store'
    program = (store / 'h-google-chrome/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
               if layout != 'canary' else store / 'p-python/bin/python3')
    work = private_dir(tmp_path / 'work')
    evidence = private_dir(tmp_path / 'evidence')
    (tmp_path / 'loader.py').write_text(LOADER)
    stub = tmp_path / 'sandbox-exec-stub'
    stub.write_text(STUB.format(python=sys.executable))
    stub.chmod(0o755)
    result = subprocess.run([sys.executable, '-B', '-c', CHAIN, str(tests), str(tmp_path / 'loader.py'),
                             str(tests / 'cnt_chrome_rendezvous.py'), str(store), str(stub), str(evidence),
                             str(program), str(work / 'report.json'), layout],
                            capture_output=True, text=True, timeout=30, env={'PATH': '/usr/bin:/bin',
                                                                             'PYTHONDONTWRITEBYTECODE': '1'})
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    report = out['report']
    assert out['code'] == 0 and report['pid'] == out['popen_pid']
    assert report['argv'][:2] == ['-D', 'CHROME_RENDEZVOUS_PID=' + str(out['popen_pid'])]
    assert report['argv'][2:] == ['-f', str(work / 'confinement.sb'), str(program),
                                  'canary' if layout == 'canary' else 'browser', str(work / 'report.json')]
    assert out['observed']['state'] == 'MATCHED_WORKLOAD'
    if layout == 'canary':
        assert out['observed']['sandboxed_pid_matches'] is True and report['fds'] == {'3': None, '4': None}
        assert out['echoed'] is None
    else:
        assert report['fds']['3'][2] is True and report['fds']['4'][2] is True and out['echoed'] == 'NONCE'


def test_wrapped_helper_ignores_python_environment_and_user_site(modules, tmp_path):
    """Real exec of wrap()'s argv: -I keeps PYTHONPATH and HOME's user site out of the unconfined helper."""
    rv, _, _, _ = modules
    evidence = private_dir(tmp_path / 'evidence')
    home = tmp_path / 'home'
    shadow = tmp_path / 'shadow'
    shadow.mkdir()
    json_sentinel = tmp_path / 'json_sentinel.txt'
    user_sentinel = tmp_path / 'usercustomize_sentinel.txt'
    (shadow / 'json.py').write_text(
        f"with open({str(json_sentinel)!r}, 'w') as stream:\n"
        "    stream.write('shadow-json\\n')\nraise SystemExit(98)\n")
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'PYTHONPATH': str(shadow)}
    site = subprocess.run([sys.executable, '-B', '-c', 'import site; print(site.getusersitepackages())'],
                          capture_output=True, text=True, timeout=30, env={'PATH': '/usr/bin:/bin',
                                                                           'HOME': str(home)}).stdout.strip()
    assert site.startswith(str(home))
    Path(site).mkdir(parents=True)
    (Path(site) / 'usercustomize.py').write_text(
        f"with open({str(user_sentinel)!r}, 'w') as stream:\n"
        "    stream.write('usercustomize\\n')\nraise SystemExit(99)\n")
    argv = rv.wrap(evidence, 'canary', ['/bin/false'])
    assert argv[:4] == [sys.executable, '-B', '-I', rv.HELPER]
    result = subprocess.run(argv, capture_output=True, timeout=30, env=env)
    # The helper ran with the standard library and refused the argv shape without exec.
    assert result.returncode == 125, result.stderr
    record = json.loads((evidence / 'rendezvous-canary.json').read_text())
    assert record == {'schema': rv.SCHEMA, 'label': 'canary', 'state': 'REFUSED', 'code': 'ARGV_SHAPE'}
    assert not json_sentinel.exists() and not user_sentinel.exists()
    # Control: without -I the same environment reaches at least one planted hook.
    # Site-init SystemExit(99) can yield process status 1; require the hook's
    # sentinel rather than depending on CPython's exception-to-status translation.
    control = subprocess.run([argv[0], '-B', *argv[3:]], capture_output=True, timeout=30, env=env)
    assert control.returncode != 0
    assert any(sentinel.exists() and sentinel.read_text() == expected
               for sentinel, expected in ((json_sentinel, 'shadow-json\n'),
                                          (user_sentinel, 'usercustomize\n')))
