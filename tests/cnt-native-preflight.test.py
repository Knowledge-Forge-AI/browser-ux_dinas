"""Injected orchestration failures: no browser, subprocess, or live sockets."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

@pytest.fixture
def harness(load_module, monkeypatch, tmp_path, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    m = load_module('tests/cnt-native-preflight.py')
    run = tmp_path / 'attempt'
    args = SimpleNamespace(engine='firefox', abnormal=False, scratch=run,
                           runtime=tmp_path / 'Firefox.app', service=[], nested_sandbox_exception=[])
    def fresh(path, on_created):
        path.mkdir()
        on_created(path)
        return path
    monkeypatch.setattr(m, 'fresh_attempt', fresh)
    def prepare(args, run, record):
        record['signature'] = {'original': True, 'frozen': True}
        record['runtime_snapshot_sha256'] = 'expected'
        record['runtime_preparation_complete'] = True
        exe = run / 'firefox'
        exe.write_bytes(b'synthetic')
        return exe, [], 'expected'
    monkeypatch.setattr(m, 'prepare_runtime', prepare)
    monkeypatch.setattr(m, 'runtime_roots', lambda _: [])
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def bind(self, *_): pass
        def listen(self): pass
        def getsockname(self): return ('127.0.0.1', 12345)
    monkeypatch.setattr(m, 'reserve_port', lambda *a: Socket())
    monkeypatch.setattr(m.socket, 'socket', Socket)
    def probe(*a, **kw):
        (run / 'confinement.sb').write_bytes(b'policy')
        return {'status': 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION',
                'policy_sha256': m.hashlib.sha256(b'policy').hexdigest()}
    monkeypatch.setattr(m, 'run_probe', probe)
    monkeypatch.setattr(m, 'arguments', lambda *a: [])
    def launch(*a, result, **kw):
        result.update(ready=True, page_nonce=True, extension_nonce=True, extension_unloaded=True,
                      quit_observed='reply', exit_before_cleanup=0,
                      parent_probes_completed=True, crash_readback_completed=True,
                      settlement={'exit_code': 0, 'zero_survivors': True, 'unsettled': False,
                                  'failures': [], 'workload_status': 'exited'})
    monkeypatch.setattr(m, 'launch_empty', launch)
    monkeypatch.setattr(m, 'tree_digest', lambda _, **kw: 'expected')
    return m, args, run


def test_runtime_drift_retains_all_observed_facts(harness, monkeypatch):
    m, args, run = harness
    monkeypatch.setattr(m, 'tree_digest', lambda _, **kw: 'changed')
    assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert r['runtime_snapshot_sha256'] == 'expected'
    assert r['runtime_observed_sha256'] == 'changed'
    assert r['settlement']['exit_code'] == 0 and r['extension_unloaded']
    assert r['runtime_failure']['stage'] == 'runtime-verification'

@pytest.mark.parametrize('code', [-11, None])
def test_no_exception_does_not_make_unknown_or_crash_normal(harness, monkeypatch, code):
    m, args, run = harness
    launch = m.launch_empty
    def bad(*a, result, **kw):
        launch(*a, result=result, **kw)
        result['exit_before_cleanup'] = code
        result['settlement']['exit_code'] = code
    monkeypatch.setattr(m, 'launch_empty', bad)
    assert m.attempt(args) == 2
    assert json.loads((run / 'result.json').read_text())['status'] == 'BLOCKED'

@pytest.mark.parametrize('stage', ['prepare_runtime', 'run_probe', 'launch_empty', 'tree_digest'])
@pytest.mark.parametrize('error', [OSError, RuntimeError, KeyboardInterrupt])
def test_failures_always_finalize(harness, monkeypatch, stage, error):
    m, args, run = harness
    def fail(*a, **kw): raise error('synthetic')
    monkeypatch.setattr(m, stage, fail)
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt): m.attempt(args)
    else: assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert r['status'] == 'BLOCKED'
    assert (r.get('primary_failure') or r.get('runtime_failure'))['type'] == error.__name__


def test_success_requires_normal_evidence(harness):
    m, args, run = harness
    assert m.attempt(args) == 0
    assert json.loads((run / 'result.json').read_text())['status'] == 'SYNTHETIC_ATTEMPT_PASSED'


def test_partial_root_setup_finalized(harness, monkeypatch):
    m, args, run = harness
    def fresh(path, on_created):
        path.mkdir(); on_created(path); raise OSError('child directory')
    monkeypatch.setattr(m, 'fresh_attempt', fresh)
    assert m.attempt(args) == 2
    assert json.loads((run / 'result.json').read_text())['primary_failure']['stage'] == 'attempt-root'


def test_evidence_io_preserves_primary_and_reports_stderr(harness, monkeypatch, capsys):
    m, args, run = harness
    def fail(*a, **kw): raise RuntimeError('primary')
    monkeypatch.setattr(m, 'prepare_runtime', fail)
    monkeypatch.setattr(m.Path, 'write_text', lambda *a, **kw: (_ for _ in ()).throw(OSError('disk')))
    assert m.attempt(args) == 2
    out = capsys.readouterr()
    assert 'Attempt evidence IO failed: OSError' in out.err
    assert json.loads(out.out)['primary_failure']['type'] == 'RuntimeError'
    assert not (run / 'result.json').exists()


@pytest.mark.parametrize('interrupt', [False, True])
def test_browser_primary_and_cleanup_remain_separate(harness, monkeypatch, interrupt):
    m, args, run = harness
    run.mkdir()
    import cnt_owned_process, cnt_synthetic_firefox
    class Owner:
        returncode = -11
        result = {'exit_code': -11, 'zero_survivors': False, 'unsettled': True}
        def __init__(self, *a, **kw): pass
        def settle(self): raise OSError('cleanup')
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    def session(*a):
        a[2]['page_nonce'] = True
        raise KeyboardInterrupt() if interrupt else RuntimeError('observation')
    monkeypatch.setattr(cnt_synthetic_firefox, 'session', session)
    # Load the real launch routine separately: harness replaces orchestration launch.
    source = (Path(m.__file__)).read_text()
    import ast
    tree = ast.parse(source)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    record = {}
    if interrupt:
        with pytest.raises(KeyboardInterrupt): namespace['launch_empty']([], run, 'firefox', result=record)
    else: namespace['launch_empty']([], run, 'firefox', result=record)
    assert record['primary_failure']['type'] == ('KeyboardInterrupt' if interrupt else 'RuntimeError')
    assert record['cleanup_failure']['type'] == 'OSError'
    assert record['settlement']['exit_code'] == -11 and record['page_nonce']


@pytest.mark.parametrize('failure', ['copy', 'original-signature', 'frozen-signature', 'drift'])
def test_real_runtime_preparation_retains_partial_facts(harness, monkeypatch, failure):
    m, args, run = harness
    import ast
    tree = ast.parse(Path(m.__file__).read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare_runtime')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    prepare = namespace['prepare_runtime']
    run.mkdir(); args.runtime.mkdir()
    (args.runtime / 'data').write_text('synthetic')
    calls = []
    def verify(*a, **kw):
        calls.append(True)
        failed = failure == ('original-signature' if len(calls) == 1 else 'frozen-signature')
        return SimpleNamespace(returncode=1 if failed else 0)
    monkeypatch.setattr(m.subprocess, 'run', verify)
    if failure == 'copy':
        monkeypatch.setattr(m.shutil, 'copytree', lambda *a, **kw: (_ for _ in ()).throw(OSError()))
    if failure == 'drift':
        namespace['tree_digest'] = lambda p: 'expected' if p == args.runtime else 'changed'
    record = {}
    with pytest.raises(Exception): prepare(args, run, record)
    assert record['runtime_source_sha256'] == 'expected'
    assert record['runtime_preparation_complete'] is False
    assert 'runtime_snapshot_sha256' not in record
    assert record['signature']['original'] is (failure != 'original-signature')


@pytest.mark.parametrize('failure', ['original-signature', 'partial-copy', 'frozen-signature',
                                     'post-launch-drift', 'preflight-drift', 'executable-drift'])
def test_preparation_through_persisted_finalization(harness, monkeypatch, failure):
    m, args, run = harness
    import ast
    from cnt_native_evidence import tree_digest
    tree = ast.parse(Path(m.__file__).read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare_runtime')
    namespace = dict(m.__dict__, tree_digest=tree_digest)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    monkeypatch.setattr(m, 'prepare_runtime', namespace['prepare_runtime'])
    monkeypatch.setattr(m, 'tree_digest', tree_digest)
    exe = args.runtime / 'Contents/MacOS/firefox'
    exe.parent.mkdir(parents=True); exe.write_bytes(b'synthetic')
    calls = []
    def verify(command, **kw):
        calls.append(command)
        label = 'original-signature' if len(calls) == 1 else 'frozen-signature'
        return SimpleNamespace(returncode=int(failure == label))
    monkeypatch.setattr(m.subprocess, 'run', verify)
    if failure == 'partial-copy':
        def partial(source, bundle, **kw):
            bundle.mkdir(parents=True); (bundle / 'partial').write_bytes(b'partial')
            raise OSError('partial copy')
        monkeypatch.setattr(m.shutil, 'copytree', partial)
    if failure in ('post-launch-drift', 'preflight-drift'):
        original = m.launch_empty if failure == 'post-launch-drift' else m.run_probe
        def drift(*a, **kw):
            (run / 'runtime/Firefox.app/drift').write_bytes(b'changed')
            if failure == 'preflight-drift': raise RuntimeError('preflight failure')
            return original(*a, **kw)
        monkeypatch.setattr(m, 'launch_empty' if failure == 'post-launch-drift' else 'run_probe', drift)
    if failure == 'executable-drift':
        original_prepare = m.prepare_runtime
        def missing(*a):
            result = original_prepare(*a)
            result[0].unlink()
            return result
        monkeypatch.setattr(m, 'prepare_runtime', missing)
    assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert r['status'] == 'BLOCKED'
    assert r['runtime_source_sha256'] == tree_digest(args.runtime)
    complete = failure.endswith('drift')
    assert r['runtime_preparation_complete'] is complete
    assert r['browser_launched'] is (failure == 'post-launch-drift')
    if complete:
        assert r['runtime_unchanged'] is False and r['runtime_failure']
        assert r['runtime_verification'] == ('POST_EXECUTION' if failure == 'post-launch-drift'
                                            else 'COMPLETED_PREPARATION_NO_LAUNCH')
        if failure == 'post-launch-drift':
            assert r['extension_unloaded'] and r['settlement']['exit_code'] == 0
        else: assert r['primary_failure']
    else:
        assert r['runtime_unchanged'] is None and 'runtime_failure' not in r
        assert 'runtime_observed_sha256' not in r and 'runtime_snapshot_sha256' not in r
        assert r['runtime_verification'] == 'NOT_APPLICABLE_PREPARATION_INCOMPLETE'
        assert r['primary_failure']['stage'] == 'runtime-preparation'


@pytest.mark.parametrize('workload', ['full', 'empty', 'page', None, 'navigate-away'])
@pytest.mark.parametrize('observer', [False, True, None])
@pytest.mark.parametrize('probes', [False, True, None])
def test_acceptance_explicitly_requires_full_uninstrumented(harness, workload, observer, probes):
    m, args, run = harness
    assert m.attempt(args) == 0
    r = json.loads((run / 'result.json').read_text())
    r.update(workload=workload, shutdown_observer=observer, parent_probes=probes)
    assert m.passed(r) is (workload == 'full' and observer is False and probes is False)
    for field in ['workload', 'shutdown_observer', 'parent_probes', 'crash_readback', 'shutdown_trace',
                  'runtime_preparation_complete']:
        missing = dict(r); missing.pop(field)
        assert not m.passed(missing)


@pytest.mark.parametrize('workload,probes', [('empty', False), ('page', False), ('full', True)])
def test_diagnostic_never_emits_acceptance(harness, workload, probes):
    m, args, run = harness
    args.workload, args.parent_probes = workload, probes
    assert m.attempt(args) == 2
    assert json.loads((run / 'result.json').read_text())['status'] == 'DIAGNOSTIC_COMPLETED'


def test_observer_and_late_log_read_removed(harness):
    m, _, _ = harness
    import cnt_synthetic_firefox
    assert not hasattr(cnt_synthetic_firefox, 'shutdown_observer')
    for module in [m, cnt_synthetic_firefox]:
        source = Path(module.__file__).read_text()
        assert 'shutdown-phases.log' not in source
        assert 'addObserver' not in source
        assert 'xpcom-shutdown' not in source


def test_active_crash_readback_is_diagnostic(harness):
    m, args, run = harness
    args.crash_readback = True
    assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert r['status'] == 'DIAGNOSTIC_COMPLETED' and not m.passed(r)


def test_passive_crash_inspection_refuses_links(harness, tmp_path):
    m, args, run = harness
    run.mkdir(); (run / 'profile').mkdir()
    outside = tmp_path / 'outside'; outside.mkdir()
    (outside / 'private.dmp').write_bytes(b'private')
    (run / 'profile/minidumps').symlink_to(outside, target_is_directory=True)
    (run / 'tmp').mkdir(); (run / 'tmp/owned.dmp').write_bytes(b'owned')
    (run / 'tmp/link.extra').symlink_to(outside / 'private.dmp')
    result = m.owned_crash_artifacts(run)
    assert result['profile/minidumps']['status'] == 'REFUSED_LINK'
    assert 'tmp' not in result
    assert result['crash-data']['status'] == 'ABSENT_DIRECTORY'


@pytest.mark.parametrize('workload,probes,readback', [('full', False, False), ('empty', False, False),
                                                    ('page', False, False), ('full', True, False),
                                                    ('empty', False, True)])
def test_real_launch_routes_only_requested_work(harness, monkeypatch, workload, probes, readback):
    m, args, run = harness
    import ast, cnt_owned_process, cnt_synthetic_firefox as firefox
    run.mkdir(); calls = []
    class Owner:
        returncode = 0
        result = {}
        def __init__(self, *a, **kw): pass
        def settle(self): return {'exit_code': 0}
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    client = SimpleNamespace(methods=[], valid=True, sample=lambda *a, **kw: None,
                             connection=SimpleNamespace(close=lambda: calls.append('close')))
    monkeypatch.setattr(firefox, 'session', lambda *a: (client, {}))
    monkeypatch.setattr(firefox, 'qualify', lambda *a, page_only=False: calls.append('page' if page_only else 'full'))
    monkeypatch.setattr(firefox, 'confinement_checks', lambda *a: calls.append('probes'))
    monkeypatch.setattr(firefox, 'crash_reporter_status', lambda *a: calls.append('readback'))
    monkeypatch.setattr(firefox, 'quit_normally', lambda *a: calls.append('quit'))
    node = next(n for n in ast.parse(Path(m.__file__).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    result = namespace['launch_empty']([], run, 'firefox', workload=workload,
                                       parent_probes=probes, crash_readback=readback)
    assert ('full' in calls) is (workload == 'full')
    assert ('page' in calls) is (workload == 'page')
    assert ('probes' in calls) is probes and ('readback' in calls) is readback
    assert calls[-2:] == ['quit', 'close'] and result['shutdown_observer'] is False


@pytest.mark.parametrize('stage', ['prepare_runtime', 'run_probe', 'launch_empty', 'tree_digest'])
@pytest.mark.parametrize('error', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_diagnostic_failure_and_interrupt_end_to_end(harness, monkeypatch, stage, error):
    m, args, run = harness; args.workload = 'empty'
    def fail(*a, **kw): raise error('synthetic')
    monkeypatch.setattr(m, stage, fail)
    if issubclass(error, Exception): assert m.attempt(args) == 2
    else:
        with pytest.raises(error): m.attempt(args)
    record = json.loads((run / 'result.json').read_text())
    assert record['status'] == 'DIAGNOSTIC_FAILED' and record['diagnostic_only'] is True
    assert (record.get('primary_failure') or record.get('runtime_failure'))['type'] == error.__name__


@pytest.mark.parametrize('bad', ['cleanup', 'drift', 'crash', 'eof', 'combined', 'missing-ready',
                                'missing-settlement', 'missing-failures', 'missing-readback', 'missing-probes'])
def test_diagnostic_outcome_requires_complete_facts(harness, monkeypatch, bad):
    m, args, run = harness; args.workload = 'empty'
    args.crash_readback = args.parent_probes = True
    launch = m.launch_empty
    def injected(*a, result, **kw):
        launch(*a, result=result, **kw)
        if bad in ('cleanup', 'combined'): result['cleanup_failure'] = {'type': 'OSError'}
        if bad in ('crash', 'combined'):
            result['primary_failure'] = {'classification': 'Unexpected normal browser exit'}
            result['exit_before_cleanup'] = -11
        if bad == 'eof': result.pop('quit_observed')
        for case, field in [('missing-ready','ready'), ('missing-settlement','settlement'),
                            ('missing-readback','crash_readback_completed'),
                            ('missing-probes','parent_probes_completed')]:
            if bad == case: result.pop(field)
        if bad == 'missing-failures': result['settlement'].pop('failures')
    monkeypatch.setattr(m, 'launch_empty', injected)
    if bad in ('drift', 'combined'): monkeypatch.setattr(m, 'tree_digest', lambda _, **kw: 'changed')
    assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert r['status'] == 'DIAGNOSTIC_FAILED' and r['diagnostic_only'] is True
    if bad == 'combined': assert r['primary_failure'] and r['cleanup_failure'] and r['runtime_failure']


@pytest.mark.parametrize('failure_call', [1, 2])
def test_diagnostic_persistence_failure_not_completed(harness, monkeypatch, capsys, failure_call):
    m, args, run = harness; args.workload = 'empty'
    original = m.persist; calls = []
    def fail_once(*a):
        calls.append(True)
        return False if len(calls) == failure_call else original(*a)
    monkeypatch.setattr(m, 'persist', fail_once)
    assert m.attempt(args) == 2
    r = json.loads(capsys.readouterr().out)
    assert r['status'] == 'DIAGNOSTIC_FAILED' and r['evidence_io_failure'] is True


def test_crash_data_separate_and_force_enable_explicit(harness, monkeypatch):
    m, args, run = harness
    monkeypatch.setenv('MOZ_CRASHREPORTER_DISABLE', '1')
    monkeypatch.setenv('MOZ_CRASHREPORTER', 'arbitrary')
    ordinary = m.browser_environment(run, 'firefox')
    enabled = m.browser_environment(run, 'firefox', crash_force_enable=True)
    assert 'MOZ_CRASHREPORTER' not in ordinary and 'MOZ_CRASHREPORTER_DISABLE' not in enabled
    assert enabled == dict(ordinary, MOZ_CRASHREPORTER='1')
    assert ordinary['MOZ_CRASHREPORTER_DATA_DIRECTORY'] == str(run / 'crash-data')
    assert ordinary['TMPDIR'] == str(run / 'tmp')
    assert ordinary['MOZ_CRASHREPORTER_NO_REPORT'] == '1'


def test_effective_crash_data_has_separate_provenance(harness):
    m, args, run = harness
    for name in ('crash-data', 'home/Library/Application Support/Firefox/Crash Reports', 'tmp'):
        (run / name).mkdir(parents=True)
        (run / name / 'sample.dmp').write_bytes(b'synthetic')
    relative = 'home/Library/Application Support/Firefox/Crash Reports'
    r = m.owned_crash_artifacts(run, {'enabled': True, 'data_directory_relative': relative})
    assert r[relative]['counts']['dmp'] == 1
    assert r[relative]['provenance'] == 'effective-data-environment-readback'
    assert 'tmp' not in r
    assert relative not in m.owned_crash_artifacts(run, {'enabled': False})


@pytest.mark.parametrize('force', [False, True])
def test_force_option_recorded_in_acceptance(harness, force):
    m, args, run = harness; args.crash_force_enable = force
    assert m.attempt(args) == 0
    record = json.loads((run / 'result.json').read_text())
    assert record['crash_force_enable'] is force
    record.pop('crash_force_enable')
    assert not m.passed(record)


def test_owned_inspection_failure_is_diagnostic_failure(harness, monkeypatch):
    m, args, run = harness; args.workload = 'empty'
    import ast, cnt_owned_process, cnt_synthetic_firefox as firefox
    class Owner:
        returncode = -11
        result = {'exit_code': -11, 'zero_survivors': True, 'unsettled': False,
                  'failures': [], 'workload_status': 'exited'}
        def __init__(self, *a, **kw): pass
        def settle(self): return self.result
        def until(self, predicate, timeout): return predicate()
    client = SimpleNamespace(methods=[], valid=True, call=lambda *a: {},
                             sample=lambda *a, **kw: None, connection=SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    monkeypatch.setattr(firefox, 'session', lambda *a: (client, {}))
    def fail(*a): raise OSError('owned inspection')
    monkeypatch.setattr(m, 'owned_crash_artifacts', fail)
    node = next(n for n in ast.parse(Path(m.__file__).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    monkeypatch.setattr(m, 'launch_empty', namespace['launch_empty'])
    assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert r['status'] == 'DIAGNOSTIC_FAILED' and r['diagnostic_only'] is True
    assert r['primary_failure']['classification'] == 'Unexpected normal browser exit'
    assert r['evidence_io_failure']['stage'] == 'owned-crash-inspection'
    assert r['exit_before_cleanup'] == -11 and r['runtime_unchanged'] is True


@pytest.mark.parametrize('interrupt', [False, True])
def test_diagnostic_root_failure_finalizes_without_directory(harness, monkeypatch, capsys, interrupt):
    m, args, run = harness; args.workload = 'empty'; retained = []
    original = m.record_failure
    def observe(record, *a):
        retained.append(record); original(record, *a)
    monkeypatch.setattr(m, 'record_failure', observe)
    def fail(*a, **kw): raise KeyboardInterrupt() if interrupt else OSError('root')
    monkeypatch.setattr(m, 'fresh_attempt', fail)
    if interrupt:
        with pytest.raises(KeyboardInterrupt): m.attempt(args)
    else: assert m.attempt(args) == 2
    assert retained[0]['status'] == 'DIAGNOSTIC_FAILED'
    assert retained[0]['diagnostic_only'] is True
    assert not run.exists()


@pytest.mark.parametrize('field', ['diagnostic_only', 'parent_probes', 'crash_readback',
                                  'crash_force_enable', 'shutdown_trace', 'shutdown_observer', 'ready',
                                  'runtime_unchanged', 'runtime_preparation_complete', 'browser_launched'])
def test_completed_diagnostic_missing_fields_fail(harness, field):
    m, args, run = harness; args.workload = 'empty'
    assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert m.completed(r)
    r.pop(field)
    assert not m.completed(r)



def test_persistence_failure_preserves_prior_evidence_io_fact(harness, monkeypatch, capsys):
    m, args, run = harness; args.workload = 'empty'
    launch = m.launch_empty
    def injected(*a, result, **kw):
        launch(*a, result=result, **kw)
        result['evidence_io_failure'] = {'stage': 'owned-crash-inspection', 'type': 'OSError'}
    monkeypatch.setattr(m, 'launch_empty', injected)
    original = m.persist; calls = []
    def persist(*a):
        calls.append(True)
        return original(*a) if len(calls) == 1 else False
    monkeypatch.setattr(m, 'persist', persist)
    assert m.attempt(args) == 2
    r = json.loads(capsys.readouterr().out)
    assert r['status'] == 'DIAGNOSTIC_FAILED'
    assert r['evidence_io_failure']['stage'] == 'owned-crash-inspection'
    assert r['evidence_persistence_failed'] is True


def test_shutdown_trace_environment_is_fixed_and_explicit(harness, monkeypatch):
    m, args, run = harness
    monkeypatch.setenv('MOZ_LOG', 'all:5')
    monkeypatch.setenv('MOZ_LOG_FILE', '/outside/log')
    ordinary = m.browser_environment(run, 'firefox')
    traced = m.browser_environment(run, 'firefox', shutdown_trace=True)
    assert 'MOZ_LOG' not in ordinary and 'MOZ_LOG_FILE' not in traced
    assert traced == dict(ordinary, MOZ_LOG='ObserverService:4,ChildProcessLifecycle:3,timestamp,sync')
    for bad in [None, 1, 'true']:
        with pytest.raises(Exception): m.browser_environment(run, 'firefox', shutdown_trace=bad)
    with pytest.raises(Exception): m.browser_environment(run, 'chrome', shutdown_trace=True)


@pytest.mark.parametrize('workload', ['full', 'empty'])
def test_shutdown_trace_is_diagnostic_never_acceptance(harness, workload):
    m, args, run = harness
    args.workload, args.shutdown_trace = workload, True
    assert m.attempt(args) == 2
    r = json.loads((run / 'result.json').read_text())
    assert r['shutdown_trace'] is True and r['diagnostic_only'] is True
    assert r['status'] == 'DIAGNOSTIC_COMPLETED' and not m.passed(r)
    r.update(shutdown_trace=False, diagnostic_only=False, workload='full')
    assert m.passed(r)
    r['shutdown_trace'] = True  # inconsistent record: trace flag alone still refuses acceptance
    assert not m.passed(r)
    r['shutdown_trace'] = None
    assert not m.passed(r) and not m.completed(r)


TRACE = '''*** You are running in headless mode.
2026-09-28 18:00:00.000000 UTC - [Parent 4242: Main Thread]: D/ObserverService nsObserverService::AddObserver(0x1234abcd: profile-before-change, strong)
2026-09-28 18:00:00.000000 UTC - [Parent 4242: Main Thread]: D/ObserverService nsObserverService::NotifyObservers(quit-application-requested)
2026-09-28 18:00:01.000000 UTC - [Parent 4242: Main Thread]: D/ObserverService nsObserverService::NotifyObservers(quit-application-granted)
2026-09-28 18:00:01.000000 UTC - [Child 5151: Main Thread]: D/ObserverService nsObserverService::NotifyObservers(content-child-shutdown)
2026-09-28 18:00:01.250000 UTC - [Parent 4242: Main Thread]: D/ObserverService nsObserverService::RemoveObserver(0xdeadbeef: profile-before-change)
2026-09-28 18:00:01.250500 UTC - [Parent 4243: Main Thread]: D/ObserverService nsObserverService::NotifyObservers(unrelated-parent-pid)
1790598861111	Marionette	INFO	Stopped listening on port 49529
2026-09-28 18:00:01.300000 UTC - [Parent 4242: IPC I/O Parent]: I/ChildProcessLifecycle --PROCESS [pid = 5151] [childID = 3] [type = tab]
2026-09-28 18:00:01.400000 UTC - [Parent 4242: Main Thread]: D/ObserverService nsObserverService::NotifyObservers(/private/path with space)
'''


def test_shutdown_trace_summary_is_attributed_ordered_and_sanitized(harness, tmp_path):
    m, args, run = harness
    run.mkdir(); (run / 'browser.log').write_text(TRACE)
    s = m.shutdown_trace_summary(run, 4242)
    assert s['status'] == 'SUMMARIZED' and s['quit_anchor'] is True
    assert s['parent_before_anchor'] == 2
    assert s['counts'] == {'parent': 6, 'other_process': {'Child': 1, 'Parent': 1}, 'unmatched': 2}
    assert s['parent_after_anchor'] == [
        {'op': 'NotifyObservers', 'topic': 'quit-application-granted', 'ms': 0.0},
        {'op': 'RemoveObserver', 'topic': 'profile-before-change', 'ms': 250.0},
        {'op': 'process-end', 'type': 'tab', 'ms': 300.0},
        {'op': 'NotifyObservers', 'topic': 'UNCLASSIFIED', 'ms': 400.0}]
    assert s['parent_last'] == s['parent_after_anchor'][-1]
    exported = json.dumps(s)
    for private in ('4242', '5151', '0x', 'deadbeef', '/private', 'unrelated-parent-pid', '49529'):
        assert private not in exported


def test_shutdown_trace_summary_bounds_and_refusals(harness, tmp_path, monkeypatch):
    m, args, run = harness
    run.mkdir()
    assert m.shutdown_trace_summary(run, 4242)['status'] == 'ABSENT'
    outside = tmp_path / 'outside.log'; outside.write_text(TRACE)
    (run / 'browser.log').symlink_to(outside)
    assert m.shutdown_trace_summary(run, 4242)['status'] == 'REFUSED_LINK'
    (run / 'browser.log').unlink(); (run / 'browser.log').write_text(TRACE)
    assert m.shutdown_trace_summary(run, None)['status'] == 'UNATTRIBUTED'
    monkeypatch.setattr(m, 'TRACE_TAIL', 2)
    s = m.shutdown_trace_summary(run, 4242)
    assert [e.get('topic', e.get('type')) for e in s['parent_after_anchor']] == ['tab', 'UNCLASSIFIED']
    assert s['parent_after_anchor_dropped'] == 2
    monkeypatch.setattr(m, 'TRACE_LIMIT', 10)
    assert m.shutdown_trace_summary(run, 4242) == {'status': 'OVERSIZED', 'modules': m.SHUTDOWN_TRACE}


def real_launch(m, run, monkeypatch, trace, summary=None):
    import ast, cnt_owned_process, cnt_synthetic_firefox as firefox
    run.mkdir(); environments = []
    class Owner:
        returncode = 0
        workload_pid = 4242
        def __init__(self, command, run, env, log, *a, **kw):
            environments.append(env)
            log.write(TRACE); log.flush()
        def settle(self): return {'exit_code': 0}
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    client = SimpleNamespace(methods=[], valid=True, sample=lambda *a, **kw: None,
                             connection=SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(firefox, 'session', lambda *a: (client, {}))
    monkeypatch.setattr(firefox, 'quit_normally', lambda *a: None)
    node = next(n for n in ast.parse(Path(m.__file__).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    if summary is not None:
        namespace['shutdown_trace_summary'] = summary
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    return environments, namespace['launch_empty']([], run, 'firefox', workload='empty', shutdown_trace=trace)


@pytest.mark.parametrize('trace', [False, True])
def test_real_launch_routes_trace_only_when_requested(harness, monkeypatch, trace):
    m, args, run = harness
    environments, result = real_launch(m, run, monkeypatch, trace)
    assert result['shutdown_trace'] is trace
    assert ('MOZ_LOG' in environments[0]) is trace
    assert ('MOZ_LOG' in result['environment_names']) is trace
    assert ('shutdown_trace_summary' in result) is trace
    if trace:
        assert result['shutdown_trace_summary']['parent_last']['topic'] == 'UNCLASSIFIED'


@pytest.mark.parametrize('error', [ValueError('bad'), RuntimeError('verification')])
def test_trace_summary_failure_is_evidence_io_not_browser_outcome(harness, monkeypatch, error):
    m, args, run = harness
    def summary(*a):
        raise error
    environments, result = real_launch(m, run, monkeypatch, True, summary)
    assert 'primary_failure' not in result and 'shutdown_trace_summary' not in result
    assert result['evidence_io_failure'] == {'stage': 'shutdown-trace-summary',
                                             'type': type(error).__name__,
                                             'classification': 'shutdown-trace-summary',
                                             'code': 'UNKNOWN', 'message_known': False}
    assert result['exit_before_cleanup'] == 0


def test_trace_summary_refuses_non_regular_without_blocking(harness):
    m, args, run = harness
    run.mkdir(); m.os.mkfifo(run / 'browser.log')
    assert m.shutdown_trace_summary(run, 4242) == {'status': 'REFUSED_NON_REGULAR', 'modules': m.SHUTDOWN_TRACE}


def test_trace_summary_counts_invalid_timestamp_without_losing_summary(harness):
    m, args, run = harness
    run.mkdir()
    bad = TRACE.replace('2026-09-28 18:00:01.250000', '2026-13-28 18:00:01.250000')
    (run / 'browser.log').write_text(bad)
    s = m.shutdown_trace_summary(run, 4242)
    assert s['status'] == 'SUMMARIZED' and s['counts']['unparsed_time'] == 1
    assert s['parent_after_anchor'][1] == {'op': 'RemoveObserver', 'topic': 'profile-before-change'}


# R4-CONT7 configd compatibility selection.
CONFIGD = 'com.apple.SystemConfiguration.configd'
D1_SERVICES = ['com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd']


def parse(m, monkeypatch, argv):
    seen = []
    monkeypatch.setattr(m.sys, 'argv', ['cnt-native-preflight.py', *argv])
    monkeypatch.setattr(m, 'attempt', lambda args: seen.append(args) or 0)
    with pytest.raises(SystemExit) as exit:
        m.main()
    return exit.value.code, seen


def test_service_choice_is_exact(harness, monkeypatch, capsys):
    m, args, run = harness
    base = ['--engine', 'firefox', '--runtime', 'Firefox.app', '--scratch', str(run)]
    code, seen = parse(m, monkeypatch, [*base, '--service', CONFIGD])
    assert code == 0 and seen[0].service == [CONFIGD]
    code, seen = parse(m, monkeypatch, base)
    assert code == 0 and seen[0].service == []
    for bad in [CONFIGD.lower(), CONFIGD + ' ', 'com.apple.SystemConfiguration.*']:
        code, seen = parse(m, monkeypatch, [*base, '--service', bad])
        assert code == 2 and seen == []
    # R5: Chrome reaches attempt(), whose selection stage refuses configd before any root
    # (test_configd_refused_for_non_firefox_before_any_step).
    code, seen = parse(m, monkeypatch, ['--engine', 'chrome', '--runtime', 'c', '--scratch', str(run),
                                        '--service', CONFIGD])
    assert code == 0 and seen[0].engine == 'chrome' and seen[0].service == [CONFIGD]
    capsys.readouterr()


def test_configd_refused_for_non_firefox_before_any_step(harness, monkeypatch, capsys):
    m, args, run = harness
    calls = []
    for name in ('fresh_attempt', 'prepare_runtime', 'run_probe', 'launch_empty', 'runtime_roots'):
        monkeypatch.setattr(m, name, lambda *a, _n=name, **kw: calls.append(_n))
    args.engine, args.service = 'chrome', [CONFIGD]
    assert m.attempt(args) == 2
    record = json.loads(capsys.readouterr().out)
    assert calls == [] and not run.exists()
    assert record['primary_failure'] == {'stage': 'selection', 'type': 'VerificationError', 'classification':
                                         'configd compatibility requires the validated frozen Firefox lane',
                                         'code': 'CONFIGD_LANE_REQUIRED', 'message_known': True}
    assert record['browser_launched'] is False and record['status'] == 'BLOCKED'


@pytest.mark.parametrize('services', [[], D1_SERVICES, [*D1_SERVICES, CONFIGD]])
def test_service_choice_recorded(harness, services):
    m, args, run = harness
    args.service = services
    assert m.attempt(args) == 0
    r = json.loads((run / 'result.json').read_text())
    assert r['mach_services'] == services
    assert r['configd_compatibility'] is (CONFIGD in services)
    assert ('permission_amendment' in r) is (CONFIGD in services)


def real_probe_launch(m, args, run, monkeypatch, tmp_path, tamper=False):
    """Real policy(), policy_evidence() and run_probe(); only the OS process is faked."""
    import cnt_confinement, cnt_owned_process
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', tmp_path)
    monkeypatch.setattr(m, 'run_probe', cnt_confinement.run_probe)
    def prepare(args, run, record):
        record['signature'] = {'original': True, 'frozen': True}
        record['runtime_snapshot_sha256'] = 'expected'
        record['runtime_preparation_complete'] = True
        executable = run / 'runtime/Firefox.app/Contents/MacOS/firefox'
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'synthetic')
        return executable, [run / 'runtime/Firefox.app'], 'expected'
    monkeypatch.setattr(m, 'prepare_runtime', prepare)
    probes, launches = [], []
    class Owner:
        returncode = 0
        def __init__(self, command, run, env, err, evidence=None):
            probes.append(command)
            (run / 'canaries.json').write_text(json.dumps({'passed': True}))
        def until(self, predicate, timeout): return predicate()
        def settle(self): return {'exit_code': 0, 'zero_survivors': True}
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    class Port:
        def __init__(self, port): self.port = port
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def getsockname(self): return ('127.0.0.1', self.port)
    def reserve(port=0):
        if port and tamper:
            with (run / 'confinement.sb').open('a') as stream: stream.write(' ')
        return Port(port or 23456)
    monkeypatch.setattr(m, 'reserve_port', reserve)
    launch = m.launch_empty
    def observed(command, *a, result, **kw):
        launches.append((command, Path(command[2]).read_bytes()))
        launch(command, *a, result=result, **kw)
    monkeypatch.setattr(m, 'launch_empty', observed)
    code = m.attempt(args)
    return code, json.loads((run / 'result.json').read_text()), probes, launches


def test_canaried_configd_policy_reaches_launch_unchanged(harness, monkeypatch, tmp_path):
    m, args, run = harness
    args.service = [*D1_SERVICES, CONFIGD]
    code, r, probes, launches = real_probe_launch(m, args, run, monkeypatch, tmp_path)
    assert code == 0 and len(probes) == 1 and len(launches) == 1
    command, launched = launches[0]
    assert command[:3] == ['/usr/bin/sandbox-exec', '-f', str(run / 'confinement.sb')] == probes[0][:3]
    line = b'(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))\n'
    assert launched.count(line) == 1
    assert m.hashlib.sha256(launched).hexdigest() == r['preflight']['policy_sha256']
    assert r['preflight']['mach_services'] == args.service and r['preflight']['configd_compatibility'] is True
    assert r['preflight']['policy_template_sha256'] != r['preflight']['policy_template_without_configd_sha256']


def test_canaried_policy_template_differs_only_by_selection(harness, monkeypatch, tmp_path):
    m, args, run = harness
    args.service = list(D1_SERVICES)
    _, default, _, (launch,) = real_probe_launch(m, args, run, monkeypatch, tmp_path)
    other = tmp_path / 'second'
    args.scratch, args.service = other, [*D1_SERVICES, CONFIGD]
    _, selected, _, (configd,) = real_probe_launch(m, args, other, monkeypatch, tmp_path)
    assert (default['preflight']['policy_template_sha256']
            == selected['preflight']['policy_template_without_configd_sha256'])
    line = b'(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))\n'
    assert configd[1].replace(line, b'', 1).replace(bytes(other), bytes(run)) == launch[1]


def test_tampered_configd_policy_never_launches(harness, monkeypatch, tmp_path):
    m, args, run = harness
    args.service = [*D1_SERVICES, CONFIGD]
    code, r, probes, launches = real_probe_launch(m, args, run, monkeypatch, tmp_path, tamper=True)
    assert code == 2 and launches == [] and r['browser_launched'] is False
    assert r['primary_failure']['classification'] == 'Canaried launch policy changed'
    assert r['configd_compatibility'] is True


@pytest.mark.parametrize('message,code', [
    ('Firefox automation port collision', 'SELECTED_PORT_FOREIGN_LISTENER'),
    ('Firefox socket observation failed', 'OBSERVATION_API_ERROR'),
    ('Firefox listener observation unresolved', 'UNRESOLVED_OWNED_TRANSITION'),
    ('Marionette effective port mismatch', 'PORT_FILE_MISMATCH'),
    ('Invalid Marionette active port', 'PORT_FILE_MALFORMED'),
    ('Firefox exited before listener', 'WORKLOAD_EXITED_BEFORE_LISTENER'),
    ('Firefox selected-port non-workload member', 'SELECTED_PORT_NON_WORKLOAD_MEMBER'),
    ('Session process mismatch', 'SESSION_PROCESS_MISMATCH'),
    ('Session profile mismatch', 'SESSION_PROFILE_MISMATCH'),
    ('Marionette greeting mismatch', 'PROTOCOL_GREETING_MISMATCH'),
    ('Extension removal incomplete', 'EXTENSION_REMOVAL_INCOMPLETE'),
    ('Frozen runtime changed', 'RUNTIME_CHANGED')])
def test_recorder_keeps_fixed_code_for_known_messages(harness, message, code):
    m, _, _ = harness
    record = {}
    m.record_failure(record, 'primary_failure', m.require.__globals__['VerificationError'](message), 'browser')
    assert record['primary_failure'] == {'stage': 'browser', 'type': 'VerificationError',
                                         'classification': message, 'code': code, 'message_known': True}


@pytest.mark.parametrize('error', [RuntimeError('/private/path 12345'), KeyboardInterrupt(), OSError(2, 'x')])
def test_recorder_unknown_stays_unknown_without_text(harness, error):
    m, _, _ = harness
    record = {'cleanup_failure': {'stage': 'earlier'}}
    m.record_failure(record, 'primary_failure', error, 'browser')
    m.record_failure(record, 'cleanup_failure', error, 'cleanup')
    assert record['primary_failure'] == {'stage': 'browser', 'type': type(error).__name__,
                                         'classification': 'browser', 'code': 'UNKNOWN',
                                         'message_known': False}
    assert record['cleanup_failure'] == {'stage': 'earlier'}


@pytest.mark.parametrize('error', [RuntimeError('Marionette protocol: other'),
                                   RuntimeError('Marionette protocol: /private/x')])
def test_recorder_variable_protocol_text_stays_unknown(harness, error):
    m, _, _ = harness
    record = {}
    m.record_failure(record, 'primary_failure', error, 'browser')
    assert record['primary_failure']['code'] == 'UNKNOWN'
    assert record['primary_failure']['classification'] == 'browser'


def test_recorder_session_codes_are_fixed_tokens_without_collision(harness):
    m, _, _ = harness
    import cnt_synthetic_firefox, cnt_firefox_observation
    session = cnt_synthetic_firefox.SESSION_CODES
    others = {**m.KNOWN_FAILURES, **cnt_firefox_observation.FAILURE_CODES, **cnt_synthetic_firefox.PORT_CODES}
    assert not set(session) & set(others)
    codes = m.failure_codes()
    for message, code in session.items():
        assert codes[message] == code and code.replace('_', '').isalnum() and code.isupper()


def test_recorder_without_observation_tables_does_not_invent_codes(harness, monkeypatch):
    m, _, _ = harness
    monkeypatch.setitem(m.sys.modules, 'cnt_firefox_observation', None)
    record = {}
    m.record_failure(record, 'primary_failure', RuntimeError('Firefox automation port collision'), 'browser')
    assert record['primary_failure']['code'] == 'UNKNOWN'
    m.record_failure(record, 'runtime_failure', RuntimeError('Frozen runtime changed'), 'runtime-verification')
    assert record['runtime_failure']['code'] == 'RUNTIME_CHANGED'


def test_listener_and_port_facts_do_not_change_acceptance(harness):
    m, args, run = harness
    assert m.attempt(args) == 0
    r = json.loads((run / 'result.json').read_text())
    for extra in ({'listener_transients': 3}, {'effective_port_status': 'MATCHED'},
                  {'effective_port_polls': {'absent': 2, 'empty': 1}}):
        assert m.passed({**r, **extra}) is True
    assert m.passed({**r, 'primary_failure': {'code': 'UNRESOLVED_OWNED_TRANSITION'}}) is False
    assert m.passed({**r, 'browser_version': None}) is True  # Version belongs to the host acceptance check.


# R4-CONT9: runtime-verification evidence. Real tree_digest over a synthetic frozen bundle,
# the real attempt() recorder and persistence; only preparation and launch are stubbed.
import errno
import os
import re

MEASUREMENT_KEYS = {'state', 'digest_complete', 'operation', 'code', 'error_type', 'errno',
                    'changed_fields', 'entry', 'entries_enumerated', 'entries_measured'}

# HOSTPREP1-FIX1: structural privacy predicate. Raw stat metadata can only surface as a key or a
# number, and private path/message text only as a string. Decimal renderings of private integers are
# never scanned across the serialized record: a short device number also occurs inside
# elapsed_seconds or a path-dependent digest.
STAT_KEYS = frozenset({'ino', 'inode', 'dev', 'device', 'rdev', 'nlink', 'uid', 'gid', 'size', 'blocks',
                       'atime', 'atime_ns', 'mtime', 'mtime_ns', 'ctime', 'ctime_ns', 'birthtime',
                       'stamp', 'stat', 'lstat'})
NUMERIC_KEYS = frozenset({'elapsed_seconds', 'exit_before_cleanup', 'exit_code', 'errno',
                          'entries_enumerated', 'entries_measured', 'automation_port'})
# A stat_result repr or 'st_ino=…' text inside a string value; \b keeps 'first_'/'test_' clear.
STAT_TEXT = re.compile(r'\bst_[a-z]')


def private_exposures(record, private_strings):
    """Violations tagged with their JSON path; empty when the exported record is private-safe.

    Keys are judged by name, so changed_fields may still list stamp field names. A number is governed
    by its nearest dict key (list items inherit it) and must sit under an allowlisted non-stat key.
    String values must hold neither a private string nor st_* identifier text.
    """
    found = []
    def walk(value, path, key):
        if isinstance(value, dict):
            for name, item in value.items():
                name, where = str(name), f'{path}.{name}'
                if name.lower() in STAT_KEYS or name.lower().startswith('st_'):
                    found.append(f'{where}: stat key')
                found.extend(f'{where}: private key text' for p in private_strings if p in name)
                walk(item, where, name)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f'{path}[{index}]', key)
        elif isinstance(value, str):
            found.extend(f'{path}: private text' for p in private_strings if p in value)
            if STAT_TEXT.search(value):
                found.append(f'{path}: stat text')
        elif isinstance(value, (int, float)) and not isinstance(value, bool) and key not in NUMERIC_KEYS:
            found.append(f'{path}: unallowlisted number')
    walk(record, '$', None)
    return found


@pytest.fixture
def frozen(harness, monkeypatch):
    """Real helper bound to the preflight module, and a stable synthetic frozen .app."""
    m, args, run = harness
    import cnt_native_evidence as ev
    assert ev.VerificationError is m.VerificationError and ev.tree_digest is m.require.__globals__['tree_digest']
    monkeypatch.setattr(m, 'tree_digest', ev.tree_digest)
    def prepare(args, run, record):
        bundle = run / 'runtime/Firefox.app'
        (bundle / 'Contents/MacOS').mkdir(parents=True)
        (bundle / 'Contents/MacOS/firefox').write_bytes(b'synthetic')
        (bundle / 'Contents/Info.plist').write_bytes(b'synthetic plist')
        digest = ev.tree_digest(bundle)
        record.update(runtime_source_sha256=digest, signature={'original': True, 'frozen': True},
                      runtime_bundle_relative='runtime/Firefox.app', runtime_snapshot_sha256=digest,
                      runtime_preparation_complete=True)
        return bundle / 'Contents/MacOS/firefox', [bundle], digest
    monkeypatch.setattr(m, 'prepare_runtime', prepare)
    armed = []
    original = ev.descendants
    def descendants(root):
        # Post-run measurement only: act when it re-enumerates for its end-of-tree checks.
        if armed and armed[0][0] == 'second' and root.name == 'Firefox.app':
            armed[0][1].append(root)
            if len(armed[0][1]) == 2:
                armed.pop()[2](root)
        return original(root)
    monkeypatch.setattr(ev, 'descendants', descendants)
    def during_measurement(action):
        # Armed after launch returns or raises, so preparation digests are never affected.
        current = m.launch_empty
        def launched(*a, **kw):
            try:
                return current(*a, **kw)
            finally:
                armed.append(('second', [], action))
        monkeypatch.setattr(m, 'launch_empty', launched)
    def launch_then(action):
        launch = m.launch_empty
        def launched(*a, result, **kw):
            launch(*a, result=result, **kw)
            action(run / 'runtime/Firefox.app', result)
        monkeypatch.setattr(m, 'launch_empty', launched)
    return m, ev, args, run, during_measurement, launch_then


def result(run):
    return json.loads((run / 'result.json').read_text())


def test_measurement_match_passes_unchanged(frozen):
    m, ev, args, run, _, _ = frozen
    assert m.attempt(args) == 0
    r = result(run)
    assert r['status'] == 'SYNTHETIC_ATTEMPT_PASSED' and m.passed(r) and m.completed(r)
    assert r['runtime_measurement'] == {'state': 'MATCH', 'digest_complete': True,
                                        'operation': 'digest-comparison', 'code': None,
                                        'entries_enumerated': 4, 'entries_measured': 4}
    assert r['runtime_observed_sha256'] == r['runtime_snapshot_sha256']


def test_measurement_not_started_when_preparation_fails(frozen, monkeypatch):
    m, ev, args, run, _, _ = frozen
    def fail(*a): raise RuntimeError('/private/preparation')
    monkeypatch.setattr(m, 'prepare_runtime', fail)
    assert m.attempt(args) == 2
    r = result(run)
    assert r['runtime_measurement'] == {'state': 'NOT_STARTED'} and 'runtime_failure' not in r


def test_preparation_refusal_carries_structured_code(harness, monkeypatch):
    """Shared recorder: a helper refusal during preparation keeps its fixed code (not UNKNOWN)."""
    m, args, run = harness
    import ast, cnt_native_evidence as ev
    tree = ast.parse(Path(m.__file__).read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare_runtime')
    namespace = dict(m.__dict__, tree_digest=ev.tree_digest)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    monkeypatch.setattr(m, 'prepare_runtime', namespace['prepare_runtime'])
    args.runtime.mkdir(); os.mkfifo(args.runtime / 'fifo')
    assert m.attempt(args) == 2
    r = result(run)
    assert r['primary_failure'] == {'stage': 'runtime-preparation', 'type': 'VerificationError',
                                    'classification': 'runtime-preparation', 'code': 'UNSUPPORTED_ENTRY',
                                    'message_known': False}
    assert r['runtime_measurement'] == {'state': 'NOT_STARTED'} and 'fifo' not in json.dumps(r)


def test_measurement_incomplete_is_not_a_mismatch(frozen):
    m, ev, args, run, during, _ = frozen
    plist = run / 'runtime/Firefox.app/Contents/Info.plist'
    during(lambda root: os.utime(plist, ns=(1, 1)))
    assert m.attempt(args) == 2
    r = result(run)
    assert r['status'] == 'BLOCKED' and not m.passed(r)
    assert 'runtime_observed_sha256' not in r and r['runtime_unchanged'] is False
    assert r['runtime_failure'] == {'stage': 'runtime-verification', 'type': 'VerificationError',
                                    'classification': 'runtime-verification', 'code': 'ENTRY_CHANGED',
                                    'message_known': False}
    measurement = r['runtime_measurement']
    assert set(measurement) == MEASUREMENT_KEYS
    assert measurement['state'] == 'INCOMPLETE' and measurement['digest_complete'] is False
    assert (measurement['operation'], measurement['code']) == ('entry-stability', 'ENTRY_CHANGED')
    assert 'mtime' in measurement['changed_fields'] and measurement['errno'] is None
    assert measurement['entry'] == {'category': 'RUNTIME_RELATIVE', 'path': 'Contents/Info.plist'}
    assert (measurement['entries_enumerated'], measurement['entries_measured']) == (4, 4)
    # Snapshot, signature, useful work and exit evidence are retained.
    assert r['runtime_snapshot_sha256'] == r['runtime_source_sha256'] and r['signature']['frozen'] is True
    assert r['extension_unloaded'] and r['exit_before_cleanup'] == 0 and r['settlement']['exit_code'] == 0
    # The same content later measures equal: current equality is not a historical pass.
    assert ev.tree_digest(run / 'runtime/Firefox.app') == r['runtime_snapshot_sha256']


def test_measurement_completed_mismatch_is_not_relabelled(frozen):
    m, ev, args, run, _, launch_then = frozen
    launch_then(lambda bundle, result: (bundle / 'Contents/added').write_bytes(b'x'))
    assert m.attempt(args) == 2
    r = result(run)
    assert r['runtime_measurement'] == {'state': 'MISMATCH', 'digest_complete': True,
                                        'operation': 'digest-comparison', 'code': 'RUNTIME_CHANGED',
                                        'entries_enumerated': 5, 'entries_measured': 5}
    assert r['runtime_observed_sha256'] != r['runtime_snapshot_sha256']
    assert r['runtime_failure']['code'] == 'RUNTIME_CHANGED' and r['runtime_failure']['message_known'] is True
    assert r['status'] == 'BLOCKED'


def test_measurement_preserves_earlier_primary_and_cleanup(frozen):
    m, ev, args, run, during, launch_then = frozen
    def failures(bundle, result):
        m.record_failure(result, 'primary_failure', RuntimeError('/private/browser'), 'browser')
        m.record_failure(result, 'cleanup_failure', OSError(errno.EPERM, '/private/cleanup'), 'cleanup')
    launch_then(failures)
    during(lambda root: (root / 'Contents/MacOS/firefox').write_bytes(b'rewritten'))
    assert m.attempt(args) == 2
    r = result(run)
    assert r['primary_failure'] == {'stage': 'browser', 'type': 'RuntimeError', 'classification': 'browser',
                                    'code': 'UNKNOWN', 'message_known': False}
    assert r['cleanup_failure']['type'] == 'PermissionError' and r['cleanup_failure']['code'] == 'UNKNOWN'
    assert r['runtime_failure']['code'] == 'ENTRY_CHANGED'
    assert r['runtime_measurement']['entry'] == {'category': 'RUNTIME_RELATIVE', 'path': 'Contents/MacOS/firefox'}
    assert r['extension_unloaded'] and r['exit_before_cleanup'] == 0


@pytest.mark.parametrize('interrupt', [KeyboardInterrupt, SystemExit])
def test_measurement_interrupt_persists_then_reraises(frozen, monkeypatch, interrupt):
    m, ev, args, run, during, _ = frozen
    def interrupted(root): raise interrupt()
    during(interrupted)
    with pytest.raises(interrupt):
        m.attempt(args)
    r = result(run)
    assert r['status'] == 'BLOCKED' and r['runtime_failure']['type'] == interrupt.__name__
    assert r['runtime_failure']['code'] == 'UNKNOWN'
    measurement = r['runtime_measurement']
    assert (measurement['state'], measurement['code'], measurement['errno']) == ('INCOMPLETE', 'INTERRUPTED', None)
    assert measurement['error_type'] == interrupt.__name__
    assert measurement['operation'] == 'entry-set-stability' and measurement['entry'] == {'category': 'ROOT'}
    assert 'runtime_observed_sha256' not in r


def test_primary_interrupt_is_delivered_with_runtime_evidence(frozen, monkeypatch):
    m, ev, args, run, during, _ = frozen
    def interrupted(*a, result, **kw): raise KeyboardInterrupt()
    monkeypatch.setattr(m, 'launch_empty', interrupted)
    during(lambda root: (root / 'Contents/MacOS/firefox').write_bytes(b'rewritten'))
    with pytest.raises(KeyboardInterrupt):
        m.attempt(args)
    r = result(run)
    assert r['primary_failure']['type'] == 'KeyboardInterrupt'
    assert r['runtime_failure']['code'] == 'ENTRY_CHANGED' and r['runtime_measurement']['state'] == 'INCOMPLETE'


def test_measurement_os_error_keeps_integer_errno_only(frozen, monkeypatch):
    m, ev, args, run, during, _ = frozen
    def fail(root): raise OSError(errno.EIO, '/private/io')
    during(fail)
    assert m.attempt(args) == 2
    r = result(run)
    measurement = r['runtime_measurement']
    assert (measurement['state'], measurement['operation']) == ('INCOMPLETE', 'entry-set-stability')
    assert (measurement['code'], measurement['errno'], measurement['error_type']) == ('OS_ERROR', errno.EIO, 'OSError')
    assert r['runtime_failure']['code'] == 'UNKNOWN' and '/private' not in json.dumps(r)
    for vocabulary_error in (m.VerificationError('x'), RuntimeError('x')):
        assert m.incomplete_measurement({}, vocabulary_error)['errno'] is None


def test_measurement_evidence_io_failure_is_not_success(frozen, monkeypatch, capsys):
    m, ev, args, run, during, _ = frozen
    during(lambda root: os.utime(root / 'Contents/Info.plist', ns=(1, 1)))
    original = m.persist; calls = []
    def persist(*a):
        calls.append(True)
        return original(*a) if len(calls) == 1 else False
    monkeypatch.setattr(m, 'persist', persist)
    assert m.attempt(args) == 2
    r = json.loads(capsys.readouterr().out)
    assert r['evidence_io_failure'] is True and r['status'] == 'BLOCKED'
    assert r['runtime_measurement']['code'] == 'ENTRY_CHANGED'


@pytest.mark.parametrize('name', ['Résumé', 'bad:name', 'x' * 129])
def test_unsafe_entry_names_use_fixed_category(frozen, name):
    m, ev, args, run, during, launch_then = frozen
    launch_then(lambda bundle, result: (bundle / 'Contents' / name).write_bytes(b'x'))
    during(lambda root: os.utime(root / 'Contents' / name, ns=(1, 1)))
    assert m.attempt(args) == 2
    r = result(run)
    assert r['runtime_measurement']['entry'] == {'category': 'UNSAFE_PATH'}
    assert name not in json.dumps(r)


def test_escaping_link_reports_entry_never_target(frozen):
    m, ev, args, run, _, launch_then = frozen
    launch_then(lambda bundle, result: (bundle / 'Contents/link').symlink_to('../../../private-target'))
    assert m.attempt(args) == 2
    r = result(run)
    measurement = r['runtime_measurement']
    assert (measurement['operation'], measurement['code']) == ('link-admission', 'LINK_ESCAPES')
    assert measurement['entry'] == {'category': 'RUNTIME_RELATIVE', 'path': 'Contents/link'}
    assert 'private-target' not in json.dumps(r)


def test_exported_measurement_has_no_private_text(frozen, tmp_path):
    m, ev, args, run, during, _ = frozen
    plist = run / 'runtime/Firefox.app/Contents/Info.plist'
    seen = []
    def change(root):
        seen.append(plist.lstat())
        os.utime(plist, ns=(1, 1))
    during(change)
    assert m.attempt(args) == 2
    assert len(seen) == 1  # the post-launch change really ran
    r = result(run)
    # Long stat values are effectively collision-free, so string values are also searched for them;
    # the short st_dev that caused the flake is covered structurally (keys and numbers) only.
    stamps = tuple(str(v) for v in (seen[0].st_ino, seen[0].st_ctime_ns, seen[0].st_mtime_ns) if v >= 10**6)
    assert len(stamps) >= 2
    private = (str(tmp_path), str(tmp_path.resolve()), 'Package entry changed', *stamps)
    assert private_exposures(r, private) == []
    # ENTRY_CHANGED keeps exactly the allowlisted sanitized projection; nothing is dropped.
    measurement = r['runtime_measurement']
    assert set(measurement) == MEASUREMENT_KEYS
    assert ({k: measurement[k] for k in ('state', 'digest_complete', 'operation', 'code', 'error_type', 'errno')}
            == {'state': 'INCOMPLETE', 'digest_complete': False, 'operation': 'entry-stability',
                'code': 'ENTRY_CHANGED', 'error_type': 'VerificationError', 'errno': None})
    changed = measurement['changed_fields']
    assert 'mtime' in changed and changed == [f for f in ev.STAMP_FIELDS if f in changed]
    assert measurement['entry'] == {'category': 'RUNTIME_RELATIVE', 'path': 'Contents/Info.plist'}
    assert (measurement['entries_enumerated'], measurement['entries_measured']) == (4, 4)
    assert r['runtime_failure']['code'] == 'ENTRY_CHANGED' and r['runtime_failure']['message_known'] is False
    # Allowlisted numbers keep their own meaning; elapsed time may contain any digits.
    assert (r['exit_before_cleanup'], r['settlement']['exit_code']) == (0, 0)
    assert type(r['elapsed_seconds']) is float and r['elapsed_seconds'] >= 0


def test_privacy_predicate_ignores_numeric_collisions_and_catches_fields(tmp_path):
    mtime_ns = '1790000000123456789'
    private = (str(tmp_path), 'Package entry changed', mtime_ns)
    device = 27
    clean = {'elapsed_seconds': 0.0271827, 'runtime_snapshot_sha256': 'ab27' * 16,
             'runtime_measurement': {'entries_measured': device, 'errno': None, 'operation': 'first_test_run',
                                     'changed_fields': ['device', 'inode', 'mtime', 'ctime']},
             'settlement': {'exit_code': 0, 'failures': []}}
    assert str(device) in json.dumps(clean)  # the retired substring scan would have failed here
    assert private_exposures(clean, private) == []
    for leak, where in (({'runtime_measurement': {'inode': device}}, '$.runtime_measurement.inode'),
                        ({'x': {'st_dev': device}}, '$.x.st_dev'),
                        ({'mtime_ns': 1}, '$.mtime_ns'),
                        ({'opaque': device}, '$.opaque'),
                        ({'survivors': [device]}, '$.survivors[0]'),
                        ({'entry': {'path': str(tmp_path / 'Info.plist')}}, '$.entry.path'),
                        ({'message': 'Package entry changed: Contents/Info.plist'}, '$.message'),
                        ({'detail': 'os.stat_result(st_mode=33188, st_ino=1)'}, '$.detail'),
                        ({'runtime_snapshot_sha256': 'ab' + mtime_ns}, '$.runtime_snapshot_sha256')):
        found = private_exposures({**clean, **leak}, private)
        assert found and all(v.startswith(where + ':') for v in found), (leak, found)


def test_projection_failure_keeps_original_error(frozen, monkeypatch):
    m, ev, args, run, during, _ = frozen
    during(lambda root: os.utime(root / 'Contents/Info.plist', ns=(1, 1)))
    def broken(*a): raise ValueError('projection')
    monkeypatch.setattr(m, 'safe_runtime_relative', broken)
    assert m.attempt(args) == 2
    r = result(run)
    assert r['runtime_measurement'] == {'state': 'INCOMPLETE', 'digest_complete': False,
                                        'code': 'MEASUREMENT_PROJECTION_UNAVAILABLE'}
    assert r['runtime_failure']['code'] == 'ENTRY_CHANGED'


@pytest.mark.parametrize('relative,expected', [
    (None, {'category': 'ROOT'}),
    ('Contents/MacOS/firefox', {'category': 'RUNTIME_RELATIVE', 'path': 'Contents/MacOS/firefox'}),
    ('Contents/en-US.lproj/a b+c@d_e', {'category': 'RUNTIME_RELATIVE', 'path': 'Contents/en-US.lproj/a b+c@d_e'}),
    ('../outside', {'category': 'UNSAFE_PATH'}), ('Contents/./x', {'category': 'UNSAFE_PATH'}),
    ('/private/x', {'category': 'UNSAFE_PATH'}), ('Contents//x', {'category': 'UNSAFE_PATH'}),
    ('a/' * 32 + 'b', {'category': 'UNSAFE_PATH'}), ('x' * 513, {'category': 'UNSAFE_PATH'}),
    ('line\nbreak', {'category': 'UNSAFE_PATH'}), (b'bytes', {'category': 'UNSAFE_PATH'})])
def test_safe_runtime_relative(harness, relative, expected):
    m, _, _ = harness
    assert m.safe_runtime_relative(relative) == expected


@pytest.mark.parametrize('error,code', [
    ('verification', 'ENTRY_CHANGED'), ('unlisted', 'UNKNOWN'), ('unhashable', 'UNKNOWN'),
    ('runtime-attribute', 'UNKNOWN'), ('system-exit', 'UNKNOWN'), ('known-message', 'RUNTIME_CHANGED')])
def test_recorder_uses_only_allowlisted_structured_codes(harness, error, code):
    m, _, _ = harness
    V = m.VerificationError
    forged = RuntimeError('/private/x'); forged.code = 'ENTRY_CHANGED'
    value = {'verification': V('Package entry changed: /private/x', code='ENTRY_CHANGED'),
             'unlisted': V('/private/x', code='NOT_A_CODE'),
             'unhashable': V('/private/x', code=['ENTRY_CHANGED']),
             'runtime-attribute': forged, 'system-exit': SystemExit('ENTRY_CHANGED'),
             'known-message': V('Frozen runtime changed', code='ENTRY_CHANGED')}[error]
    record = {}
    m.record_failure(record, 'runtime_failure', value, 'runtime-verification')
    assert record['runtime_failure']['code'] == code
    assert record['runtime_failure']['message_known'] is (error == 'known-message')
    assert '/private' not in json.dumps(record)


def test_incomplete_projection_validates_helper_attributes(harness):
    m, _, _ = harness
    V = m.VerificationError
    trace = {'operation': 'not-an-operation', 'relative': '/private/x', 'entries_enumerated': True,
             'entries_measured': -1}
    p = m.incomplete_measurement(trace, V('/private/x', code='ENTRY_CHANGED', changed=['ctime', '/private']))
    assert p['operation'] is None and p['entry'] is None and p['changed_fields'] is None
    assert p['entries_enumerated'] is None and p['entries_measured'] is None
    p = m.incomplete_measurement({'operation': 'leaf-open'}, OSError('no errno'))
    assert (p['code'], p['errno'], p['entry']) == ('OS_ERROR', None, {'category': 'ROOT'})
    p = m.incomplete_measurement({'operation': 'leaf-read'}, RuntimeError('/private/x'))
    assert (p['code'], p['error_type']) == ('UNKNOWN', 'RuntimeError')
    assert '/private' not in json.dumps(p)


# R5-CHROME-PREP1: Chrome selection, preparation and runtime measurement. Real tree_digest
# over a synthetic store-like Google Chrome.app; codesign and nix-store are faked.
import plistlib

CHROME_VERSION = '140.0.7339.80'
STORE_NAME = '0123456789abcdfghijklmnpqrsvwxyz-google-chrome-' + CHROME_VERSION


def chrome_app(store, name=STORE_NAME, identifier='com.google.Chrome', version=CHROME_VERSION,
               executable='Google Chrome'):
    app = store / name / 'Applications/Google Chrome.app'
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/MacOS/Google Chrome').write_bytes(b'synthetic chrome')
    helper = app / 'Contents/Frameworks/Google Chrome Framework.framework/Helpers'
    helper.mkdir(parents=True)
    (helper / 'chrome_crashpad_handler').write_bytes(b'synthetic crashpad')
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(
        {'CFBundleIdentifier': identifier, 'CFBundleExecutable': executable,
         'CFBundleShortVersionString': version}))
    return app


@pytest.fixture
def chrome_lane(harness, monkeypatch, tmp_path):
    m, args, run = harness
    import cnt_native_evidence as ev
    store = (tmp_path / 'store').resolve()
    store.mkdir()
    monkeypatch.setattr(m, 'CHROME_STORE', store)
    monkeypatch.setattr(m, 'tree_digest', ev.tree_digest)
    monkeypatch.setattr(m, 'prepare_runtime', lambda a, r, rec: m.prepare_chrome_runtime(a, r, rec))
    codesign, reserved, probes = [], [], []
    def signed(argv, **kw):
        codesign.append(argv)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(m.subprocess, 'run', signed)
    monkeypatch.setattr(m, 'runtime_roots', lambda executable: [store / STORE_NAME])
    monkeypatch.setattr(m, 'reserve_port', lambda *a: reserved.append(a) or pytest.fail('Chrome port'))
    probe = m.run_probe
    def recorded(*a, **kw):
        probes.append(kw)
        return probe(*a, **kw)
    monkeypatch.setattr(m, 'run_probe', recorded)
    launches = []
    launch = m.launch_empty
    def launched(*a, result, **kw):
        launches.append(kw)
        launch(*a, result=result, **kw)
    monkeypatch.setattr(m, 'launch_empty', launched)
    args.engine, args.runtime = 'chrome', chrome_app(store)
    args.service = list(D1_SERVICES)
    return SimpleNamespace(m=m, args=args, run=run, store=store, codesign=codesign, reserved=reserved,
                           probes=probes, launches=launches, ev=ev)


def test_chrome_prepared_attempt_passes_with_match(chrome_lane):
    c = chrome_lane
    assert c.m.attempt(c.args) == 0
    r = result(c.run)
    assert r['status'] == 'SYNTHETIC_ATTEMPT_PASSED' and c.m.passed(r)
    assert r['runtime_preparation_complete'] is True and r['runtime_measurement_root'] == 'SELECTED_STORE_APP'
    assert r['runtime_measurement']['state'] == 'MATCH' and r['runtime_unchanged'] is True
    assert r['runtime_snapshot_sha256'] == r['runtime_source_sha256'] == r['runtime_observed_sha256']
    assert r['runtime_bundle_version'] == CHROME_VERSION and r['runtime_bundle_id'] == 'com.google.Chrome'
    assert r['signature'] == {'original': True} and 'frozen' not in r['signature']
    assert r['runtime_closure_count'] == 1 and len(r['runtime_closure_sha256']) == 64
    assert r['executable_sha256'] == c.m.hashlib.sha256(b'synthetic chrome').hexdigest()
    assert c.codesign == [['/usr/bin/codesign', '--verify', '--deep', '--strict', str(c.args.runtime)]]
    assert c.reserved == [] and c.probes[0]['automation_port'] is None
    assert r['preflight']['automation_port'] is None and 'reservation_handoff' not in r['preflight']
    assert c.launches[0]['expected_version'] == CHROME_VERSION
    assert 'runtime_bundle_relative' not in r and not (c.run / 'runtime').exists()
    assert str(c.store) not in json.dumps(r)


@pytest.mark.parametrize('option', ['crash_force_enable', 'crash_readback', 'parent_probes', 'shutdown_trace',
                                    'nested_sandbox_exception', 'abnormal-page'])
def test_chrome_refuses_firefox_only_options_before_any_root(chrome_lane, monkeypatch, capsys, option):
    c = chrome_lane
    calls = []
    for name in ('fresh_attempt', 'prepare_runtime', 'run_probe', 'launch_empty', 'runtime_roots'):
        monkeypatch.setattr(c.m, name, lambda *a, _n=name, **kw: calls.append(_n))
    if option == 'nested_sandbox_exception':
        c.args.nested_sandbox_exception = ['content']
    elif option == 'abnormal-page':
        c.args.abnormal, c.args.workload = True, 'page'
    else:
        setattr(c.args, option, True)
    assert c.m.attempt(c.args) == 2
    record = json.loads(capsys.readouterr().out)
    assert calls == [] and not c.run.exists() and record['browser_launched'] is False
    expected = ('CHROME_ABNORMAL_REQUIRES_FULL' if option == 'abnormal-page' else 'FIREFOX_ONLY_OPTION')
    assert record['primary_failure']['stage'] == 'selection' and record['primary_failure']['code'] == expected


def test_chrome_probe_selection_has_no_firefox_port_ipc_or_configd(chrome_lane, monkeypatch):
    c = chrome_lane
    positional = []
    probe = c.m.run_probe
    def recorded(*a, **kw):
        positional.append(a)
        return probe(*a, **kw)
    monkeypatch.setattr(c.m, 'run_probe', recorded)
    assert c.m.attempt(c.args) == 0
    kw = c.probes[0]
    assert kw['automation_port'] is None and kw['firefox_child_ipc'] is False
    assert positional[0][5] == D1_SERVICES
    r = result(c.run)
    assert r['configd_compatibility'] is False and r['sandbox_disables'] == []
    assert r['mach_services'] == D1_SERVICES


@pytest.mark.parametrize('case,code', [
    ('chromium', 'CHROME_BUNDLE_IDENTITY_REFUSED'), ('testing', 'CHROME_BUNDLE_IDENTITY_REFUSED'),
    ('executable-name', 'CHROME_BUNDLE_IDENTITY_REFUSED'), ('version', 'CHROME_BUNDLE_VERSION_INVALID'),
    ('plist-missing', 'CHROME_BUNDLE_METADATA_UNREADABLE'), ('plist-garbage', 'CHROME_BUNDLE_METADATA_UNREADABLE'),
    ('store-name', 'CHROME_RUNTIME_NOT_STORE_APP'), ('outside-store', 'CHROME_RUNTIME_NOT_STORE_APP'),
    ('link', 'CHROME_RUNTIME_NOT_RESOLVED'), ('executable-link', 'UNKNOWN'),
    ('signature', 'ORIGINAL_SIGNATURE_INVALID'), ('closure', 'UNKNOWN')])
def test_chrome_preparation_refusals_retain_partial_facts(chrome_lane, monkeypatch, tmp_path, case, code):
    c = chrome_lane
    app = c.args.runtime
    if case == 'chromium':
        c.args.runtime = chrome_app(c.store, STORE_NAME[:-1] + '1', identifier='org.chromium.Chromium')
    elif case == 'testing':
        c.args.runtime = chrome_app(c.store, STORE_NAME[:-1] + '2', identifier='com.google.chrome.for.testing')
    elif case == 'executable-name':
        c.args.runtime = chrome_app(c.store, STORE_NAME[:-1] + '3', executable='Chromium')
    elif case == 'version':
        c.args.runtime = chrome_app(c.store, STORE_NAME[:-1] + '4', version='140.0')
    elif case == 'plist-missing':
        (app / 'Contents/Info.plist').unlink()
    elif case == 'plist-garbage':
        (app / 'Contents/Info.plist').write_bytes(b'not a plist')
    elif case == 'store-name':
        c.args.runtime = chrome_app(c.store, 'e' * 32 + '-google-chrome-' + CHROME_VERSION)
    elif case == 'outside-store':
        c.args.runtime = chrome_app((tmp_path / 'elsewhere').resolve(), STORE_NAME)
    elif case == 'link':
        alias = c.store / (STORE_NAME[:-1] + '5')
        (alias / 'Applications').mkdir(parents=True)
        (alias / 'Applications/Google Chrome.app').symlink_to(app)
        c.args.runtime = alias / 'Applications/Google Chrome.app'
    elif case == 'executable-link':
        (app / 'Contents/MacOS/Google Chrome').unlink()
        (app / 'Contents/MacOS/Google Chrome').symlink_to(tmp_path / 'outside-binary')
    elif case == 'signature':
        monkeypatch.setattr(c.m.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=1))
    elif case == 'closure':
        def refused(_): raise c.m.VerificationError('Source-bearing runtime closure refused')
        monkeypatch.setattr(c.m, 'runtime_roots', refused)
    assert c.m.attempt(c.args) == 2
    r = result(c.run)
    assert r['primary_failure']['stage'] == 'runtime-preparation' and r['primary_failure']['code'] == code
    assert r['runtime_preparation_complete'] is False and r['browser_launched'] is False
    assert r['runtime_measurement'] == {'state': 'NOT_STARTED'} and 'runtime_failure' not in r
    assert r['runtime_selection'] == 'EXPLICIT_STORE_APP'
    if case in ('signature', 'closure'):
        assert r['signature']['original'] is (case != 'signature') and len(r['runtime_source_sha256']) == 64
        assert r['runtime_bundle_version'] == CHROME_VERSION
    assert str(c.store) not in json.dumps(r) and str(tmp_path) not in json.dumps(r)


def test_chrome_mismatch_after_launch_is_not_relabelled(chrome_lane, monkeypatch):
    c = chrome_lane
    launch = c.m.launch_empty
    def mutate(*a, result, **kw):
        launch(*a, result=result, **kw)
        (c.args.runtime / 'Contents/Resources').mkdir()
    monkeypatch.setattr(c.m, 'launch_empty', mutate)
    assert c.m.attempt(c.args) == 2
    r = result(c.run)
    assert r['runtime_measurement']['state'] == 'MISMATCH' and r['runtime_failure']['code'] == 'RUNTIME_CHANGED'
    assert r['status'] == 'BLOCKED' and r['extension_unloaded'] is True


def test_chrome_incomplete_measurement_is_not_mismatch(chrome_lane, monkeypatch):
    c = chrome_lane
    launch = c.m.launch_empty
    def unreadable(*a, result, **kw):
        launch(*a, result=result, **kw)
        helper = c.args.runtime / 'Contents/Frameworks/Google Chrome Framework.framework/Helpers'
        (helper / 'chrome_crashpad_handler').unlink()
        os.mkfifo(helper / 'chrome_crashpad_handler')
    monkeypatch.setattr(c.m, 'launch_empty', unreadable)
    assert c.m.attempt(c.args) == 2
    r = result(c.run)
    assert r['runtime_measurement']['state'] == 'INCOMPLETE' and r['runtime_measurement']['code'] == 'UNSUPPORTED_ENTRY'
    assert 'runtime_observed_sha256' not in r and r['runtime_unchanged'] is False


def test_chrome_measurement_never_falls_back_to_run_runtime(chrome_lane, tmp_path):
    c = chrome_lane
    run = tmp_path / 'fallback-run'
    (run / 'runtime').mkdir(parents=True)
    with pytest.raises(c.m.VerificationError, match='Chrome measurement root unbound'):
        c.m.runtime_measurement_target('chrome', run, {'runtime_bundle_relative': 'runtime'}, None)
    with pytest.raises(c.m.VerificationError, match='Chrome measurement root unbound'):
        c.m.runtime_measurement_target('chrome', run, {}, c.args.runtime)
    assert c.m.runtime_measurement_target('chrome', run, {'runtime_measurement_root': 'SELECTED_STORE_APP'},
                                          c.args.runtime) == c.args.runtime
    assert c.m.runtime_measurement_target('firefox', run, {}, c.args.runtime) == run / 'runtime'
    assert c.m.runtime_measurement_target('firefox', run, {'runtime_bundle_relative': 'runtime/Firefox.app'},
                                          None) == run / 'runtime/Firefox.app'


def test_chrome_parenthesized_helper_projects_to_fixed_category(chrome_lane):
    c = chrome_lane
    assert c.m.safe_runtime_relative('Contents/Frameworks/x/Helpers/Google Chrome Helper (GPU).app') == {
        'category': 'UNSAFE_PATH'}


def test_chrome_table_failure_never_hides_firefox_codes(harness, monkeypatch):
    m, _, _ = harness
    monkeypatch.setitem(m.sys.modules, 'cnt_synthetic_chrome', None)
    codes = m.failure_codes()
    assert codes['Session process mismatch'] == 'SESSION_PROCESS_MISMATCH'
    assert codes['Chrome bundle identity refused'] == 'CHROME_BUNDLE_IDENTITY_REFUSED'
    assert 'CDP EOF' not in codes


def test_all_code_tables_agree_on_shared_messages(harness):
    m, _, _ = harness
    import cnt_protocol, cnt_synthetic_chrome, cnt_synthetic_firefox, cnt_firefox_observation
    import cnt_firefox_matrix, cnt_firefox_matrix_session  # R6 matrix tables
    import cnt_firefox_recovery  # BUX5B1 HOSTPREP1 recovery table
    merged = {}
    for table in (m.KNOWN_FAILURES, m.CHROME_PREPARATION_CODES, cnt_protocol.CDP_CODES,
                  cnt_synthetic_chrome.CHROME_CODES, cnt_synthetic_firefox.PORT_CODES,
                  cnt_synthetic_firefox.SESSION_CODES, cnt_firefox_observation.FAILURE_CODES,
                  cnt_firefox_matrix.MATRIX_CODES, cnt_firefox_matrix_session.SESSION_CODES,
                  cnt_firefox_recovery.RECOVERY_CODES):
        for message, code in table.items():
            assert merged.setdefault(message, code) == code, message
    assert m.failure_codes() == merged


def test_firefox_launch_passes_no_chrome_markers(harness, monkeypatch):
    m, args, run = harness
    import ast, cnt_owned_process, cnt_synthetic_firefox as firefox
    run.mkdir(); options = []
    class Owner:
        returncode = 0
        def __init__(self, *a, **kw): options.append(kw)
        def settle(self): return {'exit_code': 0}
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    client = SimpleNamespace(methods=[], valid=True, sample=lambda *a, **kw: None,
                             connection=SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(firefox, 'session', lambda *a: (client, {}))
    monkeypatch.setattr(firefox, 'quit_normally', lambda *a: None)
    node = next(n for n in ast.parse(Path(m.__file__).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    result = namespace['launch_empty']([], run, 'firefox', workload='empty')
    assert options == [{'evidence': result}] and 'owned_crash_artifacts' not in result


# R5-CHROME-C1A: explicit own-workload-PID rendezvous option. Real policy(), run_probe(),
# helper main() and observe(); OwnedProcess, getpid, execv and the browser are faked.
RENDEZVOUS = ['own-workload-pid']


def test_rendezvous_choice_is_exact(harness, monkeypatch, capsys):
    m, args, run = harness
    base = ['--engine', 'chrome', '--runtime', 'c', '--scratch', str(run)]
    code, seen = parse(m, monkeypatch, [*base, '--chrome-rendezvous', 'own-workload-pid'])
    assert code == 0 and seen[0].chrome_rendezvous == RENDEZVOUS
    code, seen = parse(m, monkeypatch, base)
    assert code == 0 and seen[0].chrome_rendezvous == []
    for bad in ['own-workload-pid ', 'OWN-WORKLOAD-PID', '4242', 'regex']:
        code, seen = parse(m, monkeypatch, [*base, '--chrome-rendezvous', bad])
        assert code == 2 and seen == []
    capsys.readouterr()


@pytest.mark.parametrize('engine,choices,code', [
    ('firefox', RENDEZVOUS, 'CHROME_RENDEZVOUS_LANE_REQUIRED'),
    ('chrome', RENDEZVOUS * 2, 'CHROME_RENDEZVOUS_DUPLICATE'),
    ('chrome', ['4242'], 'CHROME_RENDEZVOUS_OPTION_INVALID')])
def test_rendezvous_selection_refused_before_any_step(harness, monkeypatch, capsys, engine, choices, code):
    m, args, run = harness
    calls = []
    for name in ('fresh_attempt', 'prepare_runtime', 'run_probe', 'launch_empty', 'runtime_roots'):
        monkeypatch.setattr(m, name, lambda *a, _n=name, **kw: calls.append(_n))
    args.engine, args.chrome_rendezvous = engine, choices
    assert m.attempt(args) == 2
    record = json.loads(capsys.readouterr().out)
    assert calls == [] and not run.exists() and not (run.parent / 'attempt-rendezvous').exists()
    assert record['primary_failure']['stage'] == 'selection' and record['primary_failure']['code'] == code
    assert record['browser_launched'] is False and record['chrome_rendezvous'] == 'OWN_WORKLOAD_PID'


def test_firefox_record_has_no_rendezvous_key(harness):
    m, args, run = harness
    assert m.attempt(args) == 0
    r = result(run)
    assert 'chrome_rendezvous' not in r and not (run.parent / 'attempt-rendezvous').exists()


def test_chrome_default_probe_command_and_launch_are_unchanged(chrome_lane):
    c = chrome_lane
    assert c.m.attempt(c.args) == 0
    r = result(c.run)
    assert r['chrome_rendezvous'] == 'NOT_SELECTED' and 'rendezvous_parameter' not in r
    assert set(c.probes[0]) == {'automation_port', 'firefox_child_ipc', 'firefox_executable', 'evidence'}
    assert 'rendezvous' not in c.launches[0] and not (c.run.parent / 'attempt-rendezvous').exists()


def test_firefox_launch_refuses_rendezvous(harness, monkeypatch, tmp_path):
    m, args, run = harness
    import ast, cnt_owned_process
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', lambda *a, **kw: pytest.fail('launched'))
    node = next(n for n in ast.parse(Path(m.__file__).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    with pytest.raises(m.VerificationError, match='Chrome rendezvous requires the selected Chrome lane'):
        namespace['launch_empty']([], tmp_path, 'firefox', rendezvous={'evidence': tmp_path, 'argv': []})


class Execd(BaseException):
    pass


def c1a_attempt(m, args, run, monkeypatch, tmp_path, canary_pid=4242, browser_pid=4242, browser_record=True,
                interrupt=False):
    """Selected Chrome attempt through the real canary and helper; only processes are faked."""
    import cnt_confinement, cnt_owned_process
    import cnt_chrome_rendezvous as rv
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', tmp_path)
    monkeypatch.setattr(m, 'run_probe', cnt_confinement.run_probe)
    monkeypatch.setattr(rv, 'STORE', str(run))
    executable = run / 'runtime/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    def prepare(args, run, record):
        record['signature'] = {'original': True}
        record['runtime_snapshot_sha256'] = 'expected'
        record['runtime_measurement_root'] = 'SELECTED_STORE_APP'
        record['runtime_preparation_complete'] = True
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'synthetic chrome')
        return executable, [run / 'runtime'], 'expected'
    monkeypatch.setattr(m, 'prepare_runtime', prepare)
    monkeypatch.setattr(m, 'arguments', lambda engine, exe, run, port=None: [str(exe), '--remote-debugging-pipe'])
    probes, launches = [], []
    def helper(command, pid, effect):
        def execv(path, argv):
            effect(argv)
            raise Execd
        try:
            return rv.main(command[command.index(rv.HELPER) + 1:], {'PATH': '/usr/bin:/bin'},
                           getpid=lambda: pid, execv=execv)
        except Execd:
            return 'EXEC'
    class Owner:
        returncode = 0
        workload_pid = 4242
        def __init__(self, command, run, env, err, evidence=None):
            probes.append(command)
            def canary(argv):
                (run / 'canaries.json').write_text(json.dumps({'passed': True}))
                descriptor = os.open(run / 'canary-pid.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(descriptor, json.dumps({'pid': canary_pid}).encode())
                os.close(descriptor)
            helper(command, 4242, canary)
        def until(self, predicate, timeout): return predicate()
        def settle(self): return {'exit_code': 0, 'zero_survivors': True}
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    launch = m.launch_empty
    def launched(command, *a, result, **kw):
        launches.append((command, kw))
        if browser_record:
            helper(command, browser_pid, lambda argv: None)
        launch(command, *a, result=result, **kw)
        m.observe_rendezvous(result, kw['rendezvous'], 4242)
        if interrupt:
            raise KeyboardInterrupt
    monkeypatch.setattr(m, 'launch_empty', launched)
    args.engine, args.runtime, args.service, args.chrome_rendezvous = 'chrome', executable, list(D1_SERVICES), RENDEZVOUS
    return executable, probes, launches


def test_c1a_selected_attempt_uses_one_parameterized_path(harness, monkeypatch, tmp_path):
    m, args, run = harness
    import cnt_chrome_rendezvous as rv, cnt_confinement
    executable, probes, launches = c1a_attempt(m, args, run, monkeypatch, tmp_path)
    measured = []
    monkeypatch.setattr(m, 'tree_digest', lambda path, **kw: measured.append(path) or 'expected')
    assert m.attempt(args) == 0
    r = result(run)
    evidence = run.parent / 'attempt-rendezvous'
    assert measured == [args.runtime]  # the selected runtime, never the option's own flag
    assert r['status'] == 'SYNTHETIC_ATTEMPT_PASSED' and m.completed(r)
    assert r['chrome_rendezvous'] == 'OWN_WORKLOAD_PID' and r['preflight']['chrome_rendezvous'] == 'OWN_WORKLOAD_PID'
    assert rv.matched(r['preflight']['rendezvous_canary'], canary=True) and rv.matched(r['rendezvous_parameter'])
    assert evidence.is_dir() and evidence.stat().st_mode & 0o777 == 0o700 and not evidence.is_relative_to(run)
    probe = [str(Path(m.sys.executable).resolve()), '-B', str(run / 'probe.py'),
             str(run.parent / 'attempt-outside-canary')]
    assert probes[0][:7] == [m.sys.executable, '-B', '-I', rv.HELPER, str(evidence), 'canary', '--']
    assert probes[0][7:10] == ['/usr/bin/sandbox-exec', '-f', str(run / 'confinement.sb')]
    assert probes[0][10:14] == probe
    sandboxed = ['/usr/bin/sandbox-exec', '-f', str(run / 'confinement.sb'), str(executable), '--remote-debugging-pipe']
    command, kw = launches[0]
    assert command == [m.sys.executable, '-B', '-I', rv.HELPER, str(evidence), 'browser', '--', *sandboxed]
    assert kw['rendezvous'] == {'evidence': evidence, 'argv': sandboxed}
    # The launched policy is the canaried policy, and it is the default policy plus the one final rule.
    launched = (run / 'confinement.sb').read_text()
    default = cnt_confinement.policy(run, [run / 'runtime'], D1_SERVICES, None, firefox_child_ipc=False)
    assert launched == default + rv.RULE
    assert m.hashlib.sha256(launched.encode()).hexdigest() == r['preflight']['policy_sha256']
    assert (r['preflight']['policy_template_without_rendezvous_sha256']
            == cnt_confinement.policy_evidence(default, run, None, False)['policy_template_sha256'])
    raw = (run / 'result.json').read_text()
    assert '4242' not in raw and 'MachPortRendezvousServer.' not in raw


@pytest.mark.parametrize('case,launched,state', [
    ('canary-sandboxed-pid', False, 'PID_MISMATCH'), ('browser-pid', True, 'PID_MISMATCH'),
    ('browser-record-absent', True, 'RECORD_ABSENT')])
def test_c1a_mismatches_block_without_relabelling(harness, monkeypatch, tmp_path, case, launched, state):
    m, args, run = harness
    kw = {'canary-sandboxed-pid': {'canary_pid': 4343}, 'browser-pid': {'browser_pid': 4343},
          'browser-record-absent': {'browser_record': False}}[case]
    _, probes, launches = c1a_attempt(m, args, run, monkeypatch, tmp_path, **kw)
    assert m.attempt(args) == 2
    r = result(run)
    assert r['status'] == 'BLOCKED' and r['browser_launched'] is launched and len(launches) == int(launched)
    if launched:
        assert r['rendezvous_parameter']['state'] == state and 'primary_failure' not in r
        assert r['preflight']['rendezvous_canary']['state'] == 'MATCHED_WORKLOAD'
    else:
        assert r['preflight']['rendezvous_canary']['state'] == state
        assert r['preflight']['status'] == 'BLOCKED'
        assert r['primary_failure']['code'] == 'CONFINEMENT_PREFLIGHT_FAILED'
        assert 'rendezvous_parameter' not in r


def test_c1a_interrupt_is_persisted_with_the_observation(harness, monkeypatch, tmp_path):
    m, args, run = harness
    c1a_attempt(m, args, run, monkeypatch, tmp_path, interrupt=True)
    with pytest.raises(KeyboardInterrupt):
        m.attempt(args)
    r = result(run)
    assert r['primary_failure']['type'] == 'KeyboardInterrupt' and r['status'] == 'BLOCKED'
    assert r['rendezvous_parameter']['state'] == 'MATCHED_WORKLOAD'


def test_c1a_evidence_directory_must_be_fresh(harness, monkeypatch, tmp_path):
    m, args, run = harness
    _, probes, launches = c1a_attempt(m, args, run, monkeypatch, tmp_path)
    (run.parent / 'attempt-rendezvous').mkdir(mode=0o700)
    assert m.attempt(args) == 2
    r = result(run)
    assert r['primary_failure']['stage'] == 'confinement-preflight' and probes == [] and launches == []


@pytest.mark.parametrize('missing', [None, 'canary', 'launch', 'sandboxed'])
def test_completed_requires_both_rendezvous_matches_only_when_selected(harness, missing):
    m, _, _ = harness
    matched = {'state': 'MATCHED_WORKLOAD', 'workload_pid_matches': True, 'argv_template_matches': True,
               'sandboxed_pid_matches': None}
    record = {'shutdown_observer': False, 'diagnostic_only': True, 'parent_probes': False, 'crash_readback': False,
              'crash_force_enable': False, 'shutdown_trace': False, 'workload': 'empty', 'browser_launched': True,
              'runtime_preparation_complete': True, 'runtime_unchanged': True, 'ready': True, 'abnormal': False,
              'quit_observed': 'reply', 'exit_before_cleanup': 0,
              'settlement': {'exit_code': 0, 'workload_status': 'exited', 'zero_survivors': True,
                             'unsettled': False, 'failures': []},
              'chrome_rendezvous': 'OWN_WORKLOAD_PID',
              'preflight': {'rendezvous_canary': dict(matched, sandboxed_pid_matches=True)},
              'rendezvous_parameter': dict(matched)}
    if missing == 'canary':
        del record['preflight']['rendezvous_canary']
    elif missing == 'launch':
        del record['rendezvous_parameter']
    elif missing == 'sandboxed':
        record['preflight']['rendezvous_canary']['sandboxed_pid_matches'] = None
    assert m.completed(record) is (missing is None)
    for unaffected in ('NOT_SELECTED', None):
        other = {k: v for k, v in record.items() if k not in ('preflight', 'rendezvous_parameter')}
        if unaffected is None:
            other.pop('chrome_rendezvous')
        else:
            other['chrome_rendezvous'] = unaffected
        assert m.completed(other) is True


# --- R6 cnt-matrix workload (synthetic capture; no browser, captured code or live profile) ---

import hashlib as _hashlib
import io as _io
import zipfile as _zipfile

_FIXTURE = Path(__file__).resolve().parent / 'fixtures/cnt-native/firefox/6.12.1'


@pytest.fixture
def matrix_lane(harness, monkeypatch, tmp_path, capsys):
    m, args, run = harness
    import cnt_firefox_matrix as mx, cnt_confinement
    stream = _io.BytesIO()
    with _zipfile.ZipFile(stream, 'w') as z:
        z.writestr('manifest.json', json.dumps({'manifest_version': 3, 'version': '6.12.1',
                   'browser_specific_settings': {'gecko': {'id': 'clear-new-tab@loftyshaky'}}}))
        z.writestr('a.mjs', b'native')
    raw = stream.getvalue()
    capture = tmp_path / 'retained' / 'clear-new-tab.xpi'
    capture.parent.mkdir()
    capture.write_bytes(raw)
    meta = tmp_path / 'metadata.json'
    meta.write_text(json.dumps({'native_member_sha256': {'a.mjs': _hashlib.sha256(b'native').hexdigest()}}))
    digest = _hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(mx, 'XPI_SHA256', digest)
    real = mx.verify_capture
    monkeypatch.setattr(mx, 'verify_capture', lambda path, expected_sha256=digest: real(
        path, expected_sha256=expected_sha256, metadata_path=meta))
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', scratch)
    args.workload, args.capture, args.capture_sha256 = 'cnt-matrix', capture, digest
    args.matrix_case, args.matrix_input = 'S-RICH', None
    seen = {}
    launch = m.launch_empty
    def matrix_launch(*a, result, **kw):
        seen.update(kw)
        launch(*a, result=result, **kw)
        if kw.get('matrix_case'):
            result['matrix_completed'] = True
    monkeypatch.setattr(m, 'launch_empty', matrix_launch)
    def source(case='S-RICH', status='MATRIX_ATTEMPT_COMPLETED', data=None, artifact='rich', ready=True,
               code=None):
        root = scratch / ('source-' + case + '-' + status + ('' if ready else '-unready'))
        (root / f'artifacts/{artifact}').mkdir(parents=True)
        payload = data if data is not None else (_FIXTURE / 'export.json').read_bytes()
        (root / f'artifacts/{artifact}/part-1.json').write_bytes(payload)
        original = (_FIXTURE / 'export.json').read_bytes()
        # R6 REPAIR2: the source's recorded fixed readiness (never recomputed from ids here).
        (root / 'result.json').write_text(json.dumps({
            'status': status, 'primary_failure': {'code': code} if code else None, 'matrix': {
                'case': case, 'completed': True,
                'classifications': {'rich_source_ready': ready,
                                    'rich_source_missing': [] if ready else ['task:2:background']},
                'artifacts': {artifact: {'source_ready': ready, 'parts': [
                    {'index': 0, 'name_class': 'NATIVE_PART_1', 'bytes': len(original),
                     'sha256': _hashlib.sha256(original).hexdigest()}]}}}}))
        return root
    def outcome():
        code = m.attempt(args)
        printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        return code, printed
    return SimpleNamespace(m=m, args=args, run=run, raw=raw, source=source, outcome=outcome, seen=seen,
                           scratch=scratch)


@pytest.mark.parametrize('option', ['chrome', 'abnormal', 'parent_probes', 'crash_readback',
                                    'crash_force_enable', 'shutdown_trace', 'chrome_rendezvous'])
def test_matrix_refuses_incompatible_options_before_any_root(matrix_lane, option):
    lane = matrix_lane
    if option == 'chrome':
        lane.args.engine = 'chrome'
    elif option == 'chrome_rendezvous':
        lane.args.chrome_rendezvous = ['own-workload-pid']
    else:
        setattr(lane.args, option, True)
    code, printed = lane.outcome()
    assert code == 2 and not lane.run.exists()
    assert printed['primary_failure']['stage'] == 'selection'
    assert printed['primary_failure']['code'] in ('MATRIX_OPTION_REFUSED', 'CHROME_RENDEZVOUS_LANE_REQUIRED')
    assert printed['browser_launched'] is False and printed['captured_code_loaded'] is False


@pytest.mark.parametrize('change,code', [
    ('sha', 'CAPTURE_DIGEST_MISMATCH'), ('bytes', 'CAPTURE_DIGEST_MISMATCH'), ('relative', 'CAPTURE_ABSENT'),
    ('missing', 'MATRIX_CAPTURE_REQUIRED'), ('unknown-case', 'MATRIX_CASE_UNKNOWN'),
    ('not-drivable', 'MATRIX_CASE_NOT_DRIVABLE'), ('undeclared-input', 'MATRIX_INPUT_UNDECLARED'),
    ('required-input', 'MATRIX_INPUT_REQUIRED'), ('without-workload', 'MATRIX_OPTION_WITHOUT_WORKLOAD')])
def test_matrix_capture_case_and_input_refusals_before_any_root(matrix_lane, change, code):
    lane = matrix_lane
    if change == 'sha':
        lane.args.capture_sha256 = '0' * 64
    elif change == 'bytes':
        lane.args.capture.write_bytes(lane.raw + b'\0')
    elif change == 'relative':
        lane.args.capture = Path('clear-new-tab.xpi')
    elif change == 'missing':
        lane.args.capture = None
    elif change == 'unknown-case':
        lane.args.matrix_case = 'T-UNKNOWN'
    elif change == 'not-drivable':
        lane.args.matrix_case = 'D-EMPTY-SELECTION'
    elif change == 'undeclared-input':
        lane.args.matrix_input = lane.source()
    elif change == 'required-input':
        lane.args.matrix_case = 'T-RICH'
    else:
        lane.args.workload = 'full'
    result, printed = lane.outcome()
    assert result == 2 and not lane.run.exists()
    assert printed['primary_failure']['code'] == code


def test_matrix_source_case_completes_without_r4_acceptance(matrix_lane):
    lane = matrix_lane
    code, printed = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    assert code == 0 and r['status'] == 'MATRIX_ATTEMPT_COMPLETED' and not lane.m.passed(r)
    assert r['native_semantics'] == 'EXECUTED_CASE_RECORDED' and lane.seen['matrix_case'] == 'S-RICH'
    assert (lane.run / 'capture/clear-new-tab.xpi').read_bytes() == lane.raw
    assert r['capture_copy']['extension_id'] == 'clear-new-tab@loftyshaky' and r['matrix_materialized']
    assert 'matrix_inputs' not in r


def test_matrix_without_case_completion_is_blocked(matrix_lane, monkeypatch):
    lane = matrix_lane
    monkeypatch.setattr(lane.m, 'launch_empty', lambda *a, result, **kw: result.update(
        ready=True, page_nonce=True, quit_observed='reply', exit_before_cleanup=0,
        settlement={'exit_code': 0, 'zero_survivors': True, 'unsettled': False, 'failures': [],
                    'workload_status': 'exited'}))
    code, _ = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    assert code == 2 and r['status'] == 'BLOCKED' and r['native_semantics'] == 'NOT_EXECUTED'
    assert r['status'] != 'SYNTHETIC_ATTEMPT_PASSED'


def test_matrix_target_inputs_bound_to_source_result(matrix_lane):
    lane = matrix_lane
    lane.args.matrix_case, lane.args.matrix_input = 'T-RICH', lane.source()
    code, _ = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    export = (_FIXTURE / 'export.json').read_bytes()
    assert code == 0 and r['matrix_inputs']['source'][0]['sha256'] == _hashlib.sha256(export).hexdigest()
    assert (lane.run / 'inputs/source/part-1.json').read_bytes() == export
    assert (lane.run / 'inputs/select/0/bux-matrix Part 1.json').read_bytes() == export
    assert r['matrix_inputs']['selection'] == [{'named_part': 1, 'slot': 0, 'part_number': 1,
                                                 'sha256': _hashlib.sha256(export).hexdigest()}]


def test_matrix_declared_mutation_recorded(matrix_lane):
    lane = matrix_lane
    lane.args.matrix_case, lane.args.matrix_input = 'D-NO-CHUNKS', lane.source()
    lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    mutation = r['matrix_inputs']['mutation']
    assert mutation['mutation'] == 'drop_chunks' and mutation['part_number'] == 1
    assert mutation['after_sha256'] == r['matrix_inputs']['source'][0]['sha256'] != mutation['before_sha256']


@pytest.mark.parametrize('case,mutation', [('D-TRUNC-P1', 'truncate_json'), ('D-NO-CHUNKS', 'drop_chunks'),
                                           ('D-CHUNKS-TYPE', 'chunks_not_array'),
                                           ('D-BAD-DATAURL', 'invalid_data_url')])
def test_matrix_mutated_case_keeps_the_unmutated_source_beside_the_input(matrix_lane, case, mutation):
    """MALFORMED-D-PREP1: `source` stays the (mutated) restore input; `original` is the unmutated
    same-root source, recorded and materialized with the same exclusive, re-verified write."""
    lane = matrix_lane
    lane.args.matrix_case, lane.args.matrix_input = case, lane.source()
    code, _ = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    export = (_FIXTURE / 'export.json').read_bytes()
    inputs, digest = r['matrix_inputs'], _hashlib.sha256(export).hexdigest()
    assert code == 0 and inputs['mutation']['mutation'] == mutation
    assert inputs['original'] == [{'part_number': 1, 'bytes': len(export), 'sha256': digest}]
    assert inputs['mutation']['before_sha256'] == digest == inputs['original'][0]['sha256']
    assert (lane.run / 'inputs/original/part-1.json').read_bytes() == export
    mutated = (lane.run / 'inputs/source/part-1.json').read_bytes()
    assert mutated != export and _hashlib.sha256(mutated).hexdigest() == inputs['mutation']['after_sha256']
    assert (lane.run / 'inputs/select/0/bux-matrix Part 1.json').read_bytes() == mutated
    assert inputs['selection'] == [{'named_part': 1, 'slot': 0, 'part_number': 1,
                                    'sha256': inputs['mutation']['after_sha256']}]


@pytest.mark.parametrize('case,named', [('T-RICH', 1), ('D-NAME-NO-P1', 2)])
def test_matrix_unmutated_case_records_no_original(matrix_lane, case, named):
    """No mutation: no `original` key and no inputs/original, so RICH-VALID-shaped inputs are unchanged."""
    lane = matrix_lane
    lane.args.matrix_case, lane.args.matrix_input = case, lane.source()
    code, _ = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    export = (_FIXTURE / 'export.json').read_bytes()
    assert code == 0 and 'original' not in r['matrix_inputs'] and r['matrix_inputs']['mutation'] is None
    assert not (lane.run / 'inputs/original').exists()
    assert (lane.run / f'inputs/select/0/bux-matrix Part {named}.json').read_bytes() == export
    assert r['matrix_inputs']['selection'] == [{'named_part': named, 'slot': 0, 'part_number': 1,
                                                'sha256': _hashlib.sha256(export).hexdigest()}]


@pytest.mark.parametrize('damage', ['tampered', 'status', 'case', 'outside', 'link'])
def test_matrix_input_source_refused_before_any_root(matrix_lane, tmp_path, damage):
    lane = matrix_lane
    lane.args.matrix_case = 'T-RICH'
    if damage == 'tampered':
        lane.args.matrix_input = lane.source(data=(_FIXTURE / 'export.json').read_bytes() + b' ')
    elif damage == 'status':
        lane.args.matrix_input = lane.source(status='BLOCKED')
    elif damage == 'case':
        lane.args.matrix_input = lane.source(case='S-MULTI')
    elif damage == 'outside':
        # A live-profile-shaped location outside managed scratch is never a matrix input.
        profile = tmp_path / 'Library/Application Support/Firefox/Profiles/daily'
        profile.mkdir(parents=True)
        lane.args.matrix_input = profile
    else:
        link = lane.scratch / 'linked'
        link.symlink_to(lane.source())
        lane.args.matrix_input = link
    code, printed = lane.outcome()
    assert code == 2 and not lane.run.exists()
    assert printed['primary_failure']['code'] == (
        'MATRIX_INPUT_DIGEST_MISMATCH' if damage == 'tampered' else 'MATRIX_INPUT_SOURCE_INVALID')


def test_matrix_failure_fields_stay_distinct(matrix_lane, monkeypatch):
    lane = matrix_lane
    def launch(*a, result, **kw):
        result['captured_code_loaded'] = True
        raise RuntimeError('primary')
    monkeypatch.setattr(lane.m, 'launch_empty', launch)
    monkeypatch.setattr(lane.m, 'tree_digest', lambda _, **kw: 'changed')
    lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    assert r['status'] == 'BLOCKED' and r['captured_code_loaded'] is True
    assert r['primary_failure']['stage'] == 'browser' and r['runtime_failure']['stage'] == 'runtime-verification'
    assert 'cleanup_failure' not in r and 'evidence_io_failure' not in r


def test_existing_workload_records_gain_no_matrix_keys(harness):
    m, args, run = harness
    assert m.attempt(args) == 0
    r = json.loads((run / 'result.json').read_text())
    assert r['status'] == 'SYNTHETIC_ATTEMPT_PASSED' and r['native_semantics'] == 'NOT_EXECUTED'
    assert not [k for k in r if k.startswith(('matrix', 'capture_'))] and r['captured_code_loaded'] is False


def test_matrix_launch_branch_runs_canary_then_case_then_normal_quit(harness, monkeypatch):
    m, args, run = harness
    run.mkdir()
    import ast, cnt_owned_process, cnt_synthetic_firefox, cnt_firefox_matrix_session
    order = []
    class Owner:
        returncode = 0
        workload_pid = 1
        def __init__(self, *a, **kw): pass
        def settle(self):
            return {'exit_code': 0, 'zero_survivors': True, 'unsettled': False, 'failures': [],
                    'workload_status': 'exited'}
    class Client:
        methods, valid = [], True
        connection = SimpleNamespace(close=lambda: None)
        def sample(self, *a, **kw): pass
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    monkeypatch.setattr(cnt_synthetic_firefox, 'session', lambda *a: (Client(), {'browserVersion': '155.0.1'}))
    monkeypatch.setattr(cnt_synthetic_firefox, 'qualify',
                        lambda c, r, res, page_only=False: order.append(('qualify', page_only)))
    monkeypatch.setattr(cnt_firefox_matrix_session, 'exercise',
                        lambda c, r, res, case: order.append(('exercise', case)))
    monkeypatch.setattr(cnt_synthetic_firefox, 'quit_normally', lambda *a: order.append(('quit',)))
    tree = ast.parse(Path(m.__file__).read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    namespace['launch_empty']([], run, 'firefox', result={}, workload='cnt-matrix', matrix_case='S-RICH')
    assert order == [('qualify', True), ('exercise', 'S-RICH'), ('quit',)]


# --- R6 SRICH-REPAIR2: a source without fixed S-RICH readiness is never an input ---------------

@pytest.mark.parametrize('forged', ['completed-unready', 'blocked-incomplete'])
def test_matrix_unready_rich_source_refused_before_any_root(matrix_lane, forged):
    lane = matrix_lane
    lane.args.matrix_case = 'T-RICH'
    if forged == 'completed-unready':
        # Forged: a completed status whose own readiness is false is still refused.
        lane.args.matrix_input = lane.source(ready=False)
    else:
        lane.args.matrix_input = lane.source(status='BLOCKED', ready=False, code='MATRIX_RICH_SOURCE_INCOMPLETE')
    code, printed = lane.outcome()
    assert code == 2 and not lane.run.exists()
    assert printed['primary_failure']['code'] == 'MATRIX_INPUT_SOURCE_INVALID'
    assert printed['browser_launched'] is False and printed['captured_code_loaded'] is False


def test_matrix_rich_readiness_code_is_allowlisted(harness):
    m, _, _ = harness
    codes = m.failure_codes()
    assert codes['Matrix rich source incomplete'] == 'MATRIX_RICH_SOURCE_INCOMPLETE'
    assert codes['Matrix input source invalid'] == 'MATRIX_INPUT_SOURCE_INVALID'


# --- MULTIPART-B-PREP1: a B dependent consumes only the ready same-root S-MULTI minimum artifact ------

def _multi_parts():
    value = json.loads((_FIXTURE / 'export.json').read_bytes())
    value['settings']['prefs']['one_backup_file_size_in_bytes'] = 52428800
    chunks = [json.dumps(c, separators=(',', ':')).encode() for c in value['chunks']]
    raw = json.dumps(value, separators=(',', ':')).encode()
    header = raw[:raw.index(b'"chunks":[') + len(b'"chunks":[')]
    return [(header if n == 0 else b'{"chunks":[') + b','.join(chunks[i] for i in g) + b']}'
            for n, g in enumerate(((0,), (1, 2), (3,)))]


def _multi_source(root, ready=True, keys='multi'):
    parts = _multi_parts()
    (root / 'artifacts/minimum').mkdir(parents=True)
    for n, raw in enumerate(parts, 1):
        (root / f'artifacts/minimum/part-{n}.json').write_bytes(raw)
    classes = ({'multi_source_ready': ready, 'multi_source_missing': [] if ready else ['boundary:exact']}
               if keys == 'multi' else {'rich_source_ready': True, 'rich_source_missing': []})
    (root / 'result.json').write_text(json.dumps({'status': 'MATRIX_ATTEMPT_COMPLETED', 'matrix': {
        'case': 'S-MULTI', 'completed': True, 'classifications': classes,
        'artifacts': {'minimum': {'source_ready': ready, 'parts': [
            {'index': n, 'name_class': f'NATIVE_PART_{n + 1}', 'bytes': len(raw),
             'sha256': _hashlib.sha256(raw).hexdigest()} for n, raw in enumerate(parts)]}}}}))
    return root, parts


def _same_root(lane, monkeypatch):
    """The attempt root's parent is the claim root's cases directory (managed scratch here)."""
    import cnt_confinement
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', lane.run.parent)
    return lane.run.parent


@pytest.mark.parametrize('case', ['T-MULTI-ORDERED', 'T-MULTI-DUP', 'T-MULTI-TRUNC', 'T-MULTI-BADDATA'])
def test_b_dependent_records_the_same_root_s_multi_readiness(matrix_lane, monkeypatch, case):
    lane = matrix_lane
    source, parts = _multi_source(_same_root(lane, monkeypatch) / 'S-MULTI')
    lane.args.matrix_case, lane.args.matrix_input = case, source
    code, printed = lane.outcome()
    assert code == 0, printed.get('primary_failure')
    inputs = json.loads((lane.run / 'result.json').read_text())['matrix_inputs']
    assert inputs['source_readiness'] == {'ready': True, 'same_root': True, 'minimum_part_sha256': [
        _hashlib.sha256(raw).hexdigest() for raw in parts]}
    assert (inputs['source_case'], inputs['artifact']) == ('S-MULTI', 'minimum')
    if case in ('T-MULTI-TRUNC', 'T-MULTI-BADDATA'):
        assert [p['sha256'] for p in inputs['original']] == inputs['source_readiness']['minimum_part_sha256']
        assert inputs['mutation']['part_number'] == (3 if case == 'T-MULTI-TRUNC' else 2)
    else:
        assert 'original' not in inputs and inputs['mutation'] is None
        assert [p['sha256'] for p in inputs['source']] == inputs['source_readiness']['minimum_part_sha256']


@pytest.mark.parametrize('damage', ['other-root', 'unready', 'rich-keys-only'])
def test_b_dependent_refuses_an_unready_or_foreign_s_multi_before_any_root(matrix_lane, monkeypatch, damage):
    lane = matrix_lane
    root = _same_root(lane, monkeypatch)
    where = root / 'other-claim/cases/S-MULTI' if damage == 'other-root' else root / 'S-MULTI'
    source, _ = _multi_source(where, ready=damage != 'unready', keys='rich' if damage == 'rich-keys-only' else 'multi')
    lane.args.matrix_case, lane.args.matrix_input = 'T-MULTI-NO-P1', source
    code, printed = lane.outcome()
    assert code == 2 and not lane.run.exists()
    assert printed['primary_failure']['code'] == 'MATRIX_INPUT_SOURCE_INVALID'
    assert printed['browser_launched'] is False and printed['captured_code_loaded'] is False


def test_rich_dependents_record_no_multipart_readiness(matrix_lane):
    lane = matrix_lane
    lane.args.matrix_case, lane.args.matrix_input = 'T-RICH', lane.source()
    code, _ = lane.outcome()
    assert code == 0
    assert 'source_readiness' not in json.loads((lane.run / 'result.json').read_text())['matrix_inputs']


# --- BUX5B1 RECOVERY-HOSTPREP1 cnt-recovery workload (synthetic capture and plan; no browser) ---------

@pytest.fixture
def recovery_lane(harness, monkeypatch, tmp_path, capsys):
    m, args, _ = harness
    import cnt_firefox_matrix as mx, cnt_confinement, cnt_firefox_recovery as rec
    stream = _io.BytesIO()
    with _zipfile.ZipFile(stream, 'w') as z:
        z.writestr('manifest.json', json.dumps({'manifest_version': 3, 'version': '6.12.1',
                   'browser_specific_settings': {'gecko': {'id': 'clear-new-tab@loftyshaky'}}}))
        z.writestr('a.mjs', b'native')
    raw = stream.getvalue()
    capture = tmp_path / 'retained' / 'clear-new-tab.xpi'
    capture.parent.mkdir()
    capture.write_bytes(raw)
    meta = tmp_path / 'metadata.json'
    meta.write_text(json.dumps({'native_member_sha256': {'a.mjs': _hashlib.sha256(b'native').hexdigest()}}))
    digest = _hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(mx, 'XPI_SHA256', digest)
    real = mx.verify_capture
    monkeypatch.setattr(mx, 'verify_capture', lambda path, expected_sha256=digest: real(
        path, expected_sha256=expected_sha256, metadata_path=meta))
    scratch = tmp_path / 'scratch'
    root = scratch / 'claim'
    for name in ('cases', 'plans', 'tokens', 'staging'):
        (root / name).mkdir(parents=True)
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', scratch)
    run = root / 'cases' / '01-source'
    args.scratch = run
    args.workload, args.capture, args.capture_sha256 = 'recovery', capture, digest
    args.workload = 'cnt-recovery'
    def plan(role='source', scenario=None, name='01-source', **changes):
        value = {'schema': rec.PLAN_SCHEMA, 'role': role, 'scenario': scenario, 'plan_nonce': 'c' * 64,
                 'claim_root': str(root), 'attempt': str(root / 'cases' / name), 'attempt_name': name,
                 'source_attempt': None, 'tokens': [], 'global_claim_sha256': 'd' * 64}
        value.update(changes)
        path = root / 'plans' / (name + '.json')
        raw = json.dumps(value).encode()
        path.write_bytes(raw)
        args.recovery_plan, args.recovery_plan_sha256 = path, _hashlib.sha256(raw).hexdigest()
        return value
    plan()
    def probe(probe_run, *a, **kw):
        (probe_run / 'confinement.sb').write_bytes(b'policy')
        return {'status': 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION',
                'policy_sha256': _hashlib.sha256(b'policy').hexdigest()}
    monkeypatch.setattr(m, 'run_probe', probe)
    order, seen = [], {}
    def fresh(plan_value, run_path, expected, *, created_exclusive):
        order.append('freshness')
        seen.update(freshness=(plan_value['role'], run_path, expected, created_exclusive))
        return {'proven': True, 'role': plan_value['role'], 'home_is_run_home': True}
    monkeypatch.setattr(rec, 'prove_fresh_profile', fresh)
    launch = m.launch_empty
    def recovery_launch(*a, result, **kw):
        order.append('launch')
        seen.update(kw)
        launch(*a, result=result, **kw)
        if kw.get('recovery_plan') is not None:
            result['recovery_completed'] = True
    monkeypatch.setattr(m, 'launch_empty', recovery_launch)
    def outcome():
        code = m.attempt(args)
        printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        return code, printed
    return SimpleNamespace(m=m, args=args, run=run, root=root, raw=raw, plan=plan, outcome=outcome, seen=seen,
                           order=order, rec=rec, monkeypatch=monkeypatch)


def test_recovery_role_completes_without_r4_acceptance(recovery_lane):
    lane = recovery_lane
    code, printed = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    assert code == 0 and r['status'] == 'RECOVERY_ATTEMPT_COMPLETED' and not lane.m.passed(r)
    assert r['status'] != 'SYNTHETIC_ATTEMPT_PASSED' and r['native_semantics'] == 'EXECUTED_RECOVERY_ROLE_RECORDED'
    assert (lane.run / 'capture/clear-new-tab.xpi').read_bytes() == lane.raw and r['recovery_materialized'] is True
    assert 'matrix_materialized' not in r and not [k for k in r if k.startswith('matrix')]
    assert r['recovery_role'] == 'source' and r['recovery_scenario'] is None
    assert lane.seen['recovery_plan']['role'] == 'source' and '_capture' not in json.dumps(r)
    assert lane.order == ['freshness', 'launch']


def test_recovery_without_role_completion_is_blocked(recovery_lane, monkeypatch):
    lane = recovery_lane
    monkeypatch.setattr(lane.m, 'launch_empty', lambda *a, result, **kw: result.update(
        ready=True, page_nonce=True, quit_observed='reply', exit_before_cleanup=0,
        settlement={'exit_code': 0, 'zero_survivors': True, 'unsettled': False, 'failures': [],
                    'workload_status': 'exited'}))
    code, _ = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    assert code == 2 and r['status'] == 'BLOCKED' and r['native_semantics'] == 'NOT_EXECUTED'


@pytest.mark.parametrize('option', ['chrome', 'abnormal', 'parent_probes', 'crash_readback', 'crash_force_enable',
                                    'shutdown_trace', 'chrome_rendezvous'])
def test_recovery_refuses_incompatible_options_before_any_root(recovery_lane, option):
    lane = recovery_lane
    if option == 'chrome':
        lane.args.engine = 'chrome'
    elif option == 'chrome_rendezvous':
        lane.args.chrome_rendezvous = ['own-workload-pid']
    else:
        setattr(lane.args, option, True)
    code, printed = lane.outcome()
    assert code == 2 and not lane.run.exists()
    assert printed['primary_failure'] == {'stage': 'selection', 'type': 'VerificationError',
                                          'classification': 'Recovery workload option refused',
                                          'code': 'RECOVERY_OPTION_REFUSED', 'message_known': True}
    assert printed['browser_launched'] is False and printed['captured_code_loaded'] is False


@pytest.mark.parametrize('change,code', [
    ('plan-sha', 'RECOVERY_PLAN_INVALID'), ('plan-missing', 'RECOVERY_CAPTURE_REQUIRED'),
    ('capture-missing', 'RECOVERY_CAPTURE_REQUIRED'), ('capture-sha', 'CAPTURE_DIGEST_MISMATCH'),
    ('other-attempt', 'RECOVERY_PLAN_INVALID'), ('live-role', 'RECOVERY_PLAN_INVALID'),
    ('matrix-case', 'MATRIX_OPTION_WITHOUT_WORKLOAD'), ('without-workload', 'RECOVERY_OPTION_WITHOUT_WORKLOAD'),
    ('target-without-source', 'RECOVERY_SOURCE_INVALID'), ('plan-outside-scratch', 'RECOVERY_PLAN_INVALID')])
def test_recovery_plan_and_capture_refusals_before_any_root(recovery_lane, change, code):
    lane = recovery_lane
    if change == 'plan-sha':
        lane.args.recovery_plan_sha256 = '0' * 64
    elif change == 'plan-missing':
        lane.args.recovery_plan = None
    elif change == 'capture-missing':
        lane.args.capture = None
    elif change == 'capture-sha':
        lane.args.capture_sha256 = '0' * 64
    elif change == 'other-attempt':
        lane.plan(name='02-target-noop-match')
    elif change == 'live-role':
        lane.plan(role='live')
    elif change == 'matrix-case':
        lane.args.matrix_case = 'S-RICH'
    elif change == 'without-workload':
        lane.args.workload = 'full'
        lane.args.capture = lane.args.capture_sha256 = None
    elif change == 'target-without-source':
        name = '02-target-noop-match'
        lane.args.scratch = lane.root / 'cases' / name
        lane.run = lane.args.scratch
        tokens = [{'path': str(lane.root / 'tokens/s01-noop.token'), 'sha256': 'e' * 64, 'scenario': 'NOOP_MATCH',
                   'journal_id': 's01-noop', 'kind': 'NONE'}]
        lane.plan(role='target', scenario='NOOP_MATCH', name=name,
                  source_attempt=str(lane.root / 'cases/01-source'), tokens=tokens)
    else:
        lane.plan(claim_root=str(lane.root.parent.parent / 'elsewhere'))
    result, printed = lane.outcome()
    assert result == 2 and not lane.run.exists() and lane.order == []
    assert printed['primary_failure']['code'] == code and printed['primary_failure']['stage'] == 'selection'


def test_freshness_proof_runs_on_the_generated_user_js_immediately_before_launch(recovery_lane):
    lane = recovery_lane
    lane.outcome()
    role, run, expected, exclusive = lane.seen['freshness']
    assert (role, run, exclusive) == ('source', lane.run, True)
    assert expected == lane.m.firefox_user_js(12345)
    r = json.loads((lane.run / 'result.json').read_text())
    assert r['recovery_freshness']['proven'] is True


def test_freshness_refusal_blocks_before_any_launch(recovery_lane):
    lane = recovery_lane
    def refuse(*a, **kw):
        raise lane.m.VerificationError('Recovery staging disposability unproven')
    lane.monkeypatch.setattr(lane.rec, 'prove_fresh_profile', refuse)
    code, printed = lane.outcome()
    r = json.loads((lane.run / 'result.json').read_text())
    assert code == 2 and r['status'] == 'BLOCKED' and r['browser_launched'] is False and lane.order == []
    assert r['primary_failure']['stage'] == 'recovery-freshness'
    assert r['primary_failure']['code'] == 'STAGING_DISPOSABILITY_UNPROVEN'


def test_recovery_policy_inputs_equal_the_accepted_lane(recovery_lane, monkeypatch):
    lane = recovery_lane
    seen = []
    real = lane.m.run_probe
    def probe(run, python, roots, outside, port, services, **kw):
        seen.append((list(services), kw.get('automation_port'), kw.get('firefox_child_ipc'),
                     sorted(k for k in kw if k != 'evidence')))
        return real(run, python, roots, outside, port, services, **kw)
    monkeypatch.setattr(lane.m, 'run_probe', probe)
    lane.outcome()
    recovery = seen[-1]
    lane.args.workload, lane.args.recovery_plan, lane.args.recovery_plan_sha256 = 'page', None, None
    lane.args.capture = lane.args.capture_sha256 = None
    lane.args.scratch = lane.root / 'cases' / 'page-lane'
    lane.outcome()
    assert seen[-1] == recovery


def test_firefox_user_js_bytes_are_the_accepted_r4_prefs(harness):
    m, _, _ = harness
    assert m.firefox_user_js(12345) == (
        'user_pref("browser.shell.checkDefaultBrowser",false);\nuser_pref("app.update.auto",false);\n'
        'user_pref("app.update.enabled",false);\nuser_pref("extensions.update.enabled",false);\n'
        'user_pref("identity.fxaccounts.enabled",false);\nuser_pref("services.sync.enabled",false);\n'
        'user_pref("network.offline",true);\nuser_pref("marionette.port",12345);\n'
        'user_pref("toolkit.telemetry.enabled",false);\nuser_pref("datareporting.healthreport.uploadEnabled",false);\n'
    ).encode()


def test_recovery_launch_branch_runs_canary_then_role_then_normal_quit(harness, monkeypatch):
    m, args, run = harness
    run.mkdir()
    import ast, cnt_owned_process, cnt_synthetic_firefox, cnt_firefox_recovery
    order = []
    class Owner:
        returncode = 0
        workload_pid = 1
        def __init__(self, *a, **kw): pass
        def settle(self):
            return {'exit_code': 0, 'zero_survivors': True, 'unsettled': False, 'failures': [],
                    'workload_status': 'exited'}
    class Client:
        methods, valid = [], True
        connection = SimpleNamespace(close=lambda: None)
        def sample(self, *a, **kw): pass
    monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owner)
    monkeypatch.setattr(cnt_synthetic_firefox, 'session', lambda *a: (Client(), {'browserVersion': '156.0.1'}))
    monkeypatch.setattr(cnt_synthetic_firefox, 'qualify',
                        lambda c, r, res, page_only=False: order.append(('qualify', page_only)))
    monkeypatch.setattr(cnt_firefox_recovery, 'exercise',
                        lambda c, r, res, plan: order.append(('exercise', plan['role'])))
    monkeypatch.setattr(cnt_synthetic_firefox, 'quit_normally', lambda *a: order.append(('quit',)))
    tree = ast.parse(Path(m.__file__).read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'launch_empty')
    namespace = dict(m.__dict__)
    exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), namespace)
    namespace['launch_empty']([], run, 'firefox', result={}, workload='cnt-recovery',
                              recovery_plan={'role': 'target'})
    assert order == [('qualify', True), ('exercise', 'target'), ('quit',)]


def test_recovery_codes_are_allowlisted_in_the_preflight(harness):
    m, _, _ = harness
    codes = m.failure_codes()
    assert codes['Recovery workload option refused'] == 'RECOVERY_OPTION_REFUSED'
    assert codes['Recovery export incomplete'] == 'EXPORT_INCOMPLETE'
    assert codes['Recovery staging disposability unproven'] == 'STAGING_DISPOSABILITY_UNPROVEN'


# HOSTPREP1-NIX-CLI-COMPAT1: legacy nix-store and modern nix closure queries. The frontends are
# synthetic Python stubs on a synthetic PATH; no real Nix runs and the store is never touched.
import sys

NIX_ROOT = '/nix/store/' + '1' * 32 + '-python3-3.13.12-env'
NIX_CLOSURE = [NIX_ROOT, '/nix/store/' + '2' * 32 + '-python3-3.13.12',
               '/nix/store/' + 'a' * 32 + '-openssl-3.6.0', '/nix/store/' + 'z' * 32 + '-libffi-3.5.2']
LEGACY_ARGS = ['--query', '--requisites']
MODERN_ARGS = ['--extra-experimental-features', 'nix-command', 'path-info', '--recursive']
NIX_STUB = '''#!{python}
import json, sys
with open({log!r}, 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
sys.stdout.write({output!r})
sys.exit({code})
'''


@pytest.fixture
def nixq(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    return load_module('tests/cnt-native-preflight.py')


def nix_stub(directory, name, lines, code=0, mode=0o755):
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / name
    stub.write_text(NIX_STUB.format(python=Path(sys.executable).resolve(), log=str(directory / (name + '.argv')),
                                    output=''.join(line + '\n' for line in lines), code=code))
    stub.chmod(mode)
    return stub


def stub_calls(directory, name):
    log = directory / (name + '.argv')
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_nix_closure_frontend_names_match_the_launch_contract(nixq, monkeypatch, repo_root):
    import cnt_host_d2
    assert [name for name, _ in nixq.CLOSURE_FRONTENDS] == list(cnt_host_d2.NIX_FRONTENDS) == ['nix-store', 'nix']
    assert dict(nixq.CLOSURE_FRONTENDS) == {'nix-store': tuple(LEGACY_ARGS), 'nix': tuple(MODERN_ARGS)}


def test_nix_closure_legacy_and_modern_return_the_same_sorted_set(nixq, tmp_path, monkeypatch):
    legacy, modern = tmp_path / 'legacy/bin', tmp_path / 'modern/bin'
    nix_stub(legacy, 'nix-store', NIX_CLOSURE[::-1])
    nix_stub(modern, 'nix', [NIX_CLOSURE[2], '', NIX_CLOSURE[0], NIX_CLOSURE[3], NIX_CLOSURE[2], NIX_CLOSURE[1]])
    monkeypatch.setenv('PATH', f'{legacy}:/usr/bin:/bin')
    old = nixq.query_runtime_roots(Path(NIX_ROOT))
    monkeypatch.setenv('PATH', f'{modern}:/usr/bin:/bin')
    new = nixq.query_runtime_roots(Path(NIX_ROOT))
    assert old == new == sorted(Path(p) for p in NIX_CLOSURE)
    assert stub_calls(legacy, 'nix-store') == [[*LEGACY_ARGS, NIX_ROOT]]
    assert stub_calls(modern, 'nix') == [[*MODERN_ARGS, NIX_ROOT]]


def test_nix_closure_prefers_legacy_within_one_directory(nixq, tmp_path, monkeypatch):
    both = tmp_path / 'both/bin'
    nix_stub(both, 'nix-store', NIX_CLOSURE)
    nix_stub(both, 'nix', NIX_CLOSURE)
    monkeypatch.setenv('PATH', f'{both}:/usr/bin:/bin')
    assert nixq.query_runtime_roots(Path(NIX_ROOT)) == sorted(Path(p) for p in NIX_CLOSURE)
    assert stub_calls(both, 'nix-store') == [[*LEGACY_ARGS, NIX_ROOT]] and stub_calls(both, 'nix') == []


def test_nix_closure_first_path_directory_wins(nixq, tmp_path, monkeypatch):
    # The launch PATH is <nix_bin>:/usr/bin:/bin, so the selection is always nix_bin's own frontend.
    modern, later = tmp_path / 'modern/bin', tmp_path / 'later/bin'
    nix_stub(modern, 'nix', NIX_CLOSURE)
    nix_stub(later, 'nix-store', NIX_CLOSURE)
    monkeypatch.setenv('PATH', f'{modern}:{later}')
    nixq.query_runtime_roots(Path(NIX_ROOT))
    assert stub_calls(modern, 'nix') == [[*MODERN_ARGS, NIX_ROOT]] and stub_calls(later, 'nix-store') == []


@pytest.mark.parametrize('case', ['neither', 'not-executable', 'relative-entry', 'empty-entry', 'unset'])
def test_nix_closure_refuses_without_a_usable_frontend(nixq, tmp_path, monkeypatch, case):
    stubs = tmp_path / 'stubs'
    stubs.mkdir()
    if case != 'neither':
        mode = 0o644 if case == 'not-executable' else 0o755
        for name in ('nix-store', 'nix'):
            nix_stub(stubs, name, NIX_CLOSURE, mode=mode)
    monkeypatch.chdir(tmp_path)
    if case == 'unset':
        monkeypatch.delenv('PATH', raising=False)
    else:
        monkeypatch.setenv('PATH', {'relative-entry': 'stubs:/usr/bin:/bin',
                                    'empty-entry': ':/usr/bin:/bin'}.get(case, f'{stubs}:/usr/bin:/bin'))
    if case == 'empty-entry':
        monkeypatch.chdir(stubs)
    with pytest.raises(nixq.VerificationError, match='No supported Nix closure-query frontend'):
        nixq.query_runtime_roots(Path(NIX_ROOT))
    assert stub_calls(stubs, 'nix-store') == stub_calls(stubs, 'nix') == []


MALFORMED = {
    'exit': (NIX_CLOSURE, 1, 'Nix closure query failed'),
    'relative': ([*NIX_CLOSURE, NIX_CLOSURE[1][1:]], 0, 'Malformed Nix closure member'),
    'nested': ([*NIX_CLOSURE, NIX_ROOT + '/bin'], 0, 'Malformed Nix closure member'),
    'outside': ([*NIX_CLOSURE, '/usr/lib/libSystem.B.dylib'], 0, 'Malformed Nix closure member'),
    'dotdot': ([*NIX_CLOSURE, '/nix/store/../etc'], 0, 'Malformed Nix closure member'),
    'trailing-slash': ([*NIX_CLOSURE, NIX_CLOSURE[1] + '/'], 0, 'Malformed Nix closure member'),
    'hash-charset': ([*NIX_CLOSURE, '/nix/store/' + 'e' * 32 + '-bad'], 0, 'Malformed Nix closure member'),
    'whitespace': ([*NIX_CLOSURE, ' ' + NIX_CLOSURE[1]], 0, 'Malformed Nix closure member'),
    'root-missing': (NIX_CLOSURE[1:], 0, 'Nix closure omits its root'),
    'empty': ([], 0, 'Nix closure omits its root'),
    'source': ([*NIX_CLOSURE, '/nix/store/' + '3' * 32 + '-nixpkgs-source'], 0, 'Source-bearing runtime closure'),
}


@pytest.mark.parametrize('frontend', ['nix-store', 'nix'])
@pytest.mark.parametrize('case', sorted(MALFORMED))
def test_nix_closure_refuses_malformed_output_from_either_frontend(nixq, tmp_path, monkeypatch, frontend, case):
    lines, code, message = MALFORMED[case]
    bin_dir = tmp_path / 'bin'
    nix_stub(bin_dir, frontend, lines, code=code)
    monkeypatch.setenv('PATH', f'{bin_dir}:/usr/bin:/bin')
    with pytest.raises(nixq.VerificationError, match=message):
        nixq.query_runtime_roots(Path(NIX_ROOT))
    assert len(stub_calls(bin_dir, frontend)) == 1


def test_nix_closure_runtime_roots_queries_the_executable_store_root(nixq, tmp_path, monkeypatch):
    executable = Path(sys.executable).resolve(strict=True)
    assert executable.is_relative_to('/nix/store'), 'the launch contract requires a store interpreter'
    root = '/nix/store/' + executable.relative_to('/nix/store').parts[0]
    bin_dir = tmp_path / 'modern/bin'
    nix_stub(bin_dir, 'nix', [NIX_CLOSURE[1], root])
    monkeypatch.setenv('PATH', f'{bin_dir}:/usr/bin:/bin')
    assert nixq.runtime_roots(executable) == sorted([Path(root), Path(NIX_CLOSURE[1])])
    assert stub_calls(bin_dir, 'nix') == [[*MODERN_ARGS, root]]


def test_nix_closure_frontends_predict_the_same_policy_template(nixq, tmp_path, monkeypatch):
    """Same closure set from either frontend, so the same R4 template. This proves only that
    order, duplicates and frontend choice cannot move the template; equal sets from the two real
    frontends on one host are covered by the read-only host proof, not here."""
    import cnt_confinement
    import cnt_host_d2
    import cnt_host_firefox_matrix
    assert cnt_host_d2.D1_TEMPLATE == '2a97ea986dd5128d1fd350065a2285f82604d2cf1e3c2df501479ab5520c534b'
    assert cnt_host_firefox_matrix.ACCEPTED_TEMPLATE == (
        'aebabaf94874844ac00fed7ca76b78a0580ee39c503312c4e0aa800f2a1e69e3')
    monkeypatch.setattr(cnt_confinement, 'SCRATCH', tmp_path)
    store_roots = {'/nix/store/' + Path(p).resolve(strict=True).relative_to('/nix/store').parts[0]
                   for p in (sys.executable, pytest.__file__, json.__file__)
                   if Path(p).resolve(strict=True).is_relative_to('/nix/store')}
    root = '/nix/store/' + Path(sys.executable).resolve(strict=True).relative_to('/nix/store').parts[0]
    closure = sorted(store_roots)
    legacy, modern = tmp_path / 'legacy/bin', tmp_path / 'modern/bin'
    nix_stub(legacy, 'nix-store', closure[::-1])
    nix_stub(modern, 'nix', [*closure, '', closure[0]])
    templates = []
    for name, bin_dir in (('legacy', legacy), ('modern', modern)):
        monkeypatch.setenv('PATH', f'{bin_dir}:/usr/bin:/bin')
        roots = nixq.query_runtime_roots(Path(root))
        assert roots == [Path(p) for p in closure]
        run = tmp_path / ('run-' + name)
        run.mkdir()
        templates.append(cnt_host_d2.predicted_policy(run, roots))
    assert templates[0] == templates[1]
    assert set(templates[0]) == {'policy_template_sha256', 'policy_template_without_configd_sha256'}
