"""Deterministic lifecycle failures; no real process is signalled."""
from types import SimpleNamespace
import signal
import subprocess
import pytest

@pytest.fixture
def module(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    return load_module('tests/cnt_owned_process.py')

@pytest.fixture
def owner(module, monkeypatch):
    value = module.OwnedProcess.__new__(module.OwnedProcess)
    value.process = SimpleNamespace(pid=123)
    value.result = value.returncode = None
    value.cleaning = value.done = False
    value.control = SimpleNamespace(close=lambda: None)
    value._reap = lambda: None
    monkeypatch.setattr(module.os, 'killpg', lambda *_: pytest.fail('Parent group signal'))
    monkeypatch.setattr(module.os, 'kill', lambda *_: pytest.fail('Parent PID signal'))
    return value

@pytest.mark.parametrize('error', [ChildProcessError, OSError, ValueError, subprocess.TimeoutExpired])
def test_settle_failure_is_cached(owner, error):
    exc = error('synthetic', 1) if error is subprocess.TimeoutExpired else error('synthetic')
    def fail(): raise exc
    owner._settle = fail
    result = owner.settle()
    assert result['unsettled'] and not result['zero_survivors']
    assert result['failures'] == [error.__name__]
    assert owner.settle() is result

@pytest.mark.parametrize('error', [KeyboardInterrupt, SystemExit])
def test_base_exception_not_masked_by_wait_timeout(owner, error):
    primary = error('primary')
    def fail(): raise primary
    def timeout(): raise subprocess.TimeoutExpired('owned', 5)
    owner._settle, owner._reap = fail, timeout
    with pytest.raises(error) as caught:
        owner.settle()
    assert caught.value is primary
    assert owner.result['failures'] == [error.__name__, 'TimeoutExpired']
    assert owner.settle() is owner.result

@pytest.mark.parametrize('kind', ['auto-reaping', 'competing-waiter'])
def test_waiter_loss_fails_closed(owner, module, monkeypatch, kind):
    owner._settle = lambda: dict(unsettled=False, zero_survivors=True)
    def lost(*_): raise ChildProcessError(kind)
    monkeypatch.setattr(module.os, 'waitpid', lost)
    owner._reap = lambda: module.OwnedProcess._reap(owner)
    assert owner.settle()['unsettled']
    assert not owner.result['zero_survivors']


def test_reentry_refused(owner):
    owner._settle = lambda: owner.settle()
    assert owner.settle()['failures'] == ['VerificationError']


def test_interrupt_restored_then_delivered(module, monkeypatch):
    calls = []
    previous = lambda *args: calls.append(args)
    current = [previous]
    def install(sig, handler):
        old, current[0] = current[0], handler
        return old
    monkeypatch.setattr(module.signal, 'getsignal', lambda _: previous)
    monkeypatch.setattr(module.signal, 'signal', install)
    with module.defer_interrupt():
        current[0](signal.SIGINT, None)
        assert not calls
    assert current[0] is previous and len(calls) == 1


def test_process_table_never_adopts_unrelated(module):
    read = lambda *a, **kw: '10 900 S\n11 900 S\n123 123 Z\n42 123 S\n'
    assert module.group_rows(123, read) == [(123, 'Z'), (42, 'S')]


def test_old_settlement_has_no_signal_authority(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    boundary = load_module('tests/cnt_confinement.py')
    with pytest.raises(Exception, match='Historical PID'):
        boundary.settle(SimpleNamespace(pid=123), {123, 456})


@pytest.mark.parametrize('failure', ['inspection', 'control-eof', 'missing-ack'])
def test_observation_failure_never_signals(owner, module, monkeypatch, failure):
    owner.token, owner.ack, owner.run = 'nonce', False, None
    owner.control.sendall = lambda _: None
    owner.receive = lambda *_: None
    owner._settle = lambda: module.OwnedProcess._settle(owner)
    def inspect(_):
        if failure == 'inspection': raise OSError('inspection failed')
        return SimpleNamespace(si_pid=123)
    monkeypatch.setattr(module, 'observe_child', inspect)
    assert owner.settle()['unsettled']


def test_constructor_failure_preserves_primary(module, monkeypatch, tmp_path):
    primary = KeyboardInterrupt('construction')
    process = SimpleNamespace(pid=123)
    monkeypatch.setattr(module.subprocess, 'Popen', lambda *a, **k: process)
    def fail(*_): raise primary
    def cleanup(*_): raise RuntimeError('cleanup')
    monkeypatch.setattr(module.OwnedProcess, 'until', fail)
    monkeypatch.setattr(module.OwnedProcess, 'settle', cleanup)
    evidence = {}
    with pytest.raises(KeyboardInterrupt) as caught:
        module.OwnedProcess(['fake'], tmp_path, {}, None, evidence=evidence)
    assert caught.value is primary
    assert caught.value.__cause__ is None
    assert evidence['primary_failure']['type'] == 'KeyboardInterrupt'
    assert evidence['cleanup_failure']['type'] == 'RuntimeError'
    assert 'settlement' in evidence


def test_supervisor_self_group_only(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    supervisor = load_module('tests/cnt_supervisor.py')
    calls = []
    monkeypatch.setattr(supervisor.os, 'getpid', lambda: 123)
    monkeypatch.setattr(supervisor.os, 'getpgrp', lambda: 123)
    monkeypatch.setattr(supervisor.os, 'killpg', lambda group, sig: calls.append((group, sig)))
    control = SimpleNamespace(sendall=lambda data: calls.append(data))
    supervisor.cleanup(control, 'nonce', SimpleNamespace(returncode=0, poll=lambda: 0))
    assert calls[0] == (123, signal.SIGTERM)
    assert b'pre-kill' in calls[-2]
    assert calls[-1] == (123, signal.SIGKILL)


def test_supervisor_identity_loss_refuses_signal(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    supervisor = load_module('tests/cnt_supervisor.py')
    monkeypatch.setattr(supervisor.os, 'getpid', lambda: 123)
    monkeypatch.setattr(supervisor.os, 'getpgrp', lambda: 456)
    monkeypatch.setattr(supervisor.os, 'killpg', lambda *_: pytest.fail('uncertain signal'))
    def stopped(code): raise SystemExit(code)
    monkeypatch.setattr(supervisor.os, '_exit', stopped)
    with pytest.raises(SystemExit): supervisor.cleanup(None, 'nonce', None)


@pytest.mark.parametrize('handler', [None, 99])
def test_native_handler_refused_before_process_creation(module, monkeypatch, tmp_path, handler):
    monkeypatch.setattr(module.signal, 'getsignal', lambda _: handler)
    monkeypatch.setattr(module.signal, 'signal', lambda *_: pytest.fail('handler mutated'))
    monkeypatch.setattr(module.subprocess, 'Popen', lambda *a, **k: pytest.fail('process launched'))
    with pytest.raises(Exception, match='Unsupported native SIGINT'):
        module.OwnedProcess(['fake'], tmp_path, {}, None)
    with pytest.raises(Exception, match='Unsupported native SIGINT'):
        with module.defer_interrupt(): pass


def test_unknown_workload_status_requires_empty_observed_group(owner, module, monkeypatch):
    owner.token, owner.ack, owner.run = 'nonce', True, None
    owner.workload_status = 'unknown-before-kill'
    owner.control.sendall = lambda _: None
    owner.receive = lambda *_: None
    status = SimpleNamespace(si_pid=123, si_code=module.os.CLD_KILLED, si_status=signal.SIGKILL)
    monkeypatch.setattr(module, 'observe_child', lambda _: status)
    monkeypatch.setattr(module, 'escaped_count', lambda *_: 0)
    monkeypatch.setattr(module, 'group_rows', lambda _: [(123, 'Z')])
    owner._settle = lambda: module.OwnedProcess._settle(owner)
    result = owner.settle()
    assert result['zero_survivors'] and result['exit_code'] is None
    assert result['workload_status'] == 'unknown-before-kill'


def test_unknown_status_with_survivor_is_unsettled(owner, module, monkeypatch):
    owner.token, owner.ack, owner.run = 'nonce', True, None
    owner.workload_status = 'unknown-before-kill'
    owner.control.sendall = lambda _: None
    owner.receive = lambda *_: None
    status = SimpleNamespace(si_pid=123, si_code=module.os.CLD_KILLED, si_status=signal.SIGKILL)
    monkeypatch.setattr(module, 'observe_child', lambda _: status)
    monkeypatch.setattr(module, 'escaped_count', lambda *_: 0)
    monkeypatch.setattr(module, 'group_rows', lambda _: [(123, 'Z'), (456, 'S')])
    owner._settle = lambda: module.OwnedProcess._settle(owner)
    assert owner.settle()['unsettled']


@pytest.mark.parametrize('raw', [b'not-json\n', b'{"token":"wrong"}\n',
    b'{"token":"nonce","cleanup":"pre-kill"}\n', b''])
def test_control_messages_fail_closed(owner, module, monkeypatch, raw):
    owner.token, owner.eof, owner.buffer, owner.messages = 'nonce', False, b'', []
    owner.control.recv = lambda _: raw
    monkeypatch.setattr(module.select, 'select', lambda *a: ([owner.control], [], []))
    if raw:
        with pytest.raises(Exception): module.OwnedProcess.receive(owner, 0)
    else:
        module.OwnedProcess.receive(owner, 0)
        assert owner.eof


def test_escape_markers_default_set_unchanged_and_extra_is_additive(module, monkeypatch, tmp_path):
    run = tmp_path / 'run'
    rows = [f'10 999 /x --type=renderer --user-data-dir={run}/profile',
            f'11 999 /x/chrome_crashpad_handler --database={run}/profile/Crashpad --url=x',
            f'12 999 /x -profile {run}/profile', '13 999 /unrelated --database=/elsewhere',
            f'14 123 /x --database={run}/profile/Crashpad']
    monkeypatch.setattr(module.subprocess, 'check_output', lambda *a, **kw: '\n'.join(rows))
    assert module.escaped_count(run, 123) == 2
    assert module.escaped_count(run, 123, ()) == 2
    assert module.escaped_count(run, 123, (str(run / 'profile') + '/',)) == 3
    assert module.OwnedProcess.markers == ()


@pytest.mark.parametrize('marker', ['/elsewhere/', 'relative/', 7])
def test_escape_markers_must_be_owned_paths(module, tmp_path, marker):
    with pytest.raises(Exception, match='Escape markers must be owned attempt paths'):
        module.OwnedProcess(['never-started'], tmp_path, {}, None, markers=(marker,))
