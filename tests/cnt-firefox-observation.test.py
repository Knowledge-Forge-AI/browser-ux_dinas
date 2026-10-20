"""Synthetic ownership fixtures only; never inspect a daily-use browser."""
import json
import os
import subprocess
from types import SimpleNamespace
import pytest


@pytest.fixture(autouse=True)
def refuse_host_observation(monkeypatch, repo_root):
    """Fail closed: any OS observation a test did not script raises."""
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import cnt_owned_process, cnt_firefox_observation
    def refused(*a, **kw): raise AssertionError('unmocked host observation')
    for target in (cnt_owned_process, cnt_firefox_observation):
        for name in ('observe_child', 'group_rows', 'escaped_count'):
            monkeypatch.setattr(target, name, refused)
    for name in ('run', 'check_output', 'Popen'):
        monkeypatch.setattr(subprocess, name, refused)
    monkeypatch.setattr(os, 'getpgid', refused)


@pytest.fixture
def module(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    return load_module('tests/cnt_firefox_observation.py')


@pytest.mark.parametrize('kind', ['valid', 'ipv6', 'wildcard', 'extra', 'udp', 'collision',
                                 'lost-group', 'escape', 'missing', 'observer-error'])
def test_all_owned_sockets(module, monkeypatch, tmp_path, kind):
    owner = SimpleNamespace(process=SimpleNamespace(pid=123), workload_pid=456, run=tmp_path)
    monkeypatch.setattr(module, 'observe_child', lambda _: None)
    monkeypatch.setattr(module, 'group_rows', lambda _: [(123, 'S'), (456, 'S'), (457, 'S')])
    monkeypatch.setattr(module, 'escaped_count', lambda *_: int(kind == 'escape'))
    monkeypatch.setattr(module.os, 'getpgid', lambda _: 999 if kind == 'lost-group' else 123)
    def run(command, **kwargs):
        raw = 'p456\nf7\nn127.0.0.1:12345\n'
        if kind == 'ipv6': raw = raw.replace('127.0.0.1', '[::1]')
        if kind == 'wildcard': raw = raw.replace('127.0.0.1', '*')
        if kind == 'extra': raw += 'p457\nf8\nn127.0.0.1:23456\n'
        if kind == 'missing': raw = ''
        if '-iUDP' in command: raw = 'p457\nf9\nn*:23456\n' if kind == 'udp' else ''
        if kind == 'collision' and '-iTCP:12345' in command: raw += 'p999\nf8\nn[::1]:12345\n'
        return SimpleNamespace(stdout=raw, stderr='error' if kind == 'observer-error' else '',
                               returncode=0 if raw else 1)
    monkeypatch.setattr(module.subprocess, 'run', run)
    if kind in ('valid', 'ipv6'):
        assert module.listener_owned(owner, 12345)['owned']
    else:
        with pytest.raises(Exception): module.listener_owned(owner, 12345)


@pytest.mark.parametrize('raw', ['n127.0.0.1:1', 'p1\nf2', 'pbad\nf2\nn*:1', 'p1\nf2\nn*:1\nn*:2'])
def test_incomplete_records_refused(module, raw):
    with pytest.raises(Exception): module.socket_records(raw)


@pytest.mark.parametrize('method', ['WebDriver:Navigate', 'Addon:Install', 'Addon:Uninstall',
                                   'WebDriver:ExecuteScript', 'Marionette:Quit'])
def test_no_command_after_identity_loss(module, monkeypatch, method):
    sent = []
    client = SimpleNamespace(connection=None, methods=[], call=lambda *a, **kw: sent.append(a))
    def lost(*_, **kwargs): raise RuntimeError('lost observation')
    monkeypatch.setattr(module, 'listener_owned', lost)
    gated = module.ObservedClient(client, None, 12345, {})
    with pytest.raises(RuntimeError): gated.call(method)
    monkeypatch.setattr(module, 'listener_owned', lambda *_, **kw: {})
    with pytest.raises(Exception, match='previously lost'): gated.call(method)
    assert not sent


# Scripted OS responses: every pass is (group TCP, group UDP, selected-port TCP) lsof output.
PORT = 12345
OWN4 = 'p456\nf7\nn127.0.0.1:12345\n'
OWN6 = 'p456\nf8\nn[::1]:12345\n'
FOREIGN = 'p999\nf8\nn127.0.0.1:12345\n'
MEMBER = 'p457\nf8\nn127.0.0.1:12345\n'
WILDCARD = 'p456\nf9\nn*:12345\n'
UDP = 'p457\nf9\nn*:23456\n'
PRIVATE = ('12345', '456', '457', '999', '127.0.0.1', '::1', '*:')


class World:
    def __init__(self, module, monkeypatch, tmp_path, passes, *, supervisor=(None,), pgid=123,
                 members=((123, 'S'), (456, 'S'), (457, 'S')), stderr='', lsof_error=None, rows_error=None):
        self.passes, self.calls, self.pgids, self.received = passes, [], [], []
        self.supervisor = list(supervisor)
        self.owner = SimpleNamespace(process=SimpleNamespace(pid=123), workload_pid=456, run=tmp_path,
                                     returncode=None, eof=False, receive=self.received.append)
        def observe_child(_):
            return self.supervisor.pop(0) if len(self.supervisor) > 1 else self.supervisor[0]
        def rows(_):
            if rows_error: raise rows_error
            return list(members)
        def getpgid(pid):
            self.pgids.append(pid)
            return pgid
        def run(command, **kwargs):
            kind = ('udp' if '-iUDP' in command else 'tcp' if '-g' in command else 'selected')
            self.calls.append(kind)
            if lsof_error: raise lsof_error
            index = min(self.calls.count('tcp') - 1, len(self.passes) - 1)
            raw = self.passes[index][('tcp', 'udp', 'selected').index(kind)]
            return SimpleNamespace(stdout=raw, stderr=stderr, returncode=0 if raw else 1)
        monkeypatch.setattr(module, 'observe_child', observe_child)
        monkeypatch.setattr(module, 'group_rows', rows)
        monkeypatch.setattr(module, 'escaped_count', lambda *_: 0)
        monkeypatch.setattr(module.os, 'getpgid', getpgid)
        monkeypatch.setattr(module.subprocess, 'run', run)

    def sample(self, module, required=True, **options):
        outcomes = {}
        try:
            record = module.record_sample(outcomes, 'probe', self.owner, PORT, required, **options)
        except Exception as error:
            return None, outcomes, error
        return record, outcomes, None


@pytest.fixture
def world(module, monkeypatch, tmp_path):
    return lambda passes, **kw: World(module, monkeypatch, tmp_path, passes, **kw)


def code(outcomes):
    return outcomes['listener_failure']['code']


def test_manager_race_sequence_is_an_owned_startup_transient(module, world):
    # Group TCP empty, UDP empty, then the same workload's expected listener on the selected port.
    w = world([('', '', OWN4)])
    record, outcomes, error = w.sample(module, False, mode='startup')
    assert error is None and record['coherent'] is False and record['transition'] == 'appeared'
    assert record['owned'] is True and record['tcp_listeners'] == [] and record['udp_sockets'] == 0
    assert outcomes['listener_transients'] == 1 and 'listener_failure' not in outcomes


def test_stable_owned_listener_passes_every_mode(module, world):
    for options in ({}, {'mode': 'pre-connect', 'deadline': float('inf')}):
        w = world([(OWN4 + OWN6, '', OWN6 + OWN4)])
        record, outcomes, error = w.sample(module, **options)
        assert error is None and record['coherent'] is True and record['passes'] == 1
        assert sorted(record['tcp_listeners']) == ['127.0.0.1:12345', '[::1]:12345']
        assert 'listener_transients' not in outcomes


def test_appearing_listener_resolves_only_by_a_full_second_pass(module, world):
    w = world([('', '', OWN4), (OWN4, '', OWN4)])
    record, outcomes, error = w.sample(module, mode='pre-connect', deadline=float('inf'))
    assert error is None and record['coherent'] is True and record['passes'] == 2
    assert w.calls == ['tcp', 'udp', 'selected'] * 2 and w.received == [.05]


def test_strict_mode_never_resamples_a_transition(module, world):
    w = world([('', '', OWN4), (OWN4, '', OWN4)])
    record, outcomes, error = w.sample(module)
    assert record is None and code(outcomes) == 'OWNED_LISTENER_CHANGED'
    assert outcomes['listener_failure']['transition'] == 'appeared'
    assert w.calls == ['tcp', 'udp', 'selected'] and w.received == []


@pytest.mark.parametrize('options,expected', [
    ({'required': False, 'mode': 'startup'}, None),
    ({'required': False}, None),
    ({'required': True}, 'OWNED_LISTENER_MISSING'),
    ({'required': True, 'mode': 'pre-connect', 'deadline': float('inf')}, 'OWNED_LISTENER_MISSING')])
def test_both_empty_is_pending_only_where_optional(module, world, options, expected):
    w = world([('', '', '')])
    required = options.pop('required')
    record, outcomes, error = w.sample(module, required, **options)
    if expected is None:
        assert error is None and record['tcp_listeners'] == [] and record['coherent'] is True
    else:
        assert record is None and code(outcomes) == expected and w.calls.count('tcp') == 1


def test_disappearance_is_classified_and_required_check_stays_required(module, world):
    w = world([(OWN4, '', '')])
    record, _, error = w.sample(module, False, mode='startup')
    assert error is None and record['transition'] == 'disappeared'
    w = world([(OWN4, '', ''), ('', '', '')])
    record, outcomes, error = w.sample(module, mode='pre-connect', deadline=float('inf'))
    assert record is None and code(outcomes) == 'OWNED_LISTENER_MISSING'
    assert outcomes['listener_failure']['passes'] == 2


def test_changed_owned_records_are_classified_changed(module, world):
    w = world([(OWN4, '', OWN6)])
    record, _, error = w.sample(module, False, mode='startup')
    assert error is None and record['transition'] == 'changed'


def test_unresolved_changing_observations_stop_at_the_pass_bound(module, world):
    w = world([('', '', OWN4), (OWN4, '', ''), ('', '', OWN4), (OWN4, '', OWN4)])
    record, outcomes, error = w.sample(module, mode='pre-connect', deadline=float('inf'))
    assert record is None and code(outcomes) == 'UNRESOLVED_OWNED_TRANSITION'
    assert outcomes['listener_failure']['passes'] == module.MAX_PASSES == w.calls.count('tcp')
    assert len(w.received) == module.MAX_PASSES - 1


def test_deadline_bounds_resamples_but_not_the_first_required_pass(module, world, monkeypatch):
    monkeypatch.setattr(module.time, 'monotonic', lambda: 100.0)
    w = world([(OWN4, '', OWN4)])
    record, _, error = w.sample(module, mode='pre-connect', deadline=50.0)
    assert error is None and record['passes'] == 1
    w = world([('', '', OWN4), (OWN4, '', OWN4)])
    record, outcomes, error = w.sample(module, mode='pre-connect', deadline=50.0)
    assert record is None and code(outcomes) == 'OWNED_TRANSITION_DEADLINE'
    assert outcomes['listener_failure']['passes'] == 1 and w.received == []


@pytest.mark.parametrize('state', ['returncode', 'eof'])
def test_workload_exit_between_passes_refuses(module, world, state):
    w = world([('', '', OWN4), (OWN4, '', OWN4)])
    def receive(_):
        setattr(w.owner, state, 0 if state == 'returncode' else True)
    w.owner.receive = receive
    record, outcomes, error = w.sample(module, mode='pre-connect', deadline=float('inf'))
    assert record is None and code(outcomes) == 'WORKLOAD_EXITED_BEFORE_LISTENER'


MODES = [({'required': False, 'mode': 'startup'}), ({'required': True}), ({'required': False}),
         ({'required': True, 'mode': 'pre-connect', 'deadline': float('inf')})]


@pytest.mark.parametrize('options', MODES)
@pytest.mark.parametrize('passes,expected', [
    ([('', '', FOREIGN)], 'SELECTED_PORT_FOREIGN_LISTENER'),
    ([(OWN4, '', OWN4 + FOREIGN)], 'SELECTED_PORT_FOREIGN_LISTENER'),
    ([(OWN4, '', OWN4 + MEMBER)], 'SELECTED_PORT_NON_WORKLOAD_MEMBER'),
    ([('', '', MEMBER)], 'SELECTED_PORT_NON_WORKLOAD_MEMBER'),
    ([(OWN4, '', OWN4 + WILDCARD)], 'SELECTED_PORT_WRONG_ADDRESS'),
    ([(MEMBER, '', MEMBER)], 'GROUP_LISTENER_NON_WORKLOAD_MEMBER'),
    ([(FOREIGN, '', FOREIGN)], 'GROUP_LISTENER_FOREIGN_OWNER'),
    ([(WILDCARD, '', WILDCARD)], 'GROUP_LISTENER_WRONG_ADDRESS'),
    ([(OWN4, UDP, OWN4)], 'UDP_SOCKET'),
    ([('', UDP, '')], 'UDP_SOCKET')])
def test_foreign_or_invalid_endpoint_fails_first_pass_in_every_mode(module, world, options, passes, expected):
    # A later clean pass exists; reaching it would mean a foreign endpoint was resampled away.
    w = world(passes + [(OWN4, '', OWN4)])
    options = dict(options)
    record, outcomes, error = w.sample(module, options.pop('required'), **options)
    assert record is None and code(outcomes) == expected
    assert w.calls.count('tcp') == 1 and w.received == []
    assert 999 not in w.pgids and 457 not in w.pgids


@pytest.mark.parametrize('kwargs,expected', [
    ({'supervisor': [1]}, 'SUPERVISOR_UNAVAILABLE'),
    ({'supervisor': [None, 1]}, 'SUPERVISOR_IDENTITY_LOST'),
    ({'pgid': 999}, 'LISTENER_GROUP_CHANGED'),
    ({'members': ((123, 'S'), (456, 'Z'))}, 'WORKLOAD_NOT_LIVE_MEMBER'),
    ({'stderr': 'lsof: warning'}, 'OBSERVATION_API_ERROR'),
    ({'lsof_error': subprocess.TimeoutExpired('lsof', 3)}, 'OBSERVATION_API_ERROR'),
    ({'lsof_error': OSError('lsof')}, 'OBSERVATION_API_ERROR'),
    ({'rows_error': ValueError('ps')}, 'OBSERVATION_INVALID'),
    ({'rows_error': subprocess.CalledProcessError(1, 'ps')}, 'OBSERVATION_API_ERROR')])
@pytest.mark.parametrize('options', MODES)
def test_ownership_loss_and_observation_errors_never_resample(module, world, kwargs, expected, options):
    w = world([(OWN4, '', OWN4)], **kwargs)
    options = dict(options)
    record, outcomes, error = w.sample(module, options.pop('required'), **options)
    assert record is None and code(outcomes) == expected and w.received == []
    assert w.calls.count('tcp') <= 1


def test_selected_port_only_workload_zombie_is_not_called_foreign(module, world):
    w = world([('', '', OWN4)], members=((123, 'S'), (456, 'Z')))
    record, outcomes, error = w.sample(module, False, mode='startup')
    failure = outcomes['listener_failure']
    assert record is None and failure['code'] == 'WORKLOAD_NOT_LIVE_MEMBER'
    assert failure['selected_port_classes']['workload_not_live'] == 1
    assert failure['selected_port_classes']['foreign_owner'] == 0 and w.pgids == []


@pytest.mark.parametrize('passes,expected_step', [([(OWN4, '', OWN4)], 'group-tcp-validation'),
                                                  ([('', '', OWN4)], 'selected-port-validation')])
def test_vanished_listener_process_is_ownership_loss_not_api_error(module, world, monkeypatch,
                                                                   passes, expected_step):
    w = world(passes)
    def getpgid(pid):
        raise ProcessLookupError(3, 'No such process')
    monkeypatch.setattr(module.os, 'getpgid', getpgid)
    options = {'mode': 'pre-connect', 'deadline': float('inf')}
    record, outcomes, error = w.sample(module, **options)
    failure = outcomes['listener_failure']
    assert record is None and isinstance(error, ProcessLookupError)
    assert failure['code'] == 'LISTENER_OWNER_VANISHED' and failure['step'] == expected_step
    assert 'No such process' not in json.dumps(failure)


def test_process_lookup_outside_validation_stays_api_error(module):
    record = module.failure_observation('probe', {'step': 'group-members'}, ProcessLookupError(3, 'x'))
    assert record['code'] == 'OBSERVATION_API_ERROR'


def test_failed_later_pass_never_reports_earlier_pass_facts(module, world):
    # Pass 1 is an owned transient with a selected-port record; pass 2 fails at UDP.
    w = world([('', '', OWN4), (OWN4, UDP, OWN4)])
    record, outcomes, error = w.sample(module, mode='pre-connect', deadline=float('inf'))
    failure = outcomes['listener_failure']
    assert record is None and failure['code'] == 'UDP_SOCKET' and failure['passes'] == 2
    assert failure['step'] == 'group-udp' and failure['group_tcp'] == 1 and failure['group_udp'] == 1
    assert failure['selected_port_tcp'] is None and failure['selected_port_classes'] is None
    assert failure['transition'] is None and failure['group_tcp_classes'] is None


def test_malformed_output_is_invalid_observation_not_collision(module, world):
    w = world([('p456\nf7\n', '', OWN4)])
    record, outcomes, error = w.sample(module)
    assert record is None and code(outcomes) == 'OBSERVATION_INVALID'
    assert outcomes['listener_failure']['step'] == 'group-tcp'


def test_failure_observation_is_partial_fixed_and_private(module, world, tmp_path):
    w = world([(OWN4, '', OWN4 + FOREIGN)])
    _, outcomes, error = w.sample(module)
    failure = outcomes['listener_failure']
    assert failure == {'stage': 'probe', 'partial': True, 'code': 'SELECTED_PORT_FOREIGN_LISTENER',
                       'error_type': 'VerificationError', 'step': 'selected-port-validation',
                       'mode': 'strict', 'transition': None, 'passes': 1, 'group_members': 3,
                       'group_tcp': 1, 'group_udp': 0, 'selected_port_tcp': 2,
                       'group_tcp_classes': {'owned_expected': 1, 'workload_not_live': 0, 'foreign_owner': 0,
                                             'non_workload_member': 0, 'wrong_address': 0},
                       'selected_port_classes': {'owned_expected': 1, 'workload_not_live': 0, 'foreign_owner': 1,
                                                 'non_workload_member': 0, 'wrong_address': 0}}
    text = json.dumps(failure)
    assert not any(value in text for value in PRIVATE + (str(tmp_path),))
    assert 'listener_samples' not in outcomes


def test_unknown_error_stays_unknown(module, world, monkeypatch):
    w = world([(OWN4, '', OWN4)])
    monkeypatch.setattr(module, 'escaped_count', lambda *_: (_ for _ in ()).throw(LookupError('/private/x')))
    _, outcomes, error = w.sample(module)
    assert code(outcomes) == 'UNKNOWN' and outcomes['listener_failure']['step'] == 'marker-escape'
    assert '/private' not in json.dumps(outcomes)


def test_first_listener_failure_wins(module, world):
    w = world([(OWN4, UDP, OWN4)])
    outcomes = {}
    for _ in range(2):
        with pytest.raises(Exception):
            module.record_sample(outcomes, 'first' if not outcomes else 'second', w.owner, PORT)
    assert outcomes['listener_failure']['stage'] == 'first'


class Unprintable(Exception):
    def __str__(self): raise RuntimeError('unprintable')


@pytest.mark.parametrize('trace', [None, [], {'step': 1, 'passes': 'x', 'mode': 'other', 'transition': 'odd',
                                               'group_tcp_classes': [], 'selected_port_classes': {'foreign_owner': 'x'}}])
@pytest.mark.parametrize('error', [KeyboardInterrupt(), Unprintable(), None])
def test_failure_observation_never_raises(module, trace, error):
    import cnt_native_evidence
    if error is None:
        class Bad(cnt_native_evidence.VerificationError):
            def __str__(self): raise RuntimeError('unprintable')
        error = Bad()
    record = module.failure_observation('stage', trace, error)
    assert record['partial'] is True and record['code'] in ('INTERRUPTED', 'UNKNOWN')
    json.dumps(record)


def test_record_sample_reraises_the_original_interrupt(module):
    interrupt = KeyboardInterrupt()
    def observer(*a, trace, **kw):
        trace['step'] = object()
        raise interrupt
    outcomes = {}
    with pytest.raises(KeyboardInterrupt) as caught:
        module.record_sample(outcomes, 'probe', None, PORT, observer=observer)
    assert caught.value is interrupt and outcomes['listener_failure']['code'] == 'INTERRUPTED'


def test_record_sample_survives_failure_observation_crash(module, monkeypatch):
    original = RuntimeError('original')
    def observer(*a, **kw): raise original
    def broken(*a): raise ValueError('secondary')
    monkeypatch.setattr(module, 'failure_observation', broken)
    outcomes = {}
    with pytest.raises(RuntimeError) as caught:
        module.record_sample(outcomes, 'probe', None, PORT, observer=observer)
    assert caught.value is original
    assert outcomes['listener_failure']['code'] == 'FAILURE_OBSERVATION_UNAVAILABLE'


def test_strict_transition_after_readiness_invalidates_the_client(module, world):
    w = world([('', '', OWN4), (OWN4, '', OWN4)])
    sent, outcomes = [], {}
    client = SimpleNamespace(connection=None, methods=[], call=lambda *a, **kw: sent.append(a))
    gated = module.ObservedClient(client, w.owner, PORT, outcomes)
    with pytest.raises(Exception, match='changed after readiness'): gated.call('WebDriver:Navigate')
    assert gated.valid is False and not sent and code(outcomes) == 'OWNED_LISTENER_CHANGED'
    assert outcomes['listener_samples'][-1]['owned'] is False
    with pytest.raises(Exception, match='previously lost'): gated.call('WebDriver:Navigate')


@pytest.mark.parametrize('required,options', [(True, {'mode': 'startup'}), (True, {'mode': 'pre-connect'}),
                                              (True, {'mode': 'other'})])
def test_invalid_mode_refused_before_any_observation(module, world, required, options):
    w = world([(OWN4, '', OWN4)])
    record, outcomes, error = w.sample(module, required, **options)
    assert record is None and code(outcomes) == 'OBSERVATION_MODE_INVALID' and w.calls == []


def test_unmocked_host_observation_is_refused(module, tmp_path):
    owner = SimpleNamespace(process=SimpleNamespace(pid=123), workload_pid=456, run=tmp_path)
    with pytest.raises(AssertionError, match='unmocked host observation'):
        module.listener_owned(owner, PORT)
