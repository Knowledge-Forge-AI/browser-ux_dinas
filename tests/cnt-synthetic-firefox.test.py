"""Portable synthetic Firefox contracts; no browser launch or live endpoint."""
import os
import subprocess
from types import SimpleNamespace
import pytest


@pytest.fixture(autouse=True)
def refuse_host_observation(monkeypatch, repo_root):
    """Fail closed: an unscripted OS observation or connection raises."""
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import socket, cnt_owned_process, cnt_firefox_observation
    def refused(*a, **kw): raise AssertionError('unmocked host observation')
    for target in (cnt_owned_process, cnt_firefox_observation):
        for name in ('observe_child', 'group_rows', 'escaped_count'):
            monkeypatch.setattr(target, name, refused)
    for name in ('run', 'check_output', 'Popen'):
        monkeypatch.setattr(subprocess, name, refused)
    monkeypatch.setattr(os, 'getpgid', refused)
    monkeypatch.setattr(socket, 'create_connection', refused)


@pytest.fixture
def module(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    return load_module('tests/cnt_synthetic_firefox.py')

@pytest.mark.parametrize('text,expected', [('12345', 12345)])
def test_effective_port(module, tmp_path, text, expected):
    (tmp_path / 'MarionetteActivePort').write_text(text)
    assert module.effective_port(tmp_path) == expected


def test_configured_pref_is_not_effective_evidence(module, tmp_path):
    (tmp_path / 'prefs.js').write_text('user_pref("marionette.port", 12345);')
    assert module.effective_port(tmp_path) is None


def test_port_mismatch_never_connects(module, tmp_path, monkeypatch):
    owner = SimpleNamespace(returncode=None, eof=False, receive=lambda *_: None)
    monkeypatch.setattr(module, 'listener_owned', lambda *a, **kw: {})
    monkeypatch.setattr(module, 'read_effective_port', lambda _: ('VALID', 23456))
    def forbidden(*a, **kw): raise AssertionError('must not connect')
    monkeypatch.setattr(module.socket, 'create_connection', forbidden)
    with pytest.raises(Exception, match='effective port mismatch'):
        module.session(owner, tmp_path, {}, 12345)

@pytest.mark.parametrize('kind', ['duplicate', 'range', 'symlink'])
def test_bad_effective_port(module, tmp_path, kind):
    p = tmp_path / 'MarionetteActivePort'
    if kind == 'symlink': p.symlink_to('outside')
    else: p.write_text('65536' if kind == 'range'
                       else '2\n2')
    if kind == 'symlink': (tmp_path / 'outside').write_text('2')
    with pytest.raises(Exception): module.effective_port(tmp_path)

@pytest.mark.parametrize('eof', [False, True])
@pytest.mark.parametrize('code', [0, 1])
def test_quit_requires_owned_normal_exit(module, eof, code):
    def call(*_):
        if eof: raise module.MarionetteEOF()
        return {'cause': 'shutdown'}
    owner = SimpleNamespace(returncode=code, until=lambda predicate, _: predicate())
    client = SimpleNamespace(call=call)
    if code: 
        with pytest.raises(Exception): module.quit_normally(client, owner)
    else: module.quit_normally(client, owner)


def test_poll_bounds_calls_and_waits_for_unload(module, monkeypatch):
    now = [0.0]; budgets = []
    monkeypatch.setattr(module.time, 'monotonic', lambda: now[0])
    monkeypatch.setattr(module.time, 'sleep', lambda delay: now.__setitem__(0, now[0] + delay))
    def predicate(remaining):
        budgets.append(remaining)
        return len(budgets) == 3
    module.poll(predicate, 'timeout', timeout=1)
    assert budgets == [1, .95, .9]


def test_slow_poll_cannot_pass_after_deadline(module, monkeypatch):
    now = [0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: now[0])
    def late(_): now[0] = 2; return True
    with pytest.raises(Exception, match='timeout'): module.poll(late, 'timeout', timeout=1)

@pytest.mark.parametrize('mismatch', ['process', 'profile', 'shape', 'identity'])
def test_session_rejects_mismatch_and_closes(module, tmp_path, monkeypatch, mismatch):
    owner = SimpleNamespace(process=SimpleNamespace(pid=123), workload_pid=456,
                            returncode=None, eof=False, receive=lambda *_: None)
    monkeypatch.setattr(module, 'read_effective_port', lambda _: ('VALID', 12345))
    checked = []
    def identity(*_, **kwargs):
        checked.append(True)
        if mismatch == 'identity' and len(checked) == 4: raise RuntimeError('changed listener')
        return {}
    monkeypatch.setattr(module, 'listener_owned', identity)
    closed = []
    connection = SimpleNamespace(close=lambda: closed.append(True))
    monkeypatch.setattr(module.socket, 'create_connection', lambda *a, **k: connection)
    value = {'capabilities': {'moz:processID': 789 if mismatch == 'process' else 456,
                             'moz:profile': 'wrong' if mismatch == 'profile' else str(tmp_path / 'profile')}}
    client = SimpleNamespace(methods=[], greeting=lambda: None,
                             call=lambda *a: [] if mismatch == 'shape' else value)
    monkeypatch.setattr(module, 'Marionette', lambda _: client)
    monkeypatch.setattr(module, 'ObservedClient', lambda client, *_: client)
    outcomes = {}
    with pytest.raises(Exception): module.session(owner, tmp_path, outcomes, 12345)
    assert closed == [True] and 'protocol' in outcomes


@pytest.mark.parametrize('failure', ['id', 'origin', 'challenge', 'script-shape'])
def test_synthetic_execution_rejects_wrong_values(module, tmp_path, monkeypatch, failure):
    monkeypatch.setattr(module.secrets, 'token_hex', lambda _: 'challenge')
    monkeypatch.setattr(module, 'extension', lambda _: (tmp_path, 'synthetic@example.invalid'))
    origin = 'moz-extension://abc-def/'
    class Client:
        def call(self, method, params, **kwargs):
            if method == 'Addon:Install': return {'value': 'wrong' if failure == 'id' else 'synthetic@example.invalid'}
            if method == 'WebDriver:ExecuteScript':
                source = params['script']
                if 'getElementById' in source: return {'value': 'challenge'}
                if 'getURL' in source: return {'value': 'https://invalid/' if failure == 'origin' else origin}
                if 'dataset.result' in source:
                    return [] if failure == 'script-shape' else {'value': [origin.rstrip('/'), 'wrong']}
            return {}
    with pytest.raises(Exception): module.qualify(Client(), tmp_path, {})


@pytest.mark.parametrize('bad', [None, 'own_read', 'sibling_read', 'own_unix_bind', 'sibling_unix_bind'])
def test_parent_probe_positive_and_negative_controls(module, tmp_path, monkeypatch, bad):
    values = dict(own_read='ALLOWED', own_write='ALLOWED', own_unix_bind='ALLOWED',
                  sibling_read='DENIED_PERMISSION', sibling_write='DENIED_PERMISSION',
                  sibling_unix_bind='DENIED_PERMISSION')
    if bad: values[bad] = 'ERROR' if bad.startswith('own') else 'ALLOWED'
    monkeypatch.setattr(module, 'script', lambda *a: values)
    client = SimpleNamespace(call=lambda *a: {})
    record = {}
    if bad:
        with pytest.raises(Exception): module.confinement_checks(client, tmp_path, record)
    else: module.confinement_checks(client, tmp_path, record)
    assert record['firefox_confinement'] == values


@pytest.mark.parametrize('destination', ['owned', 'outside', 'disabled'])
def test_crash_status_does_not_read_outside(module, tmp_path, monkeypatch, destination):
    (tmp_path / 'profile/minidumps').mkdir(parents=True)
    observed = {'status': 'NOT_INITIALIZED', 'enabled': False} if destination == 'disabled' else {
        'status': 'READBACK', 'enabled': True,
        'destination': str(tmp_path / 'profile/minidumps') if destination == 'owned' else '/outside'}
    monkeypatch.setattr(module, 'script', lambda *a: observed)
    calls = []
    client = SimpleNamespace(call=lambda *a: calls.append(a))
    result = {}; module.crash_reporter_status(client, tmp_path, result)
    r = result['crash_reporter']
    assert 'destination' not in r
    assert r['status'] == {'owned': 'READBACK', 'outside': 'REFUSED_OUTSIDE_OWNED_ROOT',
                           'disabled': 'NOT_INITIALIZED'}[destination]
    assert calls[-1][1]['value'] == 'content'


def test_generic_unix_bind_error_remains_unclassified(module, tmp_path, monkeypatch):
    values = dict(own_read='ALLOWED', own_write='ALLOWED', own_unix_bind='ALLOWED',
                  sibling_read='DENIED_PERMISSION', sibling_write='DENIED_PERMISSION',
                  sibling_unix_bind='ERROR_2147500037')
    monkeypatch.setattr(module, 'script', lambda *a: values)
    result = {}; module.confinement_checks(SimpleNamespace(call=lambda *a: {}), tmp_path, result)
    assert result['unix_bind_denial_classified'] is False
    assert result['firefox_confinement']['sibling_unix_bind'] == 'ERROR_2147500037'


@pytest.mark.parametrize('value', [None, 1, [], {}, 'relative', '/outside',
                                  '{root}-sibling/dumps', '{root}/../outside',
                                  '{root}/profile/../../outside', '{root}//dumps',
                                  '{root}/./dumps', '{root}/dumps/', '{root}/bad\x00name', '{root}'])
@pytest.mark.parametrize('field', ['destination', 'data_directory'])
def test_crash_destination_lexical_refusal_before_any_access(module, tmp_path, monkeypatch, value, field):
    from pathlib import Path
    import os
    if isinstance(value, str): value = value.replace('{root}', str(tmp_path))
    monkeypatch.setattr(module, 'script', lambda *a: {
        'status': 'READBACK', 'enabled': True, 'destination': '/outside', field: value})
    calls = []
    client = SimpleNamespace(call=lambda *a: calls.append(a))
    def forbidden(*a, **kw): raise AssertionError('destination filesystem access')
    # Trusted run is already validated. Lexically refused input needs no FS calls.
    with monkeypatch.context() as patch:
        for name in ('resolve', 'stat', 'lstat', 'readlink', 'exists', 'open'):
            patch.setattr(Path, name, forbidden)
        for name in ('stat', 'lstat', 'readlink', 'open', 'scandir', 'walk', 'access', 'listdir'):
            patch.setattr(os, name, forbidden)
        for name in ('realpath', 'exists', 'lexists', 'isfile', 'isdir', 'islink',
                     'getsize', 'getmtime', 'getatime', 'getctime', 'samefile'):
            patch.setattr(os.path, name, forbidden)
        result = {}; module.crash_reporter_status(client, tmp_path, result)
    assert result['crash_reporter']['status'] == 'REFUSED_OUTSIDE_OWNED_ROOT'
    expected = {'status', 'enabled', 'destination_status'}
    if field == 'data_directory':
        expected.add('data_directory_status')
        assert result['crash_reporter']['data_directory_status'] == 'REFUSED_OUTSIDE_OWNED_ROOT'
    assert set(result['crash_reporter']) == expected
    assert calls[-1][1]['value'] == 'content'


@pytest.mark.parametrize('kind', ['ancestor-link', 'leaf-link', 'missing', 'file', 'owned'])
def test_crash_destination_owned_ancestry(module, tmp_path, monkeypatch, kind):
    outside = tmp_path / 'outside'; outside.mkdir()
    parent = tmp_path / 'profile'
    if kind == 'ancestor-link': parent.symlink_to(outside)
    else: parent.mkdir()
    destination = parent / 'minidumps'
    if kind == 'leaf-link': destination.symlink_to(outside)
    elif kind == 'owned': destination.mkdir()
    elif kind == 'file': destination.write_text('synthetic')
    monkeypatch.setattr(module, 'script', lambda *a: {
        'status': 'READBACK', 'enabled': True, 'destination': str(destination)})
    result = {}; module.crash_reporter_status(SimpleNamespace(call=lambda *a: None), tmp_path, result)
    assert result['crash_reporter']['destination_status'] == {
        'ancestor-link': 'REFUSED_LINK', 'leaf-link': 'REFUSED_LINK',
        'missing': 'ABSENT_DIRECTORY', 'file': 'NOT_DIRECTORY', 'owned': 'OWNED_DIRECTORY'}[kind]


def test_crash_readback_restores_context_on_failure(module, tmp_path, monkeypatch):
    def fail(*a): raise RuntimeError('readback')
    monkeypatch.setattr(module, 'script', fail)
    calls = []
    with pytest.raises(RuntimeError):
        module.crash_reporter_status(SimpleNamespace(call=lambda *a: calls.append(a)), tmp_path, {})
    assert calls[-1][1]['value'] == 'content'


def test_unset_crash_data_is_not_an_outside_destination(module, tmp_path, monkeypatch):
    monkeypatch.setattr(module, 'script', lambda *a: {
        'status': 'READBACK', 'enabled': True, 'destination': '/outside', 'data_directory': ''})
    result = {}
    module.crash_reporter_status(SimpleNamespace(call=lambda *a: None), tmp_path, result)
    assert result['crash_reporter']['data_directory_status'] == 'UNSET'
    assert 'data_directory_relative' not in result['crash_reporter']


def test_link_refusal_preserves_caller_oserror(module, tmp_path):
    link = tmp_path / 'link'; link.symlink_to(tmp_path)
    error = OSError('caller failure')
    with pytest.raises(OSError) as caught:
        with module.owned_directory(tmp_path, str(link)) as (admission, descriptor):
            assert admission['status'] == 'REFUSED_LINK' and descriptor is None
            raise error
    assert caught.value is error


def test_owned_counts_expose_non_regular_entries(module, tmp_path):
    import os
    from cnt_crash_paths import count_directory
    owned = tmp_path / 'crash-data'; owned.mkdir()
    (owned / 'link.dmp').symlink_to(tmp_path)
    os.mkfifo(owned / 'pipe.extra')
    (owned / 'nested').mkdir()
    (owned / 'nested' / 'sample.dmp').write_bytes(b'synthetic')
    with module.owned_directory(tmp_path, str(owned)) as (_, descriptor):
        counts = count_directory(descriptor)
    assert counts == {'dmp': 1, 'extra': 0, 'other': 0, 'non_regular': 2}


# Real session() and real listener_owned(); only lsof/ps/waitid/getpgid answers are scripted.
PORT = 12345
OWN4 = 'p456\nf7\nn127.0.0.1:12345\n'
FOREIGN = 'p999\nf8\nn127.0.0.1:12345\n'
STABLE = (OWN4, '', OWN4)
RACE = ('', '', OWN4)


class Host:
    def __init__(self, module, monkeypatch, tmp_path, passes, port_files):
        import cnt_firefox_observation as observation
        self.passes, self.port_files, self.calls, self.connected = passes, list(port_files), [], []
        self.profile = tmp_path / 'profile'
        self.profile.mkdir()
        self.owner = SimpleNamespace(process=SimpleNamespace(pid=123), workload_pid=456, run=tmp_path,
                                     returncode=None, eof=False, receive=self.receive)
        def run(command, **kwargs):
            kind = 'udp' if '-iUDP' in command else 'tcp' if '-g' in command else 'selected'
            self.calls.append(kind)
            raw = self.passes[min(self.calls.count('tcp') - 1, len(self.passes) - 1)][
                ('tcp', 'udp', 'selected').index(kind)]
            return SimpleNamespace(stdout=raw, stderr='', returncode=0 if raw else 1)
        monkeypatch.setattr(observation, 'observe_child', lambda _: None)
        monkeypatch.setattr(observation, 'group_rows', lambda _: [(123, 'S'), (456, 'S')])
        monkeypatch.setattr(observation, 'escaped_count', lambda *_: 0)
        monkeypatch.setattr(observation.os, 'getpgid', lambda _: 123)
        monkeypatch.setattr(observation.subprocess, 'run', run)
        def connect(address, timeout):
            assert address == ('127.0.0.1', PORT)
            self.connected.append(self.calls.count('tcp'))
            return SimpleNamespace(close=lambda: None)
        monkeypatch.setattr(module.socket, 'create_connection', connect)
        value = {'capabilities': {'moz:processID': 456, 'moz:profile': str(self.profile)}}
        monkeypatch.setattr(module, 'Marionette', lambda connection: SimpleNamespace(
            connection=connection, methods=[], greeting=lambda: {}, call=lambda *a, **kw: value))

    def receive(self, _):
        # Each startup iteration may change the port file before its sample.
        if self.port_files:
            change = self.port_files.pop(0)
            path = self.profile / 'MarionetteActivePort'
            if change == 'link':
                path.symlink_to('elsewhere')
            elif change is not None:
                path.write_text(change)

    def session(self, module):
        outcomes = {}
        try:
            module.session(self.owner, self.owner.run, outcomes, PORT)
        except Exception as error:
            return outcomes, error
        return outcomes, None


@pytest.fixture
def host(module, monkeypatch, tmp_path):
    return lambda passes, port_files: Host(module, monkeypatch, tmp_path, passes, port_files)


def test_session_connects_only_after_a_coherent_owned_endpoint(module, host):
    # Startup race (tolerated as a transient), then a pre-connect race resolved by a full pass.
    h = host([RACE, STABLE, RACE, STABLE], [None, str(PORT)])
    outcomes, error = h.session(module)
    assert error is None and outcomes['session_stage'] == 'identity-verified'
    assert h.connected == [4]
    identity = [s for s in outcomes['listener_samples'] if s['stage'] == 'listener-identity']
    assert identity[0]['coherent'] is True and identity[0]['passes'] == 2
    assert outcomes['listener_transients'] == 1 and 'listener_failure' not in outcomes
    assert outcomes['effective_port_status'] == 'MATCHED'
    assert outcomes['effective_port_polls'] == {'absent': 1, 'empty': 0}
    stages = [s['stage'] for s in outcomes['listener_samples']]
    assert stages[:3] == ['startup', 'startup', 'listener-identity']
    assert {'after-connect', 'before-greeting', 'after-greeting-identity',
            'after-session-identity'} <= set(stages)


@pytest.mark.parametrize('passes,files,stage', [
    ([(OWN4, '', OWN4 + FOREIGN)], [str(PORT)], 'startup'),
    ([STABLE, (OWN4, '', OWN4 + FOREIGN)], [str(PORT)], 'listener-identity')])
def test_foreign_collision_never_connects(module, host, passes, files, stage):
    h = host(passes, files)
    outcomes, error = h.session(module)
    assert 'collision' in str(error) and h.connected == []
    assert outcomes['listener_failure']['code'] == 'SELECTED_PORT_FOREIGN_LISTENER'
    assert outcomes['listener_failure']['stage'] == stage


def test_empty_port_file_is_pending_then_valid(module, host):
    h = host([STABLE], ['', str(PORT)])
    outcomes, error = h.session(module)
    assert error is None and outcomes['effective_port_polls'] == {'absent': 0, 'empty': 1}


@pytest.mark.parametrize('content,status', [('12a', 'PORT_FILE_MALFORMED'), ('2\n2', 'PORT_FILE_MALFORMED'),
                                            ('65536', 'PORT_FILE_OUT_OF_RANGE'), ('0', 'PORT_FILE_OUT_OF_RANGE'),
                                            ('link', 'PORT_FILE_LINK'), ('23456', 'PORT_FILE_MISMATCH')])
def test_port_file_refusals_are_classified_and_never_connect(module, host, content, status):
    h = host([STABLE], [content])
    outcomes, error = h.session(module)
    assert error is not None and h.connected == []
    assert outcomes['effective_port_status'] == status and module.PORT_CODES[str(error)] == status
    assert 'effective_port_readback' not in outcomes


def test_port_file_deadline_is_unavailable(module, host, monkeypatch):
    now = [0.0]
    def clock():
        now[0] += 4
        return now[0]
    monkeypatch.setattr(module.time, 'monotonic', clock)
    h = host([STABLE], [])
    outcomes, error = h.session(module)
    assert str(error) == 'Marionette effective port unavailable' and h.connected == []
    assert outcomes['effective_port_status'] == 'PORT_FILE_UNAVAILABLE'
    assert outcomes['effective_port_polls']['absent'] >= 1


def test_listener_failure_leaves_port_status_pending(module, host):
    h = host([(OWN4, 'p456\nf9\nn*:5353\n', OWN4)], [None])
    outcomes, error = h.session(module)
    assert outcomes['listener_failure']['code'] == 'UDP_SOCKET'
    assert outcomes['effective_port_status'] == 'PENDING' and h.connected == []


@pytest.mark.parametrize('passes,code', [([STABLE, ('', '', '')], 'OWNED_LISTENER_MISSING'),
                                         ([STABLE, RACE, (OWN4, '', ''), RACE], 'UNRESOLVED_OWNED_TRANSITION')])
def test_pre_connect_check_stays_required(module, host, passes, code):
    h = host(passes, [str(PORT)])
    outcomes, error = h.session(module)
    assert error is not None and h.connected == []
    assert outcomes['listener_failure']['code'] == code
    assert outcomes['listener_failure']['stage'] == 'listener-identity'


def test_post_connect_transition_is_strict_and_closes(module, host, monkeypatch):
    closed = []
    h = host([STABLE, STABLE, RACE, STABLE], [str(PORT)])
    monkeypatch.setattr(module.socket, 'create_connection',
                        lambda *a, **kw: SimpleNamespace(close=lambda: closed.append(True)))
    outcomes, error = h.session(module)
    assert 'changed after readiness' in str(error) and closed == [True]
    assert outcomes['listener_failure']['stage'] == 'after-connect'
