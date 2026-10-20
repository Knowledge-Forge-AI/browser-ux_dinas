"""Portable Chrome adapter contracts over real in-process pipes; no browser, port or host probe.

The scripted peer (tests/cnt_chrome_peer.py) follows the version-matched Chromium source for
target scope, registry listing and session errors. Its extension "computation" reads the
harness-written worker.js and hashes the embedded challenge, so a passing run proves the
harness supplied only the challenge.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from cnt_chrome_peer import (EXTENSION, SESSION, TARGET, VERSION, WORKER, WORKER_SESSION,  # noqa: E402
                             Browser, Owner)


@pytest.fixture(autouse=True)
def refuse_host_observation(monkeypatch, repo_root):
    """Fail closed: an unscripted OS observation, subprocess or connection raises."""
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    import socket, cnt_owned_process
    def refused(*a, **kw): raise AssertionError('unmocked host observation')
    for name in ('observe_child', 'group_rows', 'escaped_count'):
        monkeypatch.setattr(cnt_owned_process, name, refused)
    for name in ('run', 'check_output', 'Popen'):
        monkeypatch.setattr(subprocess, name, refused)
    monkeypatch.setattr(socket, 'create_connection', refused)


@pytest.fixture
def chrome(load_module, monkeypatch, repo_root):
    module = load_module('tests/cnt_synthetic_chrome.py')
    for name, value in (('STARTUP_DEADLINE', 1), ('CALL_TIMEOUT', 1), ('PAGE_DEADLINE', .5), ('EXTENSION_DEADLINE', .5),
                        ('REMOVAL_DEADLINE', .5), ('CLOSE_DEADLINE', .5), ('EXIT_DEADLINE', .5),
                        ('ABNORMAL_WAIT', .05), ('EOF_EXIT_OBSERVATION', .2), ('POLL_INTERVAL', .001)):
        monkeypatch.setattr(module, name, value)
    return module


@pytest.fixture
def session(chrome, tmp_path):
    from cnt_protocol import CDPPipe
    opened = []

    def start(**knobs):
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        owner = Owner()
        browser = Browser(owner, request_read, response_write, **knobs)
        opened.append((request_read, request_write, response_read, browser))
        if knobs.get('exit_before_close'):
            owner.returncode = 0
        run = tmp_path / ('run-' + str(len(opened)))
        run.mkdir()
        return SimpleNamespace(pipe=CDPPipe(response_read, request_write), owner=owner, browser=browser,
                               run=run, result={})
    yield start
    # Writer first so a reading peer sees EOF; then the response reader so a writing peer fails.
    for request_read, request_write, response_read, browser in opened:
        os.close(request_write)
        os.close(response_read)
        browser.thread.join(2)
        assert not browser.thread.is_alive()
        os.close(request_read)
        browser.close_writer()


def exercise(chrome, s, workload='full', abnormal=False, version=VERSION):
    chrome.exercise(s.pipe, s.owner, s.run, s.result, workload=workload, abnormal=abnormal,
                    expected_version=version)


def failed(chrome, s, message, **options):
    with pytest.raises(Exception) as caught:
        exercise(chrome, s, **options)
    assert str(caught.value) == message
    return caught.value


def test_full_normal_reply_passes_with_every_fact(chrome, session):
    s = session()
    exercise(chrome, s)
    r = s.result
    assert all(r[k] is True for k in chrome.USEFUL_FLAGS)
    assert r['quit_observed'] == 'reply' and r['browser_close_requested'] is True and r['close_reply'] is True
    assert (r['browser_version'], r['protocol_version'], r['version_matches']) == (VERSION, '1.3', True)
    assert (r['extension_registry_before'], r['extension_registry_after']) == ('LISTED_ENABLED', 'ABSENT')
    assert r['extension_uninstall_replied'] is True and r['extension_worker_absent'] is True
    assert r['fixture'] == 'PROJECT_AUTHORED_NO_CAPTURE' and r['cdp_stage'] == 'close'
    assert chrome.collapsed(s.pipe.methods) == chrome.expected_sequence('full', False)
    assert chrome.protocol_passed(s.pipe.methods)
    assert s.owner.received >= 1


def test_qualified_eof_requires_owned_exit_zero(chrome, session):
    s = session(close='eof')
    exercise(chrome, s)
    assert s.result['quit_observed'] == 'qualified-eof' and s.result['close_reply'] is False
    assert s.pipe.methods[-1] == {'method': 'Browser.close', 'outcome': 'failed', 'error': 'CDPEOF'}
    # The adapter keeps the truthful transport record; only the host may qualify it.
    assert not chrome.protocol_passed(s.pipe.methods)
    assert chrome.protocol_passed(s.pipe.methods, qualified_close=True)
    assert chrome.close_count(s.pipe.methods) == 1


def test_qualified_close_admits_only_the_exact_final_entry(chrome, session):
    s = session(close='eof')
    exercise(chrome, s)
    good = [dict(m) for m in s.pipe.methods]
    assert chrome.protocol_passed(good, qualified_close=True)
    for bad in ([*good[:-1], {**good[-1], 'scope': 'page'}],
                [*good[:-1], {**good[-1], 'protocol_error': 'other'}],
                [*good[:-1], {**good[-1], 'error': 'TimeoutError'}],
                [*good[:-1], {'method': 'Extensions.uninstall', 'outcome': 'failed', 'error': 'CDPEOF'}],
                [{**good[0], 'outcome': 'failed', 'error': 'CDPEOF'}, *good[1:]],
                [*good, dict(good[-1])],
                [good[-1]] + good[1:]):
        assert not chrome.protocol_passed(bad, qualified_close=True)
    assert not chrome.protocol_passed([], qualified_close=True)


def test_eof_without_owned_exit_fails(chrome, session):
    s = session(close='eof', exit_code=None)
    failed(chrome, s, 'Owned workload timeout')
    assert 'quit_observed' not in s.result and s.result['browser_close_requested'] is True


@pytest.mark.parametrize('close', ['reply', 'eof'])
def test_nonzero_exit_fails(chrome, session, close):
    s = session(close=close, exit_code=-11)
    failed(chrome, s, 'Unexpected normal browser exit')
    assert 'quit_observed' not in s.result


def test_close_reply_without_exit_fails(chrome, session):
    s = session(close='reply', exit_code=None)
    failed(chrome, s, 'Owned workload timeout')
    assert 'quit_observed' not in s.result and s.result['close_reply'] is True


def test_unanswered_close_fails(chrome, session):
    s = session(silent=('Browser.close',))
    failed(chrome, s, 'CDP deadline')
    assert 'quit_observed' not in s.result and s.owner.returncode is None


def test_exit_before_close_is_not_a_quit(chrome, session):
    s = session(exit_before_close=True)
    failed(chrome, s, 'Workload exited before Browser.close')
    assert s.result['browser_close_requested'] is False and 'Browser.close' not in s.browser.methods
    assert s.result['extension_unloaded'] is True


def test_delayed_page_and_extension_readiness_succeed(chrome, session):
    s = session(page_delay=3, storage_delay=3, worker_delay=2, removal_delay=2)
    exercise(chrome, s)
    assert s.result['quit_observed'] == 'reply'
    assert s.browser.counts['Runtime.evaluate'] == 4 and s.browser.counts['Extensions.getStorageItems'] == 4
    assert chrome.collapsed(s.pipe.methods) == chrome.expected_sequence('full', False)


def test_page_readiness_is_bounded(chrome, session):
    s = session(page_delay=10 ** 6)
    failed(chrome, s, 'Page readiness timeout')
    assert 'page_nonce' not in s.result and s.result['ready'] is True
    assert s.result['cdp_stage'] == 'page-readiness' and s.browser.counts['Runtime.evaluate'] > 1


@pytest.mark.parametrize('pending', [{'protocol': 'about:', 'readyState': 'complete', 'title': ''},
                                     {'protocol': 'about:', 'readyState': 'complete', 'title': 'about:blank'},
                                     {'protocol': 'data:', 'readyState': 'loading', 'title': ''},
                                     {'protocol': 'data:', 'readyState': 'interactive', 'title': 'partial'}])
def test_uncommitted_or_loading_document_is_not_ready_not_a_mismatch(chrome, session, pending):
    s = session(page_delay=2, page_pending=pending)
    exercise(chrome, s)
    assert s.result['page_nonce'] is True and s.browser.counts['Runtime.evaluate'] == 3


@pytest.mark.parametrize('title', ['', 'wrong', '0' * 48])
def test_complete_data_document_with_wrong_title_refuses(chrome, session, title):
    s = session(title=title)
    failed(chrome, s, 'Page challenge mismatch')
    assert 'page_nonce' not in s.result and s.result['cdp_stage'] == 'page-readiness'
    assert s.browser.counts['Runtime.evaluate'] == 1


def evaluation(value, **extra):
    return lambda r: {'id': r['id'], 'sessionId': r['sessionId'], 'result': {'result': {'value': value}, **extra}}


@pytest.mark.parametrize('frame', [evaluation(None), evaluation('title'), evaluation([]),
                                   evaluation({'protocol': 'data:', 'readyState': 'complete'}),
                                   evaluation({'protocol': 'data:', 'readyState': 'complete', 'title': 1}),
                                   evaluation({'protocol': 'data:', 'readyState': 'complete', 'title': ''},
                                              exceptionDetails={}),
                                   lambda r: {'id': r['id'], 'sessionId': r['sessionId'], 'result': {'result': 1}}])
def test_page_evaluation_shape_refuses(chrome, session, frame):
    s = session(frames={'Runtime.evaluate': frame})
    failed(chrome, s, 'Page evaluation shape')
    # The transport call passed; the adapter refuses its content, so no true fact is set.
    assert 'page_nonce' not in s.result and s.pipe.methods[-1] == {'method': 'Runtime.evaluate', 'outcome': 'passed',
                                                                'scope': 'page'}


def test_worker_to_absence_interval_is_recorded_not_invented(chrome, session):
    s = session(removal_delay=3)
    exercise(chrome, s)
    elapsed = s.result['extension_worker_to_absence_seconds']
    assert type(elapsed) is float and 0 <= elapsed < 5
    s = session(errors={'Extensions.uninstall': {'code': -32000, 'message': 'x'}})
    failed(chrome, s, 'CDP protocol error')
    assert 'extension_worker_to_absence_seconds' not in s.result


def test_extension_computation_is_bounded(chrome, session):
    s = session(storage_delay=10 ** 6)
    failed(chrome, s, 'Extension execution timeout')
    assert s.result['extension_installed'] is True and 'extension_nonce' not in s.result


@pytest.mark.parametrize('value', ['0' * 64, 'fabricated', None])
def test_fabricated_or_wrong_storage_refuses(chrome, session, value):
    s = session(storage=value if value is not None else '')
    failed(chrome, s, 'Extension challenge mismatch')
    assert 'extension_nonce' not in s.result and 'extension_unloaded' not in s.result


def test_harness_never_sends_or_writes_the_answer(chrome, session):
    s = session()
    exercise(chrome, s)
    answer = s.browser.answer
    assert answer and s.result['extension_nonce'] is True
    sent = b''.join(s.browser.sent)
    assert answer.encode() not in sent
    for path in (s.run / 'synthetic-extension').iterdir():
        assert answer not in path.read_text()
    # Separate challenges: the page challenge is not the extension's.
    worker = (s.run / 'synthetic-extension/worker.js').read_text()
    assert s.browser.challenge not in worker
    assert set(s.browser.methods) <= set(chrome.METHODS)
    assert 'Extensions.setStorageItems' not in s.browser.methods
    evaluations = [r for r in s.browser.requests if r['method'] == 'Runtime.evaluate']
    assert evaluations and all(e.get('sessionId') == SESSION for e in evaluations)
    # Storage reads only on the attached worker session; lifecycle and listing on the browser.
    storage = [r for r in s.browser.requests if r['method'] == 'Extensions.getStorageItems']
    assert storage and all(r.get('sessionId') == WORKER_SESSION for r in storage)
    for r in s.browser.requests:
        if r['method'] not in chrome.SESSION_SCOPES:
            assert 'sessionId' not in r, r['method']
    attach = [r['params'] for r in s.browser.requests if r['method'] == 'Target.attachToTarget']
    assert attach == [{'targetId': TARGET, 'flatten': True}, {'targetId': WORKER, 'flatten': True}]
    detach = [r['params'] for r in s.browser.requests if r['method'] == 'Target.detachFromTarget']
    assert detach == [{'sessionId': WORKER_SESSION}] and not s.browser.sessions
    assert [m.get('scope') for m in s.pipe.methods if 'scope' in m] == (
        ['page'] * s.browser.counts['Runtime.evaluate']
        + ['extension-worker'] * s.browser.counts['Extensions.getStorageItems'])


@pytest.mark.parametrize('error,category', [
    ({'code': -32601, 'message': "'Extensions.loadUnpacked' wasn't found"}, 'method-unavailable'),
    ({'code': -32000, 'message': 'Method not available.'}, 'method-unavailable')])
def test_unsupported_method_is_never_counted_as_passed(chrome, session, error, category):
    s = session(errors={'Extensions.loadUnpacked': error})
    failed(chrome, s, 'CDP method unavailable')
    entry = s.pipe.methods[-1]
    assert entry == {'method': 'Extensions.loadUnpacked', 'outcome': 'failed',
                     'error': 'VerificationError', 'protocol_error': category}
    assert not chrome.protocol_passed(s.pipe.methods)
    assert 'extension_installed' not in s.result and s.result['page_nonce'] is True
    assert "wasn't found" not in json.dumps(s.pipe.methods)


def test_nothing_is_optional_and_scope_labels_are_exact(chrome):
    assert not chrome.protocol_passed([])
    assert not chrome.protocol_passed([{'method': 'Extensions.setStorageItems', 'outcome': 'passed'}])
    for other in ({'protocol_error': 'method-unavailable'}, {'protocol_error': 'server-error'},
                  {'error': 'TimeoutError'}, {}):
        assert not chrome.protocol_passed([{'method': 'Extensions.getExtensions', 'outcome': 'failed',
                                            'optional': True, **other}])
    assert not chrome.protocol_passed([{'method': 'Extensions.getExtensions', 'outcome': 'passed',
                                        'optional': True}])
    assert chrome.protocol_passed([{'method': 'Extensions.getStorageItems', 'outcome': 'passed',
                                    'scope': 'extension-worker'}])
    for entry in ({'method': 'Extensions.getStorageItems', 'outcome': 'passed'},
                  {'method': 'Extensions.getStorageItems', 'outcome': 'passed', 'scope': 'page'},
                  {'method': 'Runtime.evaluate', 'outcome': 'passed', 'scope': 'extension-worker'},
                  {'method': 'Runtime.evaluate', 'outcome': 'passed'},
                  {'method': 'Extensions.uninstall', 'outcome': 'passed', 'scope': 'extension-worker'},
                  {'method': 'Extensions.getExtensions', 'outcome': 'passed', 'scope': None}):
        assert not chrome.protocol_passed([entry]), entry


def rerouted(s, target, session, scope):
    """Sends one method with a different session than the adapter chose."""
    original = s.pipe.call
    def call(method, params=None, *args, **kwargs):
        if method == target:
            return original(method, params, session, timeout=kwargs.get('timeout', 10), scope=scope)
        return original(method, params, *args, **kwargs)
    s.pipe.call = call


@pytest.mark.parametrize('session_,scope', [(None, None), (SESSION, 'page')])
def test_storage_read_outside_the_worker_session_is_refused(chrome, session, session_, scope):
    """(None, None) is the unchanged PREP1 request: getStorageItems on the browser target."""
    s = session()
    rerouted(s, 'Extensions.getStorageItems', session_, scope)
    failed(chrome, s, 'CDP protocol error')
    assert s.result['cdp_stage'] == 'extension-computation' and 'extension_nonce' not in s.result
    assert s.result['extension_session_attached'] is True
    assert s.pipe.methods[-1]['protocol_error'] == 'other'
    assert 'Extension not found' not in json.dumps(s.pipe.methods)


@pytest.mark.parametrize('method,session_,message', [
    ('Extensions.getExtensions', SESSION, 'CDP method unavailable'),
    ('Extensions.uninstall', SESSION, 'CDP method unavailable'),
    ('Extensions.loadUnpacked', SESSION, 'CDP method unavailable'),
    ('Extensions.uninstall', WORKER_SESSION, 'CDP session not found')])  # detached before uninstall
def test_lifecycle_and_listing_are_browser_scoped_only(chrome, session, method, session_, message):
    s = session()
    rerouted(s, method, session_, 'page' if session_ == SESSION else 'extension-worker')
    failed(chrome, s, message)
    assert 'extension_unloaded' not in s.result


@pytest.mark.parametrize('knobs,message,stage', [
    ({'extra_worker': True}, 'Extension worker ambiguous', 'extension-worker'),
    ({'worker_type': 'shared_worker'}, 'Extension worker identity mismatch', 'extension-worker'),
    ({'worker_url': 'chrome-extension://' + EXTENSION + '/other.js'}, 'Extension worker identity mismatch',
     'extension-worker'),
    ({'attach_session': SESSION}, 'Extension session shape', 'extension-attach'),
    ({'attach_session': 'not a session'}, 'Extension session shape', 'extension-attach'),
    ({'attach_session': 'F' * 32}, 'CDP session not found', 'extension-computation'),
    ({'worker_lost_after': 0}, 'CDP session not found', 'extension-computation'),
    ({'worker_lost_after': 2, 'storage_delay': 5}, 'CDP session not found', 'extension-computation')])
def test_wrong_targets_sessions_and_worker_loss_are_distinct(chrome, session, knobs, message, stage):
    s = session(**knobs)
    failed(chrome, s, message)
    assert s.result['cdp_stage'] == stage and 'extension_nonce' not in s.result
    assert 'extension_unloaded' not in s.result
    if message == 'CDP session not found':
        assert s.pipe.methods[-1] == {'method': 'Extensions.getStorageItems', 'outcome': 'failed',
                                      'scope': 'extension-worker', 'error': 'VerificationError',
                                      'protocol_error': 'session-not-found'}


@pytest.mark.parametrize('knobs,message,before', [
    ({'extensions': 'unavailable'}, 'CDP method unavailable', None),
    ({'extensions': 'malformed'}, 'Extension listing shape', None),
    ({'extensions': 'no-enabled'}, 'Extension listing shape', None),
    ({'enabled': False}, 'Extension not enabled', 'LISTED_DISABLED'),
    ({'duplicate': True}, 'Extension listing mismatch', 'DUPLICATE'),
    ({'absent_before': True}, 'Extension listing mismatch', 'ABSENT')])
def test_registry_presence_is_required_before_uninstall(chrome, session, knobs, message, before):
    s = session(**knobs)
    failed(chrome, s, message)
    assert s.result['cdp_stage'] == 'extension-listed' and s.result.get('extension_registry_before') == before
    assert 'extension_registry_listed' not in s.result and 'extension_unloaded' not in s.result
    assert 'Extensions.getStorageItems' not in s.browser.methods


@pytest.mark.parametrize('retained', ['enabled', 'disabled'])
def test_worker_gone_while_registry_retains_is_not_removal(chrome, session, retained):
    s = session(registry_retained=retained)
    failed(chrome, s, 'Extension registry retained')
    r = s.result
    assert r['extension_uninstall_replied'] is True and r['cdp_stage'] == 'extension-registry-removal'
    assert r['extension_registry_after'] == 'LISTED_' + retained.upper()
    assert not any(k in r for k in ('extension_registry_absent', 'extension_unloaded'))
    assert s.browser.counts['Extensions.getExtensions'] > 2  # bounded poll, not one read


def test_idle_worker_stop_before_uninstall_is_not_removal(chrome, session):
    """The registry still lists the extension; an idle stop does not change the outcome.

    The adapter lists targets only before the storage read and after uninstall, so an idle stop
    in between is indistinguishable from any other disappearance. The substantive negative is
    test_worker_gone_while_registry_retains_is_not_removal.
    """
    s = session(idle_stop=1, registry_retained='enabled')
    failed(chrome, s, 'Extension registry retained')
    assert 'extension_unloaded' not in s.result and 'extension_worker_absent' not in s.result


@pytest.mark.parametrize('frame', [
    lambda r: {'id': r['id'], 'error': {'code': -32000, 'message': 'Method not available.'}},
    lambda r: {'id': r['id'], 'error': {'code': -32000, 'message': 'private detail'}},
    lambda r: {'id': r['id'], 'result': {'extensions': None}},
    lambda r: {'id': r['id'], 'result': {'extensions': [{'id': 7}]}}])
def test_failed_or_malformed_listing_after_uninstall_is_not_removal(chrome, session, frame):
    s = session(frames={('Extensions.getExtensions', 2): frame})
    with pytest.raises(Exception):
        exercise(chrome, s)
    assert s.result['extension_uninstall_replied'] is True and 'extension_unloaded' not in s.result
    assert 'extension_registry_absent' not in s.result
    assert 'private detail' not in json.dumps([s.result, s.pipe.methods])


def test_uninstall_failure_is_not_removal(chrome, session):
    s = session(errors={'Extensions.uninstall': {'code': -32000, 'message': 'private detail'}})
    failed(chrome, s, 'CDP protocol error')
    assert s.result['extension_nonce'] is True and 'extension_unloaded' not in s.result
    assert s.pipe.methods[-1]['protocol_error'] == 'server-error'
    assert 'private detail' not in json.dumps(s.pipe.methods)


def test_removal_poll_is_bounded(chrome, session):
    s = session(removal_delay=10 ** 6)
    failed(chrome, s, 'Extension removal incomplete')
    assert 'extension_unloaded' not in s.result and s.result['extension_registry_absent'] is True
    assert 'extension_worker_absent' not in s.result


def test_worker_never_observed_refuses(chrome, session):
    s = session(worker_visible=False)
    failed(chrome, s, 'Extension worker not observed')
    assert s.result['extension_installed'] is True and 'extension_worker_observed' not in s.result


@pytest.mark.parametrize('product,message', [
    ('HeadlessChrome/139.0.0.1', 'Browser version mismatch'),
    ('Chromium/140.0.7339.80', 'Browser version shape'),
    ('HeadlessChrome/140', 'Browser version shape')])
def test_version_must_match_prepared_bundle(chrome, session, product, message):
    s = session(product=product)
    failed(chrome, s, message)
    assert 'ready' not in s.result and s.pipe.methods[0]['outcome'] == 'passed'


def mismatched_id(request):
    return {'id': request['id'] + 7, 'result': {}}


def wrong_session(request):
    return {'id': request['id'], 'sessionId': 'Z' * 32, 'result': {'result': {'value': None}}}


def browser_session(request):
    return {'id': request['id'], 'sessionId': SESSION, 'result': {'targetId': TARGET}}


@pytest.mark.parametrize('frames,message', [
    ({'Browser.getVersion': mismatched_id}, 'CDP request mismatch'),
    ({'Browser.getVersion': lambda r: {'id': True, 'result': {}}}, 'CDP request mismatch'),
    ({'Runtime.evaluate': wrong_session}, 'CDP session mismatch'),
    ({'Target.createTarget': browser_session}, 'CDP session mismatch'),
    ({'Browser.getVersion': b'{not json\0'}, 'CDP frame malformed'),
    ({'Browser.getVersion': b'[1]\0'}, 'CDP frame malformed'),
    ({'Browser.getVersion': b'\xff\0'}, 'CDP frame malformed'),
    ({'Browser.getVersion': lambda r: {'id': r['id'], 'result': []}}, 'CDP result required'),
    ({'Browser.getVersion': lambda r: {'params': {}}}, 'Invalid CDP event'),
    ({'Browser.getVersion': lambda r: {'id': r['id'], 'error': 'text'}}, 'CDP protocol error')])
def test_invalid_responses_refuse_with_fixed_messages(chrome, session, frames, message):
    s = session(frames=frames)
    failed(chrome, s, message)
    assert s.pipe.methods[-1]['outcome'] == 'failed'


def test_oversized_frame_refuses(chrome, session):
    s = session(frames={'Browser.getVersion': b'x' * (1024 * 1024 + 1)})
    failed(chrome, s, 'Oversized CDP frame')


def test_startup_timeout_and_eof_are_distinct(chrome, session):
    s = session(silent=('Browser.getVersion',))
    error = failed(chrome, s, 'CDP deadline')
    assert isinstance(error, TimeoutError) and 'ready' not in s.result
    s = session(silent=('Browser.getVersion',))
    s.browser.close_writer()
    from cnt_protocol import CDPEOF
    error = failed(chrome, s, 'CDP EOF')
    assert isinstance(error, CDPEOF)
    chrome.observe_exit_after_eof(s.owner, error, s.result)
    assert s.result['eof_exit_observation'] == 'NOT_OBSERVED'
    later = Owner()
    threading.Timer(.02, lambda: setattr(later, 'returncode', -11)).start()
    chrome.observe_exit_after_eof(later, error, s.result)
    assert s.result['eof_exit_observation'] == 'EXITED' and later.returncode == -11
    unrelated = {}
    chrome.observe_exit_after_eof(later, TimeoutError('CDP deadline'), unrelated)
    assert unrelated == {}


def test_useful_abnormal_times_out_deliberately_without_close(chrome, session):
    s = session()
    exercise(chrome, s, abnormal=True)
    r = s.result
    assert r['intended_timeout'] is True and all(r[k] is True for k in chrome.USEFUL_FLAGS)
    assert r['browser_close_requested'] is False and 'quit_observed' not in r
    assert 'Browser.close' not in s.browser.methods
    assert chrome.collapsed(s.pipe.methods) == chrome.expected_sequence('full', True)


def test_startup_timeout_is_never_an_intended_timeout(chrome, session):
    s = session(silent=('Browser.getVersion',))
    failed(chrome, s, 'CDP deadline', abnormal=True)
    assert 'intended_timeout' not in s.result


@pytest.mark.parametrize('workload', ['empty', 'page'])
def test_abnormal_requires_complete_useful_work(chrome, session, workload):
    s = session()
    failed(chrome, s, 'Abnormal wait before useful work', workload=workload, abnormal=True)
    assert 'intended_timeout' not in s.result


def test_abnormal_exit_during_wait_is_not_intended(chrome, session, monkeypatch):
    s = session()
    original = s.owner.until
    def until(predicate, timeout):
        s.owner.returncode = -11
        return original(predicate, timeout)
    s.owner.until = until
    failed(chrome, s, 'Workload exited before intended timeout', abnormal=True)
    assert 'intended_timeout' not in s.result


@pytest.mark.parametrize('workload', ['empty', 'page'])
def test_diagnostic_workloads_close_normally(chrome, session, workload):
    s = session()
    exercise(chrome, s, workload=workload)
    assert s.result['quit_observed'] == 'reply' and 'extension_installed' not in s.result
    assert chrome.collapsed(s.pipe.methods) == chrome.expected_sequence(workload, False)


def test_interrupt_mid_poll_preserves_partial_facts(chrome, session, monkeypatch):
    s = session(storage_delay=10 ** 6)
    sleeps = []
    def interrupt(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:
            raise KeyboardInterrupt
    monkeypatch.setattr(chrome.time, 'sleep', interrupt)
    with pytest.raises(KeyboardInterrupt):
        exercise(chrome, s)
    assert s.result['extension_installed'] is True and s.result['cdp_stage'] == 'extension-computation'
    assert 'extension_nonce' not in s.result
    assert all(m['outcome'] == 'passed' for m in s.pipe.methods if not m.get('optional'))


def test_exported_facts_carry_no_paths_ids_or_challenges(chrome, session):
    s = session()
    exercise(chrome, s)
    exported = json.dumps([s.result, s.pipe.methods])
    for secret in (str(s.run), EXTENSION, SESSION, TARGET, WORKER, WORKER_SESSION, s.browser.challenge,
                   s.browser.answer, '/private/fixture'):
        assert secret not in exported


def test_codes_are_fixed_tokens_and_agree_with_firefox(chrome):
    import cnt_protocol, cnt_synthetic_firefox, cnt_firefox_observation
    tables = [chrome.CHROME_CODES, cnt_protocol.CDP_CODES, cnt_synthetic_firefox.SESSION_CODES,
              cnt_synthetic_firefox.PORT_CODES, cnt_firefox_observation.FAILURE_CODES]
    merged = {}
    for table in tables:
        for message, code in table.items():
            assert merged.setdefault(message, code) == code, message
            assert code.replace('_', '').isalnum() and code.isupper()
    # Shared abnormal messages stay unclassified so Firefox records are unchanged.
    assert 'Unexpected abnormal failure' not in merged
    assert 'Workload exited before intended timeout' not in merged


@pytest.fixture
def launch(load_module, monkeypatch, tmp_path):
    """Real launch_empty Chrome branch; the owned supervisor is replaced by the scripted peer."""
    preflight = load_module('tests/cnt-native-preflight.py')
    import cnt_owned_process, cnt_synthetic_chrome as canonical
    for name, value in (('STARTUP_DEADLINE', 1), ('CALL_TIMEOUT', 1), ('EOF_EXIT_OBSERVATION', .5),
                        ('POLL_INTERVAL', .001)):
        monkeypatch.setattr(canonical, name, value)
    seen, browsers = {}, []

    def start(**knobs):
        class Owned:
            def __init__(self, command, run, env, log, pipe_fds=(), evidence=None, markers=()):
                seen.update(command=command, env=env, pipe_fds=pipe_fds, markers=markers)
                self.returncode, self.workload_pid, self.received = None, 4242, 0
                reader, writer = (os.dup(fd) for fd in pipe_fds)  # launch_empty closes its copies
                self.browser = Browser(self, reader, writer, **knobs)
                browsers.append((reader, self.browser))
                if knobs.get('startup_eof') is not None:
                    self.browser.close_writer()
                    threading.Timer(.02, lambda: setattr(self, 'returncode', knobs['startup_eof'])).start()
            receive = Owner.receive
            until = Owner.until
            def settle(self):
                return {'exit_code': self.returncode, 'workload_status': 'exited', 'zero_survivors': True,
                        'unsettled': False, 'failures': []}
        monkeypatch.setattr(cnt_owned_process, 'OwnedProcess', Owned)
        run = tmp_path / 'attempt'
        for name in ('profile', 'home', 'tmp'):
            (run / name).mkdir(parents=True, exist_ok=True)
        return preflight, run
    yield start, seen
    for reader, browser in browsers:
        browser.thread.join(2)
        os.close(reader)
        browser.close_writer()


def test_launch_chrome_branch_records_protocol_and_quit(launch):
    start, seen = launch
    preflight, run = start()
    r = preflight.launch_empty(['sandboxed-chrome'], run, 'chrome', expected_version=VERSION)
    assert r['quit_observed'] == 'reply' and r['exit_before_cleanup'] == 0 and 'primary_failure' not in r
    assert all(r[k] is True for k in ('ready', 'page_nonce', 'extension_nonce', 'extension_unloaded'))
    assert [m['method'] for m in r['protocol']][-1] == 'Browser.close'
    assert seen['markers'] == (str(run / 'profile') + '/',) and len(seen['pipe_fds']) == 2
    assert not any(name.startswith('MOZ_') for name in seen['env'])
    assert r['owned_crash_artifacts']['profile/Crashpad']['status'] == 'ABSENT_DIRECTORY'
    assert r['settlement']['exit_code'] == 0


def test_launch_chrome_startup_eof_keeps_exit_and_crash_counts(launch):
    start, seen = launch
    preflight, run = start(startup_eof=-11)
    (run / 'profile/Crashpad/completed').mkdir(parents=True)
    (run / 'profile/Crashpad/completed/report.dmp').write_bytes(b'synthetic')
    r = preflight.launch_empty(['sandboxed-chrome'], run, 'chrome', expected_version=VERSION)
    assert r['primary_failure'] == {'stage': 'browser', 'type': 'CDPEOF', 'classification': 'CDP EOF',
                                    'code': 'CDP_EOF', 'message_known': True}
    assert r['eof_exit_observation'] == 'EXITED' and r['exit_before_cleanup'] == -11
    assert r['ready'] is False and 'quit_observed' not in r
    assert r['protocol'] == [{'method': 'Browser.getVersion', 'outcome': 'failed', 'error': 'CDPEOF'}]
    crash = r['owned_crash_artifacts']['profile/Crashpad']
    assert crash['status'] == 'INSPECTED' and crash['counts']['dmp'] == 1
    assert str(run) not in json.dumps(r)


def test_hung_call_inside_a_poll_is_transport_not_readiness(chrome, session, monkeypatch):
    monkeypatch.setattr(chrome, 'CALL_TIMEOUT', .2)
    monkeypatch.setattr(chrome, 'PAGE_DEADLINE', 5)
    s = session(silent=('Runtime.evaluate',))
    started = chrome.time.monotonic()
    error = failed(chrome, s, 'CDP deadline')
    assert isinstance(error, TimeoutError) and chrome.time.monotonic() - started < 2
    assert 'page_nonce' not in s.result and s.result['cdp_stage'] == 'page-readiness'


def test_never_ready_page_is_deterministically_a_readiness_timeout(chrome, session, monkeypatch):
    monkeypatch.setattr(chrome, 'PAGE_DEADLINE', .05)
    for _ in range(20):
        s = session(page_delay=10 ** 6)
        failed(chrome, s, 'Page readiness timeout')
