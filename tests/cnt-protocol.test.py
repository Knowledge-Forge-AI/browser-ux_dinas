"""Portable framed protocol tests; real private pipes, no browser or network."""
import json
import os
import time

import pytest


@pytest.fixture
def pipe(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    module = load_module('tests/cnt_protocol.py')
    response_read, response_write = os.pipe()
    request_read, request_write = os.pipe()
    try:
        yield module.CDPPipe(response_read, request_write), response_write
    finally:
        for fd in (response_read, response_write, request_read, request_write):
            os.close(fd)


def test_fragmented_and_coalesced_frames(pipe):
    transport, writer = pipe
    transport.buffer = b'{"result":'
    os.write(writer, b'{}}\0{"second":2}\0')
    assert transport.frame(time.monotonic() + 1) == {'result': {}}
    assert transport.frame(time.monotonic() + 1) == {'second': 2}


@pytest.mark.parametrize('reply', [b'bad\0', b'[]\0', b'{"id":2,"result":{}}\0',
                                 b'{"id":1,"error":{"code":-1}}\0', b'{"id":1}\0'])
def test_rejects_invalid_and_mismatched_responses(pipe, reply):
    transport, writer = pipe
    os.write(writer, reply)
    with pytest.raises(Exception):
        transport.call('Browser.getVersion', timeout=.1)


def test_deeply_nested_frame_is_malformed_not_unknown(pipe):
    transport, _ = pipe
    transport.buffer = b'[' * 200000 + b']' * 200000 + b'\0'
    with pytest.raises(Exception) as caught:
        transport.frame(time.monotonic() + 1)
    assert type(caught.value).__name__ == 'VerificationError' and str(caught.value) == 'CDP frame malformed'


def test_timeout(pipe):
    transport, _ = pipe
    with pytest.raises(TimeoutError):
        transport.call('Browser.getVersion', timeout=.01)


def test_oversized(pipe):
    transport, writer = pipe
    transport.buffer = b'x' * (1024 * 1024)
    os.write(writer, b'x')
    with pytest.raises(Exception, match='Oversized'):
        transport.frame(time.monotonic() + 1)


def test_request_response_and_event(pipe):
    transport, writer = pipe
    os.write(writer, json.dumps({'method': 'event'}).encode() + b'\0' +
             json.dumps({'id': 1, 'result': {'product': 'synthetic'}}).encode() + b'\0')
    assert transport.call('Browser.getVersion') == {'product': 'synthetic'}


def test_eof(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    module = load_module('tests/cnt_protocol.py')
    reader, writer = os.pipe()
    os.close(writer)
    sink = os.open(os.devnull, os.O_WRONLY)
    try:
        with pytest.raises(Exception, match='EOF'):
            module.CDPPipe(reader, sink).frame(time.monotonic() + 1)
    finally:
        os.close(reader)
        os.close(sink)


@pytest.mark.parametrize('raw', [b'12345678:', b'x:', b'0:', b'1048577:', b'4:xx', b''])
def test_marionette_bad_frames(module, raw):
    import time
    class Connection:
        def settimeout(self, _): pass
        def recv(self, n):
            nonlocal raw
            value, raw = raw[:n], raw[n:]
            return value
    with pytest.raises(Exception):
        module.Marionette(Connection()).frame(time.monotonic() + 1)


def test_marionette_split_frame_and_mismatch(module):
    import json
    class Connection:
        def __init__(self): self.raw = b''
        def settimeout(self, _): pass
        def sendall(self, request):
            response = json.dumps([1, 99, None, {}]).encode()
            self.raw = str(len(response)).encode() + b':' + response
        def recv(self, n):
            value, self.raw = self.raw[:1], self.raw[1:]
            return value
    client = module.Marionette(Connection())
    with pytest.raises(Exception, match='response mismatch'):
        client.call('WebDriver:NewSession')
    assert client.methods[0]['outcome'] == 'failed'


@pytest.fixture
def module(load_module, monkeypatch, repo_root):
    monkeypatch.syspath_prepend(str(repo_root / 'tests'))
    return load_module('tests/cnt_protocol.py')


def test_marionette_send_failure_is_recorded(module):
    class Connection:
        def settimeout(self, _): pass
        def sendall(self, _): raise BrokenPipeError()
    client = module.Marionette(Connection())
    with pytest.raises(BrokenPipeError): client.call('WebDriver:NewSession')
    assert client.methods == [{'method': 'WebDriver:NewSession', 'outcome': 'failed', 'error': 'BrokenPipeError'}]


def test_cdp_outcomes_are_fixed_keys_without_error_text(pipe):
    transport, writer = pipe
    os.write(writer, json.dumps({'id': 1, 'error': {'code': -32601, 'message': '/private/x'}}).encode() + b'\0')
    with pytest.raises(Exception, match='^CDP method unavailable$'):
        transport.call('Extensions.getExtensions', optional=True)
    os.write(writer, json.dumps({'id': 2, 'error': {'code': -32602, 'message': 'x'}}).encode() + b'\0')
    with pytest.raises(Exception, match='^CDP protocol error$'):
        transport.call('Extensions.uninstall')
    assert transport.methods == [
        {'method': 'Extensions.getExtensions', 'outcome': 'failed', 'optional': True,
         'error': 'VerificationError', 'protocol_error': 'method-unavailable'},
        {'method': 'Extensions.uninstall', 'outcome': 'failed', 'error': 'VerificationError',
         'protocol_error': 'invalid-params'}]


@pytest.mark.parametrize('reply,session', [({'id': 1, 'result': {}}, 'S'),
                                           ({'id': 1, 'sessionId': 'T', 'result': {}}, 'S'),
                                           ({'id': 1, 'sessionId': 'S', 'result': {}}, None)])
def test_cdp_session_scope_must_match(pipe, reply, session):
    transport, writer = pipe
    os.write(writer, json.dumps(reply).encode() + b'\0')
    with pytest.raises(Exception, match='^CDP session mismatch$'):
        transport.call('Runtime.evaluate', session=session, timeout=.5, scope='page' if session else None)


def test_cdp_eof_is_typed(module):
    reader, writer = os.pipe()
    os.close(writer)
    sink = os.open(os.devnull, os.O_WRONLY)
    try:
        transport = module.CDPPipe(reader, sink)
        with pytest.raises(module.CDPEOF, match='^CDP EOF$'):
            transport.call('Browser.close', timeout=.5)
        assert isinstance(module.CDPEOF('x'), EOFError)
        assert transport.methods == [{'method': 'Browser.close', 'outcome': 'failed', 'error': 'CDPEOF'}]
    finally:
        os.close(reader)
        os.close(sink)


@pytest.mark.parametrize('error,category', [
    ({'code': -32601}, 'method-unavailable'), ({'code': -32000, 'message': 'Method not available.'},
                                                'method-unavailable'),
    ({'code': -32000, 'message': 'Method not available here'}, 'server-error'),
    ({'code': -32602}, 'invalid-params'), ({'code': 1}, 'other'), ({'code': '1'}, 'other'), ('x', 'other')])
def test_protocol_error_categories(module, error, category):
    assert module.protocol_error(error) == category


@pytest.mark.parametrize('session,scope', [('S', None), ('S', 'browser'), ('S', 'other'), (None, 'page')])
def test_cdp_scope_label_is_required_for_and_only_for_session_calls(pipe, session, scope):
    transport, _ = pipe
    with pytest.raises(Exception, match='^CDP scope label invalid$'):
        transport.call('Runtime.evaluate', session=session, scope=scope, timeout=.1)
    assert transport.methods == [{'method': 'Runtime.evaluate', 'outcome': 'failed', 'error': 'VerificationError'}]


def test_cdp_scope_label_is_recorded_without_the_session_id(pipe):
    transport, writer = pipe
    os.write(writer, json.dumps({'id': 1, 'sessionId': 'SECRET', 'result': {}}).encode() + b'\0' +
             json.dumps({'id': 2, 'result': {}}).encode() + b'\0')
    transport.call('Extensions.getStorageItems', session='SECRET', scope='extension-worker')
    transport.call('Extensions.uninstall')
    assert transport.methods == [
        {'method': 'Extensions.getStorageItems', 'outcome': 'passed', 'scope': 'extension-worker'},
        {'method': 'Extensions.uninstall', 'outcome': 'passed'}]
    assert module_codes(transport)['CDP session not found'] == 'CDP_SESSION_NOT_FOUND'


def module_codes(transport):
    import sys
    return sys.modules[type(transport).__module__].CDP_CODES


@pytest.mark.parametrize('reply,session,message,category', [
    # Chromium's browser session answers an unknown child session: -32001, no sessionId.
    ({'id': 1, 'error': {'code': -32001, 'message': 'private-detail'}}, 'S', 'CDP session not found', 'session-not-found'),
    # Any other error without the echo, or -32001 echoed by another session, stays a mismatch.
    ({'id': 1, 'error': {'code': -32000, 'message': 'private-detail'}}, 'S', 'CDP session mismatch', None),
    ({'id': 1, 'sessionId': 'T', 'error': {'code': -32001}}, 'S', 'CDP session mismatch', None),
    # Echoed by the same session, or on a browser call, it is an ordinary protocol error.
    ({'id': 1, 'sessionId': 'S', 'error': {'code': -32001}}, 'S', 'CDP protocol error', 'session-not-found'),
    ({'id': 1, 'error': {'code': -32001}}, None, 'CDP protocol error', 'session-not-found')])
def test_session_not_found_is_distinct(pipe, reply, session, message, category):
    transport, writer = pipe
    os.write(writer, json.dumps(reply).encode() + b'\0')
    with pytest.raises(Exception, match='^' + message + '$'):
        transport.call('Extensions.getStorageItems', session=session,
                       scope='extension-worker' if session else None, timeout=.5)
    assert transport.methods[-1].get('protocol_error') == category
    assert 'private-detail' not in json.dumps(transport.methods)
