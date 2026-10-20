"""Bounded CDP pipe transport for the exact inherited browser instance."""
import json
import os
import select
import time

from cnt_native_evidence import require


class CDPEOF(EOFError):
    """Peer closed the inherited CDP pipe."""


# Fixed transport refusals. Protocol error text, params and results are never messages.
CDP_CODES = {'CDP EOF': 'CDP_EOF',
             'CDP deadline': 'CDP_READ_DEADLINE',
             'CDP write deadline': 'CDP_WRITE_DEADLINE',
             'Oversized CDP frame': 'CDP_FRAME_OVERSIZED',
             'Oversized CDP request': 'CDP_REQUEST_OVERSIZED',
             'CDP frame malformed': 'CDP_FRAME_MALFORMED',
             'Invalid CDP event': 'CDP_EVENT_INVALID',
             'CDP request mismatch': 'CDP_RESPONSE_MISMATCH',
             'CDP session mismatch': 'CDP_SESSION_MISMATCH',
             'CDP method unavailable': 'CDP_METHOD_UNAVAILABLE',
             'CDP session not found': 'CDP_SESSION_NOT_FOUND',
             'CDP scope label invalid': 'CDP_SCOPE_LABEL_INVALID',
             'CDP protocol error': 'CDP_PROTOCOL_ERROR',
             'CDP result required': 'CDP_RESULT_SHAPE'}
# Exact texts Chrome uses for a registered but disabled method; anything else is 'other'.
UNAVAILABLE_TEXTS = frozenset(('Method not available.', 'Method not available'))
# Fixed labels for a flattened-session call. Session ids themselves are never recorded.
CDP_SCOPES = ('page', 'extension-worker')
# crdtp DispatchCode SESSION_NOT_FOUND (SERVER_ERROR - 1) at Chromium 149.0.7827.201.
SESSION_NOT_FOUND = -32001


def protocol_error(error):
    """Fixed category for a CDP error object; its message is never exported."""
    code = error.get('code') if isinstance(error, dict) else None
    if type(code) is not int:
        return 'other'
    if code == -32601 or error.get('message') in UNAVAILABLE_TEXTS:
        return 'method-unavailable'
    return {-32602: 'invalid-params', -32000: 'server-error',
            SESSION_NOT_FOUND: 'session-not-found'}.get(code, 'other')


class CDPPipe:
    """Requests are strictly sequential. Each call appends one fixed-key outcome."""
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.buffer, self.sequence = b'', 0
        self.methods = []
        os.set_blocking(writer, False)

    def frame(self, deadline):
        while b'\0' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.reader], [], [], remaining)[0]:
                raise TimeoutError('CDP deadline')
            chunk = os.read(self.reader, 65536)
            if not chunk:
                raise CDPEOF('CDP EOF')
            self.buffer += chunk
            require(len(self.buffer) <= 1024 * 1024, 'Oversized CDP frame')
        raw, self.buffer = self.buffer.split(b'\0', 1)
        try:
            result = json.loads(raw)
        except (ValueError, RecursionError):
            result = None
        require(isinstance(result, dict), 'CDP frame malformed')
        return result

    def call(self, method, params=None, session=None, timeout=10, optional=False, scope=None):
        """A session call carries exactly one fixed scope label; a browser call carries none."""
        self.sequence += 1
        outcome = {'method': method, 'outcome': 'pending'}
        if optional:
            outcome['optional'] = True
        self.methods.append(outcome)
        try:
            require(scope in CDP_SCOPES if session else scope is None, 'CDP scope label invalid')
            if session:
                outcome['scope'] = scope
            result = self._call(method, params, session, timeout, outcome)
        except BaseException as error:
            outcome.update(outcome='failed', error=type(error).__name__)
            raise
        outcome['outcome'] = 'passed'
        return result

    def _call(self, method, params, session, timeout, outcome):
        request = {'id': self.sequence, 'method': method, 'params': params or {}}
        if session:
            request['sessionId'] = session
        raw = json.dumps(request).encode() + b'\0'
        require(len(raw) <= 65536, 'Oversized CDP request')
        deadline = time.monotonic() + timeout
        while raw:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [self.writer], [], remaining)[1]:
                raise TimeoutError('CDP write deadline')
            try:
                raw = raw[os.write(self.writer, raw):]
            except BlockingIOError:
                continue
        while True:
            response = self.frame(deadline)
            if 'id' not in response:
                require(type(response.get('method')) is str, 'Invalid CDP event')
                continue
            require(type(response['id']) is int and response['id'] == self.sequence,
                    'CDP request mismatch')
            # Chromium answers a request for an unknown child session from the browser session,
            # so that one error carries no sessionId. Only that exact code is recognized here.
            if (session and 'sessionId' not in response
                    and protocol_error(response.get('error')) == 'session-not-found'):
                outcome['protocol_error'] = 'session-not-found'
                require(False, 'CDP session not found')
            # Flattened sessions echo their id; browser-scoped replies carry none.
            require(response.get('sessionId') == session if session else 'sessionId' not in response,
                    'CDP session mismatch')
            if 'error' in response:
                outcome['protocol_error'] = protocol_error(response['error'])
                require(outcome['protocol_error'] != 'method-unavailable', 'CDP method unavailable')
                require(False, 'CDP protocol error')
            require(isinstance(response.get('result'), dict), 'CDP result required')
            return response['result']


class MarionetteEOF(EOFError):
    """Peer closed an otherwise owned Marionette connection."""


class Marionette:
    """Bounded v3 transport; endpoint ownership is checked by the caller."""
    def __init__(self, connection):
        self.connection = connection
        self.sequence = 0
        self.methods = []

    def _read(self, size, deadline):
        chunks = bytearray()
        while len(chunks) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Marionette read deadline')
            self.connection.settimeout(remaining)
            part = self.connection.recv(size - len(chunks))
            if not part:
                raise MarionetteEOF('Marionette EOF')
            chunks.extend(part)
        return bytes(chunks)

    def frame(self, deadline):
        header = b''
        while True:
            char = self._read(1, deadline)
            if char == b':':
                break
            require(char.isdigit() and len(header) < 7, 'Marionette invalid length')
            header += char
        require(bool(header) and 0 < int(header) <= 1024 * 1024, 'Marionette oversized frame')
        return json.loads(self._read(int(header), deadline))

    def greeting(self):
        value = self.frame(time.monotonic() + 5)
        require(isinstance(value, dict) and value.get('marionetteProtocol') == 3
                and value.get('applicationType') == 'gecko', 'Marionette greeting mismatch')

    def call(self, method, params=None, timeout=10):
        self.sequence += 1
        raw = json.dumps([0, self.sequence, method, params or {}]).encode()
        require(len(raw) < 65536, 'Marionette oversized request')
        deadline = time.monotonic() + timeout
        outcome = {'method': method, 'outcome': 'pending'}
        self.methods.append(outcome)
        try:
            self.connection.settimeout(timeout)
            self.connection.sendall(str(len(raw)).encode() + b':' + raw)
            value = self.frame(deadline)
            require(isinstance(value, list) and len(value) == 4
                    and value[:2] == [1, self.sequence], 'Marionette response mismatch')
            if value[2] is not None:
                code = value[2].get('error', 'unknown') if isinstance(value[2], dict) else 'malformed'
                safe = code if code in {'unknown command', 'unknown error', 'invalid argument',
                                        'session not created', 'javascript error', 'script timeout',
                                        'timeout', 'no such window', 'unsupported operation'} else 'other'
                outcome['protocol_error'] = safe
                raise RuntimeError('Marionette protocol: ' + safe)
            outcome['outcome'] = 'passed'
            return value[3]
        except BaseException as error:
            outcome.update(outcome='failed', error=type(error).__name__)
            raise
