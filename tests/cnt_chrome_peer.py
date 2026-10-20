"""Scripted CDP peer and owner stand-in shared by the portable Chrome suites. Not a test module.

Scope and error shapes follow Chromium 149.0.7827.201 (commit 6a7b3dbec3b2) source, not an
installed browser:
- chrome_devtools_session.cc wires ExtensionsHandler with the session's own target id and
  allows load/list/uninstall only for the browser target; elsewhere they fail with
  ServerError "Method not available.".
- extensions_handler.cc GetStorageItems refuses with InvalidRequest "Extension not found."
  unless the handler's target may access the enabled extension's storage (its service worker).
  GetExtensions lists installed unpacked extensions with a separate enabled field.
- devtools_session.cc answers a request for an unknown child session from the browser session:
  code -32001 (crdtp SESSION_NOT_FOUND) and no sessionId.
Its extension "computation" reads the harness-written worker.js and hashes the embedded
challenge, so a passing run proves the harness supplied only the challenge.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time

VERSION = '140.0.7339.80'
TARGET = 'A' * 32
SESSION = 'B' * 32
WORKER = 'C' * 32
WORKER_SESSION = 'D' * 32
EXTENSION = 'abcdefghijklmnopabcdefghijklmnop'
WORKER_URL = 'chrome-extension://' + EXTENSION + '/worker.js'
NOT_AVAILABLE = {'code': -32000, 'message': 'Method not available.'}
NOT_FOUND = {'code': -32600, 'message': 'Extension not found.'}
SESSION_NOT_FOUND = {'code': -32001, 'message': 'Session with given id not found.'}
BROWSER_ONLY = ('Extensions.loadUnpacked', 'Extensions.getExtensions', 'Extensions.uninstall')


class Owner:
    """Stands in for OwnedProcess: returncode arrives only through the authenticated channel."""
    def __init__(self):
        self.returncode = None
        self.received = 0

    def receive(self, timeout=0):
        self.received += 1

    def until(self, predicate, timeout):
        from cnt_native_evidence import require
        deadline = time.monotonic() + timeout
        while not predicate():
            require(time.monotonic() < deadline, 'Owned workload timeout')
            time.sleep(.002)


class Browser:
    """Scripted CDP peer. Every knob defaults to a successful, source-faithful Chrome.

    Registry knobs: extensions ('available', 'unavailable', 'malformed', 'no-enabled'),
    enabled, duplicate, absent_before, registry_retained ('enabled' or 'disabled').
    Worker knobs: worker_visible, worker_delay, removal_delay, idle_stop (the worker target
    disappears after this many listings while the registry keeps the extension), extra_worker,
    worker_type, worker_url, worker_lost_after (storage reads served before the session is
    lost), attach_session. eof_on names a method answered by EOF and owned exit exit_code.
    """
    def __init__(self, owner, reader, writer, **knobs):
        self.owner, self.reader, self.writer = owner, reader, writer
        self.knobs = dict(page_delay=0, storage_delay=0, removal_delay=0, worker_delay=0,
                          version=VERSION, product=None, close='reply', exit_code=0,
                          storage=None, extensions='available', errors={}, frames={}, silent=(),
                          worker_visible=True, exit_before_close=False, title=None,
                          enabled=True, duplicate=False, absent_before=False, registry_retained=None,
                          idle_stop=None, extra_worker=False, worker_type='service_worker',
                          worker_url=WORKER_URL, worker_lost_after=None, attach_session=WORKER_SESSION,
                          eof_on=None,
                          page_pending={'protocol': 'about:', 'readyState': 'complete', 'title': ''})
        self.knobs.update(knobs)
        self.sent, self.methods, self.requests = [], [], []
        self.challenge = self.answer = None
        self.loaded = self.removed = False
        self.sessions = {}
        self.counts = {}
        self.lock, self.closed = threading.Lock(), False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def count(self, name):
        self.counts[name] = self.counts.get(name, 0) + 1
        return self.counts[name]

    def close_writer(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                os.close(self.writer)

    def write(self, value):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode() + b'\0'
        os.write(self.writer, raw)

    def serve(self):
        buffer = b''
        while True:
            try:
                chunk = os.read(self.reader, 65536)
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk
            while b'\0' in buffer:
                raw, buffer = buffer.split(b'\0', 1)
                self.sent.append(raw)
                request = json.loads(raw)
                self.methods.append(request['method'])
                self.requests.append(request)
                try:
                    if self.respond(request) == 'EOF':
                        self.close_writer()
                        return
                except OSError:
                    return

    def reply(self, request, result):
        response = {'id': request['id'], 'result': result}
        if 'sessionId' in request:
            response['sessionId'] = request['sessionId']
        self.write(response)

    def error(self, request, error):
        response = {'id': request['id'], 'error': error}
        if 'sessionId' in request:
            response['sessionId'] = request['sessionId']
        self.write(response)

    def worker_listed(self):
        k = self.knobs
        if self.removed:
            return self.count('removal-poll') <= k['removal_delay']
        listed = self.loaded and k['worker_visible'] and self.counts['Target.getTargets'] > k['worker_delay']
        if listed and k['idle_stop'] is not None:
            listed = self.count('worker-listing') <= k['idle_stop']
        return listed

    def registry(self):
        """Installed unpacked extensions; a disabled or idle extension is still listed."""
        k = self.knobs
        installed = self.loaded and not k['absent_before'] if not self.removed else k['registry_retained'] is not None
        if not installed:
            return []
        enabled = k['enabled'] if not self.removed else k['registry_retained'] == 'enabled'
        entry = {'id': EXTENSION, 'name': 'x', 'version': '1.0', 'enabled': enabled, 'path': '/private/fixture'}
        return [entry, dict(entry)] if k['duplicate'] else [entry]

    def respond(self, request):
        k, method = self.knobs, request['method']
        n = self.count(method)
        session = request.get('sessionId')
        if method in k['silent']:
            return None
        if method == k['eof_on']:
            self.owner.returncode = k['exit_code']
            return 'EOF'
        if (method, n) in k['frames'] or method in k['frames']:
            frame = k['frames'].get((method, n), k['frames'].get(method))
            self.write(frame(request) if callable(frame) else frame)
            return None
        if method in k['errors']:
            self.error(request, k['errors'][method])
            return None
        if session is not None and session not in (SESSION, *self.sessions):
            # Answered by the browser session: no sessionId on the error.
            self.write({'id': request['id'], 'error': SESSION_NOT_FOUND})
            return None
        if method in BROWSER_ONLY and session is not None:
            return self.error(request, NOT_AVAILABLE)
        if method == 'Browser.getVersion':
            self.write({'method': 'Target.targetCreated', 'params': {}})  # events are skipped
            product = k['product'] or 'HeadlessChrome/' + k['version']
            return self.reply(request, {'product': product, 'protocolVersion': '1.3',
                                        'userAgent': 'synthetic', 'jsVersion': '14.0'})
        if method == 'Target.createTarget':
            self.challenge = re.search(r'<title>([0-9a-f]+)</title>', request['params']['url']).group(1)
            return self.reply(request, {'targetId': TARGET})
        if method == 'Target.attachToTarget':
            if request['params']['targetId'] == TARGET:
                return self.reply(request, {'sessionId': SESSION})
            if request['params']['targetId'] == WORKER and self.loaded:
                if k['attach_session'] == WORKER_SESSION:
                    self.sessions[WORKER_SESSION] = 'worker'
                return self.reply(request, {'sessionId': k['attach_session']})
            return self.error(request, {'code': -32602, 'message': 'No target with given id found'})
        if method == 'Target.detachFromTarget':
            if self.sessions.pop(request['params'].get('sessionId'), None) is None:
                return self.error(request, {'code': -32602, 'message': 'No session with given id'})
            return self.reply(request, {})
        if method == 'Target.getTargets':
            infos = [{'targetId': TARGET, 'type': 'page', 'url': 'data:', 'attached': True}]
            if self.worker_listed():
                infos.append({'targetId': WORKER, 'type': k['worker_type'], 'url': k['worker_url']})
                if k['extra_worker']:
                    infos.append({'targetId': 'E' * 32, 'type': 'service_worker', 'url': WORKER_URL})
            return self.reply(request, {'targetInfos': infos})
        if method == 'Runtime.evaluate':
            # Before the data: navigation commits, Chrome's initial about:blank is complete and untitled.
            state = (dict(k['page_pending']) if n <= k['page_delay'] else
                     {'protocol': 'data:', 'readyState': 'complete',
                      'title': self.challenge if k['title'] is None else k['title']})
            return self.reply(request, {'result': {'type': 'object', 'value': state}})
        if method == 'Extensions.loadUnpacked':
            source = (Path(request['params']['path']) / 'worker.js').read_text()
            challenge = re.search(r'const challenge = "([0-9a-f]+)";', source).group(1)
            self.answer = hashlib.sha256(challenge.encode()).hexdigest()
            self.loaded = True
            return self.reply(request, {'id': EXTENSION})
        if method == 'Extensions.getExtensions':
            if k['extensions'] == 'unavailable':
                return self.error(request, NOT_AVAILABLE)
            if k['extensions'] == 'malformed':
                return self.reply(request, {'extensions': {'id': EXTENSION}})
            listed = self.registry()
            if k['extensions'] == 'no-enabled':
                listed = [{key: v for key, v in e.items() if key != 'enabled'} for e in listed]
            return self.reply(request, {'extensions': listed})
        if method == 'Extensions.getStorageItems':
            # Only the owned worker's attached session may read this extension's storage.
            if self.sessions.get(session) != 'worker' or not self.loaded or self.removed:
                return self.error(request, NOT_FOUND)
            if k['worker_lost_after'] is not None and n > k['worker_lost_after']:
                self.sessions.pop(session)
                self.write({'id': request['id'], 'error': SESSION_NOT_FOUND})
                return None
            if n <= k['storage_delay']:
                return self.reply(request, {'data': {}})
            value = k['storage'] if k['storage'] is not None else self.answer
            return self.reply(request, {'data': {'response': value}})
        if method == 'Extensions.uninstall':
            self.removed = True
            return self.reply(request, {})
        if method == 'Browser.close':
            if k['close'] == 'reply':
                self.reply(request, {})
            self.owner.returncode = k['exit_code']
            return 'EOF' if k['close'] in ('eof', 'reply') else None
        raise AssertionError('unexpected method ' + method)
