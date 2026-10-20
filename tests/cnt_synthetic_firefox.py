"""Project-authored Firefox extension; no captured packages or live profiles."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time

from cnt_native_evidence import VerificationError, require
from cnt_crash_paths import owned_directory
from cnt_protocol import Marionette, MarionetteEOF
from cnt_firefox_observation import listener_owned, ObservedClient, record_sample

PORT_CODES = {'Unexpected active-port link': 'PORT_FILE_LINK',
              'Invalid Marionette active port': 'PORT_FILE_MALFORMED',
              'Invalid Marionette port': 'PORT_FILE_OUT_OF_RANGE',
              'Marionette effective port unavailable': 'PORT_FILE_UNAVAILABLE',
              'Marionette effective port mismatch': 'PORT_FILE_MISMATCH'}
# Fixed session, protocol and workload refusals. Variable text (for example
# 'Marionette protocol: <error>') is deliberately absent and stays UNKNOWN.
SESSION_CODES = {'Marionette EOF': 'PROTOCOL_EOF',
                 'Marionette read deadline': 'PROTOCOL_READ_DEADLINE',
                 'Marionette invalid length': 'PROTOCOL_FRAME_INVALID',
                 'Marionette oversized frame': 'PROTOCOL_FRAME_INVALID',
                 'Marionette oversized request': 'PROTOCOL_REQUEST_OVERSIZED',
                 'Marionette greeting mismatch': 'PROTOCOL_GREETING_MISMATCH',
                 'Marionette response mismatch': 'PROTOCOL_RESPONSE_MISMATCH',
                 'Session response shape': 'SESSION_RESPONSE_SHAPE',
                 'Session capabilities shape': 'SESSION_RESPONSE_SHAPE',
                 'Session process mismatch': 'SESSION_PROCESS_MISMATCH',
                 'Session profile mismatch': 'SESSION_PROFILE_MISMATCH',
                 'Marionette script result shape': 'SCRIPT_RESULT_SHAPE',
                 'Page challenge mismatch': 'PAGE_CHALLENGE_MISMATCH',
                 'Installed extension ID mismatch': 'EXTENSION_ID_MISMATCH',
                 'Invalid registered extension origin': 'EXTENSION_ORIGIN_INVALID',
                 'Extension result shape': 'EXTENSION_RESULT_SHAPE',
                 'Extension document origin mismatch': 'EXTENSION_ORIGIN_MISMATCH',
                 'Extension challenge mismatch': 'EXTENSION_CHALLENGE_MISMATCH',
                 'Extension execution timeout': 'EXTENSION_EXECUTION_TIMEOUT',
                 'Extension removal incomplete': 'EXTENSION_REMOVAL_INCOMPLETE',
                 'Marionette quit result shape': 'QUIT_RESULT_SHAPE'}


def read_effective_port(profile):
    """('ABSENT'|'EMPTY', None) while pending, else ('VALID', port); anything else refuses.

    A zero-byte file is pending: its write order is not verified here. Non-empty
    invalid or partial content is never repaired or reinterpreted.
    """
    path = profile / 'MarionetteActivePort'
    require(not path.is_symlink(), 'Unexpected active-port link')
    if not path.exists():
        return 'ABSENT', None
    raw = path.read_text()
    if raw == '':
        return 'EMPTY', None
    require(re.fullmatch(r'[0-9]{1,5}', raw) is not None, 'Invalid Marionette active port')
    port = int(raw)
    require(0 < port < 65536, 'Invalid Marionette port')
    return 'VALID', port


def effective_port(profile):
    return read_effective_port(profile)[1]


def session(owner, run, outcomes, expected_port):
    outcomes = outcomes if outcomes is not None else {}
    def sample(stage, required, **options):
        # Looked up at call time so the module-level listener_owned stays the one seam.
        return record_sample(outcomes, stage, owner, expected_port, required,
                             observer=listener_owned, **options)
    outcomes["session_stage"] = "effective-port"
    outcomes['effective_port_status'] = 'PENDING'
    polls = outcomes['effective_port_polls'] = {'absent': 0, 'empty': 0}
    deadline = time.monotonic() + 20
    port = None
    try:
        while port is None and time.monotonic() < deadline:
            owner.receive(.05)
            require(owner.returncode is None and not owner.eof, 'Firefox exited before listener')
            sample('startup', False, mode='startup')
            status, port = read_effective_port(run / 'profile')
            if port is None:
                polls[status.lower()] += 1
        require(port is not None, 'Marionette effective port unavailable')
        require(port == expected_port, 'Marionette effective port mismatch')
    except BaseException as error:
        # Only port-file refusals change the status; any other cause leaves it PENDING.
        if isinstance(error, VerificationError) and str(error) in PORT_CODES:
            outcomes['effective_port_status'] = PORT_CODES[str(error)]
        raise
    outcomes['effective_port_status'] = 'MATCHED'
    outcomes['effective_port_readback'] = True
    outcomes['effective_port_source'] = 'MarionetteActivePort'
    outcomes['session_stage'] = 'listener-identity'
    # The first required pass always runs; the deadline bounds only extra resamples.
    sample('listener-identity', True, mode='pre-connect', deadline=deadline)
    connection = socket.create_connection(('127.0.0.1', port), timeout=3)
    try:
        sample('after-connect', True)
        client = ObservedClient(Marionette(connection), owner, port, outcomes)
        outcomes["protocol"] = client.methods
        outcomes["session_stage"] = "greeting"
        client.greeting()
        sample('after-greeting-identity', True)
        outcomes['session_stage'] = 'new-session'
        value = client.call('WebDriver:NewSession', {'capabilities': {'alwaysMatch': {}}})
        require(isinstance(value, dict), 'Session response shape')
        caps = value.get('capabilities', {})
        require(isinstance(caps, dict), 'Session capabilities shape')
        require(caps.get('moz:processID') == owner.workload_pid, 'Session process mismatch')
        require(caps.get('moz:profile') == str(run / 'profile'), 'Session profile mismatch')
        sample('after-session-identity', True)
        outcomes['session_stage'] = 'identity-verified'
        return client, caps
    except BaseException:
        connection.close()
        raise


def script(client, source, arguments=(), timeout=10):
    result = client.call('WebDriver:ExecuteScript', {
        'script': source, 'args': list(arguments), 'newSandbox': True,
        'sandbox': 'default', 'line': 0, 'filename': 'synthetic-trial'}, timeout=timeout)
    require(isinstance(result, dict) and 'value' in result, 'Marionette script result shape')
    return result['value']


def extension(run):
    target = run / 'synthetic-extension'
    target.mkdir(mode=0o700)
    identity = 'bux-synthetic-' + secrets.token_hex(8) + '@example.invalid'
    manifest = {'manifest_version': 2, 'name': 'Browser UX synthetic trial', 'version': '1.0',
                'browser_specific_settings': {'gecko': {'id': identity}}}
    (target / 'manifest.json').write_text(json.dumps(manifest))
    (target / 'page.html').write_text('<!doctype html><meta charset="utf-8"><script src="compute.js"></script>')
    (target / 'compute.js').write_text('''
(async () => {
  const challenge = location.hash.slice(1);
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(challenge));
  document.documentElement.dataset.result = Array.from(new Uint8Array(bytes),
      byte => byte.toString(16).padStart(2, '0')).join('');
})();
''')
    return target, identity


def qualify(client, run, outcomes, *, page_only=False):
    nonce = secrets.token_hex(24)
    page = run / 'page.html'
    page.write_text('<!doctype html><p id="nonce">' + nonce + '</p>')
    client.call('WebDriver:Navigate', {'url': page.as_uri()})
    require(script(client, "return document.getElementById('nonce').textContent") == nonce,
            'Page challenge mismatch')
    outcomes['page_nonce'] = True
    if page_only:
        return
    target, expected_id = extension(run)
    installed = client.call('Addon:Install', {'path': str(target), 'temporary': True})['value']
    require(installed == expected_id, 'Installed extension ID mismatch')
    outcomes['extension_installed'] = True
    client.call('Marionette:SetContext', {'value': 'chrome'})
    origin = script(client, 'return WebExtensionPolicy.getByID(arguments[0]).getURL("");', [installed])
    require(isinstance(origin, str) and re.fullmatch(r'moz-extension://[a-f0-9-]+/', origin),
            'Invalid registered extension origin')
    outcomes['extension_origin_verified'] = True
    client.call('Marionette:SetContext', {'value': 'content'})
    challenge = secrets.token_hex(24)
    client.call('WebDriver:Navigate', {'url': origin + 'page.html#' + challenge})
    expected = hashlib.sha256(challenge.encode()).hexdigest()
    def computed(remaining):
        value = script(client, 'return [location.origin, document.documentElement.dataset.result || null]',
                       timeout=remaining)
        require(isinstance(value, list) and len(value) == 2, 'Extension result shape')
        require(value[0] == origin.rstrip('/'), 'Extension document origin mismatch')
        if value[1] is None:
            return False
        require(value[1] == expected, 'Extension challenge mismatch')
        return True
    poll(computed, 'Extension execution timeout')
    outcomes['extension_nonce'] = True
    client.call('Addon:Uninstall', {'id': installed})
    client.call('Marionette:SetContext', {'value': 'chrome'})
    poll(lambda remaining: script(client,
         'return WebExtensionPolicy.getByID(arguments[0]) === null;', [installed],
         timeout=remaining) is True, 'Extension removal incomplete')
    outcomes['extension_unloaded'] = True
    client.call('Marionette:SetContext', {'value': 'content'})


def confinement_checks(client, run, outcomes):
    """Direct parent-process XPCOM IO and socket binds, never user canaries."""
    outside = run.parent / (run.name + '-outside-canary')
    own = run / 'io-canary'
    own.write_text('synthetic')
    client.call('Marionette:SetContext', {'value': 'chrome'})
    source = r'''const [own, sibling, socketPath] = arguments;
function file(path) {
  const f = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
  f.initWithPath(path); return f;
}
function read(path) {
  const stream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(Ci.nsIFileInputStream);
  try { stream.init(file(path), 1, 0, 0); return stream.available(); }
  finally { try { stream.close(); } catch (_) {} }
}
function write(path) {
  const stream = Cc["@mozilla.org/network/file-output-stream;1"].createInstance(Ci.nsIFileOutputStream);
  try { stream.init(file(path), 2 | 8 | 32, 384, 0); stream.write("synthetic", 9); }
  finally { try { stream.close(); } catch (_) {} }
}
function bind(path) {
  const server = Cc["@mozilla.org/network/server-socket;1"].createInstance(Ci.nsIServerSocket);
  try { server.initWithFilename(file(path), 384, -1); }
  finally { try { server.close(); } catch (_) {} }
}
function outcome(operation) {
  try { operation(); return "ALLOWED"; }
  catch (e) { return e.result === Cr.NS_ERROR_FILE_ACCESS_DENIED ? "DENIED_PERMISSION" : "ERROR_" + e.result; }
}
return {context: "Firefox parent chrome-context XPCOM",
  own_read: outcome(() => read(own)), own_write: outcome(() => write(own)),
  sibling_read: outcome(() => read(sibling)), sibling_write: outcome(() => write(sibling)),
  own_unix_bind: outcome(() => bind(socketPath)),
  sibling_unix_bind: outcome(() => bind(sibling + "-socket"))};'''
    observed = script(client, source, [str(own), str(outside), str(run / 'probe.sock')])
    outcomes['firefox_confinement'] = observed
    require(isinstance(observed, dict), 'Firefox IO probe shape')
    require(all(observed.get(k) == 'ALLOWED' for k in ('own_read', 'own_write', 'own_unix_bind')),
            'Firefox IO positive control failed')
    require(all(observed.get(k) == 'DENIED_PERMISSION' for k in
                ('sibling_read', 'sibling_write')),
            'Firefox IO denial unqualified')
    require(observed.get('sibling_unix_bind') != 'ALLOWED', 'Firefox prohibited Unix bind')
    outcomes['unix_bind_denial_classified'] = observed.get('sibling_unix_bind') == 'DENIED_PERMISSION'
    outcomes['firefox_confinement_coverage'] = {
        'tested': 'Parent XPCOM direct file read/write and Unix-domain bind',
        'untested': 'Child-component direct IO; TCP outbound; GPU/RDD/GMP/utility internals',
        'outer_python_canaries': 'Separate outer-policy evidence only'}
    client.call('Marionette:SetContext', {'value': 'content'})


def poll(predicate, message, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, message)
        passed = predicate(remaining)
        require(time.monotonic() <= deadline, message)
        if passed:
            return
        time.sleep(min(.05, max(0, deadline - time.monotonic())))


def quit_normally(client, owner, outcomes=None):
    outcomes = outcomes if outcomes is not None else {}
    try:
        result = client.call('Marionette:Quit', {'flags': ['eAttemptQuit']})
        require(isinstance(result, dict), 'Marionette quit result shape')
        outcomes['quit_observed'] = 'reply'
    except MarionetteEOF:
        # EOF alone is not acceptance: independently require the owned workload
        # to report a normal exit through its authenticated supervisor channel.
        pass
    owner.until(lambda: owner.returncode is not None, 10)
    require(owner.returncode == 0, 'Unexpected normal browser exit')
    outcomes.setdefault('quit_observed', 'qualified-eof')


def crash_reporter_status(client, run, outcomes):
    """Read supported status only; never enable, redirect, or submit a report."""
    client.call('Marionette:SetContext', {'value': 'chrome'})
    try:
        observed = script(client, r'''try {
  const reporter = Cc["@mozilla.org/toolkit/crash-reporter;1"].getService(Ci.nsICrashReporter);
  const enabled = reporter.crashReporterEnabled;
  if (typeof enabled !== "boolean") return {status: "UNAVAILABLE_INTERFACE"};
  if (!enabled) return {status: "NOT_INITIALIZED", enabled: false};
  try { return {status: "READBACK", enabled, destination: reporter.minidumpPath.path,
               data_directory: Services.env.get("MOZ_CRASHREPORTER_DATA_DIRECTORY")}; }
  catch (e) { return {status: "DESTINATION_UNAVAILABLE", enabled, result: e.result}; }
} catch (e) { return {status: "UNAVAILABLE_INTERFACE", result: e.result}; }''')
        require(isinstance(observed, dict) and observed.get('status') in (
            'READBACK', 'NOT_INITIALIZED', 'UNAVAILABLE_INTERFACE', 'DESTINATION_UNAVAILABLE'),
            'Crash reporter result shape')
        require(observed.get('status') not in ('READBACK', 'NOT_INITIALIZED', 'DESTINATION_UNAVAILABLE')
                or type(observed.get('enabled')) is bool, 'Crash reporter enabled shape')
        # Export only known scalar fields; never leak reporter-supplied paths.
        safe = {key: observed[key] for key in ('status', 'enabled', 'result')
                if key in observed and (type(observed[key]) in (bool, int)
                                        or key == 'status' and observed[key] in (
                                            'READBACK', 'NOT_INITIALIZED', 'UNAVAILABLE_INTERFACE',
                                            'DESTINATION_UNAVAILABLE'))}
        if observed.get('status') == 'READBACK':
            with owned_directory(run, observed.get('destination')) as (admission, _):
                safe['destination_status'] = admission['status']
                if admission['status'] == 'OWNED_DIRECTORY':
                    safe['destination_relative'] = admission['relative']
                else:
                    safe['status'] = admission['status']
        if observed.get('enabled') is True and 'data_directory' in observed:
            if observed['data_directory'] == '':
                safe['data_directory_status'] = 'UNSET'
            else:
                with owned_directory(run, observed['data_directory']) as (admission, _):
                    safe['data_directory_status'] = admission['status']
                    if admission['status'] == 'OWNED_DIRECTORY':
                        safe['data_directory_relative'] = admission['relative']
        observed = safe
        outcomes['crash_reporter'] = observed
    finally:
        client.call('Marionette:SetContext', {'value': 'content'})
