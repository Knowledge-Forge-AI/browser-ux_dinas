"""Project-authored synthetic page and extension trial over the inherited CDP pipe.

Never imports CNT, never opens a debugging port and never discovers other sessions.
Each true fact is set only after the response that verifies it. The harness sends
challenges, never the expected extension answer, and never writes extension storage.

Scope follows Chromium 149.0.7827.201 (commit 6a7b3dbec3b2) chrome_devtools_session.cc and
protocol/extensions_handler.cc: load, list and uninstall are served only by the browser
target; getStorageItems is checked against the handler's own target, so it is read through
a flattened session attached to the owned extension's service worker. getExtensions reads the
installed registry and reports enabled state separately. Version-tag source is interface
guidance, not installed-build proof.
"""
import hashlib
import json
from pathlib import Path
import re
import secrets
import time

from cnt_native_evidence import require
from cnt_protocol import CDPEOF

STARTUP_DEADLINE = 20
# Each call inside a poll gets this fixed bound; the stage deadline is checked only between
# calls. A hung transport therefore reports CDP_READ_DEADLINE and a never-ready page its stage
# timeout, deterministically. Worst case per stage: its deadline plus one call.
CALL_TIMEOUT = 5
PAGE_DEADLINE = 10
EXTENSION_DEADLINE = 10
REMOVAL_DEADLINE = 10
CLOSE_DEADLINE = 10
EXIT_DEADLINE = 10
# Same deliberate live interval as the accepted Firefox abnormal attempt.
ABNORMAL_WAIT = .25
EOF_EXIT_OBSERVATION = 2
POLL_INTERVAL = .05

PRODUCT = re.compile(r'(?:Headless)?Chrome/([0-9]{1,5}(?:\.[0-9]{1,5}){3})')
PROTOCOL = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}')
TARGET = re.compile(r'[A-Za-z0-9]{1,64}')
EXTENSION_ID = re.compile(r'[a-p]{32}')
# Raw document state; readiness is decided here. The initial about:blank document can be
# complete with an empty title before the data: navigation commits, so it is not-ready, not
# a mismatch. Only a complete data: document is compared with the challenge.
READY = '({protocol: location.protocol, readyState: document.readyState, title: document.title})'
WORKER_SCRIPT = 'worker.js'
# The only methods this adapter sends. No setStorageItems, no evaluation in the extension.
METHODS = ('Browser.getVersion', 'Target.createTarget', 'Target.attachToTarget', 'Target.getTargets',
           'Runtime.evaluate', 'Extensions.loadUnpacked', 'Extensions.getExtensions',
           'Extensions.getStorageItems', 'Target.detachFromTarget', 'Extensions.uninstall', 'Browser.close')
# Session-scoped methods and their fixed scope labels; every other method is browser-scoped.
SESSION_SCOPES = {'Runtime.evaluate': 'page', 'Extensions.getStorageItems': 'extension-worker'}
# Consecutive repeats collapsed. Every call is required; none is optional.
STARTUP_SEQUENCE = ('Browser.getVersion',)
PAGE_SEQUENCE = STARTUP_SEQUENCE + ('Target.createTarget', 'Target.attachToTarget', 'Target.getTargets',
                                    'Runtime.evaluate')
FULL_SEQUENCE = PAGE_SEQUENCE + ('Extensions.loadUnpacked', 'Target.getTargets', 'Extensions.getExtensions',
                                 'Target.attachToTarget', 'Extensions.getStorageItems',
                                 'Target.detachFromTarget', 'Extensions.uninstall', 'Extensions.getExtensions',
                                 'Target.getTargets')
# The truthful transport record of a close answered by EOF. Only the host decides whether it
# qualifies; it is never rewritten.
QUALIFIED_CLOSE_ENTRY = {'method': 'Browser.close', 'outcome': 'failed', 'error': 'CDPEOF'}
USEFUL_FLAGS = ('ready', 'page_nonce', 'extension_installed', 'extension_worker_observed',
                'extension_registry_listed', 'extension_session_attached', 'extension_nonce',
                'extension_uninstall_replied', 'extension_registry_absent', 'extension_worker_absent',
                'extension_unloaded')
CHROME_CODES = {'Browser version shape': 'BROWSER_VERSION_SHAPE',
                'Browser version mismatch': 'BROWSER_VERSION_MISMATCH',
                'Target identity shape': 'TARGET_IDENTITY_SHAPE',
                'Target session shape': 'TARGET_SESSION_SHAPE',
                'Target list shape': 'TARGET_LIST_SHAPE',
                'Owned page target not listed': 'PAGE_TARGET_NOT_LISTED',
                'Page evaluation shape': 'PAGE_EVALUATION_SHAPE',
                'Page challenge mismatch': 'PAGE_CHALLENGE_MISMATCH',
                'Page readiness timeout': 'PAGE_READINESS_TIMEOUT',
                'Extension identity shape': 'EXTENSION_IDENTITY_SHAPE',
                'Extension worker not observed': 'EXTENSION_WORKER_NOT_OBSERVED',
                'Extension worker ambiguous': 'EXTENSION_WORKER_AMBIGUOUS',
                'Extension worker identity mismatch': 'EXTENSION_WORKER_IDENTITY_MISMATCH',
                'Extension session shape': 'EXTENSION_SESSION_SHAPE',
                'Extension listing shape': 'EXTENSION_LISTING_SHAPE',
                'Extension listing mismatch': 'EXTENSION_LISTING_MISMATCH',
                'Extension not enabled': 'EXTENSION_NOT_ENABLED',
                'Extension registry retained': 'EXTENSION_REGISTRY_RETAINED',
                'Extension storage shape': 'EXTENSION_STORAGE_SHAPE',
                'Extension challenge mismatch': 'EXTENSION_CHALLENGE_MISMATCH',
                'Extension execution timeout': 'EXTENSION_EXECUTION_TIMEOUT',
                'Extension removal incomplete': 'EXTENSION_REMOVAL_INCOMPLETE',
                'Workload exited before Browser.close': 'WORKLOAD_EXITED_BEFORE_CLOSE',
                'Abnormal wait before useful work': 'ABNORMAL_BEFORE_USEFUL_WORK'}
# 'Unexpected abnormal failure' and 'Workload exited before intended timeout' are shared with
# the Firefox branch and deliberately stay UNKNOWN, so Firefox classification is unchanged.


def poll(predicate, deadline, message):
    """Bounded repeated reads until the stage deadline; never one immediate read."""
    end = time.monotonic() + deadline
    while True:
        require(time.monotonic() < end, message)
        if predicate():
            return
        require(time.monotonic() < end, message)
        time.sleep(min(POLL_INTERVAL, max(0, end - time.monotonic())))


def valid(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def page_url(challenge):
    return 'data:text/html,<!doctype html><title>' + challenge + '</title>'


def fixture(run, challenge):
    """Project-authored MV3 worker. It receives the challenge and computes the answer itself."""
    target = Path(run) / 'synthetic-extension'
    target.mkdir(mode=0o700)
    (target / 'manifest.json').write_text(json.dumps({
        'manifest_version': 3, 'name': 'Browser UX synthetic harness fixture', 'version': '1.0',
        'permissions': ['storage'], 'background': {'service_worker': WORKER_SCRIPT}}))
    (target / WORKER_SCRIPT).write_text('const challenge = ' + json.dumps(challenge) + ''';
(async () => {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(challenge));
  const response = Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  await chrome.storage.local.set({response});
})();
''')
    return target


def targets(pipe):
    infos = pipe.call('Target.getTargets', timeout=CALL_TIMEOUT).get('targetInfos')
    require(isinstance(infos, list) and all(isinstance(i, dict) for i in infos), 'Target list shape')
    return infos


def extension_targets(pipe, identity):
    """Every listed target of the owned extension's origin, whatever its type."""
    origin = 'chrome-extension://' + identity + '/'
    return [i for i in targets(pipe) if type(i.get('url')) is str and i['url'].startswith(origin)]


def worker_target(infos, identity):
    """The unique expected worker's target id, or None while none is listed.

    Judged on one observation: several origin targets are ambiguous, and a single one must be
    the fixture's service worker at its exact URL.
    """
    if not infos:
        return None
    require(len(infos) == 1, 'Extension worker ambiguous')
    info = infos[0]
    require(info.get('type') == 'service_worker'
            and info.get('url') == 'chrome-extension://' + identity + '/' + WORKER_SCRIPT
            and valid(TARGET, info.get('targetId')), 'Extension worker identity mismatch')
    return info['targetId']


def registry(pipe, identity):
    """Installed-registry state of the owned id, as a fixed token. Listing content is never kept."""
    extensions = pipe.call('Extensions.getExtensions', timeout=CALL_TIMEOUT).get('extensions')
    require(isinstance(extensions, list)
            and all(isinstance(e, dict) and type(e.get('id')) is str for e in extensions),
            'Extension listing shape')
    owned = [e for e in extensions if e['id'] == identity]
    require(all(type(e.get('enabled')) is bool for e in owned), 'Extension listing shape')
    if not owned:
        return 'ABSENT'
    if len(owned) > 1:
        return 'DUPLICATE'
    return 'LISTED_ENABLED' if owned[0]['enabled'] else 'LISTED_DISABLED'


def startup(pipe, result, expected_version):
    result['cdp_stage'] = 'startup'
    version = pipe.call('Browser.getVersion', timeout=STARTUP_DEADLINE)
    product = PRODUCT.fullmatch(version.get('product')) if type(version.get('product')) is str else None
    require(product is not None and valid(PROTOCOL, version.get('protocolVersion')), 'Browser version shape')
    result.update(browser_version=product.group(1), protocol_version=version['protocolVersion'],
                  version_matches=product.group(1) == expected_version)
    require(result['version_matches'], 'Browser version mismatch')
    result['ready'] = True


def page(pipe, result):
    challenge = secrets.token_hex(24)
    result['cdp_stage'] = 'page-target'
    target = pipe.call('Target.createTarget', {'url': page_url(challenge)}).get('targetId')
    require(valid(TARGET, target), 'Target identity shape')
    result['cdp_stage'] = 'page-attach'
    session = pipe.call('Target.attachToTarget', {'targetId': target, 'flatten': True}).get('sessionId')
    require(valid(TARGET, session), 'Target session shape')
    result['cdp_stage'] = 'page-listed'
    owned = [i for i in targets(pipe) if i.get('targetId') == target]
    require(len(owned) == 1 and owned[0].get('type') == 'page', 'Owned page target not listed')
    result['cdp_stage'] = 'page-readiness'

    def ready():
        reply = pipe.call('Runtime.evaluate', {'expression': READY, 'returnByValue': True}, session,
                          timeout=CALL_TIMEOUT, scope='page')
        require('exceptionDetails' not in reply and isinstance(reply.get('result'), dict),
                'Page evaluation shape')
        state = reply['result'].get('value')
        require(isinstance(state, dict) and all(type(state.get(k)) is str
                                                for k in ('protocol', 'readyState', 'title')),
                'Page evaluation shape')
        if state['protocol'] != 'data:' or state['readyState'] != 'complete':
            return False
        require(state['title'] == challenge, 'Page challenge mismatch')
        return True
    poll(ready, PAGE_DEADLINE, 'Page readiness timeout')
    result['page_nonce'] = True
    return session


def extension(pipe, run, result, page_session=None):
    # Distinct from the page challenge. Only the worker computes the SHA-256 answer.
    challenge = secrets.token_hex(24)
    expected = hashlib.sha256(challenge.encode()).hexdigest()
    path = fixture(run, challenge)
    result['fixture'] = 'PROJECT_AUTHORED_NO_CAPTURE'
    result['cdp_stage'] = 'extension-load'
    identity = pipe.call('Extensions.loadUnpacked', {'path': str(path)}).get('id')
    require(valid(EXTENSION_ID, identity), 'Extension identity shape')
    result['extension_installed'] = True
    result['cdp_stage'] = 'extension-worker'
    found = []

    def worker():
        target = worker_target(extension_targets(pipe, identity), identity)
        found.append(target)
        return target is not None
    poll(worker, EXTENSION_DEADLINE, 'Extension worker not observed')
    observed = time.monotonic()
    result['extension_worker_observed'] = True
    # Required registry presence (browser scope): exactly one enabled entry for the owned id.
    result['cdp_stage'] = 'extension-listed'
    state = result['extension_registry_before'] = registry(pipe, identity)
    require(state in ('LISTED_ENABLED', 'LISTED_DISABLED'), 'Extension listing mismatch')
    require(state == 'LISTED_ENABLED', 'Extension not enabled')
    result['extension_registry_listed'] = True
    # Storage is target-scoped: attach the owned worker on the private pipe (browser scope).
    result['cdp_stage'] = 'extension-attach'
    session = pipe.call('Target.attachToTarget', {'targetId': found[-1], 'flatten': True}).get('sessionId')
    require(valid(TARGET, session) and session != page_session, 'Extension session shape')
    result['extension_session_attached'] = True
    result['cdp_stage'] = 'extension-computation'

    def computed():
        data = pipe.call('Extensions.getStorageItems', {'id': identity, 'storageArea': 'local',
                                                        'keys': ['response']}, session,
                         timeout=CALL_TIMEOUT, scope='extension-worker').get('data')
        require(isinstance(data, dict), 'Extension storage shape')
        if 'response' not in data:
            return False
        require(data['response'] == expected, 'Extension challenge mismatch')
        return True
    poll(computed, EXTENSION_DEADLINE, 'Extension execution timeout')
    result['extension_nonce'] = True
    # Release the harness's own attachment so it cannot keep the worker target alive.
    result['cdp_stage'] = 'extension-detach'
    pipe.call('Target.detachFromTarget', {'sessionId': session})
    result['cdp_stage'] = 'extension-uninstall'
    pipe.call('Extensions.uninstall', {'id': identity})
    result['extension_uninstall_replied'] = True
    # Required registry absence: successful, correctly shaped listings until the id is gone.
    # A disabled, idle or duplicated entry is still installed.
    result['cdp_stage'] = 'extension-registry-removal'

    def absent():
        result['extension_registry_after'] = registry(pipe, identity)
        return result['extension_registry_after'] == 'ABSENT'
    poll(absent, REMOVAL_DEADLINE, 'Extension registry retained')
    result['extension_registry_absent'] = True
    # Corroboration, still required: no target of the extension's origin remains.
    result['cdp_stage'] = 'extension-removal'
    poll(lambda: not extension_targets(pipe, identity), REMOVAL_DEADLINE, 'Extension removal incomplete')
    result['extension_worker_absent'] = True
    # Evidence only; a worker's idle stop also removes its target and never proves uninstall.
    result['extension_worker_to_absence_seconds'] = round(time.monotonic() - observed, 3)
    result['extension_unloaded'] = True


def close_normally(pipe, owner, result):
    """Requested close, reply or EOF, then authenticated owned exit 0 before any cleanup."""
    result['cdp_stage'] = 'close'
    owner.receive(0)
    require(owner.returncode is None, 'Workload exited before Browser.close')
    result['browser_close_requested'] = True
    try:
        pipe.call('Browser.close', timeout=CLOSE_DEADLINE)
        result['close_reply'] = True
    except CDPEOF:
        # EOF alone is never acceptance; the owned exit status below decides.
        result['close_reply'] = False
    owner.until(lambda: owner.returncode is not None, EXIT_DEADLINE)
    require(owner.returncode == 0, 'Unexpected normal browser exit')
    result['quit_observed'] = 'reply' if result['close_reply'] else 'qualified-eof'


def abnormal_wait(owner, result):
    """Deliberate bounded live timeout after complete useful work; settlement is the owner's."""
    result['cdp_stage'] = 'abnormal-wait'
    require(all(result.get(k) is True for k in USEFUL_FLAGS), 'Abnormal wait before useful work')
    try:
        owner.until(lambda: False, ABNORMAL_WAIT)
    except Exception as error:
        require(str(error) == 'Owned workload timeout', 'Unexpected abnormal failure')
        require(owner.returncode is None, 'Workload exited before intended timeout')
        result['intended_timeout'] = True


def exercise(pipe, owner, run, result, workload='full', abnormal=False, expected_version=None):
    """Progressive; any failure leaves the facts reached so far and pipe.methods intact."""
    result['browser_close_requested'] = False
    startup(pipe, result, expected_version)
    page_session = None
    if workload in ('page', 'full'):
        page_session = page(pipe, result)
    if workload == 'full':
        extension(pipe, run, result, page_session)
    result['cdp_stage'] = 'work-complete'
    if abnormal:
        abnormal_wait(owner, result)
    else:
        close_normally(pipe, owner, result)


def observe_exit_after_eof(owner, error, result):
    """Failure evidence only: a bounded exit-status read after EOF. Never masks the failure."""
    if not isinstance(error, CDPEOF) or owner.returncode is not None:
        return
    try:
        owner.until(lambda: owner.returncode is not None, EOF_EXIT_OBSERVATION)
        result['eof_exit_observation'] = 'EXITED'
    except Exception:
        result['eof_exit_observation'] = 'NOT_OBSERVED'


def collapsed(methods):
    sequence = []
    for entry in methods:
        name = entry.get('method') if isinstance(entry, dict) else None
        if not sequence or sequence[-1] != name:
            sequence.append(name)
    return tuple(sequence)


def expected_sequence(workload, abnormal):
    base = {'empty': STARTUP_SEQUENCE, 'page': PAGE_SEQUENCE, 'full': FULL_SEQUENCE}[workload]
    return base if abnormal else base + ('Browser.close',)


def close_count(methods):
    """Browser.close entries before collapsing, so a duplicate close is visible."""
    return sum(1 for m in methods if isinstance(m, dict) and m.get('method') == 'Browser.close')


def entry_passed(entry):
    """A passed, required, known call carrying exactly its method's scope label."""
    return (isinstance(entry, dict) and entry.get('method') in METHODS and entry.get('outcome') == 'passed'
            and 'optional' not in entry
            and ('scope' in entry) == (entry['method'] in SESSION_SCOPES)
            and entry.get('scope') == SESSION_SCOPES.get(entry['method']))


def protocol_passed(methods, qualified_close=False):
    """Every call passed. Nothing is optional.

    qualified_close is the host's decision, from independent exit and settlement facts, that
    the sole final Browser.close answered by EOF qualifies. It admits only that exact last
    record; every earlier entry must still have passed.
    """
    methods = list(methods)
    if not methods:
        return False
    if qualified_close:
        return methods[-1] == QUALIFIED_CLOSE_ENTRY and all(entry_passed(m) for m in methods[:-1])
    return all(entry_passed(m) for m in methods)
