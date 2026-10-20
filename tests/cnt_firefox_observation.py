"""Bounded socket observation, never signal authority or continuous proof.

One observation pass is several separate lsof/ps reads, so it is not atomic.
Every endpoint seen in any scan must first belong to the authenticated workload
on the expected loopback address. Only after that may a difference between the
group scan and the selected-port scan be classified as a self-owned transition.
Equality alone never authorizes a connection.
"""
import os
import subprocess
import time

from cnt_native_evidence import VerificationError, require
from cnt_owned_process import escaped_count, group_rows, observe_child

# Extra full passes are allowed only before connect, and only for a self-owned transition.
MAX_PASSES = 3
MODES = ('strict', 'startup', 'pre-connect')

# Fixed, code-owned messages mapped to fixed codes. Nothing else is exported.
FAILURE_CODES = {
    'Firefox supervisor unavailable': 'SUPERVISOR_UNAVAILABLE',
    'Firefox supervisor identity lost': 'SUPERVISOR_IDENTITY_LOST',
    'Firefox observed marker escape': 'MARKER_ESCAPE',
    'Firefox socket observation failed': 'OBSERVATION_API_ERROR',
    'Firefox invalid socket owner': 'OBSERVATION_INVALID',
    'Firefox socket owner missing': 'OBSERVATION_INVALID',
    'Firefox ambiguous socket': 'OBSERVATION_INVALID',
    'Firefox incomplete socket observation': 'OBSERVATION_INVALID',
    'Firefox unexpected UDP socket': 'UDP_SOCKET',
    'Firefox workload not a live group member': 'WORKLOAD_NOT_LIVE_MEMBER',
    'Firefox unexpected listener owner': 'GROUP_LISTENER_FOREIGN_OWNER',
    'Firefox listener on non-workload member': 'GROUP_LISTENER_NON_WORKLOAD_MEMBER',
    'Firefox unexpected listener address': 'GROUP_LISTENER_WRONG_ADDRESS',
    'Firefox listener identity changed': 'LISTENER_GROUP_CHANGED',
    'Firefox automation port collision': 'SELECTED_PORT_FOREIGN_LISTENER',
    'Firefox selected-port non-workload member': 'SELECTED_PORT_NON_WORKLOAD_MEMBER',
    'Firefox selected-port listener address': 'SELECTED_PORT_WRONG_ADDRESS',
    'Firefox listener observation unresolved': 'UNRESOLVED_OWNED_TRANSITION',
    'Firefox listener resolution deadline': 'OWNED_TRANSITION_DEADLINE',
    'Firefox owned listener changed after readiness': 'OWNED_LISTENER_CHANGED',
    'Firefox owned listener missing': 'OWNED_LISTENER_MISSING',
    'Firefox identity previously lost': 'IDENTITY_PREVIOUSLY_LOST',
    'Firefox exited before listener': 'WORKLOAD_EXITED_BEFORE_LISTENER',
    'Firefox listener mode invalid': 'OBSERVATION_MODE_INVALID',
}
_COUNTS = ('passes', 'group_members', 'group_tcp', 'group_udp', 'selected_port_tcp')
_CLASSES = ('owned_expected', 'workload_not_live', 'foreign_owner', 'non_workload_member', 'wrong_address')
_PARSE_STEPS = ('group-members', 'marker-escape')
_VALIDATION_STEPS = ('group-tcp-validation', 'selected-port-validation')
# Cleared at the start of every pass so a failed pass never reports an earlier pass's facts.
_PASS_KEYS = ('step', 'group_members', 'group_tcp', 'group_udp', 'group_tcp_classes',
              'selected_port_tcp', 'selected_port_classes', 'transition')


def socket_records(raw):
    records, pid, current = [], None, None
    for line in raw.splitlines():
        if line.startswith('p'):
            require(line[1:].isdigit(), 'Firefox invalid socket owner')
            pid = int(line[1:])
            current = None
        elif line.startswith('f'):
            require(pid is not None, 'Firefox socket owner missing')
            current = {'pid': pid}
            records.append(current)
        elif line.startswith('n'):
            require(current is not None and 'address' not in current, 'Firefox ambiguous socket')
            current['address'] = line[1:]
    require(all('address' in r for r in records), 'Firefox incomplete socket observation')
    return records


def inspect_sockets(selectors):
    result = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', *selectors, '-Fpf n'.replace(' ', '')],
                            capture_output=True, text=True, timeout=3)
    require(not result.stderr and (result.returncode == 0 or
            (result.returncode == 1 and not result.stdout)), 'Firefox socket observation failed')
    return socket_records(result.stdout)


def _classes(records, owner, members, expected):
    counts = dict.fromkeys(_CLASSES, 0)
    for record in records:
        if record['pid'] == owner.workload_pid and record['pid'] not in members:
            counts['workload_not_live'] += 1
        elif record['pid'] not in members:
            counts['foreign_owner'] += 1
        elif record['pid'] != owner.workload_pid:
            counts['non_workload_member'] += 1
        elif record['address'] not in expected:
            counts['wrong_address'] += 1
        else:
            counts['owned_expected'] += 1
    return counts


def observe(owner, port, trace):
    """One validated pass. Raises at the first foreign or invalid fact; `trace` keeps progress."""
    group = owner.process.pid
    expected = {'127.0.0.1:' + str(port), '[::1]:' + str(port)}
    for key in _PASS_KEYS:
        trace.pop(key, None)
    trace['step'] = 'supervisor'
    require(observe_child(group) is None, 'Firefox supervisor unavailable')
    trace['step'] = 'group-members'
    members = {pid for pid, state in group_rows(group) if not state.startswith('Z')}
    trace['group_members'] = len(members)
    trace['step'] = 'marker-escape'
    require(not escaped_count(owner.run, group), 'Firefox observed marker escape')
    trace['step'] = 'group-tcp'
    tcp = inspect_sockets(['-g', str(group), '-iTCP', '-sTCP:LISTEN'])
    trace['group_tcp'] = len(tcp)
    trace['step'] = 'group-udp'
    udp = inspect_sockets(['-g', str(group), '-iUDP'])
    trace['group_udp'] = len(udp)
    require(not udp, 'Firefox unexpected UDP socket')
    trace['step'] = 'group-tcp-validation'
    trace['group_tcp_classes'] = _classes(tcp, owner, members, expected)
    for record in tcp:
        require(record['pid'] != owner.workload_pid or record['pid'] in members,
                'Firefox workload not a live group member')
        require(record['pid'] in members, 'Firefox unexpected listener owner')
        require(record['pid'] == owner.workload_pid, 'Firefox listener on non-workload member')
        require(record['address'] in expected, 'Firefox unexpected listener address')
        require(os.getpgid(record['pid']) == group, 'Firefox listener identity changed')
    # A collision is an observation failure, never permission to connect to it.
    trace['step'] = 'selected-port-tcp'
    selected = inspect_sockets(['-iTCP:' + str(port), '-sTCP:LISTEN'])
    trace['selected_port_tcp'] = len(selected)
    trace['step'] = 'selected-port-validation'
    trace['selected_port_classes'] = _classes(selected, owner, members, expected)
    for record in selected:
        require(record['pid'] != owner.workload_pid or record['pid'] in members,
                'Firefox workload not a live group member')
        require(record['pid'] in members, 'Firefox automation port collision')
        require(record['pid'] == owner.workload_pid, 'Firefox selected-port non-workload member')
        require(record['address'] in expected, 'Firefox selected-port listener address')
        require(os.getpgid(record['pid']) == group, 'Firefox listener identity changed')
    trace['step'] = 'consistency'
    # Every record in both scans is now the workload's expected loopback endpoint.
    group_set = sorted((r['pid'], r['address']) for r in tcp)
    selected_set = sorted((r['pid'], r['address']) for r in selected)
    if group_set == selected_set:
        transition = None
    elif set(group_set) < set(selected_set):
        transition = 'appeared'
    elif set(selected_set) < set(group_set):
        transition = 'disappeared'
    else:
        transition = 'changed'
    trace['transition'] = transition
    trace['step'] = 'supervisor-final'
    require(observe_child(group) is None, 'Firefox supervisor identity lost')
    trace['step'] = 'complete'
    return {'tcp_listeners': [r['address'] for r in tcp], 'selected_port_listener_count': len(selected),
            'udp_sockets': 0, 'observed_group_members': len(members), 'owned': True,
            'coherent': transition is None, 'transition': transition,
            'workload_member': owner.workload_pid in members}


def listener_owned(owner, port, required=True, *, mode='strict', deadline=None, trace=None):
    """strict: any transition fails. startup (optional only): an owned transition is
    returned, not accepted as readiness. pre-connect: bounded full resamples until
    one coherent owned pass, under the caller's existing startup deadline."""
    trace = trace if trace is not None else {}
    trace.update(mode=mode, passes=0)
    require(mode in MODES and (mode != 'startup' or not required)
            and (mode != 'pre-connect' or type(deadline) in (int, float)), 'Firefox listener mode invalid')
    while True:
        trace['passes'] += 1
        record = observe(owner, port, trace)
        if record['coherent'] or mode == 'startup':
            break
        trace['step'] = 'transition'
        require(mode == 'pre-connect', 'Firefox owned listener changed after readiness')
        require(trace['passes'] < MAX_PASSES, 'Firefox listener observation unresolved')
        require(time.monotonic() < deadline, 'Firefox listener resolution deadline')
        owner.receive(.05)
        require(owner.returncode is None and not owner.eof, 'Firefox exited before listener')
    trace['step'] = 'required-listener'
    require(not required or (record['tcp_listeners'] and record['workload_member']),
            'Firefox owned listener missing')
    trace['step'] = 'complete'
    record['passes'] = trace['passes']
    del record['workload_member']
    return record


def failure_observation(stage, trace, error):
    """Partial fixed facts about a failed pass: codes, steps and counts only.

    Never exception text, addresses, ports, PIDs or paths. Must not raise.
    """
    trace = trace if isinstance(trace, dict) else {}
    message = None
    if isinstance(error, VerificationError):
        try:
            message = str(error)
        except Exception:
            message = None
    step = trace.get('step')
    if message in FAILURE_CODES:
        code = FAILURE_CODES[message]
    elif isinstance(error, ProcessLookupError) and step in _VALIDATION_STEPS:
        # The listening process disappeared between lsof and getpgid: ownership lost, not an API fault.
        code = 'LISTENER_OWNER_VANISHED'
    elif isinstance(error, (OSError, subprocess.SubprocessError)):
        code = 'OBSERVATION_API_ERROR'
    elif isinstance(error, ValueError) and step in _PARSE_STEPS:
        code = 'OBSERVATION_INVALID'
    elif isinstance(error, KeyboardInterrupt):
        code = 'INTERRUPTED'
    else:
        code = 'UNKNOWN'
    record = {'stage': stage if isinstance(stage, str) else 'UNKNOWN', 'partial': True, 'code': code,
              'error_type': type(error).__name__,
              'step': step if isinstance(step, str) else None,
              'mode': trace.get('mode') if trace.get('mode') in MODES else None,
              'transition': trace.get('transition')
              if trace.get('transition') in ('appeared', 'disappeared', 'changed') else None}
    for key in _COUNTS:
        value = trace.get(key)
        record[key] = value if type(value) is int else None
    for key in ('group_tcp_classes', 'selected_port_classes'):
        value = trace.get(key)
        record[key] = ({k: value[k] for k in _CLASSES if type(value.get(k)) is int}
                       if isinstance(value, dict) else None)
    return record


def record_sample(outcomes, stage, owner, port, required=True, *, observer=None, **options):
    """Append a successful sample; on any failure keep the first failure observation, then re-raise."""
    observer = observer or listener_owned
    trace = {}
    try:
        record = observer(owner, port, required, trace=trace, **options)
    except BaseException as error:
        try:
            observed = failure_observation(stage, trace, error)
        except Exception:
            observed = {'stage': 'UNKNOWN', 'partial': True, 'code': 'FAILURE_OBSERVATION_UNAVAILABLE'}
        outcomes.setdefault('listener_failure', observed)
        raise
    record = dict(record, stage=stage, monotonic=time.monotonic())
    outcomes.setdefault('listener_samples', []).append(record)
    if record.get('coherent') is False:
        outcomes['listener_transients'] = outcomes.get('listener_transients', 0) + 1
    return record


class ObservedClient:
    """Fail-closed command gate; a failed sample permanently invalidates it."""
    def __init__(self, client, owner, port, outcomes):
        self.client, self.owner, self.port, self.outcomes = client, owner, port, outcomes
        self.valid = True
        self.connection, self.methods = client.connection, client.methods

    def sample(self, stage, required=True):
        require(self.valid, 'Firefox identity previously lost')
        try:
            # Strict: after readiness, no transition is resampled or tolerated.
            record_sample(self.outcomes, stage, self.owner, self.port, required)
        except BaseException:
            self.valid = False
            self.outcomes.setdefault('listener_samples', []).append(
                {'stage': stage, 'monotonic': time.monotonic(), 'owned': False})
            raise

    def greeting(self):
        self.sample('before-greeting')
        result = self.client.greeting()
        self.sample('after-greeting')
        return result

    def call(self, method, *args, **kwargs):
        self.sample('before-' + method)
        result = self.client.call(method, *args, **kwargs)
        if method != 'Marionette:Quit':
            self.sample('after-' + method)
        return result
