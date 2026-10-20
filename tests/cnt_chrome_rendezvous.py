"""R5-CHROME-C1A: own-workload-PID rendezvous parameter. Chrome lane only, default off.

As a module it supplies the one exact Seatbelt rule and the parent-side comparison. As an
exec entrypoint it is the last unconfined step before sandbox-exec:

    python -B -I cnt_chrome_rendezvous.py <evidence-dir> <canary|browser> -- \
        /usr/bin/sandbox-exec -f <abs>/confinement.sb <abs program> ...

It takes the parameter from its own os.getpid() immediately before execv. Every step of
supervisor Popen -> cnt_pipe_exec (CDP descriptors only) -> this helper -> sandbox-exec ->
program is an exec, so that number is the supervisor-authenticated workload PID if and only
if sandbox-exec also execs in place (host-unobserved; see the C1A candidate document).
There is no caller, environment, parent-PID or process-listing source for the number, and
no fallback: any refusal writes a fixed code and exits without exec.

The rule narrows which name may be registered or looked up. It does not isolate the
per-user bootstrap namespace, and every process inheriting the policy may use that name.
Imports only the standard library so the exec path loads no project module.
"""
import hashlib
import json
import os
import re
import stat
import sys

PARAMETER = 'CHROME_RENDEZVOUS_PID'
SERVICE_PREFIX = 'com.google.Chrome.MachPortRendezvousServer.'
# One exact global name. The PID arrives only through the named parameter; the policy file
# itself carries no number, so its bytes are identical for every launch.
RULE = ('(allow mach-register mach-lookup (global-name (string-append '
        + json.dumps(SERVICE_PREFIX) + ' (param ' + json.dumps(PARAMETER) + '))))\n')
RESIDUAL = ('Exact own-workload-PID name only; narrows the name, not the per-user bootstrap namespace, '
            'and not the process: every process inheriting the policy (Chrome helpers including '
            'chrome_crashpad_handler) may register or look up that name. The parameter is fixed for the '
            'inherited policy lifetime; after exit an unrelated process may reuse the PID. Not exercised.')
SANDBOX_EXEC = '/usr/bin/sandbox-exec'
LABELS = ('canary', 'browser')
CHROME_TAIL = ('Google Chrome.app', 'Contents', 'MacOS', 'Google Chrome')
CHROME_APP_PARTS = ('Applications', *CHROME_TAIL)
STORE = '/nix/store'
PLACEHOLDER = '<RENDEZVOUS_PID>'
SCHEMA = 'bux-r5-chrome-rendezvous-v1'
RECORD_LIMIT = 4096
PID_TEXT = re.compile(r'[1-9][0-9]{0,9}')
# Fixed helper refusal codes; the parent exports nothing else from a refusal line.
REFUSALS = ('USAGE', 'EVIDENCE_DIRECTORY', 'RECORD_PRESENT', 'LABEL', 'ARGV_SHAPE', 'PROGRAM',
            'INJECTED_PARAMETER', 'INVALID_PARAMETER')
STATES = ('MATCHED_WORKLOAD', 'PID_MISMATCH', 'INVALID_PARAMETER', 'HELPER_REFUSED', 'EXEC_FAILED',
          'RECORD_ABSENT', 'RECORD_INVALID', 'ARGV_MISMATCH', 'WORKLOAD_UNOBSERVED', 'SANDBOXED_PID_UNOBSERVED')
MATCHED = 'MATCHED_WORKLOAD'
HELPER = os.path.abspath(__file__)


class Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def record_name(label):
    return 'rendezvous-' + label + '.json'


def chrome_program(path):
    """The bound Google Chrome.app executable inside a store closure root, by layout only."""
    parts = tuple(str(path).split('/'))
    return (str(path).startswith(STORE + '/') and len(parts) == len(STORE.split('/')) + 1 + len(CHROME_APP_PARTS)
            and parts[-len(CHROME_APP_PARTS):] == CHROME_APP_PARTS)


def wrap(evidence, label, sandboxed):
    """Launch argv for the supervisor: this helper, then the unchanged sandbox-exec command.

    -I: the helper runs unconfined with HOME inside the writable run, so it ignores PYTHON*
    variables, user site-packages and its own directory; it needs only the standard library.
    """
    return [sys.executable, '-B', '-I', HELPER, str(evidence), label, '--', *sandboxed]


def expected_argv(sandboxed):
    """Final argv the helper must exec, with the number replaced by a fixed placeholder."""
    return [SANDBOX_EXEC, '-D', PARAMETER + '=' + PLACEHOLDER, *sandboxed[1:]]


def argv_template_sha256(argv):
    return hashlib.sha256(json.dumps(list(argv), separators=(',', ':')).encode()).hexdigest()


def valid_pid(pid):
    return type(pid) is int and 1 < pid < 2 ** 31 and PID_TEXT.fullmatch(str(pid)) is not None


def evidence_directory(path):
    """Absolute, link-free, private, owned by this user; the confined program cannot write it."""
    if type(path) is not str or not os.path.isabs(path) or os.path.realpath(path) != path:
        raise Refused('EVIDENCE_DIRECTORY')
    try:
        info = os.lstat(path)
    except OSError:
        raise Refused('EVIDENCE_DIRECTORY') from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused('EVIDENCE_DIRECTORY')
    return path


def validate(label, command, environ):
    if label not in LABELS:
        raise Refused('LABEL')
    if (len(command) < 4 or command[0] != SANDBOX_EXEC or command[1] != '-f'
            or not all(type(a) is str for a in command)
            or not os.path.isabs(command[2]) or os.path.basename(command[2]) != 'confinement.sb'
            or not os.path.isabs(command[3])):
        raise Refused('ARGV_SHAPE')
    # Browser authority only for the bound Chrome executable; the canary may never run it.
    if (label == 'browser') != chrome_program(command[3]) or (label == 'canary' and 'Google Chrome' in command[3]):
        raise Refused('PROGRAM')
    if (PARAMETER in environ or any(a in ('-D', '-p', '-n') or a.startswith('-D') or PARAMETER in a
                                    or 'MachPortRendezvousServer' in a for a in command)):
        raise Refused('INJECTED_PARAMETER')


def write_line(evidence, label, value, create):
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_CREAT | os.O_EXCL if create else os.O_APPEND)
    directory = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            descriptor = os.open(record_name(label), flags, 0o600, dir_fd=directory)
        except FileExistsError:
            raise Refused('RECORD_PRESENT') from None
    finally:
        os.close(directory)
    try:
        os.write(descriptor, (json.dumps(value, sort_keys=True) + '\n').encode())
    finally:
        os.close(descriptor)


def main(argv, environ, getpid=os.getpid, execv=os.execv):
    """Returns only on refusal or exec failure. Never calls getppid."""
    evidence = None
    label = argv[1] if len(argv) > 1 else None
    try:
        if len(argv) < 4 or argv[2] != '--':
            raise Refused('USAGE')
        evidence = evidence_directory(argv[0])
        command = list(argv[3:])
        validate(label, command, environ)
        pid = getpid()
        if not valid_pid(pid):
            raise Refused('INVALID_PARAMETER')
        final = [SANDBOX_EXEC, '-D', PARAMETER + '=' + str(pid), *command[1:]]
        # Closed before exec. The salt keeps the exported record digest from revealing the PID.
        write_line(evidence, label, {'schema': SCHEMA, 'label': label, 'state': 'EXEC', 'pid': pid,
                                     'salt': os.urandom(16).hex(),
                                     'argv_template_sha256': argv_template_sha256(expected_argv(command))}, True)
    except Refused as refusal:
        if evidence is not None and label in LABELS and refusal.code != 'RECORD_PRESENT':
            try:
                write_line(evidence, label, {'schema': SCHEMA, 'label': label, 'state': 'REFUSED',
                                             'code': refusal.code}, True)
            except (OSError, Refused):
                pass
        return 125
    try:
        execv(SANDBOX_EXEC, final)
    except OSError as error:
        try:
            write_line(evidence, label, {'schema': SCHEMA, 'label': label, 'state': 'EXEC_FAILED',
                                         'errno': error.errno if type(error.errno) is int else None}, False)
        except (OSError, Refused):
            pass
        return 127
    return 127


def read_private(path, limit=RECORD_LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Rendezvous record refused')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Oversized rendezvous record')
    return raw


def observation(state, **facts):
    base = {'state': state, 'workload_pid_matches': None, 'argv_template_matches': None,
            'sandboxed_pid_matches': None, 'record_sha256': None, 'helper_code': None, 'exec_errno': None}
    base.update(facts)
    return base


def observe(evidence, label, workload_pid, sandboxed, sandboxed_pid_path=None):
    """Fixed keys only. Never a raw PID, service name, path or argv. Missing is never a match.

    The canary label also requires the confined program's own getpid() report to equal the
    helper's number; without that report the canary is SANDBOXED_PID_UNOBSERVED.
    """
    if label not in LABELS or (label == 'canary') != (sandboxed_pid_path is not None):
        raise ValueError('Rendezvous observation label')
    try:
        raw = read_private(os.path.join(str(evidence), record_name(label)))
    except FileNotFoundError:
        return observation('RECORD_ABSENT')
    except (OSError, ValueError):
        return observation('RECORD_INVALID')
    digest = hashlib.sha256(raw).hexdigest()
    try:
        lines = [json.loads(line) for line in raw.decode().splitlines()]
    except ValueError:
        return observation('RECORD_INVALID', record_sha256=digest)
    if (not 1 <= len(lines) <= 2 or not all(isinstance(v, dict) and v.get('schema') == SCHEMA
                                            and v.get('label') == label for v in lines)):
        return observation('RECORD_INVALID', record_sha256=digest)
    first = lines[0]
    if first.get('state') == 'REFUSED' and len(lines) == 1:
        code = first.get('code') if first.get('code') in REFUSALS else None
        return observation('INVALID_PARAMETER' if code == 'INVALID_PARAMETER' else 'HELPER_REFUSED',
                           record_sha256=digest, helper_code=code)
    if first.get('state') != 'EXEC' or not valid_pid(first.get('pid')) \
            or type(first.get('argv_template_sha256')) is not str:
        return observation('RECORD_INVALID', record_sha256=digest)
    if len(lines) == 2:
        if lines[1].get('state') != 'EXEC_FAILED':
            return observation('RECORD_INVALID', record_sha256=digest)
        number = lines[1].get('errno')
        return observation('EXEC_FAILED', record_sha256=digest,
                           exec_errno=number if type(number) is int else None)
    argv_matches = first['argv_template_sha256'] == argv_template_sha256(expected_argv(list(sandboxed)))
    if type(workload_pid) is not int or type(workload_pid) is bool:
        return observation('WORKLOAD_UNOBSERVED', argv_template_matches=argv_matches, record_sha256=digest)
    pid_matches = first['pid'] == workload_pid
    facts = dict(workload_pid_matches=pid_matches, argv_template_matches=argv_matches, record_sha256=digest)
    if not argv_matches:
        return observation('ARGV_MISMATCH', **facts)
    if not pid_matches:
        return observation('PID_MISMATCH', **facts)
    if label == 'canary':
        try:
            reported = json.loads(read_private(sandboxed_pid_path, 256))
        except (OSError, ValueError):
            return observation('SANDBOXED_PID_UNOBSERVED', **facts)
        own = reported.get('pid') if isinstance(reported, dict) and set(reported) == {'pid'} else None
        if not valid_pid(own):
            return observation('SANDBOXED_PID_UNOBSERVED', **facts)
        facts['sandboxed_pid_matches'] = own == first['pid']
        if not facts['sandboxed_pid_matches']:
            return observation('PID_MISMATCH', **facts)
    return observation(MATCHED, **facts)


def project(value):
    """Re-validated fixed-key export of an observation; anything unexpected becomes None."""
    if not isinstance(value, dict):
        return None
    digest = value.get('record_sha256')
    return {'state': value.get('state') if value.get('state') in STATES else 'UNCLASSIFIED',
            **{k: value.get(k) if type(value.get(k)) is bool else None
               for k in ('workload_pid_matches', 'argv_template_matches', 'sandboxed_pid_matches')},
            'record_sha256': digest if type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) else None,
            'helper_code': value.get('helper_code') if value.get('helper_code') in REFUSALS else None,
            'exec_errno': value.get('exec_errno') if type(value.get('exec_errno')) is int else None}


def matched(value, canary=False):
    return (isinstance(value, dict) and value.get('state') == MATCHED and value.get('workload_pid_matches') is True
            and value.get('argv_template_matches') is True
            and (value.get('sandboxed_pid_matches') is True if canary else value.get('sandboxed_pid_matches') is None))


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:], os.environ))
