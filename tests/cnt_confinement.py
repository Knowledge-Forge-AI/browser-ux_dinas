"""Dispatch-only deny-default boundary. No captured code in qualification probes.

No permission here establishes native characterization. Credential IPC is denied
by policy, never probed by calling Security.framework or a user's Keychain.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from cnt_native_evidence import require

SCRATCH = Path('/Users/Shared/agent-scratch/r')
CREDENTIAL_SERVICES = ('com.apple.securityd', 'com.apple.SecurityServer',
                       'com.apple.secd', 'com.apple.trustd', 'com.apple.trustd.agent')
REVIEWED_SERVICES = ('com.apple.windowserver.active', 'com.apple.coreservices.launchservicesd')
# R4-CONT7 trusted-synthetic compatibility selection only: SystemConfiguration's
# Dynamic Store server (Apple SCD_SERVER). Explicit, Firefox-lane only, never default.
CONFIGD = 'com.apple.SystemConfiguration.configd'
CONFIGD_RULE = '(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))\n'
CONFIGD_RESIDUAL = ('Mach lookup grant, not read-only message filtering; the service can expose system '
                    'network configuration/metadata and broker operations. Semantic read-only use is '
                    'trusted-synthetic procedure, not OS-enforced.')


def fresh_attempt(path, on_created=None):
    path = Path(path).absolute()
    require(path.is_relative_to(SCRATCH), 'Attempt must be under managed scratch')
    require(path.parent.resolve() == path.parent, 'Symlink scratch ancestor')
    path.mkdir(mode=0o700, exist_ok=False)
    if on_created is not None:
        on_created(path)
    for name in ('home', 'profile', 'tmp', 'downloads', 'crash-data'):
        (path / name).mkdir(mode=0o700)
    return path


def environment(run):
    return {'HOME': str(run / 'home'), 'CFFIXED_USER_HOME': str(run / 'home'),
            'TMPDIR': str(run / 'tmp'), 'TMP': str(run / 'tmp'),
            'TEMP': str(run / 'tmp'), 'PATH': '/usr/bin:/bin',
            'LANG': 'en_US.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}


def valid_port(port):
    require(type(port) is int and 0 < port < 65536, 'Invalid automation port')
    return port


def policy(run, runtimes, services=(), automation_port=None, *, firefox_child_ipc=False,
           firefox_executable=None, chrome_rendezvous=False, chrome_executable=None):
    """No broad Mach lookup, network, home reads, sandbox disables, or imports."""
    require(run.resolve() == run and run.is_relative_to(SCRATCH), 'Unsafe run')
    roots = tuple(Path(p) for p in runtimes)
    require(bool(roots), 'Runtime closure required')
    for root in roots:
        require((root.parent == Path('/nix/store') or root in (run / 'runtime', run / 'runtime/Firefox.app'))
                and root.is_dir(), 'Immutable or owned frozen runtime root required')
    services = tuple(services)
    require(all(type(n) is str for n in services)
            and set(services) <= {*REVIEWED_SERVICES, CONFIGD}, 'Unreviewed service')
    # Exact string equality only. The rule is emitted once, outside the {mach} join,
    # so selection position never changes bytes and absence leaves them identical.
    configd = services.count(CONFIGD)
    require(configd <= 1, 'Duplicate configd selection')
    require(not configd or firefox_child_ipc is True,
            'configd compatibility requires the validated frozen Firefox lane')
    automation = (f'(allow network-bind network-inbound (local ip "localhost:{valid_port(automation_port)}"))\n'
                  if automation_port is not None else '')
    # Firefox's installed XUL uses org.mozilla.machname.<random integer> for
    # parent/child bootstrap, before the child's own sandbox is applied. This
    # application-specific namespace is not attempt-exclusive; trusted fixtures
    # only. Credential and general Mach lookup remain denied.
    if firefox_child_ipc:
        require(firefox_executable == run / 'runtime/Firefox.app/Contents/MacOS/firefox'
                and run / 'runtime/Firefox.app' in roots,
                'Firefox child IPC requires the validated frozen Firefox.app executable')
    firefox_ipc = ('(allow mach-register mach-lookup (global-name-regex #"^org[.]mozilla[.]machname[.][0-9]+$"))\n'
                   if firefox_child_ipc else '')
    rendezvous = chrome_rendezvous_rule(run, roots, services, automation_port, firefox_child_ipc,
                                        chrome_rendezvous, chrome_executable)
    mach = ''.join('(allow mach-lookup (global-name ' + json.dumps(n) + '))\n'
                   for n in services if n != CONFIGD)
    compatibility = CONFIGD_RULE if configd else ''
    scope = ' '.join('(subpath ' + json.dumps(str(p)) + ')' for p in roots)
    owned = '(subpath ' + json.dumps(str(run)) + ')'
    deny_credentials = ' '.join('(global-name ' + json.dumps(n) + ')' for n in CREDENTIAL_SERVICES)
    return f'''(version 1)
(deny default)
(allow process-fork)
(allow process-exec {scope})
(allow file-read-metadata)
(allow file-read* (literal "/") (subpath "/System") (subpath "/usr/lib")
 (subpath "/private/var/db/dyld") (literal "/dev/urandom") (literal "/dev/random")
 (literal "/dev/null") {scope} {owned})
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") {scope})
(allow file-write* {owned} (literal "/dev/null"))
(deny file-write* (subpath {json.dumps(str(run / 'runtime'))}))
(allow sysctl-read)
(deny network*)
(allow network-bind network-inbound network-outbound {owned})
(deny mach-lookup {deny_credentials})
{mach}{compatibility}{firefox_ipc}{automation}{rendezvous}'''


def chrome_rendezvous_rule(run, roots, services, automation_port, firefox_child_ipc, selected, executable):
    """R5-CHROME-C1A: the one exact own-workload-PID rule, or ''. Chrome lane only, default off.

    Appended after every other rule so that absence leaves the policy bytes unchanged.
    """
    require(type(selected) is bool, 'Chrome rendezvous option invalid')
    if not selected:
        require(executable is None, 'Chrome rendezvous requires the selected Chrome lane')
        return ''
    # Lazy: Firefox and default Chrome policies gain no import.
    from cnt_chrome_rendezvous import RULE, chrome_program
    require(firefox_child_ipc is False and automation_port is None and CONFIGD not in services
            and isinstance(executable, Path) and chrome_program(executable) and executable.parents[4] in roots,
            'Chrome rendezvous requires the selected Chrome lane')
    return RULE


def without_rendezvous(normalized):
    """The template with exactly one trailing rendezvous rule removed, else None (never a match)."""
    from cnt_chrome_rendezvous import RULE
    if normalized.count(RULE) == 1 and normalized.endswith(RULE):
        return normalized[:-len(RULE)]
    return None


def policy_evidence(profile, run, port, firefox_child_ipc, services=(), *, chrome_rendezvous=False):
    normalized = profile.replace(str(run / 'runtime/Firefox.app'), '<BUNDLE>').replace(str(run), '<RUN>')
    if port is not None:
        normalized = normalized.replace('localhost:' + str(port), 'localhost:<PORT>')
    configd = CONFIGD in services
    # Template with the one compatibility rule removed: the one-factor comparison key.
    base = normalized.replace(CONFIGD_RULE, '', 1) if configd else normalized
    return {'policy_sha256': hashlib.sha256(profile.encode()).hexdigest(),
            'policy_template_sha256': hashlib.sha256(normalized.encode()).hexdigest(),
            'policy_template_without_configd_sha256': hashlib.sha256(base.encode()).hexdigest(),
            'mach_services': list(services),
            'configd_compatibility': configd,
            'configd_lookup': 'POLICY_ALLOWED_NOT_EXERCISED' if configd else 'NOT_SELECTED',
            'configd_residual': CONFIGD_RESIDUAL if configd else None,
            'firefox_child_ipc': firefox_child_ipc,
            'firefox_child_ipc_scope': '^org[.]mozilla[.]machname[.][0-9]+$' if firefox_child_ipc else None,
            'mach_canary': 'NOT_EXERCISED',
            'ipc_residual': 'Potential cross-instance global-name lookup; not an OS own-instance boundary.',
            **(rendezvous_evidence(normalized) if chrome_rendezvous is True else {})}


def rendezvous_evidence(normalized):
    from cnt_chrome_rendezvous import PARAMETER, RESIDUAL, RULE
    base = without_rendezvous(normalized)
    return {'chrome_rendezvous': 'OWN_WORKLOAD_PID', 'rendezvous_parameter': PARAMETER,
            'rendezvous_rule_sha256': hashlib.sha256(RULE.encode()).hexdigest(),
            'policy_template_without_rendezvous_sha256':
                hashlib.sha256(base.encode()).hexdigest() if base is not None else None,
            'rendezvous_lookup_register': 'POLICY_ALLOWED_NOT_EXERCISED', 'rendezvous_residual': RESIDUAL}


CANARY_PID = ("import json as _json,os as _os,sys as _sys\n"
              "if len(_sys.argv)==4:\n"
              "    _fd=_os.open('canary-pid.json',_os.O_WRONLY|_os.O_CREAT|_os.O_EXCL|_os.O_NOFOLLOW,0o600)\n"
              "    _os.write(_fd,_json.dumps({'pid':_os.getpid()}).encode()); _os.close(_fd)\n")


def settle(process, known=None):
    """Refuse the historical PID API, including optimized Python."""
    from cnt_owned_process import OwnedProcess
    require(isinstance(process, OwnedProcess) and known is None,
            'Historical PID settlement refused; reserved supervisor required')
    return process.settle()


def run_probe(run, executable, roots, outside, port, services=(), automation_port=None, *,
              firefox_child_ipc=False, firefox_executable=None, evidence=None,
              chrome_rendezvous=False, chrome_executable=None, rendezvous_evidence=None):
    """Positive scratch IO and denied sibling IO/loopback, also in a child.

    With the C1A option the same canary runs through the rendezvous helper under its own
    PID and parameter; it never runs Chrome and never tests Chrome's eventual PID.
    """
    require(automation_port != port, 'Canary target must differ from automation port')
    profile = policy(run, roots, services, automation_port,
                     firefox_child_ipc=firefox_child_ipc, firefox_executable=firefox_executable,
                     chrome_rendezvous=chrome_rendezvous, chrome_executable=chrome_executable)
    require((rendezvous_evidence is not None) is chrome_rendezvous, 'Rendezvous evidence requires the option')
    (run / 'confinement.sb').write_text(profile)
    script = r'''
import errno,json,pathlib,socket,subprocess,sys
outside=pathlib.Path(sys.argv[1]); port=int(sys.argv[2]); automation=int(sys.argv[3])
def outcome(operation):
    try: operation()
    except OSError as e:
        if e.errno in (errno.EPERM,errno.EACCES): return 'DENIED'
        if e.errno == errno.EADDRINUSE: return 'COLLISION'
        return 'ERROR_' + str(e.errno)
    return 'ALLOWED'
def refused(operation):
    return outcome(operation) == 'DENIED'
def bind(address, number):
    with socket.socket() as s:
        s.bind((address,number)); s.listen()
def connect():
    with socket.socket() as s:
        s.settimeout(1);s.connect(('127.0.0.1',port))
pathlib.Path('allowed').write_text('synthetic')
result={'scratch_io':pathlib.Path('allowed').read_text()=='synthetic',
 'outside_read':refused(lambda:outside.read_bytes()),
 'outside_write':refused(lambda:outside.write_text('wrong')),
 'network':refused(connect), 'unrelated_bind':refused(lambda:bind('127.0.0.1',0)),
 'unrelated_public_bind':refused(lambda:bind('0.0.0.0',0))}
result['loopback_exception']=outcome(lambda:bind('127.0.0.1',automation)) if automation else 'NOT_REQUESTED'
result['same_port_wildcard_bind']=outcome(lambda:bind('0.0.0.0',automation)) if automation else 'NOT_REQUESTED'
result['public_bind_refused']=result['same_port_wildcard_bind']=='DENIED'
passed=all(result[k] for k in ('scratch_io','outside_read','outside_write','network','unrelated_bind','unrelated_public_bind'))
passed=passed and (not automation or (result['loopback_exception']=='ALLOWED' and result['same_port_wildcard_bind'] in ('ALLOWED','DENIED')))
if len(sys.argv)==4:
    child=subprocess.run([sys.executable,__file__,str(outside),str(port),str(automation),'child'],capture_output=True,text=True)
    result['child']=json.loads(pathlib.Path('child-canaries.json').read_text())
    passed=passed and child.returncode==0 and result['child']['passed']
result['passed']=bool(passed)
pathlib.Path('canaries.json' if len(sys.argv)==4 else 'child-canaries.json').write_text(json.dumps(result))
sys.exit(0 if passed else 1)
'''
    if chrome_rendezvous:
        # Top-level canary only: its own getpid(), written privately inside the owned run.
        script = CANARY_PID + script
    (run / 'probe.py').write_text(script)
    command = ['/usr/bin/sandbox-exec', '-f', str(run / 'confinement.sb'),
               str(executable), '-B', str(run / 'probe.py'), str(outside), str(port), str(automation_port or 0)]
    sandboxed = command
    if chrome_rendezvous:
        from cnt_chrome_rendezvous import wrap
        command = wrap(rendezvous_evidence, 'canary', sandboxed)
    from cnt_owned_process import OwnedProcess
    result = evidence if evidence is not None else {}
    result.update(policy_evidence(profile, run, automation_port, firefox_child_ipc, tuple(services),
                                  **({'chrome_rendezvous': True} if chrome_rendezvous else {})))
    result.update(environment_names=sorted(environment(run)),
                  keychain='POLICY_DENIED_BEHAVIORALLY_UNTESTED',
                  status='BLOCKED', browser_sandbox_disables=[])
    with (run / 'stdout.json').open('w') as out, (run / 'stderr.log').open('w') as err:
        process = OwnedProcess(command, run, environment(run), err, evidence=result)
        try:
            process.until(lambda: process.returncode is not None, 15)
        finally:
            primary = __import__('sys').exception()
            try:
                result['settlement'] = process.settle()
            except BaseException as cleanup:
                result['settlement'] = process.result
                result['cleanup_failure'] = {'type': type(cleanup).__name__}
                if primary is None:
                    raise
    settlement = result['settlement']
    rendezvous = True
    if chrome_rendezvous:
        from cnt_chrome_rendezvous import matched, observe
        result['rendezvous_canary'] = observe(rendezvous_evidence, 'canary', process.workload_pid, sandboxed,
                                              run / 'canary-pid.json')
        rendezvous = matched(result['rendezvous_canary'], canary=True)
    if (run / 'canaries.json').is_file():
        observed = json.loads((run / 'canaries.json').read_text())
        result['canaries'] = observed
        if observed.get('passed') and settlement['exit_code'] == 0 and settlement['zero_survivors'] and rendezvous:
            result['status'] = 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION'
    (run / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
