"""Synthetic browser trials: the accepted R4 Firefox lane and the R5 Chrome adapter.

The empty/page/full workloads never load captured CNT. An empty browser failure is a
confinement prerequisite, not evidence that the installed browser or CDP extension API is
unavailable. Chrome support here is source preparation only; no installed Chrome is qualified.

R6 `--workload cnt-matrix` (Firefox only) is the one route that loads captured code: it
copies the retained, digest-verified captured XPI into the fresh attempt and runs one
native semantic-matrix case (cnt_firefox_matrix_session) inside the unchanged R4 lifecycle.
It can never report SYNTHETIC_ATTEMPT_PASSED; its outcome is MATRIX_ATTEMPT_COMPLETED or BLOCKED.

BUX5B1 RECOVERY-HOSTPREP1 `--workload cnt-recovery` (Firefox only, UNEXECUTED) runs one role of the
disposable guarded-recovery qualification (cnt_firefox_recovery: source, staging or target) inside
the same unchanged R4 lifecycle, from a host-written, digest-bound plan read before any root. Its
fresh-profile proof runs after arguments() wrote user.js and immediately before the launch. Its
outcome is RECOVERY_ATTEMPT_COMPLETED or BLOCKED, never SYNTHETIC_ATTEMPT_PASSED.
"""
import argparse
import datetime
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import select
import shutil
import socket
import stat
import subprocess
import sys
import time

from cnt_confinement import (CONFIGD, REVIEWED_SERVICES, environment, fresh_attempt, run_probe,
                             settle, valid_port)
from cnt_native_evidence import (MEASUREMENT_CODES, MEASUREMENT_OPERATIONS, STAMP_FIELDS,
                                 VerificationError, plain_descendant, require, tree_digest)
from cnt_crash_paths import owned_directory, count_directory

# Built-in Gecko logging on the existing browser.log stderr only. Module names,
# levels and modifiers were checked against the matching 155.0.1 source; the
# installed XUL contains the same format strings. MOZ_LOG_FILE is never set.
SHUTDOWN_TRACE = 'ObserverService:4,ChildProcessLifecycle:3,timestamp,sync'
TRACE_LIMIT = 64 * 1024 * 1024
TRACE_TAIL = 400
TRACE_LINE = re.compile(r'(?:(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6}) UTC - )?'
                        r'\[([A-Za-z]{1,16}) (\d+): [^\]]*\]: [VDIWE]/'
                        r'(ObserverService|ChildProcessLifecycle) (.*)')
OBSERVER_CALL = re.compile(r'nsObserverService::(NotifyObservers|AddObserver|RemoveObserver|'
                           r'EnumerateObservers)\((?:0x[0-9a-fA-F]+: )?([^,)]*)')
LIFECYCLE = re.compile(r'(\+\+|--)PROCESS \[pid = \d+\] \[childID = -?\d+\] \[type = ([A-Za-z]+)\]')
TOPIC = re.compile(r'[A-Za-z0-9:_.-]{1,80}')


# HOSTPREP1-NIX-CLI-COMPAT1: supported closure-query frontends. `nix-store --query --requisites P`
# and `nix path-info --recursive P` both print P's closure, one store path per line; the output is
# normalized to a sorted set, so either frontend yields the same roots and the same R4 policy.
NIX_STORE_PATH = re.compile(r'/nix/store/[0-9a-df-np-sv-z]{32}-[0-9A-Za-z+._?=-]+')
CLOSURE_FRONTENDS = (('nix-store', ('--query', '--requisites')),
                     ('nix', ('--extra-experimental-features', 'nix-command', 'path-info', '--recursive')))


def closure_frontend(search_path):
    """First absolute PATH directory holding an executable frontend; nix-store preferred within it."""
    candidates = [(Path(directory) / name, arguments) for directory in search_path.split(os.pathsep)
                  if os.path.isabs(directory) for name, arguments in CLOSURE_FRONTENDS]
    usable = [(path, arguments) for path, arguments in candidates
              if path.is_file() and os.access(path, os.X_OK)]
    require(bool(usable), 'No supported Nix closure-query frontend')
    return usable[0]


def query_runtime_roots(root):
    """Closure of one valid store root. No shell, build, substitution or store mutation."""
    frontend, arguments = closure_frontend(os.environ.get('PATH', ''))
    completed = subprocess.run([str(frontend), *arguments, str(root)], stdout=subprocess.PIPE, text=True)
    require(completed.returncode == 0, 'Nix closure query failed')
    members = {line for line in completed.stdout.splitlines() if line}
    require(all(NIX_STORE_PATH.fullmatch(member) for member in members), 'Malformed Nix closure member')
    require(str(root) in members, 'Nix closure omits its root')
    roots = sorted(Path(member) for member in members)
    require(not any(p.name.endswith('-source') for p in roots), 'Source-bearing runtime closure refused')
    return roots


def runtime_roots(executable):
    executable = executable.resolve(strict=True)
    require(executable.is_relative_to('/nix/store'), 'Nix runtime required')
    return query_runtime_roots(Path('/nix/store') / executable.relative_to('/nix/store').parts[0])


# Chrome runs in place from the explicitly selected immutable store app; nothing is copied,
# re-signed or substituted. The store root is a constant so tests can use a synthetic store.
CHROME_STORE = Path('/nix/store')
CHROME_STORE_NAME = re.compile(r'[0-9a-df-np-sv-z]{32}-google-chrome-[0-9][0-9A-Za-z.+_-]{0,63}')
CHROME_APP = ('Applications', 'Google Chrome.app')
CHROME_EXECUTABLE = 'Contents/MacOS/Google Chrome'
CHROME_BUNDLE_ID = 'com.google.Chrome'
CHROME_VERSION = re.compile(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}')
PLIST_LIMIT = 4 * 1024 * 1024
CHROME_MEASUREMENT_SCOPE = (
    'Measured before and after launch: every entry of the selected Google Chrome.app (MacOS stub, '
    'framework, Helpers apps including chrome_crashpad_handler, libraries, resources, _CodeSignature). '
    'Provenance only: the store path name, siblings outside the .app, and other closure members as a '
    'sorted identity list digest and count. Not covered: /System, /usr/lib, the dyld shared cache and '
    'the supervisor Python closure. Executed bytes equal measured bytes only through pre/post MATCH.')
CHROME_PREPARATION_CODES = {
    'Chrome runtime must be a resolved link-free path': 'CHROME_RUNTIME_NOT_RESOLVED',
    'Chrome runtime must be the selected Nix store Google Chrome.app': 'CHROME_RUNTIME_NOT_STORE_APP',
    'Chrome bundle metadata unreadable': 'CHROME_BUNDLE_METADATA_UNREADABLE',
    'Chrome bundle identity refused': 'CHROME_BUNDLE_IDENTITY_REFUSED',
    'Chrome bundle version invalid': 'CHROME_BUNDLE_VERSION_INVALID',
    'Chrome original signature invalid': 'ORIGINAL_SIGNATURE_INVALID',
    'Chrome measurement root unbound': 'CHROME_MEASUREMENT_ROOT_UNBOUND',
    'Firefox-only option refused for Chrome': 'FIREFOX_ONLY_OPTION',
    'Chrome abnormal attempt requires the full workload': 'CHROME_ABNORMAL_REQUIRES_FULL',
    # R5-CHROME-C1A: explicit own-workload-PID rendezvous option.
    'Chrome rendezvous requires the selected Chrome lane': 'CHROME_RENDEZVOUS_LANE_REQUIRED',
    'Duplicate rendezvous selection': 'CHROME_RENDEZVOUS_DUPLICATE',
    'Chrome rendezvous option invalid': 'CHROME_RENDEZVOUS_OPTION_INVALID',
    'Rendezvous evidence requires the option': 'CHROME_RENDEZVOUS_EVIDENCE_UNBOUND'}
RENDEZVOUS_CHOICE = 'own-workload-pid'


def chrome_bundle(app):
    """Identity of an explicitly selected store Google Chrome.app. Reads only its plist and layout."""
    app = Path(app)
    require(app.is_absolute() and app.resolve(strict=True) == app,
            'Chrome runtime must be a resolved link-free path')
    relative = app.relative_to(CHROME_STORE).parts if app.is_relative_to(CHROME_STORE) else ()
    require(len(relative) == 3 and CHROME_STORE_NAME.fullmatch(relative[0]) is not None
            and relative[1:] == CHROME_APP, 'Chrome runtime must be the selected Nix store Google Chrome.app')
    plain_descendant(app, 'Contents', directory=True)
    executable = plain_descendant(app, CHROME_EXECUTABLE)
    try:
        descriptor = os.open(plain_descendant(app, 'Contents/Info.plist'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            raw = stream.read(PLIST_LIMIT + 1)
        info = plistlib.loads(raw) if len(raw) <= PLIST_LIMIT else None
    except (OSError, ValueError, plistlib.InvalidFileException):
        info = None
    require(isinstance(info, dict), 'Chrome bundle metadata unreadable')
    # Refuses Chromium, Chrome for Testing and any renamed substitute.
    require(info.get('CFBundleIdentifier') == CHROME_BUNDLE_ID
            and info.get('CFBundleExecutable') == 'Google Chrome', 'Chrome bundle identity refused')
    version = info.get('CFBundleShortVersionString')
    require(type(version) is str and CHROME_VERSION.fullmatch(version) is not None,
            'Chrome bundle version invalid')
    return executable, version


def closure_identity(roots):
    names = sorted(str(r) for r in roots)
    return len(names), hashlib.sha256('\n'.join(names).encode()).hexdigest()


def prepare_chrome_runtime(args, run, record):
    """In place; partial facts survive any refusal. Preparation is complete only at the end."""
    app = Path(args.runtime)
    record['runtime_selection'] = 'EXPLICIT_STORE_APP'
    executable, version = chrome_bundle(app)
    record.update(runtime_bundle_id=CHROME_BUNDLE_ID, runtime_bundle_version=version,
                  runtime_measurement_scope=CHROME_MEASUREMENT_SCOPE)
    started = time.monotonic()
    before = tree_digest(app)
    record['runtime_digest_seconds'] = round(time.monotonic() - started, 3)
    record['runtime_source_sha256'] = before
    signature = record.setdefault('signature', {})
    verified = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)],
                              capture_output=True, timeout=120)
    signature['original'] = verified.returncode == 0
    require(signature['original'], 'Chrome original signature invalid')
    roots = runtime_roots(executable)
    record['runtime_closure_count'], record['runtime_closure_sha256'] = closure_identity(roots)
    record['runtime_snapshot_sha256'] = before
    record['runtime_measurement_root'] = 'SELECTED_STORE_APP'
    record['runtime_preparation_complete'] = True
    return executable, roots, before


def runtime_measurement_target(engine, run, record, selected):
    """Chrome measures only its prepared store app and can never fall back to run/runtime."""
    if engine == 'chrome':
        require(record.get('runtime_measurement_root') == 'SELECTED_STORE_APP' and selected is not None,
                'Chrome measurement root unbound')
        return selected
    return run / record.get('runtime_bundle_relative', 'runtime')


def prepare_runtime(args, run, record):
    if args.engine == 'chrome':
        return prepare_chrome_runtime(args, run, record)
    source = args.runtime.resolve(strict=True)
    require(source.name == 'Firefox.app', 'Expected installed Firefox application')
    before = tree_digest(source)
    record["runtime_source_sha256"] = before
    record["runtime_preparation_complete"] = False
    signature = record.setdefault("signature", {})
    for label, target in [('original', source)]:
        verified = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(target)],
                                  capture_output=True, timeout=30)
        signature[label] = verified.returncode == 0
        require(signature[label], 'Firefox original signature invalid')
    bundle = run / 'runtime/Firefox.app'
    record['runtime_bundle_relative'] = 'runtime/Firefox.app'
    shutil.copytree(source, bundle, symlinks=True)
    require(before == tree_digest(bundle) == tree_digest(source), 'Firefox snapshot drift')
    verified = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(bundle)],
                              capture_output=True, timeout=30)
    signature['frozen'] = verified.returncode == 0
    (run / 'signature.json').write_text(json.dumps(signature))
    require(signature['frozen'], 'Firefox frozen signature invalid')
    record['runtime_snapshot_sha256'] = before
    record['runtime_preparation_complete'] = True
    return bundle / 'Contents/MacOS/firefox', [bundle], before


def firefox_user_js(automation_port):
    """The exact Firefox user.js bytes arguments() writes (the recovery freshness proof compares them)."""
    prefs = {'browser.shell.checkDefaultBrowser': False, 'app.update.auto': False,
             'app.update.enabled': False, 'extensions.update.enabled': False,
             'identity.fxaccounts.enabled': False, 'services.sync.enabled': False,
             'network.offline': True, 'marionette.port': valid_port(automation_port), 'toolkit.telemetry.enabled': False,
             'datareporting.healthreport.uploadEnabled': False}
    return ''.join(f'user_pref({json.dumps(k)},{json.dumps(v)});\n' for k, v in prefs.items()).encode()


def arguments(engine, executable, run, automation_port=None):
    if engine == 'chrome':
        return [str(executable), '--headless=new', '--user-data-dir=' + str(run / 'profile'),
                '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
                '--disable-component-update', '--disable-sync', '--use-mock-keychain',
                '--enable-logging=stderr',
                '--password-store=basic', '--enable-unsafe-extension-debugging',
                '--remote-debugging-pipe', 'about:blank']
    (run / 'profile/user.js').write_bytes(firefox_user_js(automation_port))
    require(not (run / 'profile/prefs.js').exists() and not (run / 'profile/MarionetteActivePort').exists(),
            'Stale Marionette profile')
    return [str(executable), '--headless', '--no-remote', '--marionette',
            '-remote-allow-system-access', '-profile', str(run / 'profile'), 'about:blank']


def browser_environment(run, engine, exceptions=(), *, crash_force_enable=False, shutdown_trace=False):
    require(type(crash_force_enable) is bool, 'Explicit crash initialization option required')
    require(engine == 'firefox' or not crash_force_enable, 'Firefox initialization only')
    require(type(shutdown_trace) is bool, 'Explicit shutdown trace option required')
    require(engine == 'firefox' or not shutdown_trace, 'Firefox shutdown trace only')
    env = environment(run)
    allowed = {'content': 'MOZ_DISABLE_CONTENT_SANDBOX',
               'socket': 'MOZ_DISABLE_SOCKET_PROCESS_SANDBOX',
               'utility': 'MOZ_DISABLE_UTILITY_SANDBOX',
               'utility-generic': 'MOZ_DISABLE_UTILITY_SANDBOX',
               'rdd': 'MOZ_DISABLE_RDD_SANDBOX'}
    require(not {'utility', 'utility-generic'} <= set(exceptions), 'Duplicate utility exception')
    require(set(exceptions) <= allowed.keys(), 'Unreviewed sandbox component')
    require(engine == 'firefox' or not exceptions, 'Firefox exceptions only')
    if engine == 'firefox':
        env.update(MOZ_HEADLESS='1', MOZ_NO_REMOTE='1',
                   MOZ_CRASHREPORTER_NO_REPORT='1',
                   MOZ_CRASHREPORTER_DATA_DIRECTORY=str(run / 'crash-data'))
        if crash_force_enable:
            env['MOZ_CRASHREPORTER'] = '1'
        if shutdown_trace:
            env['MOZ_LOG'] = SHUTDOWN_TRACE
        env.update({allowed[component]: ('utility:0' if component == 'utility-generic' else '1')
                    for component in exceptions})
    return env


def launch_empty(command, run, engine, abnormal=False, automation_port=None, exceptions=(), result=None, workload="full", parent_probes=False, crash_readback=False, crash_force_enable=False, shutdown_trace=False, expected_version=None, rendezvous=None, matrix_case=None, recovery_plan=None):
    from cnt_owned_process import OwnedProcess
    from cnt_protocol import CDPPipe
    require(rendezvous is None or engine == 'chrome', 'Chrome rendezvous requires the selected Chrome lane')
    input_read, input_write = os.pipe()
    output_read, output_write = os.pipe()
    env = browser_environment(run, engine, exceptions, crash_force_enable=crash_force_enable,
                              shutdown_trace=shutdown_trace)
    result = result if result is not None else {}
    result.update(ready=False, workload=workload, shutdown_observer=False,
                  crash_force_enable=crash_force_enable, shutdown_trace=shutdown_trace,
                  parent_probes=parent_probes, crash_readback=crash_readback, environment_names=sorted(env),
                  sampling_limits='Finite unprivileged lsof samples see only visible sockets/processes, not exhaustive host-wide collisions. Marker-stripping descendants and changes between samples are not proven absent.')
    with (run / 'browser.log').open('w') as log:
        try:
            # Chrome's reparented crash handler carries --database=<profile>/Crashpad, not
            # --user-data-dir=, so its owned-profile path is an additional escape marker.
            process = OwnedProcess(command, run, env, log,
                                   (input_read, output_write) if engine == 'chrome' else (), evidence=result,
                                   **({'markers': (str(run / 'profile') + '/',)} if engine == 'chrome' else {}))
        except BaseException:
            for fd in (input_read, input_write, output_read, output_write):
                os.close(fd)
            if rendezvous is not None:
                observe_rendezvous(result, rendezvous, None)
            raise
        os.close(input_read)
        os.close(output_write)
        try:
            if engine == 'chrome':
                from cnt_synthetic_chrome import exercise, observe_exit_after_eof
                pipe = CDPPipe(output_read, input_write)
                try:
                    exercise(pipe, process, run, result, workload=workload, abnormal=abnormal,
                             expected_version=expected_version)
                except BaseException as error:
                    record_failure(result, 'primary_failure', error, 'browser')
                    observe_exit_after_eof(process, error, result)
                    raise
                finally:
                    result['protocol'] = pipe.methods
            else:
                from cnt_synthetic_firefox import session, qualify, quit_normally, confinement_checks, crash_reporter_status
                client, caps = session(process, run, result, automation_port)
                result['ready'] = True
                result['browser_version'] = caps.get('browserVersion')
                try:
                    if crash_readback:
                        crash_reporter_status(client, run, result)
                        result['crash_readback_completed'] = True
                    if workload == 'cnt-matrix':
                        # The page-nonce canary first, then one native matrix case.
                        from cnt_firefox_matrix_session import exercise as exercise_matrix
                        qualify(client, run, result, page_only=True)
                        exercise_matrix(client, run, result, matrix_case)
                    elif workload == 'cnt-recovery':
                        # The page-nonce canary first, then one disposable recovery role.
                        from cnt_firefox_recovery import exercise as exercise_recovery
                        qualify(client, run, result, page_only=True)
                        exercise_recovery(client, run, result, recovery_plan)
                    elif workload != 'empty':
                        qualify(client, run, result, page_only=workload == 'page')
                    if parent_probes:
                        confinement_checks(client, run, result)
                        result['parent_probes_completed'] = True
                    if abnormal:
                        try:
                            def still_waiting():
                                client.sample('intentional-timeout')
                                return False
                            process.until(still_waiting, .25)
                        except Exception as error:
                            require(str(error) == 'Owned workload timeout', 'Unexpected abnormal failure')
                            require(process.returncode is None, 'Workload exited before intended timeout')
                            result['intended_timeout'] = True
                    else:
                        quit_normally(client, process, result)
                except BaseException as error:
                    record_failure(result, 'primary_failure', error, 'browser')
                    raise
                finally:
                    result['protocol'] = client.methods
                    try:
                        if client.valid:
                            client.sample('before-cleanup', required=False)
                    finally:
                        client.connection.close()
        except BaseException as error:
            record_failure(result, 'primary_failure', error, 'browser')
            if not isinstance(error, Exception):
                raise
        finally:
            primary = sys.exception()
            result['exit_before_cleanup'] = process.returncode
            try:
                result['settlement'] = process.settle()
            except BaseException as cleanup:
                result['settlement'] = process.result
                record_failure(result, 'cleanup_failure', cleanup, 'cleanup')
                if primary is None and not isinstance(cleanup, Exception):
                    raise
            finally:
                os.close(input_write)
                os.close(output_read)
                if rendezvous is not None:
                    # After settlement: the private record cannot change after exec, and the
                    # canary already compared the same helper path immediately before.
                    observe_rendezvous(result, rendezvous, process.workload_pid)
    if engine == 'chrome':
        try:
            result['owned_crash_artifacts'] = chrome_crash_artifacts(run)
        except OSError as error:
            record_failure(result, 'evidence_io_failure', error, 'owned-crash-inspection')
    if engine == 'firefox' and result.get('exit_before_cleanup') not in (None, 0):
        try:
            result['owned_crash_artifacts'] = owned_crash_artifacts(run, result.get('crash_reporter'))
        except OSError as error:
            record_failure(result, 'evidence_io_failure', error, 'owned-crash-inspection')
    if engine == 'firefox' and shutdown_trace:
        try:
            result['shutdown_trace_summary'] = shutdown_trace_summary(run, process.workload_pid)
        except Exception as error:
            # Runs after settlement: a summary failure is evidence collection, never the browser outcome.
            record_failure(result, 'evidence_io_failure', error, 'shutdown-trace-summary')
    return result


def observe_rendezvous(result, rendezvous, workload_pid):
    """Fixed-key comparison with the supervisor-authenticated workload; never a raw PID."""
    try:
        from cnt_chrome_rendezvous import observe
        result['rendezvous_parameter'] = observe(rendezvous['evidence'], 'browser', workload_pid,
                                                 rendezvous['argv'])
    except Exception as error:
        record_failure(result, 'evidence_io_failure', error, 'rendezvous-observation')


def shutdown_trace_summary(run, workload_pid):
    """Ordered parent observer topics and child lifecycle; never pids, pointers or paths.

    Parent lines require the authenticated workload pid. The anchor is the
    parent's first quit-application-granted notification; entries before it
    are counted, not exported.
    """
    try:
        descriptor = os.open(run / 'browser.log', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {'status': 'ABSENT', 'modules': SHUTDOWN_TRACE}
    except OSError as error:
        if error.errno == errno.ELOOP:
            return {'status': 'REFUSED_LINK', 'modules': SHUTDOWN_TRACE}
        raise
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            return {'status': 'REFUSED_NON_REGULAR', 'modules': SHUTDOWN_TRACE}
        raw = stream.read(TRACE_LIMIT + 1)
    if len(raw) > TRACE_LIMIT:
        return {'status': 'OVERSIZED', 'modules': SHUTDOWN_TRACE}
    if type(workload_pid) is not int:
        return {'status': 'UNATTRIBUTED', 'modules': SHUTDOWN_TRACE}
    counts = {'parent': 0, 'other_process': {}, 'unmatched': 0}
    anchor, anchor_time, before, after, dropped, last = False, None, 0, [], 0, None
    for line in raw.decode('utf-8', 'replace').splitlines():
        match = TRACE_LINE.fullmatch(line)
        if not match:
            counts['unmatched'] += 1
            continue
        stamp, mode, pid, module, message = match.groups()
        if mode != 'Parent' or int(pid) != workload_pid:
            counts['other_process'][mode] = counts['other_process'].get(mode, 0) + 1
            continue
        counts['parent'] += 1
        if module == 'ObserverService':
            call = OBSERVER_CALL.match(message)
            if call is None:
                entry = {'op': 'other'}
            else:
                topic = call.group(2)
                entry = {'op': call.group(1), 'topic': topic if TOPIC.fullmatch(topic) else 'UNCLASSIFIED'}
        else:
            event = LIFECYCLE.fullmatch(message)
            entry = ({'op': 'process-start' if event.group(1) == '++' else 'process-end',
                      'type': event.group(2)} if event else {'op': 'lifecycle-other'})
        when = None
        if stamp is not None:
            try:
                when = datetime.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                counts['unparsed_time'] = counts.get('unparsed_time', 0) + 1
        if not anchor and entry.get('op') == 'NotifyObservers' and entry.get('topic') == 'quit-application-granted':
            anchor, anchor_time = True, when
        last = entry
        if not anchor:
            before += 1
            continue
        if anchor_time is not None and when is not None:
            entry['ms'] = round((when - anchor_time).total_seconds() * 1000, 3)
        after.append(entry)
        if len(after) > TRACE_TAIL:
            after.pop(0)
            dropped += 1
    return {'status': 'SUMMARIZED', 'modules': SHUTDOWN_TRACE, 'counts': counts,
            'quit_anchor': anchor, 'parent_before_anchor': before,
            'parent_after_anchor': after, 'parent_after_anchor_dropped': dropped,
            'parent_last': last,
            'scope': 'Last logged parent event bounds, but does not locate, a silent fault.'}


def owned_crash_artifacts(run, reporter=None):
    # Provenance is directory-specific. TMPDIR is never a crash-data location.
    result = {}
    roots = [
            ('profile/minidumps', 'profile-minidumps'),
            ('profile/crashes/events', 'profile-events'),
            ('crash-data', 'requested-data-environment-not-effective-readback')]
    if reporter and reporter.get('enabled') is True and reporter.get('data_directory_relative'):
        roots.append((reporter['data_directory_relative'], 'effective-data-environment-readback'))
    for relative, provenance in roots:
        with owned_directory(run, str(run / relative)) as (admission, descriptor):
            entry = dict(admission, provenance=provenance)
            if descriptor is not None:
                entry.update(status='INSPECTED', counts=count_directory(descriptor))
            result[relative] = entry
    return result


def chrome_crash_artifacts(run):
    """Counts only, from the owned profile's Crashpad database; never report contents."""
    with owned_directory(run, str(run / 'profile/Crashpad')) as (admission, descriptor):
        entry = dict(admission, provenance='chrome-user-data-crashpad')
        if descriptor is not None:
            entry.update(status='INSPECTED', counts=count_directory(descriptor))
    return {'profile/Crashpad': entry}


def reserve_port(port=0):
    reservation = socket.socket()
    try:
        reservation.bind(('127.0.0.1', port))
        reservation.listen()
    except BaseException:
        reservation.close()
        raise
    return reservation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=('chrome', 'firefox'), required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--abnormal', action='store_true')
    parser.add_argument('--workload', choices=('full', 'empty', 'page', 'cnt-matrix', 'cnt-recovery'),
                        default='full')
    parser.add_argument('--capture', type=Path,
                        help='R6 cnt-matrix only: the retained captured Firefox XPI (read, verified, copied)')
    parser.add_argument('--capture-sha256', help='R6 cnt-matrix only: must equal the pinned capture digest')
    parser.add_argument('--matrix-case', help='R6 cnt-matrix only: one catalogue case id')
    parser.add_argument('--matrix-input', type=Path,
                        help='R6 cnt-matrix only: completed source attempt root under managed scratch')
    parser.add_argument('--recovery-plan', type=Path,
                        help='BUX5B1 cnt-recovery only: host-written qualification plan under managed scratch')
    parser.add_argument('--recovery-plan-sha256', help='BUX5B1 cnt-recovery only: the plan digest')
    parser.add_argument('--crash-force-enable', action='store_true',
                        help='Explicit process-local MOZ_CRASHREPORTER=1 application gate comparison')
    parser.add_argument('--crash-readback', action='store_true',
                        help='Diagnostic supported crash-handler status readback')
    parser.add_argument('--parent-probes', action='store_true',
                        help='Diagnostic parent boundary trial; never full acceptance')
    parser.add_argument('--shutdown-trace', action='store_true',
                        help='Diagnostic built-in observer/child-lifecycle log on browser.log; never acceptance')
    parser.add_argument('--nested-sandbox-exception', action='append', default=[],
                        choices=['content', 'socket', 'utility', 'utility-generic', 'rdd'],
                        help='Only after a retained component-specific nesting failure; outer Seatbelt canaries remain mandatory')
    parser.add_argument('--service', action='append', default=[],
                        choices=[*REVIEWED_SERVICES, CONFIGD],
                        help=CONFIGD + ' is R4-CONT7 trusted-synthetic Firefox-lane compatibility only')
    parser.add_argument('--chrome-rendezvous', action='append', default=[], choices=[RENDEZVOUS_CHOICE],
                        help='R5-CHROME-C1A: exact own-workload-PID rendezvous name; Chrome lane only, default off')
    args = parser.parse_args()
    raise SystemExit(attempt(args))


KNOWN_FAILURES = {'Frozen runtime changed': 'RUNTIME_CHANGED',
                  'Marionette effective port unavailable': 'PORT_FILE_UNAVAILABLE',
                  'Firefox exited before listener': 'WORKLOAD_EXITED_BEFORE_LISTENER',
                  'Owned workload timeout': 'OWNED_WORKLOAD_TIMEOUT',
                  'Unexpected normal browser exit': 'UNEXPECTED_NORMAL_EXIT',
                  'Firefox original signature invalid': 'ORIGINAL_SIGNATURE_INVALID',
                  'Firefox frozen signature invalid': 'FROZEN_SIGNATURE_INVALID',
                  'Firefox snapshot drift': 'SNAPSHOT_DRIFT',
                  'Canaried launch policy changed': 'LAUNCH_POLICY_CHANGED',
                  'Confinement preflight failed': 'CONFINEMENT_PREFLIGHT_FAILED',
                  'configd compatibility requires the validated frozen Firefox lane': 'CONFIGD_LANE_REQUIRED',
                  # R6 cnt-matrix selection refusals (before any attempt root).
                  'Matrix workload option refused': 'MATRIX_OPTION_REFUSED',
                  'Matrix options require the matrix workload': 'MATRIX_OPTION_WITHOUT_WORKLOAD',
                  'Matrix capture required': 'MATRIX_CAPTURE_REQUIRED',
                  # BUX5B1 cnt-recovery selection refusals (before any attempt root).
                  'Recovery workload option refused': 'RECOVERY_OPTION_REFUSED',
                  'Recovery options require the recovery workload': 'RECOVERY_OPTION_WITHOUT_WORKLOAD',
                  'Recovery capture required': 'RECOVERY_CAPTURE_REQUIRED'}


def failure_codes():
    codes = dict(KNOWN_FAILURES)
    codes.update(CHROME_PREPARATION_CODES)
    # Lazy: preserves import order. An unavailable table leaves messages UNKNOWN, never invented.
    # Separate block: a Chrome table failure can never hide the Firefox tables. Messages shared
    # between tables map to identical codes (tested), so update order is not a precedence rule.
    try:
        from cnt_protocol import CDP_CODES
        from cnt_synthetic_chrome import CHROME_CODES
    except Exception:
        pass
    else:
        codes.update(CDP_CODES)
        codes.update(CHROME_CODES)
    try:
        from cnt_firefox_matrix import MATRIX_CODES
        from cnt_firefox_matrix_session import SESSION_CODES as MATRIX_SESSION_CODES
    except Exception:
        pass
    else:
        codes.update(MATRIX_CODES)
        codes.update(MATRIX_SESSION_CODES)
    try:
        from cnt_firefox_recovery import RECOVERY_CODES
    except Exception:
        pass
    else:
        codes.update(RECOVERY_CODES)
    try:
        from cnt_firefox_observation import FAILURE_CODES
        from cnt_synthetic_firefox import PORT_CODES, SESSION_CODES
    except Exception:
        return codes
    codes.update(FAILURE_CODES)
    codes.update(PORT_CODES)
    codes.update(SESSION_CODES)
    return codes


def structured_code(error):
    """Allowlisted refusal code attached by the measurement helper, else None."""
    code = getattr(error, 'code', None) if isinstance(error, VerificationError) else None
    return code if type(code) is str and code in MEASUREMENT_CODES else None


def record_failure(record, field, error, stage):
    # Exception text may contain private paths or payloads. Keep classification
    # deterministic; raw diagnostics remain in the owned attempt directory.
    if field in record:
        return
    codes = failure_codes()
    message = str(error)
    known = message in codes
    record[field] = {'stage': stage, 'type': type(error).__name__,
                     'classification': message if known else stage,
                     'code': codes[message] if known else structured_code(error) or 'UNKNOWN',
                     'message_known': known}


RUNTIME_PART = re.compile(r'[A-Za-z0-9 ._+@-]{1,128}')
ERROR_TYPE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')


def safe_runtime_relative(relative):
    """Bounded lexical path inside the frozen .app, or a fixed category. Never follows links."""
    if relative is None:
        return {'category': 'ROOT'}
    if type(relative) is not str or len(relative) > 512:
        return {'category': 'UNSAFE_PATH'}
    parts = relative.split('/')
    if len(parts) > 32 or not all(p not in ('.', '..') and RUNTIME_PART.fullmatch(p) for p in parts):
        return {'category': 'UNSAFE_PATH'}
    return {'category': 'RUNTIME_RELATIVE', 'path': relative}


def measurement_count(value):
    return value if type(value) is int and value >= 0 else None


def incomplete_measurement(trace, error):
    """Fixed-key projection of an incomplete runtime measurement.

    Never message text, absolute paths, link text, stamp values or digests.
    Unknown failures stay UNKNOWN with their type and last operation.
    """
    try:
        operation = trace.get('operation')
        operation = operation if type(operation) is str and operation in MEASUREMENT_OPERATIONS else None
        code, number = structured_code(error), None
        if code is None:
            if not isinstance(error, Exception):
                code = 'INTERRUPTED'
            elif isinstance(error, OSError):
                code = 'OS_ERROR'
                number = error.errno if type(error.errno) is int else None
            else:
                code = 'UNKNOWN'
        changed = getattr(error, 'changed', None) if isinstance(error, VerificationError) else None
        if not (type(changed) is list and changed and all(f in STAMP_FIELDS for f in changed)):
            changed = None
        name = type(error).__name__
        return {'state': 'INCOMPLETE', 'digest_complete': False, 'operation': operation, 'code': code,
                'error_type': name if ERROR_TYPE.fullmatch(name) else 'UNCLASSIFIED', 'errno': number,
                'changed_fields': [f for f in STAMP_FIELDS if f in changed] if changed else None,
                'entry': safe_runtime_relative(trace.get('relative')) if operation else None,
                'entries_enumerated': measurement_count(trace.get('entries_enumerated')),
                'entries_measured': measurement_count(trace.get('entries_measured'))}
    except Exception:
        return {'state': 'INCOMPLETE', 'digest_complete': False,
                'code': 'MEASUREMENT_PROJECTION_UNAVAILABLE'}


def persist(run, record):
    try:
        temporary = run / 'result.json.tmp'
        temporary.write_text(json.dumps(record, indent=2) + '\n')
        temporary.replace(run / 'result.json')
        return True
    except Exception as error:
        print('Attempt evidence IO failed: ' + type(error).__name__, file=sys.stderr)
        return False


def completed(record):
    settlement = record.get('settlement') or {}
    if record.get('chrome_rendezvous') == 'OWN_WORKLOAD_PID':
        from cnt_chrome_rendezvous import matched
        if not (matched((record.get('preflight') or {}).get('rendezvous_canary'), canary=True)
                and matched(record.get('rendezvous_parameter'))):
            return False
    fields = ['ready']
    if record.get('workload') in ('page', 'full', 'cnt-matrix', 'cnt-recovery'):
        fields.append('page_nonce')
    if record.get('workload') == 'cnt-matrix':
        fields.append('matrix_completed')
    if record.get('workload') == 'cnt-recovery':
        fields.append('recovery_completed')
    if record.get('workload') == 'full':
        fields.extend(('extension_nonce', 'extension_unloaded'))
    if record.get('parent_probes') is True:
        fields.append('parent_probes_completed')
    if record.get('crash_readback') is True:
        fields.append('crash_readback_completed')
    normal = (record.get('quit_observed') in ('reply', 'qualified-eof')
              and type(record.get('exit_before_cleanup')) is int
              and record['exit_before_cleanup'] == 0
              and type(settlement.get('exit_code')) is int
              and settlement['exit_code'] == 0
              and settlement.get('workload_status') == 'exited')
    return bool(record.get('shutdown_observer') is False
                and all(type(record.get(k)) is bool for k in
                        ('diagnostic_only', 'parent_probes', 'crash_readback', 'crash_force_enable',
                         'shutdown_trace'))
                and record.get('workload') in ('empty', 'page', 'full', 'cnt-matrix', 'cnt-recovery')
                and record.get('browser_launched') is True
                and record.get('runtime_preparation_complete') is True
                and record.get('runtime_unchanged') is True
                and all(record.get(k) is True for k in fields)
                and settlement.get('zero_survivors') is True
                and settlement.get('unsettled') is False
                and settlement.get('failures') == []
                and not any(record.get(k) for k in
                            ('primary_failure', 'cleanup_failure', 'runtime_failure', 'evidence_io_failure'))
                and (record.get('intended_timeout') is True
                     if record.get('abnormal') is True else record.get('abnormal') is False and normal))


def passed(record):
    return bool(record.get('diagnostic_only') is False
                and record.get('workload') == 'full'
                and record.get('shutdown_observer') is False
                and record.get('parent_probes') is False
                and record.get('crash_readback') is False
                and record.get('shutdown_trace') is False
                and type(record.get('crash_force_enable')) is bool and completed(record))


def outcome(record):
    if record.get('workload') == 'cnt-matrix':
        # Never R4 acceptance: passed() requires the full workload.
        return 'MATRIX_ATTEMPT_COMPLETED' if completed(record) else 'BLOCKED'
    if record.get('workload') == 'cnt-recovery':
        # Never R4 acceptance either.
        return 'RECOVERY_ATTEMPT_COMPLETED' if completed(record) else 'BLOCKED'
    if record['diagnostic_only']:
        return 'DIAGNOSTIC_COMPLETED' if completed(record) else 'DIAGNOSTIC_FAILED'
    return 'SYNTHETIC_ATTEMPT_PASSED' if passed(record) else 'BLOCKED'


MATRIX_REFUSED_OPTIONS = ('abnormal', 'parent_probes', 'crash_readback', 'crash_force_enable', 'shutdown_trace')
MATRIX_RESULT_LIMIT = 8 * 1024 * 1024


def matrix_selection(args, record):
    """R6: all refusals and reads happen before any attempt root exists. Returns the plan."""
    import cnt_firefox_matrix as matrix
    options = [getattr(args, n, None) for n in ('capture', 'capture_sha256', 'matrix_case', 'matrix_input')]
    if record['workload'] != 'cnt-matrix':
        # The capture options are shared with cnt-recovery; the case options never are.
        shared = 2 if record['workload'] == 'cnt-recovery' else 0
        require(not any(o is not None for o in options[shared:]), 'Matrix options require the matrix workload')
        return None
    require(args.engine == 'firefox' and not getattr(args, 'chrome_rendezvous', None)
            and not any(getattr(args, n, False) for n in MATRIX_REFUSED_OPTIONS),
            'Matrix workload option refused')
    require(args.capture is not None and args.capture_sha256 is not None, 'Matrix capture required')
    entry = matrix.case(args.matrix_case)
    require(entry['runnable'], 'Matrix case not drivable')
    capture = Path(args.capture)
    require(capture.is_absolute() and capture.resolve() == capture, 'Capture absent or not a regular file')
    identity = matrix.verify_capture(capture, expected_sha256=args.capture_sha256)
    record.update(matrix_case=entry['id'], capture_identity=identity)
    plan = {'entry': entry, 'capture': matrix.file_bytes(capture, matrix.XPI_LIMIT), 'source': [],
            'selection': []}
    require(hashlib.sha256(plan['capture']).hexdigest() == matrix.XPI_SHA256, 'Capture digest mismatch')
    if entry['source'] is None:
        require(args.matrix_input is None, 'Matrix input undeclared')
        return plan
    require(args.matrix_input is not None, 'Matrix input required')
    parts = matrix_source_parts(Path(args.matrix_input), entry)
    readiness = None
    if entry['source'] == 'S-MULTI':
        # MULTIPART-B-PREP1: a B dependent consumes only the S-MULTI attempt of its own claim root (a
        # sibling of this attempt), whose readiness matrix_source_parts() has just required. The ready
        # minimum part digests are recorded for the in-session pre-selection proof.
        same_root = Path(args.matrix_input).parent == Path(args.scratch).absolute().parent
        require(same_root, 'Matrix input source invalid')
        readiness = {'ready': True, 'same_root': same_root,
                     'minimum_part_sha256': [hashlib.sha256(raw).hexdigest() for raw in parts]}
    mutation = None
    if entry['mutation'] is not None:
        # MALFORMED-D-PREP1: the unmutated same-root source parts are kept beside the mutated input
        # (inputs/original), so the source binding and the post-vs-source relation use the real
        # source bytes. `source` below stays the restore input, as before.
        plan['original'] = list(parts)
        at = len(parts) - 1 if entry['mutate_part'] == -1 else entry['mutate_part'] - 1
        require(0 <= at < len(parts), 'Mutation target absent')
        parts[at], mutation = matrix.mutate(parts[at], entry['mutation'])
        mutation['part_number'] = at + 1
    plan['source'] = parts
    plan['selection'] = matrix.select_parts(parts, entry['selection'])
    record['matrix_inputs'] = {
        'source_case': entry['source'], 'artifact': entry['artifact'], 'selection_kind': entry['selection'],
        'source': [{'part_number': n, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                   for n, raw in enumerate(parts, 1)],
        'mutation': mutation,
        'selection': [{'named_part': named, 'slot': slot, 'part_number': number,
                       'sha256': hashlib.sha256(raw).hexdigest()} for named, raw, number, slot in plan['selection']]}
    if 'original' in plan:
        record['matrix_inputs']['original'] = [{'part_number': n, 'bytes': len(raw),
                                                'sha256': hashlib.sha256(raw).hexdigest()}
                                               for n, raw in enumerate(plan['original'], 1)]
    if readiness is not None:
        record['matrix_inputs']['source_readiness'] = readiness
    return plan


def matrix_source_parts(source, entry):
    """Native parts of a completed source attempt, bound to its own result.json projection.

    The source is a link-free attempt root under managed scratch; no live profile or other
    location can be named. Every part digest must equal the recorded native readout digest.
    """
    import cnt_firefox_matrix as matrix
    from cnt_confinement import SCRATCH
    require(source.is_absolute() and source.is_relative_to(SCRATCH) and source.resolve() == source
            and source.is_dir(), 'Matrix input source invalid')
    try:
        raw = matrix.file_bytes(source / 'result.json', MATRIX_RESULT_LIMIT)
        result = json.loads(raw)
    except (VerificationError, ValueError):
        raise VerificationError('Matrix input source invalid') from None
    facts = result.get('matrix') if isinstance(result, dict) else None
    require(isinstance(facts, dict) and result.get('status') == 'MATRIX_ATTEMPT_COMPLETED'
            and facts.get('case') == entry['source'] and facts.get('completed') is True,
            'Matrix input source invalid')
    # R6 REPAIR2: an S-RICH source is usable only when its fixed source readiness held; MULTIPART-B-PREP1:
    # likewise an S-MULTI source (cnt_firefox_matrix.source_ready).
    require(matrix.source_ready(facts, entry), 'Matrix input source invalid')
    recorded = ((facts.get('artifacts') or {}).get(entry['artifact']) or {}).get('parts')
    require(isinstance(recorded, list) and recorded, 'Matrix input source invalid')
    parts = []
    for number, item in enumerate(recorded, 1):
        require(isinstance(item, dict) and item.get('index') == number - 1
                and item.get('name_class') == f'NATIVE_PART_{number}', 'Matrix input source invalid')
        path = plain_descendant(source, f'artifacts/{entry["artifact"]}/part-{number}.json')
        data = matrix.file_bytes(path, 512 * 1024 * 1024)
        require(hashlib.sha256(data).hexdigest() == item.get('sha256') and len(data) == item.get('bytes'),
                'Matrix input digest mismatch')
        parts.append(data)
    return parts


def materialize_matrix(run, plan, record):
    """Inside the fresh attempt: the capture copy and the declared inputs, each re-verified."""
    import cnt_firefox_matrix as matrix
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
        require(hashlib.sha256(matrix.file_bytes(path, len(data))).hexdigest()
                == hashlib.sha256(data).hexdigest(), 'Matrix input digest mismatch')
    write(run / 'capture/clear-new-tab.xpi', plan['capture'])
    record['capture_copy'] = matrix.verify_capture(run / 'capture/clear-new-tab.xpi')
    for number, data in enumerate(plan['source'], 1):
        write(run / f'inputs/source/part-{number}.json', data)
    for number, data in enumerate(plan.get('original') or [], 1):
        write(run / f'inputs/original/part-{number}.json', data)
    for named, data, _, slot in plan['selection']:
        write(run / 'inputs/select' / str(slot) / matrix.INPUT_NAME.format(named), data)
    record['matrix_materialized'] = True


RECOVERY_REFUSED_OPTIONS = MATRIX_REFUSED_OPTIONS


def recovery_selection(args, record):
    """BUX5B1: every refusal, the capture and the digest-bound plan (with its same-root source inputs)
    are verified before any attempt root. Returns the in-memory plan, never recorded."""
    import cnt_firefox_matrix as matrix
    options = [getattr(args, n, None) for n in ('recovery_plan', 'recovery_plan_sha256')]
    if record['workload'] != 'cnt-recovery':
        require(not any(o is not None for o in options), 'Recovery options require the recovery workload')
        return None
    require(args.engine == 'firefox' and not getattr(args, 'chrome_rendezvous', None)
            and not any(getattr(args, n, False) for n in RECOVERY_REFUSED_OPTIONS),
            'Recovery workload option refused')
    require(args.capture is not None and args.capture_sha256 is not None
            and all(o is not None for o in options), 'Recovery capture required')
    capture = Path(args.capture)
    require(capture.is_absolute() and capture.resolve() == capture, 'Capture absent or not a regular file')
    record['capture_identity'] = matrix.verify_capture(capture, expected_sha256=args.capture_sha256)
    import cnt_firefox_recovery as recovery
    plan = recovery.load_plan(Path(args.recovery_plan), args.recovery_plan_sha256, Path(args.scratch))
    plan['_capture'] = matrix.file_bytes(capture, matrix.XPI_LIMIT)
    require(hashlib.sha256(plan['_capture']).hexdigest() == matrix.XPI_SHA256, 'Capture digest mismatch')
    record.update(recovery_role=plan['role'], recovery_scenario=plan['scenario'])
    return plan


def attempt(args):
    started = time.monotonic()
    record = {'status': 'IN_PROGRESS', 'engine': args.engine, 'abnormal': args.abnormal,
              'browser_launched': False, 'captured_code_loaded': False,
              'workload': getattr(args, 'workload', 'full'),
              'crash_readback': getattr(args, 'crash_readback', False),
              'crash_force_enable': getattr(args, 'crash_force_enable', False),
              'shutdown_trace': getattr(args, 'shutdown_trace', False),
              'shutdown_observer': False, 'parent_probes': getattr(args, 'parent_probes', False),
              'runtime_preparation_complete': False, 'runtime_unchanged': None,
              'runtime_digest_scope': 'Content and link text only; excludes modes',
              'runtime_verification': 'NOT_APPLICABLE_PREPARATION_INCOMPLETE',
              'runtime_measurement': {'state': 'NOT_STARTED'},
              'sandbox_disables': args.nested_sandbox_exception,
              'mach_services': list(args.service),
              'configd_compatibility': CONFIGD in args.service,
              'native_semantics': 'NOT_EXECUTED'}
    if record['configd_compatibility']:
        record['permission_amendment'] = 'R4-CONT7 configd lookup (trusted synthetic only)'
    rendezvous = list(getattr(args, 'chrome_rendezvous', None) or [])
    if args.engine == 'chrome' or rendezvous:
        # Firefox records gain no key unless the option was (wrongly) requested.
        record['chrome_rendezvous'] = 'OWN_WORKLOAD_PID' if rendezvous else 'NOT_SELECTED'
    rendezvous_selected = record.get('chrome_rendezvous') == 'OWN_WORKLOAD_PID'
    sandboxed = evidence = None
    record['diagnostic_only'] = (record['workload'] != 'full' or record['parent_probes']
                                 or record['crash_readback'] or record['shutdown_trace'])
    run = selected = plan = recovery_plan = None
    stage = 'selection'
    try:
        # R6: every cnt-matrix refusal and capture/input verification precedes the root.
        plan = matrix_selection(args, record)
        # BUX5B1: likewise every cnt-recovery refusal, the capture and the plan.
        recovery_plan = recovery_selection(args, record)
        # Refused before any root, runtime or probe; no attempt directory exists to persist into.
        require(not record['configd_compatibility'] or args.engine == 'firefox',
                'configd compatibility requires the validated frozen Firefox lane')
        require(all(choice == RENDEZVOUS_CHOICE for choice in rendezvous), 'Chrome rendezvous option invalid')
        require(len(rendezvous) <= 1, 'Duplicate rendezvous selection')
        require(not rendezvous or args.engine == 'chrome', 'Chrome rendezvous requires the selected Chrome lane')
        if args.engine == 'chrome':
            # Firefox TCP port, nested-sandbox exceptions and Firefox diagnostics are not a
            # Chrome contract. An abnormal Chrome attempt must first finish all useful work.
            require(not (record['crash_force_enable'] or record['crash_readback'] or record['parent_probes']
                         or record['shutdown_trace'] or args.nested_sandbox_exception),
                    'Firefox-only option refused for Chrome')
            require(not args.abnormal or record['workload'] == 'full',
                    'Chrome abnormal attempt requires the full workload')
        stage = 'attempt-root'
        # The callback runs immediately after mkdir, before child setup can fail.
        run = fresh_attempt(args.scratch, on_created=lambda root: initialize(root, record))
        record.pop('_created_root', None)
        if plan is not None:
            stage = 'matrix-inputs'
            materialize_matrix(run, plan, record)
        if recovery_plan is not None:
            # The capture copy only; recovery inputs are written by the role, in-session.
            stage = 'recovery-inputs'
            materialize_matrix(run, {'capture': recovery_plan['_capture'], 'source': [], 'selection': []}, record)
            record['recovery_materialized'] = record.pop('matrix_materialized')
        stage = 'runtime-preparation'
        executable, roots, digest = prepare_runtime(args, run, record)
        if args.engine == 'chrome':
            selected = Path(args.runtime)
        record['runtime_snapshot_sha256'] = digest
        record['executable_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
        stage = 'confinement-preflight'
        python = Path(sys.executable).resolve(strict=True)
        roots = sorted(set(roots + runtime_roots(python)))
        outside = run.parent / (run.name + '-outside-canary')
        with outside.open('x') as stream:
            stream.write('synthetic private canary')
        automation_port = None
        if args.engine == 'firefox':
            with reserve_port() as reservation:
                automation_port = reservation.getsockname()[1]
        if rendezvous_selected:
            # Sibling of the owned run, outside the sandbox's writable subpath (the same
            # placement as the outside canary); created fresh and private for this attempt.
            evidence = run.parent / (run.name + '-rendezvous')
            evidence.mkdir(mode=0o700)
            evidence.chmod(0o700)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            preflight = run_probe(run, python, roots, outside, listener.getsockname()[1],
                                  args.service, automation_port=automation_port,
                                  firefox_child_ipc=args.engine == 'firefox' and record['signature'].get('frozen') is True,
                                  firefox_executable=executable,
                                  evidence=record.setdefault('preflight', {}),
                                  **({'chrome_rendezvous': True, 'chrome_executable': executable,
                                      'rendezvous_evidence': evidence} if rendezvous_selected else {}))
        record['preflight'] = preflight
        preflight['automation_port'] = automation_port
        if automation_port is not None:
            preflight['reservation_handoff'] = 'Same-port canaries then reacquisition; bind/close is not endpoint identity.'
        require(preflight['status'] == 'CANARIES_PASSED_NOT_BROWSER_QUALIFICATION',
                'Confinement preflight failed')
        command = ['/usr/bin/sandbox-exec', '-f', str(run / 'confinement.sb'),
                   *arguments(args.engine, executable, run, automation_port)]
        if rendezvous_selected:
            # supervisor -> cnt_pipe_exec (CDP descriptors) -> helper -> sandbox-exec -D -> Chrome.
            from cnt_chrome_rendezvous import wrap
            sandboxed, command = command, wrap(evidence, 'browser', command)
        if automation_port is not None:
            stage = 'port-reacquisition'
            with reserve_port(automation_port):
                pass
        require(hashlib.sha256((run / 'confinement.sb').read_bytes()).hexdigest()
                == preflight['policy_sha256'], 'Canaried launch policy changed')
        if recovery_plan is not None:
            # Immediately before the launch: the fresh, contained, generated-only profile.
            stage = 'recovery-freshness'
            import cnt_firefox_recovery as recovery
            record['recovery_freshness'] = recovery.prove_fresh_profile(
                recovery_plan, run, firefox_user_js(automation_port), created_exclusive=True)
        stage = 'browser'
        record['browser_launched'] = True
        launch_empty(command, run, args.engine, args.abnormal, automation_port,
                     args.nested_sandbox_exception, result=record,
                     workload=record['workload'], parent_probes=record['parent_probes'],
                     crash_readback=record['crash_readback'],
                     crash_force_enable=record['crash_force_enable'],
                     shutdown_trace=record['shutdown_trace'],
                     **({'expected_version': record.get('runtime_bundle_version')}
                        if args.engine == 'chrome' else {}),
                     **({'rendezvous': {'evidence': evidence, 'argv': sandboxed}} if rendezvous_selected else {}),
                     **({'matrix_case': plan['entry']['id']} if plan is not None else {}),
                     **({'recovery_plan': recovery_plan} if recovery_plan is not None else {}))
        if plan is not None and record.get('matrix_completed') is True:
            record['native_semantics'] = 'EXECUTED_CASE_RECORDED'
        if recovery_plan is not None and record.get('recovery_completed') is True:
            record['native_semantics'] = 'EXECUTED_RECOVERY_ROLE_RECORDED'
    except BaseException as error:
        record_failure(record, 'primary_failure', error, stage)
        if not isinstance(error, Exception):
            raise
    finally:
        # Root may have been created before setup failed. initialize records it
        # in memory without exposing it in exported attempt facts.
        primary = sys.exception()
        run = run or record.pop('_created_root', None)
        record.pop('_created_root', None)
        if run is not None:
            expected = record.get('runtime_snapshot_sha256')
            if record['runtime_preparation_complete'] is True:
                record['runtime_verification'] = ('POST_EXECUTION' if record['browser_launched']
                                                  else 'COMPLETED_PREPARATION_NO_LAUNCH')
                # INCOMPLETE until tree_digest returns: an absent digest is never a mismatch.
                trace = {}
                record['runtime_measurement'] = {'state': 'INCOMPLETE', 'digest_complete': False}
                try:
                    observed = tree_digest(runtime_measurement_target(args.engine, run, record, selected),
                                           trace=trace)
                    unchanged = observed == expected
                    record['runtime_measurement'] = {
                        'state': 'MATCH' if unchanged else 'MISMATCH',
                        'digest_complete': True, 'operation': 'digest-comparison',
                        'code': None if unchanged else 'RUNTIME_CHANGED',
                        'entries_enumerated': measurement_count(trace.get('entries_enumerated')),
                        'entries_measured': measurement_count(trace.get('entries_measured'))}
                    record['runtime_observed_sha256'] = observed
                    record['runtime_unchanged'] = unchanged
                    require(record['runtime_unchanged'], 'Frozen runtime changed')
                except BaseException as error:
                    record_failure(record, 'runtime_failure', error, 'runtime-verification')
                    record['runtime_unchanged'] = False
                    if record['runtime_measurement'].get('state') == 'INCOMPLETE':
                        record['runtime_measurement'] = incomplete_measurement(trace, error)
                    if not isinstance(error, Exception) and primary is None:
                        # Persist before delivering interruption below.
                        record['status'] = outcome(record)
                        if not persist(run, record):
                            record.setdefault('evidence_io_failure', True)
                            record['evidence_persistence_failed'] = True
                        raise
        record['elapsed_seconds'] = time.monotonic() - started
        record['status'] = outcome(record)
        if run is not None:
            if not persist(run, record):
                record.setdefault('evidence_io_failure', True)
                record['evidence_persistence_failed'] = True
                record['status'] = outcome(record)
    print(json.dumps(record))
    # A completed matrix case exits 0 too; host runners still decide from result.json status.
    return 0 if passed(record) or record['status'] in ('MATRIX_ATTEMPT_COMPLETED', 'RECOVERY_ATTEMPT_COMPLETED') else 2


def initialize(run, record):
    if not persist(run, record):
        record.setdefault('evidence_io_failure', True)
        record['evidence_persistence_failed'] = True
    record['_created_root'] = run


if __name__ == '__main__':
    main()
