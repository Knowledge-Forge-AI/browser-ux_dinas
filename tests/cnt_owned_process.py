"""Private-channel cleanup; process observation never authorizes signals."""
import contextlib
import json
import os
from pathlib import Path
import select
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time

from cnt_native_evidence import require, VerificationError


def observe_child(pid):
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def group_rows(group, read=None):
    """Observation only. No ancestry expansion and no per-PID signals."""
    read = read or subprocess.check_output
    raw = read(['/bin/ps', '-axo', 'pid=,pgid=,stat='], text=True, timeout=2)
    rows = [line.split() for line in raw.splitlines()]
    return [(int(pid), state) for pid, pgid, state in rows if int(pgid) == group]


def escaped_count(run, group, extra=()):
    """Observation only, bounded to unique profile/runtime argument markers.

    Does not detect an arbitrary daemon that strips these arguments. Never
    exports argv and never grants signal authority to a matching process.
    `extra` adds caller-selected owned-path markers; empty keeps the default set.
    """
    raw = subprocess.check_output(['/bin/ps', '-axo', 'pid=,pgid=,command='], text=True, timeout=2)
    markers = ('--user-data-dir=' + str(run / 'profile'), str(run / 'runtime/'), '-profile ' + str(run / 'profile'),
               *extra)
    return sum(1 for line in raw.splitlines()
               if len(parts := line.split(None, 2)) == 3 and int(parts[1]) != group
               and int(parts[0]) != os.getpid() and any(m in parts[2] for m in markers))


@contextlib.contextmanager
def defer_interrupt():
    """Coalesce pending SIGINT, restore disposition, then deliver its effect."""
    previous = signal.getsignal(signal.SIGINT)
    require(previous in (signal.SIG_DFL, signal.SIG_IGN) or callable(previous),
            "Unsupported native SIGINT disposition")
    pending = []
    signal.signal(signal.SIGINT, lambda sig, frame: pending.append((sig, frame)))
    try:
        yield
    finally:
        primary = sys.exception()
        signal.signal(signal.SIGINT, previous)
        if pending and previous != signal.SIG_IGN:
            try:
                if previous == signal.SIG_DFL:
                    signal.raise_signal(signal.SIGINT)
                else:
                    previous(*pending[0])
            except BaseException as interrupt:
                if primary is not None:
                    raise primary from interrupt
                raise


class OwnedProcess:
    """Only the private supervisor has group signal authority.

    Inspection and child status are qualification evidence, never authority.
    Competing waiters can invalidate evidence but cannot redirect cleanup signals.
    """
    markers = ()

    def __init__(self, command, run, env, log, pipe_fds=(), evidence=None, markers=()):
        require(hasattr(os, 'WNOWAIT') and hasattr(os, 'waitid'), 'WNOWAIT required')
        require(threading.current_thread() is threading.main_thread(), 'Main-thread owner required')
        require(sys.version_info >= (3, 11), 'Python 3.11 or newer required')
        require(signal.getsignal(signal.SIGINT) in (signal.SIG_DFL, signal.SIG_IGN)
                or callable(signal.getsignal(signal.SIGINT)), 'Unsupported native SIGINT disposition')
        self.result, self.messages, self.buffer = None, [], b''
        self.workload_pid = self.returncode = None
        self.process = self.control = None
        self.cleaning = self.done = self.eof = self.ack = False
        self.workload_status = None
        self.token = secrets.token_hex(32)
        self.run = Path(run)
        self.markers = tuple(markers)
        require(all(type(m) is str and m.startswith(str(self.run) + '/') for m in self.markers),
                'Escape markers must be owned attempt paths')
        self.control, child = socket.socketpair()
        self.control.settimeout(1)
        argv = [sys.executable, '-B', str(Path(__file__).with_name('cnt_supervisor.py')),
                str(child.fileno()), json.dumps(list(pipe_fds)), self.token, *command]
        try:
            self.process = subprocess.Popen(argv, cwd=run, env=env, stdout=log, stderr=log,
                                            start_new_session=True,
                                            pass_fds=(child.fileno(), *pipe_fds))
        except BaseException:
            self.control.close()
            raise
        finally:
            child.close()
        try:
            self.until(lambda: self.workload_pid is not None, 5)
            (Path(run) / 'process-private.json').write_text(json.dumps({
                'supervisor': self.process.pid, 'workload': self.workload_pid}))
        except BaseException as primary:
            if evidence is not None:
                evidence['primary_failure'] = {'stage': 'supervisor-startup', 'type': type(primary).__name__}
            try:
                self.settle()
            except BaseException as cleanup:
                if evidence is not None:
                    evidence['cleanup_failure'] = {'stage': 'supervisor-startup', 'type': type(cleanup).__name__}
            finally:
                if evidence is not None:
                    evidence['settlement'] = self.result
            raise

    def receive(self, timeout=.05):
        if self.eof or not select.select([self.control], [], [], timeout)[0]:
            return
        raw = self.control.recv(65536)
        if not raw:
            self.eof = True
            return
        self.buffer += raw
        require(len(self.buffer) <= 65536, 'Oversized supervisor response')
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            msg = json.loads(line)
            require(isinstance(msg, dict) and msg.get('token') == self.token,
                    'Supervisor authentication failure')
            self.messages.append(msg)
            if 'started' in msg:
                require(msg['supervisor'] == self.process.pid, 'Supervisor mismatch')
                require(type(msg['started']) is int and msg['started'] > 0, 'Invalid workload')
                self.workload_pid = msg['started']
            if 'exit' in msg:
                require(type(msg['exit']) is int, 'Missing workload status')
                self.returncode = msg['exit']
            if msg.get('cleanup') == 'pre-kill':
                require(msg.get('workload_status') in ('exited', 'unknown-before-kill'),
                        'Invalid cleanup status')
                self.workload_status = msg['workload_status']
                self.ack = True

    def until(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while not predicate():
            require(time.monotonic() < deadline, 'Owned workload timeout')
            self.receive()
            require(not self.eof, 'Supervisor control EOF')
            require(observe_child(self.process.pid) is None, 'Supervisor exited early')

    def _failure(self, error):
        self.result['failures'].append(type(error).__name__)
        self.result.update(unsettled=True, zero_survivors=False)

    def _reap(self):
        # Popen.wait suppresses ECHILD on some Python versions; use waitpid
        # directly so auto-reaping and competing waiters cannot fabricate zero.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.process.pid, os.WNOHANG)
            if pid:
                self.process.returncode = os.waitstatus_to_exitcode(status)
                require(self.process.returncode == -signal.SIGKILL,
                        'Unexpected supervisor status')
                return
            time.sleep(.02)
        raise subprocess.TimeoutExpired('owned supervisor', 5)

    def settle(self):
        if self.done:
            return self.result
        require(not self.cleaning, 'Cleanup re-entry refused')
        self.cleaning = True
        self.result = {'exit_code': self.returncode, 'zero_survivors': False,
                       'unsettled': True, 'failures': []}
        primary = None
        with defer_interrupt():
            try:
                self.result.update(self._settle())
            except BaseException as error:
                self._failure(error)
                primary = error
            finally:
                try:
                    self.control.close()
                    self._reap()
                except BaseException as error:
                    self._failure(error)
                    if primary is None:
                        primary = error
                self.done, self.cleaning = True, False
            if primary is not None and not isinstance(primary, Exception):
                raise primary
        return self.result

    def _settle(self):
        self.control.sendall(json.dumps({'token': self.token, 'command': 'shutdown'}).encode() + b'\n')
        deadline = time.monotonic() + 5
        status = None
        while time.monotonic() < deadline:
            self.receive(.02)
            status = observe_child(self.process.pid)
            if status is not None:
                break
        require(status is not None and status.si_pid == self.process.pid, 'Supervisor status unavailable')
        # Drain authenticated acknowledgement before inspecting the still-unreaped
        # group. No process-table result is ever sent to a signal syscall.
        self.receive(0)
        require(self.ack and (self.workload_status == 'unknown-before-kill'
                             or self.returncode is not None), 'Incomplete cleanup acknowledgement')
        require(status.si_code == os.CLD_KILLED and status.si_status == signal.SIGKILL,
                'Unexpected supervisor termination')
        rows = group_rows(self.process.pid)
        require(observe_child(self.process.pid) == status, 'Lost supervisor observation')
        survivors = [pid for pid, state in rows
                     if pid != self.process.pid and not state.startswith('Z')]
        escapes = escaped_count(self.run, self.process.pid, self.markers)
        return {'exit_code': self.returncode, 'workload_status': self.workload_status,
                'observed_process_count': len(rows),
                'observed_escapes': escapes, 'survivors': survivors,
                'zero_survivors': not survivors and not escapes,
                'unsettled': bool(survivors or escapes)}
