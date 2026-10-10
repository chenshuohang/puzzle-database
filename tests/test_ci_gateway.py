import ctypes
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest


GATEWAY = Path(__file__).parents[1] / 'deploy' / 'ci-gateway.py'
COMMIT = 'b' * 40
WRAPPER = '''import importlib.util, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location('fixture_gateway', sys.argv[1])
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
gateway.os.getuid = lambda: 0
if len(sys.argv) > 6 and sys.argv[6] == 'forward-fail':
    original = gateway.Forwarder.consume
    def failed_forward(self, block):
        original(self, block)
        raise OSError('SENSITIVE_FIXTURE_ERROR')
    gateway.Forwarder.consume = failed_forward
sys.exit(gateway.entrypoint(root=sys.argv[2], release_script=sys.argv[3],
                           idle_seconds=float(sys.argv[4]), receive_seconds=float(sys.argv[5])))
'''
HELPER = '''import hashlib, json, os, pathlib, stat, sys
root = pathlib.Path(__file__).parent
incoming = pathlib.Path(sys.argv[1])
payload = (incoming / 'release.tar').read_bytes()
(root / 'received.tar').write_bytes(payload)
mode = (root / 'mode').read_text()
gate = os.open(root / 'gate', os.O_RDWR) if mode == 'hold' else None
lock_inode = (root / 'gateway' / 'deploy.lock').stat().st_ino
has_lock_fd = False
for entry in pathlib.Path('/proc/self/fd').iterdir():
    try:
        has_lock_fd |= os.fstat(int(entry.name)).st_ino == lock_inode
    except OSError:
        pass
(root / 'child.json').write_text(json.dumps({
    'pid': os.getpid(), 'sid': os.getsid(0), 'pgid': os.getpgrp(),
    'commit': sys.argv[2], 'checksum': sys.argv[3],
    'hash': hashlib.sha256(payload).hexdigest(),
    'stdin_eof': sys.stdin.buffer.read() == b'', 'has_lock_fd': has_lock_fd,
    'incoming': str(incoming), 'directory_mode': stat.S_IMODE(incoming.stat().st_mode),
    'log_mode': stat.S_IMODE((incoming / 'release.log').stat().st_mode)}))
print('service_active=true', flush=True)
print('Created private backup: /SENSITIVE_BACKUP_PATH', flush=True)
print('private_backup_directory=/SENSITIVE_BACKUP_PATH', flush=True)
print('SENSITIVE_MEMBER_VALUE', file=sys.stderr, flush=True)
print('baseline_rows=7', flush=True)
if gate is not None:
    os.read(gate, 1)
    os.close(gate)
if mode == 'fail':
    print('preservation_check_failed=true', file=sys.stderr, flush=True)
    sys.exit(23)
(root / 'child_done').write_text('complete')
sys.stdout.write('deployed_commit=' + sys.argv[2])
sys.stdout.flush()
'''


@unittest.skipUnless(sys.platform == 'linux', 'gateway deployment uses Linux flock and process sessions')
class CiGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reap the orphaned fixture child after deliberately killing its parent.
        cls.libc = ctypes.CDLL(None, use_errno=True)
        original = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(original), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'cannot query fixture subreaper')
        cls.original_subreaper = original.value
        if cls.libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'cannot adopt fixture child')

    @classmethod
    def tearDownClass(cls):
        cls.libc.prctl(36, cls.original_subreaper, 0, 0, 0)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='puzarchive-gateway-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.gateway_root = self.root / 'gateway'
        self.gateway_root.mkdir(mode=0o700)
        self.helper = self.root / 'release.sh'
        self.helper.write_text('exec ' + sys.executable + ' "$(dirname -- "$0")/helper.py" "$@"\n')
        (self.root / 'helper.py').write_text(HELPER)
        (self.root / 'mode').write_text('done')
        os.mkfifo(self.root / 'gate', 0o600)
        self.processes = []
        self.addCleanup(self.stop_fixtures)

    def stop_fixtures(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        state = self.root / 'child.json'
        if state.exists():
            pid = json.loads(state.read_text())['pid']
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass

    def archive(self, corrupt=False):
        sources = {'server.mjs': b'fixture server', 'db.mjs': b'fixture database',
                   'docs/penpa.md': b'fixture spec', 'binary.dat': bytes(range(256)) * 128}
        hashes = {name: hashlib.sha256(body).hexdigest() for name, body in sources.items()}
        if corrupt:
            sources['db.mjs'] += b' changed after manifest'
        sources['.release.json'] = json.dumps({'commit': COMMIT, 'files': hashes}).encode()
        result = io.BytesIO()
        with tarfile.open(fileobj=result, mode='w') as tar:
            for name, body in sources.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                member.size = len(body)
                tar.addfile(member, io.BytesIO(body))
            data = tarfile.TarInfo('data')
            data.type = tarfile.DIRTYPE
            data.mode = 0o755
            tar.addfile(data)
        return result.getvalue()

    def wire(self, payload=None):
        payload = self.archive() if payload is None else payload
        header = json.dumps({'commit': COMMIT, 'sha256': hashlib.sha256(payload).hexdigest()}).encode()
        return header + b'\n' + payload

    def start(self, idle_seconds=1, receive_seconds=3, mode='normal'):
        process = subprocess.Popen([sys.executable, '-c', WRAPPER, str(GATEWAY),
                                    str(self.gateway_root), str(self.helper),
                                    str(idle_seconds), str(receive_seconds), mode],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.fixture_prefix = b''
        self.processes.append(process)
        return process

    def wait_marker(self, process, marker):
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 5
            while marker not in process.fixture_prefix:
                ready = selector.select(max(0, deadline - time.monotonic()))
                self.assertTrue(ready, 'fixture did not reach expected phase')
                block = os.read(process.stdout.fileno(), 4096)
                self.assertTrue(block, 'gateway exited before expected phase')
                process.fixture_prefix += block

    def finish(self, process, wire=None):
        stdout, stderr = process.communicate(input=wire, timeout=5)
        return process.returncode, process.fixture_prefix + (stdout or b''), stderr

    def send(self, wire):
        return self.finish(self.start(), wire)

    def feed_and_close(self, process, wire):
        process.stdin.write(wire)
        process.stdin.close()
        process.stdin = None

    def assert_lock_free(self):
        with (self.gateway_root / 'deploy.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assert_lock_busy(self):
        with (self.gateway_root / 'deploy.lock').open('a') as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def assert_no_release(self):
        self.assertFalse((self.root / 'child.json').exists())
        self.assertFalse(list(self.gateway_root.glob('incoming-*')))
        self.assert_lock_free()

    def release_gate(self):
        fd = os.open(self.root / 'gate', os.O_WRONLY | os.O_NONBLOCK)
        try:
            os.write(fd, b'1')
        finally:
            os.close(fd)

    def start_held_release(self, mode='normal'):
        for name in ('child.json', 'child_done'):
            (self.root / name).unlink(missing_ok=True)
        (self.root / 'mode').write_text('hold')
        process = self.start(mode=mode)
        self.feed_and_close(process, self.wire())
        self.wait_marker(process, b'service_active=true\n')
        return process, json.loads((self.root / 'child.json').read_text())

    def test_binary_protocol_eof_and_safe_release_output(self):
        payload = self.archive()
        code, stdout, stderr = self.send(self.wire(payload))
        self.assertEqual(code, 0, stderr.decode())
        self.assertEqual((self.root / 'received.tar').read_bytes(), payload)
        state = json.loads((self.root / 'child.json').read_text())
        self.assertEqual(state['commit'], COMMIT)
        self.assertEqual(state['checksum'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(state['checksum'], state['hash'])
        self.assertTrue(state['stdin_eof'])
        self.assertTrue(state['has_lock_fd'])
        self.assertEqual(state['pid'], state['sid'])
        self.assertEqual(state['pid'], state['pgid'])
        self.assertEqual(state['directory_mode'], 0o700)
        self.assertEqual(state['log_mode'], 0o600)
        self.assertIn(b'private_backup_created=true', stdout)
        self.assertIn(b'baseline_rows=7', stdout)
        self.assertIn(b'deployed_commit=' + COMMIT.encode(), stdout)
        self.assertNotIn(b'SENSITIVE_', stdout + stderr)
        self.assertNotIn(str(self.root).encode(), stdout + stderr)
        self.assertFalse(list(self.gateway_root.glob('incoming-*')))
        self.assert_lock_free()

    def test_partial_header_and_body_have_a_bounded_idle_failure(self):
        for fragment in (b'{"commit":', self.wire()[:-100]):
            with self.subTest(fragment_size=len(fragment)):
                process = self.start()
                self.wait_marker(process, b'deployment_gateway_receiving=true\n')
                process.stdin.write(fragment)
                process.stdin.flush()
                process.wait(timeout=5)
                code, stdout, stderr = self.finish(process)
                self.assertNotEqual(code, 0)
                self.assertIn(b'deployment_gateway_receive_idle_timeout=true', stdout)
                self.assertIn(b'deployment_gateway_failed=true', stderr)
                self.assert_no_release()

    def test_absolute_receive_deadline_is_not_extended_by_real_input_progress(self):
        process = self.start(idle_seconds=2, receive_seconds=1)
        self.wait_marker(process, b'deployment_gateway_receiving=true\n')
        started = time.monotonic()
        while process.poll() is None and time.monotonic() - started < 3:
            try:
                process.stdin.write(b' ')
                process.stdin.flush()
            except BrokenPipeError:
                break
            time.sleep(0.1)
        code, stdout, _ = self.finish(process)
        self.assertNotEqual(code, 0)
        self.assertIn(b'deployment_gateway_receive_timeout=true', stdout)
        self.assertNotIn(b'deployment_gateway_receive_idle_timeout=true', stdout)
        self.assert_no_release()

    def test_complete_archive_without_eof_does_not_start_a_release(self):
        process = self.start()
        process.stdin.write(self.wire())
        process.stdin.flush()
        process.wait(timeout=5)
        code, stdout, _ = self.finish(process)
        self.assertNotEqual(code, 0)
        self.assertNotIn(b'deployment_gateway_received=true', stdout)
        self.assert_no_release()

    def test_eof_truncation_identity_checksum_and_manifest_fail_before_release(self):
        wire = self.wire()
        invalid = (b'', b'{}\n', b'x' * 4097, wire[:30], wire[:-100],
                   wire[:-1] + bytes([wire[-1] ^ 1]), self.wire(self.archive(corrupt=True)))
        for body in invalid:
            with self.subTest(size=len(body)):
                code, stdout, stderr = self.send(body)
                self.assertNotEqual(code, 0)
                self.assertIn(b'deployment_gateway_failed=true', stderr)
                self.assertNotIn(b'deployment_gateway_release_started=true', stdout)
                self.assert_no_release()

    def test_busy_lock_is_checked_only_after_receiving_and_validating_the_archive(self):
        with (self.gateway_root / 'deploy.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            process = self.start()
            self.wait_marker(process, b'deployment_gateway_receiving=true\n')
            self.assertIsNone(process.poll())
            code, stdout, _ = self.finish(process, self.wire())
            self.assertNotEqual(code, 0)
            self.assertIn(b'deployment_gateway_received=true', stdout)
            self.assertIn(b'deployment_gateway_busy=true', stdout)
            code, stdout, _ = self.send(self.wire(self.archive(corrupt=True)))
            self.assertNotEqual(code, 0)
            self.assertNotIn(b'deployment_gateway_received=true', stdout)
            self.assertNotIn(b'deployment_gateway_busy=true', stdout)
        self.assert_no_release()

    def test_cancellation_before_eof_cleans_input_without_starting_a_child(self):
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                process = self.start()
                self.wait_marker(process, b'deployment_gateway_receiving=true\n')
                process.stdin.write(b'{')
                process.stdin.flush()
                process.send_signal(signum)
                code, stdout, _ = self.finish(process)
                self.assertEqual(code, 128 + signum)
                self.assertIn(b'deployment_gateway_cancelled=true', stdout)
                self.assert_no_release()

    def test_cancellation_after_child_start_waits_for_the_release_before_unlocking(self):
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                process, _ = self.start_held_release()
                process.send_signal(signum)
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=0.15)
                self.assert_lock_busy()
                code, stdout, _ = self.send(self.wire())
                self.assertNotEqual(code, 0)
                self.assertIn(b'deployment_gateway_busy=true', stdout)
                self.release_gate()
                code, stdout, stderr = self.finish(process)
                self.assertEqual(code, 128 + signum, stderr.decode())
                self.assertIn(b'deployment_gateway_cancelled=true', stdout)
                self.assertTrue((self.root / 'child_done').exists())
                self.assert_lock_free()
                self.assertFalse(list(self.gateway_root.glob('incoming-*')))

    def test_disconnected_stdout_does_not_interrupt_the_child(self):
        process, _ = self.start_held_release()
        process.stdout.close()
        process.stdout = None
        self.release_gate()
        code, _, stderr = self.finish(process)
        self.assertEqual(code, 0, stderr.decode())
        self.assertTrue((self.root / 'child_done').exists())
        self.assert_lock_free()

    def test_forwarding_error_waits_for_the_child_before_cleaning_incoming(self):
        process, state = self.start_held_release(mode='forward-fail')
        with self.assertRaises(subprocess.TimeoutExpired):
            process.wait(timeout=0.15)
        self.assertTrue(Path(state['incoming']).is_dir())
        self.assert_lock_busy()
        self.release_gate()
        code, stdout, stderr = self.finish(process)
        self.assertNotEqual(code, 0)
        self.assertIn(b'deployment_gateway_failed=true', stderr)
        self.assertNotIn(b'SENSITIVE_', stdout + stderr)
        self.assertTrue((self.root / 'child_done').exists())
        self.assertFalse(list(self.gateway_root.glob('incoming-*')))
        self.assert_lock_free()

    def test_sigkill_parent_leaves_child_output_and_lock_alive_until_completion(self):
        process, state = self.start_held_release()
        process.kill()
        code, _, _ = self.finish(process)
        self.assertEqual(code, -signal.SIGKILL)
        self.assert_lock_busy()
        log_path = Path(state['incoming']) / 'release.log'
        self.assertTrue(log_path.exists())
        self.release_gate()
        deadline = time.monotonic() + 5
        status = None
        while time.monotonic() < deadline:
            pid, current = os.waitpid(state['pid'], os.WNOHANG)
            if pid:
                status = current
                break
            time.sleep(0.02)
        self.assertIsNotNone(status, 'orphaned fixture release did not finish')
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertTrue((self.root / 'child_done').exists())
        self.assertIn(b'deployed_commit=' + COMMIT.encode(), log_path.read_bytes())
        self.assert_lock_free()

    def test_child_nonzero_status_remains_failure_and_releases_the_lock(self):
        (self.root / 'mode').write_text('fail')
        code, stdout, stderr = self.send(self.wire())
        self.assertNotEqual(code, 0)
        self.assertIn(b'preservation_check_failed=true', stdout)
        self.assertIn(b'deployment_gateway_failed=true', stderr)
        self.assertNotIn(b'deployed_commit=', stdout)
        self.assertNotIn(b'SENSITIVE_', stdout + stderr)
        self.assert_lock_free()


if __name__ == '__main__':
    unittest.main()
