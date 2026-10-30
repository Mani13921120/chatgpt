import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from app_catalog import App
from app_runtime import Sessions, save_app
from guardian import Guardian
import guardian_state as state


class GuardianStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.app = App.desktop(r'C:\Selected\app.exe')
        self.request = {'key': self.app.key, 'name': self.app.name, 'exe': self.app.executable,
                        'pid': 99, 'hwnd': 0, 'started': 123.0, 'cwd': r'C:\Selected', 'command': [self.app.executable, '--file', 'a.txt']}

    def tearDown(self):
        self.temp.cleanup()

    def test_queue_is_auth_only_validated_and_consumed_once(self):
        self.assertTrue(state.queue(self.directory, self.request))
        self.assertEqual(state.take_requests(self.directory, {self.app.key: self.app}), [self.request])
        self.assertEqual(state.take_requests(self.directory, {self.app.key: self.app}), [])
        self.assertFalse(Sessions().allows([self.app.key]))

    def test_unknown_removed_or_redirected_apps_cannot_be_launched(self):
        state.queue(self.directory, self.request)
        self.assertEqual(state.take_requests(self.directory, {}), [])
        state.queue(self.directory, dict(self.request, command=[r'C:\Other\bad.exe']))
        self.assertEqual(state.take_requests(self.directory, {self.app.key: self.app}), [])

    def test_request_cannot_inject_a_folder_unlock_action(self):
        state.queue(self.directory, dict(self.request, kind='folder_unlock', backup='untrusted'))
        self.assertEqual(state.take_requests(self.directory, {self.app.key: self.app}), [self.request])

    def test_runtime_state_rejects_a_recycled_pid(self):
        state.publish(self.directory, 'gui', Sessions())
        self.assertEqual(state.read(self.directory, 'gui')['pid'], os.getpid())
        with state.connection(self.directory) as con:
            con.execute("UPDATE guardian_runtime SET started=started-10 WHERE role='gui'")
        self.assertIsNone(state.read(self.directory, 'gui'))

    def test_disable_has_no_automatic_reenable_or_resurrection(self):
        state.set_enabled(self.directory, False)
        with patch('guardian.Monitor'):
            guardian = Guardian(self.directory, 'main.py', wake=Mock())
        self.assertFalse(guardian.tick())
        guardian.wake.assert_not_called()
        self.assertFalse(state.enabled(self.directory))

    def test_missing_gui_wakes_on_request_without_granting_a_session(self):
        with patch('guardian.Monitor') as monitor, patch.object(state, 'read', return_value=None):
            monitor.return_value.scan.return_value = ([self.request], [])
            monitor.return_value.known = set()
            wake = Mock(); wake.return_value.poll.return_value = None
            guardian = Guardian(self.directory, 'main.py', wake=wake)
            self.assertTrue(guardian.tick())
            self.assertTrue(guardian.tick())
        wake.assert_called_once()
        self.assertFalse(guardian.sessions.allows([self.app.key]))
        self.assertIn(self.app.key, state.pending_keys(self.directory))


@unittest.skipUnless(os.name == 'nt', 'Requires actual Windows detached processes and Qt tray runtime')
class WindowsGuardianTests(unittest.TestCase):
    def test_guardian_survives_gui_end_task_and_wakes_for_protected_app(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            module_root = str(Path(__file__).resolve().parent)
            script = directory / 'main.py'
            script.write_text('''
import sys, time
from pathlib import Path
sys.path.insert(0, MODULE_ROOT)
import guardian_state as state
from app_runtime import Sessions
directory=Path(__file__).resolve().parent
if '--guardian' in sys.argv:
    from guardian import run
    raise SystemExit(run(directory,__file__))
if '--guardian-wake' in sys.argv:
    (directory/'wake.txt').write_text(str(__import__('os').getpid()))
else:
    state.spawn(__file__,'--guardian')
state.publish(directory,'gui',Sessions())
time.sleep(90)
'''.replace('MODULE_ROOT', repr(module_root)), encoding='utf-8')
            unique = 'import time; time.sleep(60) # FaceGate disposable protected process'
            app = App('test:guarded-python', 'Disposable app', executable=sys.executable,
                      arguments=('-c', unique), process_paths=(sys.executable,))
            with sqlite3.connect(directory / 'users.db') as con:
                con.execute('CREATE TABLE locked_apps(path TEXT PRIMARY KEY COLLATE NOCASE,display_name TEXT,enabled INTEGER)')
                save_app(con, app)
            con.close()
            parent = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            child = None; guard_pid = None; wake_pid = None
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    snapshot = state.read(directory, 'guardian', script)
                    if snapshot:
                        guard_pid = snapshot['pid']; break
                    if parent.poll() is not None:
                        self.fail('GUI fixture failed: ' + parent.stderr.read().decode(errors='replace'))
                    time.sleep(0.1)
                self.assertIsNotNone(guard_pid, 'Independent guardian did not start')
                # Popen.kill uses TerminateProcess on Windows: the same abrupt
                # process termination used by End Task, with no close callback.
                parent.kill(); parent.wait(timeout=10)
                self.assertIsNotNone(state.read(directory, 'guardian', script))
                child = subprocess.Popen([sys.executable, '-c', unique])
                child.wait(timeout=15)
                self.assertNotEqual(child.returncode, 0, 'Protected app was not stopped')
                deadline = time.monotonic() + 20
                while not (directory / 'wake.txt').exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
                self.assertTrue((directory / 'wake.txt').exists(), 'Face authentication GUI was not relaunched')
                wake_pid = int((directory / 'wake.txt').read_text())
                requests = state.take_requests(directory, {app.key: app})
                self.assertEqual([r['key'] for r in requests], [app.key])
                self.assertEqual(requests[0]['command'][1:], ['-c', unique])
                snapshot = state.read(directory, 'guardian', script)
                self.assertFalse(snapshot['sessions'], 'A restart must never grant authentication')
            finally:
                state.set_enabled(directory, False)
                if child and child.poll() is None:
                    child.kill(); child.wait(timeout=10)
                if parent.poll() is None:
                    parent.kill(); parent.wait(timeout=10)
                parent.stderr.close()
                import psutil
                for pid in (wake_pid, guard_pid):
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            if pid == guard_pid:
                                try: proc.wait(timeout=10); continue
                                except psutil.TimeoutExpired: pass
                            proc.kill(); proc.wait(timeout=10)
                        except psutil.NoSuchProcess:
                            pass


if __name__ == '__main__':
    unittest.main()
