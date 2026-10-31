"""Qt tests with mocked camera; real Windows/NTFS tests are in test_folder_gate."""
import importlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox
from instance_bridge import InstanceServer, forward_request

APP = QApplication.instance() or QApplication([])


class FolderUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.import_temp = tempfile.TemporaryDirectory()
        with patch.dict(os.environ, {'LOCALAPPDATA': cls.import_temp.name}):
            cls.main = importlib.import_module('main')

    @classmethod
    def tearDownClass(cls):
        cls.import_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        data = base / 'appdata'; data.mkdir()
        self.root = base / 'selected'; self.root.mkdir()
        (self.root / 'sample.txt').write_text('original')
        self.patches = [patch.object(self.main, 'APP_DIR', data),
                        patch.object(self.main, 'DB_PATH', data / 'users.db'),
                        patch.object(self.main.FaceGate, 'load_model'),
                        patch.object(self.main.FaceGate, '_update_guardian'),
                        patch.object(self.main.FaceGate, '_clear_gui_state'),
                        patch.object(self.main.FaceGate, '_setup_tray', self._no_tray)]
        for p in self.patches:
            p.start()
        self.win = self.main.FaceGate()
        self.win.app_lock_timer.stop()
        self.win.recognizer = object()
        self.win.face_template = self.main.np.array([1.0, 0.0], dtype='float32')
        self.win.face_templates = {1: self.win.face_template}
        self.mp = self.main.inplace_crypto.write_manifest(self.root, self.win._metadata_root(), {'test': True}, '', 'locked')
        con = self.main.db()
        con.execute('INSERT INTO protected_folders VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)', (str(self.root), 'selected', str(self.mp)))
        con.commit(); con.close()
        self.record = self.win._folder_record(str(self.root))
        self.camera = Mock()
        self.camera.isOpened.return_value = True
        self.camera.read.return_value = (False, None)
        self.dialogs = []

    @staticmethod
    def _no_tray(win):
        win.tray = None
        win._allow_real_exit = True

    def tearDown(self):
        self.win.cancel_action()
        self.win._stop_explorer_observation()
        self.win._explorer_sessions.sessions.clear()
        self.win._instance_request_timer.stop()
        self.win._queued_shell_requests.clear()
        self.win.close()
        self.win.deleteLater()
        APP.processEvents()
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def _start_camera(self):
        self.win.cap = self.camera
        self.win.timer.start(33)
        return True

    def _dismiss(self, box):
        self.dialogs.append(box.text())
        return 0

    @staticmethod
    def _run_sync(task, complete, status):
        try:
            result = task()
        except Exception as exc:
            complete(False, {'error': str(exc)})
        else:
            complete(True, result)

    def test_window_and_picker_do_not_create_new_folder(self):
        self.assertFalse(list(Path(self.temp.name).rglob('New folder')))
        with patch.object(self.main.QFileDialog, 'exec', return_value=0), \
             patch.object(self.win, 'protect_folder_path') as protect:
            self.win.choose_and_protect_folder()
        protect.assert_not_called()
        self.assertEqual([p.name for p in self.root.iterdir()], ['sample.txt'])

    def test_existing_path_alias_resolves_to_stored_database_record(self):
        alias = str(self.root.parent / 'SELECT~1')
        actual_key = self.main.inplace_crypto.folder_gate._key
        expected = actual_key(self.root)
        def canonical(path):
            return expected if str(path) == alias else actual_key(path)
        with patch.object(self.main.inplace_crypto.folder_gate, '_key', side_effect=canonical):
            record = self.win._folder_record(alias)
        self.assertIsNotNone(record)
        self.assertEqual(record['path'], str(self.root))

    def test_camera_times_out_without_frames_and_never_unlocks(self):
        with patch.object(self.win, 'start_camera', self._start_camera), \
             patch.object(QMessageBox, 'exec', lambda box: self._dismiss(box)), \
             patch.object(self.win, '_finish_folder_unlock') as unlock:
            self.win._start_folder_face_auth(self.record)
            self.assertTrue(self.win._folder_auth_timer.isActive())
            self.assertEqual(self.win._folder_auth_timer.interval(), 3000)
            QTest.qWait(3200)
        unlock.assert_not_called()
        self.assertIsNone(self.win.cap)
        self.assertIsNone(self.win._pending_app_unlock)
        self.assertFalse(self.win._folder_auth_timer.isActive())
        self.camera.release.assert_called_once()
        self.assertIn('تشخیص چهره ناموفق', self.dialogs[0])
        self.assertTrue(self.win._folder_record(str(self.root))['locked'])

    def test_valid_face_unlocks_once_and_stops_camera_and_deadline(self):
        face = (0, 0, 200, 200, self.win.face_template)
        with patch.object(self.win, 'start_camera', self._start_camera), \
             patch.object(self.win, '_finish_folder_unlock') as unlock:
            self.win._start_folder_face_auth(self.record)
            for _ in range(5):
                self.win.check_liveness(None, face)
            QTest.qWait(20)
        unlock.assert_called_once()
        self.assertIsNone(self.win.cap)
        self.assertFalse(self.win._folder_auth_timer.isActive())
        self.assertIsNone(self.win._pending_app_unlock)

    def test_double_click_does_not_launch_explorer_before_authentication(self):
        with patch.object(self.win, 'start_camera', self._start_camera), \
             patch.object(self.main.explorer_integration, 'open_directory') as open_directory:
            self.win._handle_instance_request({'action': 'open-face', 'path': str(self.root)})
        open_directory.assert_not_called()
        self.assertEqual(self.win.mode, 'login')
        self.assertTrue(self.win._folder_open_from_shell)
        self.assertTrue(self.win._folder_record(str(self.root))['locked'])

    def test_authenticated_open_starts_observation_before_launching_explorer(self):
        def opened(path):
            self.assertIn(self.main.explorer_sessions.path_key(path), self.win._explorer_sessions.tokens())
            self.assertFalse(self.win._folder_record(path)['locked'])
        with patch.object(self.main.explorer_integration, 'open_directory', side_effect=opened) as launch:
            self.win._folder_open_from_shell = True
            self.win._on_folder_unlock_done(self.record, True, {})
        launch.assert_called_once()
        self.assertTrue(self.win._folder_session_timer.isActive())
        self.assertFalse(self.win.isVisible())

    def test_double_click_child_with_live_session_reuses_access_to_correct_child(self):
        child = self.root / 'child'; child.mkdir()
        self.win._explorer_sessions.begin(str(self.root))
        self.win._explorer_sessions.observe([str(self.root)], self.win._explorer_sessions.tokens())
        with patch.object(self.main.explorer_integration, 'open_directory') as launch, \
             patch.object(self.win, '_start_folder_face_auth') as authenticate:
            self.win._handle_instance_request({'action': 'open-face', 'path': str(child)})
        launch.assert_called_once_with(str(child))
        authenticate.assert_not_called()

    def test_double_click_child_without_session_authenticates_root_and_preserves_destination(self):
        child = self.root / 'child'; child.mkdir()
        with patch.object(self.win, '_start_folder_face_auth') as authenticate, \
             patch.object(self.main.explorer_integration, 'open_directory') as launch:
            self.win._handle_instance_request({'action': 'open-face', 'path': str(child)})
        authenticate.assert_called_once()
        self.assertEqual(authenticate.call_args.args[0]['path'], str(self.root))
        self.assertEqual(self.win._folder_open_target, str(child))
        launch.assert_not_called()

    def test_successful_child_authentication_opens_child_and_observes_its_root(self):
        child = self.root / 'child'; child.mkdir()
        self.win._folder_open_target = str(child)
        with patch.object(self.main.explorer_integration, 'open_directory') as launch:
            self.win._on_folder_unlock_done(self.record, True, {})
        launch.assert_called_once_with(str(child))
        self.assertIn(self.main.explorer_sessions.path_key(str(self.root)), self.win._explorer_sessions.tokens())

    def test_failed_child_explorer_launch_relocks_its_registered_root(self):
        child = self.root / 'child'; child.mkdir()
        with patch.object(self.main.explorer_integration, 'open_directory', side_effect=OSError('Explorer failed')), \
             patch.object(QMessageBox, 'warning'), \
             patch.object(self.win, '_automatic_relock') as relock:
            self.win._open_folder_in_explorer(str(child))
        relock.assert_called_once_with(str(self.root))

    def test_automatic_relock_encrypts_changed_files_and_marks_database_only_on_success(self):
        crypto = self.main.inplace_crypto
        key = b'k' * 32
        crypto.write_manifest(self.root, self.win._metadata_root(), {'test': True}, '', 'unlocked')
        con = self.main.db()
        con.execute('UPDATE protected_folders SET is_locked=0'); con.commit(); con.close()
        (self.root / 'sample.txt').write_text('edited while Explorer was open')
        self.win._explorer_sessions.begin(str(self.root), now=0)
        probe = Mock(paths=[], tokens=self.win._explorer_sessions.tokens(), error='')
        self.win._explorer_probe = probe
        # Exercise the real background transform, manifest and SQLite callbacks;
        # only Windows ACL bindings and DPAPI are replaced in this Linux test.
        with patch.object(crypto, 'unwrap_key', return_value=key), \
             patch.object(crypto.folder_gate, '_api'), \
             patch.object(crypto.folder_gate, 'engage') as engage, \
             patch.object(QMessageBox, 'warning'):
            self.win._explorer_probe_done(probe)
            deadline = __import__('time').monotonic() + 10
            while self.win._folder_worker is not None and __import__('time').monotonic() < deadline:
                QTest.qWait(20)
        self.assertIsNone(self.win._folder_worker, 'Real folder worker did not finish')
        engage.assert_called_once()
        self.assertTrue(self.win._folder_record(str(self.root))['locked'])
        self.assertFalse(self.win._explorer_sessions.sessions)
        self.assertEqual(crypto.read_manifest(self.mp)['state'], 'locked')
        self.assertTrue(crypto.is_encrypted_file(self.root / 'sample.txt'))
        crypto.decrypt_file_in_place(self.root / 'sample.txt', key)
        self.assertEqual((self.root / 'sample.txt').read_text(), 'edited while Explorer was open')

    def test_failed_automatic_relock_keeps_session_and_unlocked_database_for_retry(self):
        con = self.main.db()
        con.execute('UPDATE protected_folders SET is_locked=0'); con.commit(); con.close()
        self.win._explorer_sessions.begin(str(self.root))
        with patch.object(self.win, '_run_folder_worker', self._run_sync), \
             patch.object(self.main.inplace_crypto, 'lock_folder_in_place', side_effect=PermissionError('file is busy')), \
             patch.object(QMessageBox, 'warning') as warning:
            self.win._automatic_relock(str(self.root))
            self.win._automatic_relock(str(self.root))
        warning.assert_called_once()
        self.assertFalse(self.win._folder_record(str(self.root))['locked'])
        self.assertTrue(self.win._explorer_sessions.sessions)
        self.assertEqual((self.root / 'sample.txt').read_text(), 'original')

    def test_closing_window_keeps_watcher_alive_until_folder_is_relocked(self):
        self.win._request_only = True
        self.win._explorer_sessions.begin(str(self.root))
        with patch.object(self.win._guardian_timer, 'stop') as stop, \
             patch.object(self.main.QTimer, 'singleShot') as schedule:
            self.win.show()
            self.win.close()
        self.assertFalse(self.win.isVisible())
        self.assertTrue(self.win._explorer_sessions.sessions)
        stop.assert_not_called()
        schedule.assert_not_called()

    def test_app_authentication_cannot_quit_while_a_folder_session_is_open(self):
        self.win._request_only = True
        self.win._explorer_sessions.begin(str(self.root))
        app = self.main.app_catalog.App.desktop(str(self.root / 'selected.exe'))
        self.win._app_targets = {app.key: app}
        pending = {'key': app.key, 'name': app.name, 'pid': 123, 'hwnd': 0, 'command': [app.executable]}
        with patch.object(self.win, '_publish_gui_state'), \
             patch.object(self.main.app_runtime, 'launch'), \
             patch.object(self.main.QTimer, 'singleShot') as schedule:
            self.win._launch_pending_app(pending)
        schedule.assert_not_called()

    def test_missing_camera_offers_pin_without_releasing_folder(self):
        def choose_pin(box):
            return next(b for b in box.buttons() if b.text() == 'ورود PIN')
        with patch.object(self.win, 'start_camera', return_value=False), \
             patch.object(QMessageBox, 'exec', lambda box: self._dismiss(box)), \
             patch.object(QMessageBox, 'clickedButton', choose_pin), \
             patch.object(self.win, '_open_folder_with_pin') as pin, \
             patch.object(self.win, '_finish_folder_unlock') as unlock:
            self.win._start_folder_face_auth(self.record)
        pin.assert_called_once()
        self.assertEqual(pin.call_args.args[0]['path'], str(self.root))
        unlock.assert_not_called()
        self.assertTrue(self.win._folder_record(str(self.root))['locked'])

    def test_retry_starts_new_three_second_attempt(self):
        def choose_retry(box):
            return next(b for b in box.buttons() if b.text() == 'تلاش مجدد')
        with patch.object(self.win, 'start_camera', self._start_camera), \
             patch.object(QMessageBox, 'exec', lambda box: self._dismiss(box)), \
             patch.object(QMessageBox, 'clickedButton', choose_retry):
            self.win._start_folder_face_auth(self.record)
            original = self.win._folder_face_attempt
            self.win._folder_face_failed()
            QTest.qWait(20)
        self.assertIsNot(self.win._folder_face_attempt, original)
        self.assertTrue(self.win._folder_auth_timer.isActive())
        self.assertEqual(self.win._folder_face_attempt.matches, 0)

    def test_repeated_shell_requests_do_not_reset_deadline(self):
        with patch.object(self.win, 'start_camera', self._start_camera):
            self.win._start_folder_face_auth(self.record)
            original = self.win._folder_face_attempt
            self.win._handle_instance_request({'action': 'open-face', 'path': str(self.root)})
        self.assertIs(self.win._folder_face_attempt, original)
        self.assertEqual(self.win._queued_shell_requests, [])

    def test_retired_manifest_not_rediscovered_or_relocked_with_stale_db_row(self):
        self.main.inplace_crypto.write_manifest(self.root, self.win._metadata_root(), {'test': True}, '', 'unprotected')
        with patch.object(self.main.inplace_crypto, 'lock_folder_in_place') as lock:
            self.win._recover_folder_acl_state()
            self.assertEqual(self.win._startup_relock_paths, [])
            self.assertEqual(self.win._lock_all_protected_folders(), [])
            lock.assert_not_called()
        con = self.main.db()
        con.execute('DELETE FROM protected_folders'); con.commit(); con.close()
        self.win._sync_orphaned_folder_manifests()
        self.assertIsNone(self.win._folder_record(str(self.root)))

    def test_repeated_double_click_during_failure_dialog_does_not_queue_a_retry(self):
        self.win._folder_prompt_active = True
        self.win._folder_prompt_path = str(self.root)
        self.win._handle_instance_request({'action': 'open-face', 'path': str(self.root)})
        self.assertEqual(self.win._queued_shell_requests, [])
        self.win._folder_prompt_active = False
        self.win._folder_prompt_path = None

    def test_registered_unlocked_folder_still_authenticates_a_new_shell_open(self):
        self.main.inplace_crypto.write_manifest(self.root, self.win._metadata_root(), {'test': True}, '', 'unlocked')
        record = dict(self.record, locked=False)
        with patch.object(self.win, 'start_camera', self._start_camera):
            self.win._start_folder_face_auth(record)
        self.assertIsNotNone(self.win._folder_face_attempt)
        self.assertTrue(self.win._folder_auth_timer.isActive())

    def test_repeated_open_during_decryption_does_not_queue_another_authentication(self):
        self.win._folder_worker = object()
        self.win._folder_unlocking_path = str(self.root)
        self.win._handle_instance_request({'action': 'open-face', 'path': str(self.root)})
        self.assertEqual(self.win._queued_shell_requests, [])
        self.win._folder_worker = None
        self.win._folder_unlocking_path = None

    def test_remove_wrong_pin_keeps_database_record_and_source_files(self):
        self.win.refresh_protected_folders()
        self.win.protected_folder_list.setCurrentRow(0)
        with patch.object(self.win, '_run_folder_worker', self._run_sync), \
             patch.object(QMessageBox, 'question', return_value=QMessageBox.Yes), \
             patch.object(self.main.QInputDialog, 'getText', return_value=('87654321', True)), \
             patch.object(QMessageBox, 'critical'), \
             patch.object(self.main.inplace_crypto, 'unwrap_key', side_effect=RuntimeError('wrong PIN')):
            self.win.remove_selected_folder_protection()
        self.assertIsNotNone(self.win._folder_record(str(self.root)))
        self.assertEqual((self.root / 'sample.txt').read_text(), 'original')

    def test_remove_decrypts_then_deletes_record_and_never_readds_it(self):
        key = b'k' * 32
        self.main.inplace_crypto.encrypt_file_in_place(self.root / 'sample.txt', key, {'test': True})
        self.win.refresh_protected_folders()
        self.win.protected_folder_list.setCurrentRow(0)
        with patch.object(self.win, '_run_folder_worker', self._run_sync), \
             patch.object(QMessageBox, 'question', return_value=QMessageBox.Yes), \
             patch.object(self.main.QInputDialog, 'getText', return_value=('12345678', True)), \
             patch.object(QMessageBox, 'information'), \
             patch.object(self.main.inplace_crypto, 'unwrap_key', return_value=key):
            self.win.remove_selected_folder_protection()
        self.assertIsNone(self.win._folder_record(str(self.root)))
        self.assertEqual((self.root / 'sample.txt').read_text(), 'original')
        self.win.refresh_protected_folders()
        self.assertEqual(self.win.protected_folder_list.count(), 0)

    def test_app_camera_failure_preserves_pending_request_for_backup_password(self):
        app = self.main.app_catalog.App.desktop(str(self.root / 'selected.exe'))
        self.win._app_targets = {app.key: app}
        pending = {'key': app.key, 'name': app.name, 'pid': 123, 'hwnd': 0, 'command': [app.executable]}
        with patch.object(self.win, 'start_camera', return_value=False):
            self.win._begin_app_gate_request(pending)
        self.assertIs(self.win._pending_app_unlock, pending)
        self.assertFalse(self.win._app_sessions.allows([app.key]))

    def test_request_only_success_exits_but_manual_window_does_not(self):
        app = self.main.app_catalog.App.desktop(str(self.root / 'selected.exe'))
        self.win._app_targets = {app.key: app}
        pending = {'key': app.key, 'name': app.name, 'pid': 123, 'hwnd': 0, 'command': [app.executable]}
        for temporary in (False, True):
            self.win._request_only = temporary
            self.win._pending_app_unlock = pending
            with patch.object(self.win, '_publish_gui_state'), \
                 patch.object(self.main.app_runtime, 'launch') as launch, \
                 patch.object(self.main.QTimer, 'singleShot') as schedule:
                self.win._launch_pending_app(pending)
            launch.assert_called_once()
            self.assertEqual(schedule.call_count, int(temporary))
            if temporary:
                self.assertEqual(schedule.call_args.args[1], APP.quit)
            self.assertTrue(self.win._app_sessions.allows([app.key]))

    def test_failed_app_launch_revokes_authentication_and_stops_camera(self):
        app = self.main.app_catalog.App.desktop(str(self.root / 'selected.exe'))
        self.win._app_targets = {app.key: app}
        pending = {'key': app.key, 'name': app.name, 'pid': 123, 'hwnd': 0, 'command': [app.executable]}
        self.win._pending_app_unlock = pending
        with patch.object(self.win, '_publish_gui_state'), \
             patch.object(self.main.app_runtime, 'launch', side_effect=OSError('missing executable')):
            self.win._launch_pending_app(pending)
        self.assertFalse(self.win._app_sessions.allows([app.key]))
        self.assertIsNone(self.win._pending_app_unlock)
        self.assertIsNone(self.win.cap)

    def test_app_request_during_folder_auth_stays_queued(self):
        app = self.main.app_catalog.App.desktop(str(self.root / 'selected.exe'))
        self.win._app_targets = {app.key: app}
        request = {'key': app.key, 'name': app.name, 'pid': 123, 'hwnd': 0, 'command': [app.executable]}
        folder = {'kind': 'folder_unlock', 'path': str(self.root), 'name': 'selected'}
        self.win._pending_app_unlock = folder
        self.win.mode = 'login'
        with patch.object(self.win._app_monitor, 'scan', return_value=([request], [])):
            self.win._scan_app_processes()
        self.assertIs(self.win._pending_app_unlock, folder)
        self.assertEqual(list(self.win._app_gate_queue), [request])

    def test_ending_guardian_requires_management_authentication(self):
        with patch.object(self.main.os, 'name', 'nt'), \
             patch.object(self.win, '_require_management_password', return_value=False), \
             patch.object(self.main.guardian_state, 'set_enabled') as change:
            self.win.toggle_guardian()
        change.assert_not_called()


class SingleInstanceTests(unittest.TestCase):
    def setUp(self):
        self.name = 'FaceGateTest-' + uuid.uuid4().hex
        self.server = InstanceServer(self.name)
        self.requests = []
        self.server.request_received.connect(self.requests.append)

    def tearDown(self):
        self.server.server.close()
        self.server.deleteLater()
        APP.processEvents()

    def test_shell_request_reaches_existing_handle_owner(self):
        request = {'action': 'open-face', 'path': 'C:\\Private Folder'}
        # Windows named-pipe delivery needs the receiving event loop to run.
        # Exercise the actual Explorer arrangement: a separate sender process,
        # rather than blocking the same thread that must accept the request.
        import json
        code = '''
import json,sys
from PySide6.QtCore import QCoreApplication
from instance_bridge import forward_request
app=QCoreApplication([])
raise SystemExit(0 if forward_request(sys.argv[1],json.loads(sys.argv[2])) else 2)
'''
        sender = subprocess.Popen([sys.executable, '-c', code, self.name, json.dumps(request)],
                                  cwd=str(Path(__file__).resolve().parent), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = __import__('time').monotonic() + 8
        while sender.poll() is None and __import__('time').monotonic() < deadline:
            QTest.qWait(20)
        if sender.poll() is None:
            sender.kill()
        out, error = sender.communicate(timeout=5)
        self.assertEqual(sender.returncode, 0, error.decode(errors='replace'))
        QTest.qWait(30)
        self.assertEqual(self.requests, [request])

    def test_requests_cannot_grant_unlock_or_execute_commands(self):
        for action in ('unlock', 'eval', 'exec', 'remove'):
            with self.assertRaises(ValueError):
                forward_request(self.name, {'action': action, 'path': 'C:\\Private'})
        self.assertEqual(self.requests, [])

    def test_primary_startup_connects_server_and_defers_requests_until_gui_exists(self):
        code = '''
import sys
import main
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
class Window:
    def __init__(self):
        self.tray = None
        QTimer.singleShot(25, QApplication.instance().quit)
    def set_workspace_mode(self, mode): pass
    def show(self): pass
    def start_startup_recovery(self): pass
    def _handle_instance_request(self, request): pass
main.FaceGate = Window
sys.argv = ['FaceGate', '--autostart']
main.main()
'''
        with tempfile.TemporaryDirectory() as d:
            settings = dict(os.environ, LOCALAPPDATA=d)
            result = subprocess.run([sys.executable, '-c', code], env=settings,
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Failed to disconnect', result.stderr)


if __name__ == '__main__':
    unittest.main()
