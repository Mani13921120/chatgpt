import unittest
from unittest.mock import Mock, patch

from app_catalog import App
from app_monitor import Monitor
from app_runtime import Sessions


class AppMonitorTests(unittest.TestCase):
    def setUp(self):
        self.app = App.desktop(r'C:\Selected\app.exe')
        self.targets = {self.app.key: self.app}
        self.proc = Mock()
        self.proc.info = {'pid': 424242, 'create_time': 100, 'exe': self.app.executable,
                          'cmdline': [self.app.executable, '--document', 'file.txt']}
        self.proc.create_time.return_value = 100
        self.proc.cwd.return_value = r'C:\Selected'
        with patch('app_monitor.psutil.process_iter', return_value=[]):
            self.monitor = Monitor()
        self.sessions = Sessions()

    def scan(self, pending=()):
        with patch('app_monitor.psutil.process_iter', return_value=[self.proc]):
            return self.monitor.scan(self.targets, self.sessions, pending, foreground=(0, None))

    def test_another_launch_is_blocked_while_face_prompt_is_pending(self):
        requests, errors = self.scan({self.app.key})
        self.proc.terminate.assert_called_once()
        self.assertEqual(requests, [])
        self.assertEqual(errors, [])

    def test_new_launch_preserves_argv_and_requests_authentication(self):
        requests, errors = self.scan()
        self.proc.terminate.assert_called_once()
        self.assertEqual(requests[0]['command'], self.proc.info['cmdline'])
        self.assertEqual(requests[0]['cwd'], r'C:\Selected')
        self.assertFalse(self.sessions.allows([self.app.key]))

    def test_authenticated_running_session_is_not_terminated(self):
        self.sessions.grant(self.app.key)
        self.assertEqual(self.scan(), ([], []))
        self.proc.terminate.assert_not_called()

    def test_recycled_pid_is_not_terminated(self):
        self.proc.create_time.return_value = 101
        self.assertEqual(self.scan(), ([], []))
        self.proc.terminate.assert_not_called()

    def test_access_denied_is_reported_without_fake_success(self):
        import psutil
        self.proc.terminate.side_effect = psutil.AccessDenied(self.proc.info['pid'])
        requests, errors = self.scan()
        self.assertEqual(requests, [])
        self.assertEqual(len(errors), 1)


if __name__ == '__main__':
    unittest.main()
