import subprocess
from pathlib import Path
import unittest
from unittest.mock import patch

from explorer_sessions import ExplorerSessions, file_url_path, inside, snapshot


class ExplorerSessionTests(unittest.TestCase):
    def setUp(self):
        self.root = r'C:\Private Folder'
        self.tracker = ExplorerSessions()
        self.tracker.begin(self.root, now=0)

    def observe(self, paths, now):
        return self.tracker.observe(paths, self.tracker.tokens(), now=now)

    def test_navigating_to_child_keeps_access_until_last_view_leaves(self):
        self.assertEqual(self.observe([self.root], 1), [])
        self.assertEqual(self.observe([self.root + r'\child', r'C:\Other'], 2), [])
        self.assertEqual(self.observe([r'C:\Other'], 3), [])
        self.assertEqual(self.observe([r'C:\Other'], 4), [self.root])

    def test_minimized_or_second_window_still_keeps_session_open(self):
        self.assertEqual(self.observe([self.root, self.root + r'\child'], 1), [])
        self.assertEqual(self.observe([self.root + r'\child'], 40), [])
        self.assertEqual(self.observe([], 41), [])
        self.assertEqual(self.observe([], 42), [self.root])

    def test_brief_navigation_gap_does_not_interrupt_the_session(self):
        self.observe([self.root], 1)
        self.observe([], 2)
        self.assertEqual(self.observe([self.root + r'\child'], 2.5), [])
        self.assertEqual(self.observe([], 3), [])
        self.assertEqual(self.observe([], 3.9), [])
        self.assertEqual(self.observe([], 4), [self.root])

    def test_explorer_never_opens_relocks_after_bounded_launch_grace(self):
        self.assertEqual(self.observe([], 14.9), [])
        self.assertEqual(self.observe([], 15), [self.root])

    def test_probe_error_does_not_mean_no_windows_but_cannot_leave_access_forever(self):
        self.observe([self.root], 1)
        self.assertEqual(self.observe(None, 2), [])
        self.assertEqual(self.observe(None, 6.9), [])
        self.assertEqual(self.observe(None, 7), [self.root])

    def test_recovered_observation_resets_error_deadline(self):
        self.observe(None, 1)
        self.assertEqual(self.observe([self.root], 5), [])
        self.assertEqual(self.observe(None, 7), [])
        self.assertEqual(self.observe(None, 11.9), [])

    def test_new_authentication_ignores_old_inflight_snapshot(self):
        old = self.tracker.tokens()
        self.tracker.begin(self.root, now=20)
        self.assertEqual(self.tracker.observe([], old, now=100), [])

    def test_removed_protection_cannot_be_relocked_by_a_late_probe(self):
        old = self.tracker.tokens()
        self.tracker.discard(self.root)
        self.assertEqual(self.tracker.observe([], old, now=100), [])

    def test_busy_file_retry_is_bounded_and_can_succeed_later(self):
        self.observe([self.root], 1)
        self.observe([], 2)
        self.assertEqual(self.observe([], 3), [self.root])
        self.tracker.retry_later(self.root, now=3)
        self.assertEqual(self.observe([], 7.9), [])
        self.assertEqual(self.observe([], 8), [self.root])
        self.tracker.discard(self.root)
        self.assertEqual(self.observe([], 20), [])

    def test_each_protected_folder_has_an_independent_session(self):
        other = r'D:\Second'
        self.tracker.begin(other, now=0)
        self.observe([self.root, other], 1)
        self.observe([other], 2)
        self.assertEqual(self.observe([other], 3), [self.root])

    def test_subfolder_navigation_reuses_only_fresh_authenticated_session(self):
        self.assertTrue(self.tracker.reusable(self.root, now=1))
        self.observe([self.root], 1)
        self.assertTrue(self.tracker.reusable(self.root, now=2))
        self.assertFalse(self.tracker.reusable(self.root, now=4))
        self.observe([], 4)
        self.assertFalse(self.tracker.reusable(self.root, now=4))
        self.tracker.discard(self.root)
        self.assertFalse(self.tracker.reusable(self.root, now=5))

    def test_error_or_relock_attempt_never_reuses_session(self):
        self.observe([self.root], 1)
        self.observe(None, 2)
        self.assertFalse(self.tracker.reusable(self.root, now=2))
        self.observe([self.root], 3)
        self.tracker.retry_later(self.root, now=3)
        self.assertFalse(self.tracker.reusable(self.root, now=3))


class ExplorerPathTests(unittest.TestCase):
    def test_windows_paths_use_component_boundaries_and_case(self):
        self.assertTrue(inside(r'C:\Private Folder', r'c:\PRIVATE FOLDER\child'))
        self.assertFalse(inside(r'C:\Private Folder', r'C:\Private Folder Copy'))
        self.assertFalse(inside(r'C:\Private Folder', r'D:\Private Folder'))
        self.assertFalse(inside(r'C:\Private Folder', r'C:\Private Folder\..\Other'))
        self.assertFalse(inside(r'C:\Private Folder', None))

    def test_shell_urls_preserve_unicode_percent_hash_and_unc_paths(self):
        self.assertEqual(file_url_path('file:///C:/My%20Folder/%D8%AA%D8%B3%D8%AA%23%25'), 'C:\\My Folder\\تست#%')
        self.assertEqual(file_url_path('file://server/share/Private%20Folder'), r'\\server\share\Private Folder')
        self.assertIsNone(file_url_path('shell:Home'))
        self.assertIsNone(file_url_path(''))

    def test_com_timeout_is_propagated_and_never_becomes_an_empty_snapshot(self):
        with patch('explorer_sessions.subprocess.run', side_effect=subprocess.TimeoutExpired('probe', 4)):
            with self.assertRaises(subprocess.TimeoutExpired):
                snapshot()

    def test_probe_error_is_propagated(self):
        def write_error(command, **kwargs):
            Path(command[-1]).write_text('{"error": "Shell unavailable"}')
        with patch('explorer_sessions.subprocess.run', side_effect=write_error):
            with self.assertRaisesRegex(RuntimeError, 'Shell unavailable'):
                snapshot()
