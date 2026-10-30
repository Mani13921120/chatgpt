from pathlib import Path
import sqlite3
import tempfile
import unittest

import explorer_integration as shell
from explorer_router import find_protected_root
from folder_auth import FolderFaceAttempt


class FakeKey:
    def __init__(self, path):
        self.path = path
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass


class FakeRegistry:
    HKEY_CURRENT_USER = 1
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1
    REG_EXPAND_SZ = 2

    def __init__(self):
        self.keys = {}
    def OpenKey(self, hive, path, *args):
        if path not in self.keys:
            raise FileNotFoundError(path)
        return FakeKey(path)
    def CreateKeyEx(self, hive, path, *args):
        self.keys.setdefault(path, {})
        return FakeKey(path)
    def QueryValueEx(self, key, name):
        try:
            return self.keys[key.path][name]
        except KeyError:
            raise FileNotFoundError(name)
    def SetValueEx(self, key, name, reserved, kind, value):
        self.keys[key.path][name] = (value, kind)
    def DeleteValue(self, key, name):
        try:
            del self.keys[key.path][name]
        except KeyError:
            raise FileNotFoundError(name)
    def DeleteKey(self, hive, path):
        if path not in self.keys:
            raise FileNotFoundError(path)
        if any(p.startswith(path + '\\') for p in self.keys):
            raise OSError('Key has children')
        del self.keys[path]


class ShellSettingsTests(unittest.TestCase):
    def test_repeated_install_preserves_original_value_and_type(self):
        reg = FakeRegistry()
        original = ('custom-open', reg.REG_EXPAND_SZ)
        reg.keys[shell.SHELL_KEY] = {None: original}
        shell.install('first-command', 'icon', reg)
        shell.install('updated-command', 'icon', reg)
        shell.uninstall(reg)
        self.assertEqual(reg.keys[shell.SHELL_KEY][None], original)
        self.assertNotIn(shell.STATE_KEY, reg.keys)

    def test_uninstall_restores_absent_default(self):
        reg = FakeRegistry()
        shell.install('command', 'icon', reg)
        shell.uninstall(reg)
        self.assertNotIn(None, reg.keys[shell.SHELL_KEY])

    def test_uninstall_preserves_newer_user_default(self):
        reg = FakeRegistry()
        shell.install('command', 'icon', reg)
        reg.keys[shell.SHELL_KEY][None] = ('other-app', reg.REG_SZ)
        shell.uninstall(reg)
        self.assertEqual(reg.keys[shell.SHELL_KEY][None][0], 'other-app')

    def test_missing_recovery_does_not_delete_live_default_command(self):
        reg = FakeRegistry()
        reg.keys[shell.SHELL_KEY] = {None: (shell.VERB, reg.REG_SZ)}
        with self.assertRaises(RuntimeError):
            shell.uninstall(reg)
        self.assertEqual(reg.keys[shell.SHELL_KEY][None][0], shell.VERB)


class ExplorerRoutingTests(unittest.TestCase):
    def test_missing_database_does_not_create_anything(self):
        with tempfile.TemporaryDirectory() as d:
            missing = Path(d) / 'nonexistent' / 'users.db'
            self.assertIsNone(find_protected_root(r'C:\Ordinary', missing))
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_windows_case_child_paths_and_component_boundaries(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / 'users.db'
            with sqlite3.connect(db) as con:
                con.execute('CREATE TABLE protected_folders (path TEXT)')
                con.execute('INSERT INTO protected_folders VALUES (?)', (r'C:\Private Folder',))
            self.assertEqual(find_protected_root(r'c:\PRIVATE folder\nested', db), r'C:\Private Folder')
            self.assertIsNone(find_protected_root(r'C:\Private Folder Copy', db))
            self.assertIsNone(find_protected_root(r'D:\Private Folder', db))


class FolderDeadlineTests(unittest.TestCase):
    def test_match_at_or_after_deadline_is_rejected(self):
        attempt = FolderFaceAttempt(started=100, matches=4)
        self.assertFalse(attempt.observe(1.0, 0.47, now=103.0))
        self.assertTrue(attempt.expired(now=103.0))

    def test_missing_or_mismatched_face_resets_consecutive_matches(self):
        attempt = FolderFaceAttempt(started=100)
        for _ in range(4):
            self.assertFalse(attempt.observe(0.9, 0.47, now=101))
        attempt.no_face()
        self.assertFalse(attempt.observe(0.9, 0.47, now=101))
        self.assertFalse(attempt.observe(float('nan'), 0.47, now=101))
        self.assertEqual(attempt.matches, 0)
        for _ in range(4):
            self.assertFalse(attempt.observe(0.9, 0.47, now=102))
        self.assertTrue(attempt.observe(0.9, 0.47, now=102.9))


if __name__ == '__main__':
    unittest.main()
