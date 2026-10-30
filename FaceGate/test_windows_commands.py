"""Real child-process access tests; only disposable NTFS directories are touched."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import folder_gate as gate


@unittest.skipUnless(os.name == 'nt', 'Requires real Windows and NTFS')
class WindowsCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'selected folder'
        (self.root / 'nested').mkdir(parents=True)
        self.file = self.root / 'nested' / 'data.txt'
        self.file.write_bytes(b'FaceGate command test payload')
        self.manifest = self.base / 'metadata.json'

    def tearDown(self):
        try:
            if self.root.exists():
                gate.disengage(self.root, self.manifest)
            else:
                gate.release(self.root)
        finally:
            self.temp.cleanup()

    def command(self, kind, command, target):
        environment = dict(os.environ, FG_SOURCE=str(self.root), FG_TARGET=str(target))
        if kind == 'cmd':
            # list2cmdline escapes embedded quotes for C runtimes, not CMD.
            # A batch file preserves CMD's actual quoting and variable expansion.
            script = self.base / 'operation.cmd'
            script.write_bytes(('@echo off\r\n' + command + '\r\nexit /b %errorlevel%\r\n').encode('ascii'))
            args = [os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/c', str(script)]
        else:
            args = ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', "$ErrorActionPreference='Stop'; " + command]
        return subprocess.run(args, env=environment, capture_output=True, timeout=30)

    def assert_copy_blocked(self, kind, command, persistent=False):
        allowed = self.base / 'positive control'
        result = self.command(kind, command, allowed)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        copies = [p for p in self.base.rglob('*') if p.is_file() and p != self.file]
        self.assertTrue(any(p.read_bytes() == self.file.read_bytes() for p in copies), 'Positive control did not copy the test data')
        for p in list(self.base.iterdir()):
            if p != self.root:
                shutil.rmtree(p) if p.is_dir() else p.unlink()
        gate.engage(self.root, self.manifest)
        if persistent:
            gate.release(self.root)  # Simulate GUI/process exit; persistent policy must remain.
        blocked = self.base / 'blocked copy'
        result = self.command(kind, command, blocked)
        self.assertNotEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertTrue(self.file.exists(), 'Copy attempt destroyed the original')
        if blocked.is_dir():
            copied = [p.read_bytes() for p in blocked.rglob('*') if p.is_file()]
        elif blocked.is_file():
            copied = [blocked.read_bytes()]
        else:
            copied = []
        self.assertNotIn(b'FaceGate command test payload', copied)

    def test_cmd_copy_known_file_is_denied(self):
        self.assert_copy_blocked('cmd', 'copy /y "%FG_SOURCE%\\nested\\data.txt" "%FG_TARGET%"')

    def test_cmd_xcopy_tree_is_denied(self):
        self.assert_copy_blocked('cmd', 'xcopy "%FG_SOURCE%" "%FG_TARGET%\\" /e /i /h /y /q')

    def test_powershell_copy_tree_is_denied(self):
        self.assert_copy_blocked('powershell', 'Copy-Item -LiteralPath $env:FG_SOURCE -Destination $env:FG_TARGET -Recurse -Force')

    def test_cmd_copy_known_file_stays_denied_after_process_handles_close(self):
        self.assert_copy_blocked('cmd', 'copy /y "%FG_SOURCE%\\nested\\data.txt" "%FG_TARGET%"', persistent=True)

    def test_powershell_copy_known_file_stays_denied_after_process_handles_close(self):
        self.assert_copy_blocked('powershell', "Copy-Item -LiteralPath (Join-Path $env:FG_SOURCE 'nested\\data.txt') -Destination $env:FG_TARGET -Force", persistent=True)

    def assert_delete_blocked(self, kind, command, persistent=False):
        gate.engage(self.root, self.manifest)
        if persistent:
            gate.release(self.root)
        result = self.command(kind, command, self.base / 'unused')
        self.assertTrue(self.root.exists(), (result.stdout, result.stderr))
        self.assertTrue(self.file.exists(), (result.stdout, result.stderr))
        # CMD del can return zero on access denial; source survival is authoritative.
        gate.disengage(self.root, self.manifest)
        self.assertEqual(self.file.read_bytes(), b'FaceGate command test payload')
        result = self.command(kind, command, self.base / 'unused')
        self.assertFalse(self.file.exists(), 'Positive control did not delete the disposable source')

    def test_cmd_rmdir_tree_is_denied(self):
        self.assert_delete_blocked('cmd', 'rmdir /s /q "%FG_SOURCE%"')

    def test_cmd_del_known_file_stays_denied_after_handles_close(self):
        self.assert_delete_blocked('cmd', 'del /f /q "%FG_SOURCE%\\nested\\data.txt"', persistent=True)

    def test_powershell_remove_tree_is_denied(self):
        self.assert_delete_blocked('powershell', 'Remove-Item -LiteralPath $env:FG_SOURCE -Recurse -Force')

    def test_cmd_rmdir_tree_stays_denied_after_handles_close(self):
        self.assert_delete_blocked('cmd', 'rmdir /s /q "%FG_SOURCE%"', persistent=True)

    def test_powershell_remove_known_file_stays_denied_after_handles_close(self):
        self.assert_delete_blocked('powershell', "Remove-Item -LiteralPath (Join-Path $env:FG_SOURCE 'nested\\data.txt') -Force", persistent=True)

    def test_empty_folder_cannot_be_removed_after_handles_close(self):
        self.file.unlink()
        self.file.parent.rmdir()
        gate.engage(self.root, self.manifest)
        gate.release(self.root)
        result = self.command('cmd', 'rmdir /q "%FG_SOURCE%"', self.base / 'unused')
        self.assertTrue(self.root.is_dir(), (result.stdout, result.stderr))
        gate.disengage(self.root, self.manifest)
        result = self.command('cmd', 'rmdir /q "%FG_SOURCE%"', self.base / 'unused')
        self.assertFalse(self.root.exists(), (result.stdout, result.stderr))

    def test_parent_guard_is_shared_and_survives_unlocking_one_sibling(self):
        second = self.base / 'protected sibling'
        second.mkdir()
        second_manifest = self.base / 'second.json'
        gate.engage(self.root, self.manifest)
        try:
            gate.engage(second, second_manifest)
            gate.release(second)
            gate.disengage(self.root, self.manifest)
            with self.assertRaises(OSError):
                second.rmdir()
            # The unlocked sibling has its own DELETE right and remains usable.
            moved = self.base / 'unlocked renamed'
            self.root.rename(moved)
            moved.rename(self.root)
            gate.disengage(second, second_manifest)
            second.rmdir()
        finally:
            if second.exists():
                gate.disengage(second, second_manifest)

    def test_all_original_acls_and_parent_acl_are_restored(self):
        import windows_acl_policy as policy
        paths = [self.base, self.root, self.file.parent, self.file]
        original = {str(p): policy.dacl(p) for p in paths}
        gate.engage(self.root, self.manifest)
        gate.release(self.root)
        gate.disengage(self.root, self.manifest)
        self.assertEqual({str(p): policy.dacl(p) for p in paths}, original)
