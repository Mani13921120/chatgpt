"""Run: python -m unittest -v test_folder_gate (Windows NTFS for integration)."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import folder_gate as gate
import folder_inplace_crypto as crypto


class AuthenticationTests(unittest.TestCase):
    def test_lock_handles_request_real_read_access_for_sharing_enforcement(self):
        kernel = Mock()
        kernel.CreateFileW.return_value = 42
        with tempfile.TemporaryDirectory() as d:
            with patch.object(gate, '_api', return_value=(kernel, None)), \
                 patch.object(gate, '_paths', return_value=[Path(d)]):
                try:
                    gate.acquire(d)
                    args = kernel.CreateFileW.call_args.args
                    self.assertEqual(args[1], gate.LOCK_ACCESS)
                    self.assertEqual(args[2], 0)
                finally:
                    gate.release(d)

    def test_successful_read_probe_rejects_lock_without_deleting_anything(self):
        kernel = Mock()
        kernel.CreateFileW.return_value = 42
        with patch.object(gate, '_api', return_value=(kernel, None)):
            with self.assertRaises(RuntimeError):
                gate.verify_exclusion('folder')
        kernel.CloseHandle.assert_called_once_with(42)

    def test_failed_enforcement_probe_rolls_back_gate_and_reports_failure(self):
        with patch.object(gate, 'active', return_value=False), \
             patch.object(gate.policy, 'preflight_parent'), \
             patch.object(gate, 'saved', return_value=None), \
             patch.object(gate, '_paths', return_value=[]), \
             patch.object(gate.policy, 'snapshot', return_value={'state': 'locking'}), \
             patch.object(gate.policy, 'write_journal'), patch.object(gate.policy, 'apply_tree'), \
             patch.object(gate.policy, 'restore_tree') as restore, \
             patch.object(gate, 'acquire'), patch.object(gate, 'release') as release, \
             patch.object(gate, 'verify_exclusion', side_effect=RuntimeError('not blocked')):
            with self.assertRaisesRegex(RuntimeError, 'not blocked'):
                gate.engage('folder', 'metadata')
        release.assert_called_once()
        restore.assert_called_once()

    def test_empty_folder_and_empty_subdirectories_support_full_lifecycle(self):
        import vault_crypto
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory() as d:
                base = Path(d)
                root = base / 'selected'; root.mkdir()
                if nested:
                    (root / 'empty-child').mkdir()
                metadata = base / 'metadata'
                with patch.object(vault_crypto, '_dpapi_protect', side_effect=lambda b: b), \
                     patch.object(vault_crypto, '_dpapi_unprotect', side_effect=lambda b: b), \
                     patch.object(gate, '_api'), patch.object(gate, 'engage') as engage:
                    result = crypto.protect_folder_in_place(root, '12345678', metadata, base / 'backups')
                    self.assertEqual(result['file_count'], 0)
                    self.assertEqual(crypto.read_manifest(result['manifest_path'])['state'], 'locked')
                    self.assertTrue(Path(result['backup_path']).is_file())
                    engage.assert_called_once()
                    with self.assertRaises(RuntimeError):
                        crypto.unlock_folder_in_place(root, metadata, pin='87654321')
                    crypto.unlock_folder_in_place(root, metadata, pin='12345678')
                    (root / 'later.txt').write_text('added after unlocking')
                    crypto.lock_folder_in_place(root, metadata)
                    self.assertTrue(crypto.is_encrypted_file(root / 'later.txt'))
                    crypto.unprotect_folder_in_place(root, metadata, '12345678')
                    self.assertEqual((root / 'later.txt').read_text(), 'added after unlocking')

    def test_unprotect_restores_contents_and_retires_manifest_without_deleting_backup(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root = base / 'selected'; root.mkdir()
            (root / 'nested').mkdir()
            data = os.urandom(8192)
            file = root / 'nested' / 'data.bin'; file.write_bytes(data)
            backup = base / 'recovery.fgvault'; backup.write_bytes(b'keep recovery data')
            metadata = base / 'metadata'
            key = b'k' * 32
            envelope = {'test': True}
            mp = crypto.write_manifest(root, metadata, envelope, backup, 'locked')
            crypto.encrypt_file_in_place(file, key, envelope)
            with patch.object(crypto, 'unwrap_key', return_value=key):
                result = crypto.unprotect_folder_in_place(root, metadata, '12345678', manifest=mp)
            self.assertEqual(result['state'], 'unprotected')
            self.assertEqual(file.read_bytes(), data)
            self.assertEqual(crypto.read_manifest(mp)['state'], 'unprotected')
            self.assertEqual(backup.read_bytes(), b'keep recovery data')
            self.assertEqual(sorted(p.relative_to(root).as_posix() for p in root.rglob('*')), ['nested', 'nested/data.bin'])

    def test_unprotect_wrong_pin_leaves_everything_untouched(self):
        with patch.object(crypto, 'read_manifest', return_value={'key_envelope': {}}), \
             patch.object(crypto, 'unwrap_key', side_effect=RuntimeError('wrong PIN')), \
             patch.object(crypto, 'unlock_folder_in_place') as unlock, \
             patch.object(crypto, 'write_manifest') as write:
            with self.assertRaisesRegex(RuntimeError, 'wrong PIN'):
                crypto.unprotect_folder_in_place('folder', 'metadata', '87654321')
            unlock.assert_not_called()
            write.assert_not_called()

    def test_retired_folder_cannot_be_silently_relocked(self):
        with patch.object(crypto, 'read_manifest', return_value={'state': 'unprotected'}), \
             patch.object(crypto, '_content_lock') as lock:
            with self.assertRaises(RuntimeError):
                crypto.lock_folder_in_place('folder', 'metadata')
            lock.assert_not_called()

    def test_wrong_pin_never_changes_acl_or_handles(self):
        with patch.object(gate, 'saved', return_value={'original_dacl': 'D:'}), \
             patch.object(crypto, 'read_manifest', return_value={'key_envelope': {}}), \
             patch.object(crypto, 'unwrap_key', side_effect=RuntimeError('wrong PIN')), \
             patch.object(gate, 'disengage') as release:
            with self.assertRaisesRegex(RuntimeError, 'wrong PIN'):
                crypto.unlock_folder_in_place('folder', 'metadata', pin='00000000')
            release.assert_not_called()

    def test_decryption_failure_reengages_gate(self):
        with patch.object(gate, 'saved', return_value={}), \
             patch.object(crypto, 'read_manifest', return_value={'key_envelope': {}}), \
             patch.object(crypto, 'unwrap_key', return_value=b'k'*32), \
             patch.object(gate, 'disengage') as release, \
             patch.object(gate, 'engage') as relock, \
             patch.object(crypto, '_content_unlock', side_effect=RuntimeError('damaged')):
            with self.assertRaisesRegex(RuntimeError, 'damaged'):
                crypto.unlock_folder_in_place('folder', 'metadata', pin='12345678')
            release.assert_called_once()
            relock.assert_called_once()

    def test_gate_failure_is_not_successful_protection(self):
        with patch.object(gate, '_api'), \
             patch.object(crypto, '_content_protect', return_value={'root':'folder','manifest_path':'meta'}), \
             patch.object(gate, 'engage', side_effect=OSError('busy')):
            with self.assertRaisesRegex(RuntimeError, 'busy'):
                crypto.protect_folder_in_place('folder', '12345678', 'metadata', 'backup')

    def test_content_roundtrip_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'sample.bin'
            data = os.urandom(crypto.CHUNK_SIZE + 123)
            p.write_bytes(data)
            key = b'k' * 32
            crypto.encrypt_file_in_place(p, key, {'test': True})
            ciphertext = p.read_bytes()
            self.assertNotEqual(ciphertext, data)
            broken = bytearray(ciphertext); broken[-1] ^= 1; p.write_bytes(broken)
            with self.assertRaises(RuntimeError):
                crypto.decrypt_file_in_place(p, key)
            self.assertEqual(p.read_bytes(), broken)
            p.write_bytes(ciphertext)
            crypto.decrypt_file_in_place(p, key)
            self.assertEqual(p.read_bytes(), data)


@unittest.skipUnless(os.name == 'nt', 'Requires real Windows/NTFS')
class WindowsIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'selected'
        self.root.mkdir()
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'data.txt').write_text('original data')
        self.mp = self.base / 'manifest.json'
        self.original = gate._get_dacl(self.root)

    def tearDown(self):
        try:
            gate.disengage(self.root, self.mp)
        finally:
            self.temp.cleanup()

    def test_block_directory_copy_direct_file_read_rename_delete_and_restore(self):
        gate.engage(self.root, self.mp)
        with self.assertRaises(OSError):
            list(self.root.iterdir())
        with self.assertRaises(OSError):
            (self.root / 'nested' / 'data.txt').read_bytes()
        with self.assertRaises(OSError):
            shutil.copytree(self.root, self.base / 'copy')
        with self.assertRaises(OSError):
            self.root.rename(self.base / 'renamed')
        with self.assertRaises(OSError):
            (self.root / 'nested' / 'data.txt').unlink()
        gate.disengage(self.root, self.mp)
        self.assertEqual(gate._get_dacl(self.root), self.original)
        self.assertEqual((self.root / 'nested' / 'data.txt').read_text(), 'original data')
        self.root.rename(self.base / 'renamed')
        (self.base / 'renamed').rename(self.root)
        shutil.copytree(self.root, self.base / 'copy')

    def test_empty_tree_has_real_directory_gate_and_can_be_unprotected(self):
        (self.root / 'nested' / 'data.txt').unlink()
        metadata = self.base / 'metadata'
        result = crypto.protect_folder_in_place(self.root, '12345678', metadata, self.base / 'backups')
        self.mp = Path(result['manifest_path'])
        self.assertEqual(result['file_count'], 0)
        self.assertTrue(gate.active(self.root))
        with self.assertRaises(OSError):
            list(self.root.iterdir())
        crypto.unprotect_folder_in_place(self.root, metadata, '12345678', manifest=self.mp)
        self.assertEqual(list(self.root.iterdir()), [self.root / 'nested'])
        self.assertEqual(gate._get_dacl(self.root), self.original)

    def test_full_crypto_and_pin_workflow(self):
        metadata = self.base / 'metadata'
        backups = self.base / 'backups'
        result = crypto.protect_folder_in_place(self.root, '12345678', metadata, backups)
        self.mp = Path(result['manifest_path'])
        self.assertTrue(gate.active(self.root))
        with self.assertRaises(RuntimeError):
            crypto.unlock_folder_in_place(self.root, metadata, pin='87654321', manifest=self.mp)
        self.assertTrue(gate.active(self.root))
        crypto.unlock_folder_in_place(self.root, metadata, pin='12345678', manifest=self.mp)
        self.assertFalse(gate.active(self.root))
        self.assertEqual((self.root / 'nested' / 'data.txt').read_text(), 'original data')
        crypto.lock_folder_in_place(self.root, metadata, manifest=self.mp)
        self.assertTrue(gate.active(self.root))
        crypto.unlock_folder_in_place(self.root, metadata, pin='12345678', manifest=self.mp)
        self.assertEqual((self.root / 'nested' / 'data.txt').read_text(), 'original data')

    def test_busy_file_rejects_partial_lock(self):
        with (self.root / 'nested' / 'data.txt').open('rb'):
            with self.assertRaises(OSError):
                gate.engage(self.root, self.mp)
        self.assertFalse(gate.active(self.root))
        self.assertEqual(gate._get_dacl(self.root), self.original)
        self.assertEqual((self.root / 'nested' / 'data.txt').read_text(), 'original data')

    def test_unprotect_removes_real_windows_gate_and_preserves_files(self):
        metadata = self.base / 'metadata'
        result = crypto.protect_folder_in_place(self.root, '12345678', metadata, self.base / 'backups')
        self.mp = Path(result['manifest_path'])
        backup = Path(result['backup_path'])
        crypto.unprotect_folder_in_place(self.root, metadata, '12345678', manifest=self.mp)
        self.assertFalse(gate.active(self.root))
        self.assertFalse(gate.sidecar(self.mp).exists())
        self.assertEqual(gate._get_dacl(self.root), self.original)
        self.assertEqual((self.root / 'nested' / 'data.txt').read_text(), 'original data')
        self.assertTrue(backup.is_file())
        self.assertEqual(crypto.read_manifest(self.mp)['state'], 'unprotected')

    def test_persistent_dacl_survives_process_exit_and_can_be_recovered(self):
        code = 'import folder_gate as g; import sys; g.engage(sys.argv[1],sys.argv[2])'
        subprocess.run([sys.executable, '-c', code, str(self.root), str(self.mp)], check=True)
        with self.assertRaises(OSError):
            list(self.root.iterdir())
        gate.engage(self.root, self.mp)
        self.assertTrue(gate.active(self.root))
        gate.disengage(self.root, self.mp)
        self.assertEqual(gate._get_dacl(self.root), self.original)

    def test_legacy_root_only_journal_upgrades_to_recursive_protection(self):
        import json
        legacy = {'root': gate._key(self.root), 'original_dacl': self.original}
        gate.sidecar(self.mp).write_text(json.dumps(legacy), encoding='utf-8')
        offset = self.original.index('(')
        gate._set_dacl(self.root, self.original[:offset] + '(D;;0x00010047;;;WD)' + self.original[offset:])
        gate.engage(self.root, self.mp)
        self.assertEqual(gate.saved(self.root, self.mp)['version'], 2)
        gate.release(self.root)
        with self.assertRaises(OSError):
            (self.root / 'nested' / 'data.txt').read_bytes()
        gate.disengage(self.root, self.mp)
        self.assertEqual((self.root / 'nested' / 'data.txt').read_text(), 'original data')


if __name__ == '__main__':
    unittest.main()
