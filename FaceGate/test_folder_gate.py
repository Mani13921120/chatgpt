"""Run: python -m unittest -v test_folder_gate (Windows NTFS for integration)."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import folder_gate as gate
import folder_inplace_crypto as crypto


class AuthenticationTests(unittest.TestCase):
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

    def test_persistent_dacl_survives_process_exit_and_can_be_recovered(self):
        code = 'import folder_gate as g; import sys; g.engage(sys.argv[1],sys.argv[2])'
        subprocess.run([sys.executable, '-c', code, str(self.root), str(self.mp)], check=True)
        with self.assertRaises(OSError):
            list(self.root.iterdir())
        gate.engage(self.root, self.mp)
        self.assertTrue(gate.active(self.root))
        gate.disengage(self.root, self.mp)
        self.assertEqual(gate._get_dacl(self.root), self.original)


if __name__ == '__main__':
    unittest.main()
