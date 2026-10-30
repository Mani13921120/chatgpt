import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import windows_acl_policy as policy


class AclPolicySafetyTests(unittest.TestCase):
    def test_recovery_metadata_cannot_be_locked_inside_selected_tree(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'selected'
            for location in (root, root / 'keys', root / 'keys' / 'metadata.json'):
                with self.subTest(location=location), self.assertRaises(RuntimeError):
                    policy.ensure_external_metadata(root, location)
            policy.ensure_external_metadata(root, Path(d) / 'external-keys')
    def test_relative_metadata_paths_cannot_escape_selected_root(self):
        for path in ('../outside', r'\outside', r'C:\outside', r'C:outside', r'\\server\share', 'file:stream'):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                policy.relative_path(Path('selected'), path)

    def test_metadata_handles_close_on_exception(self):
        file = Mock()
        handle = file.CreateFile.return_value
        with patch.object(policy, 'bindings', return_value=(file, None)):
            with self.assertRaisesRegex(RuntimeError, 'test failure'):
                with policy.metadata_handle('selected') as actual:
                    self.assertIs(actual, handle)
                    raise RuntimeError('test failure')
        handle.Close.assert_called_once()

    def test_identity_mismatch_never_writes_permissions(self):
        file, security = Mock(), Mock()
        file.GetFileInformationByHandle.return_value = (0x20, None, None, None, 12, 0, 0, 1, 34, 56)
        descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor.return_value
        descriptor.GetSecurityDescriptorControl.return_value = (0, 1)
        with patch.object(policy, 'bindings', return_value=(file, security)):
            with self.assertRaises(RuntimeError):
                policy.set_dacl('selected', 'D:(A;;FA;;;WD)', [99, 99, 99])
        security.SetSecurityInfo.assert_not_called()
        security.SetKernelObjectSecurity.assert_not_called()
        file.CreateFile.return_value.Close.assert_called_once()
