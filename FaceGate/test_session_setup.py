import unittest
import xml.etree.ElementTree as ET
from session_setup import task_xml, NS
from test_shell_integration import FakeRegistry
import explorer_integration as shell


class SessionSetupTests(unittest.TestCase):
    def test_task_runs_current_user_on_logon_and_unlock_without_elevation(self):
        root = ET.fromstring(task_xml('S-1-5-21-123', r'C:\App & Data\pythonw.exe', r'C:\App & Data\main.py'))
        ns = {'t': NS}
        self.assertEqual(root.findtext('t:Triggers/t:SessionStateChangeTrigger/t:StateChange', namespaces=ns), 'SessionUnlock')
        self.assertEqual(root.findtext('t:Triggers/t:LogonTrigger/t:UserId', namespaces=ns), 'S-1-5-21-123')
        self.assertEqual(root.findtext('t:Principals/t:Principal/t:RunLevel', namespaces=ns), 'LeastPrivilege')
        self.assertIn('--guardian', root.findtext('t:Actions/t:Exec/t:Arguments', namespaces=ns))
        self.assertEqual(root.findtext('t:Settings/t:ExecutionTimeLimit', namespaces=ns), 'PT0S')

    def test_double_click_can_be_updated_and_removed_without_losing_original(self):
        reg = FakeRegistry()
        original = ('custom', reg.REG_EXPAND_SZ)
        reg.keys[shell.SHELL_KEY] = {None: original}
        shell.install_double_click('first', 'icon', reg)
        shell.install_double_click('second', 'icon', reg)
        self.assertTrue(shell.double_click_enabled(reg))
        self.assertEqual(shell._read(reg, shell.SHELL_KEY)[0], shell.VERB)
        shell.uninstall(reg)
        self.assertEqual(shell._read(reg, shell.SHELL_KEY), original)
        self.assertFalse(shell.double_click_enabled(reg))

    def test_ordinary_folder_with_guardian_only_database_still_opens(self):
        import sqlite3
        import tempfile
        from pathlib import Path
        from explorer_router import find_protected_root
        with tempfile.TemporaryDirectory() as d:
            database = Path(d) / 'users.db'
            with sqlite3.connect(database) as con:
                con.execute('CREATE TABLE guardian_pending (key TEXT)')
            con.close()  # sqlite3's transaction context does not close the handle.
            self.assertIsNone(find_protected_root(r'C:\Ordinary', database))
