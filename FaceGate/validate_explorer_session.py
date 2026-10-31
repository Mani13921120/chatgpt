r"""Opt-in interactive Windows smoke test; touches only its disposable data.

Run with .venv\Scripts\python.exe validate_explorer_session.py on the Windows
desktop. Tests actual Explorer navigation/closure, crypto and NTFS denial.
Camera authentication is deliberately not part of this automated smoke test.
"""
import os
from pathlib import Path
import tempfile
import time

import explorer_integration
import explorer_sessions
import folder_inplace_crypto as crypto


def wait_for(predicate, description, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.25)
    raise RuntimeError('Timed out: ' + description)


def main():
    if os.name != 'nt':
        raise SystemExit('Requires a real interactive Windows desktop and NTFS.')
    import pythoncom
    import pywintypes
    import win32file
    import win32com.client
    pythoncom.CoInitialize()
    try:
        with tempfile.TemporaryDirectory(prefix='facegate-explorer-test-') as temporary:
            base = Path(temporary)
            root = base / 'protected'; root.mkdir()
            child = root / 'child'; child.mkdir()
            file = child / 'data.txt'; file.write_text('original', encoding='utf-8')
            result = crypto.protect_folder_in_place(root, '12345678', base / 'metadata', base / 'backups')
            manifest = result['manifest_path']
            shell = win32com.client.Dispatch('Shell.Application')
            opened = []
            try:
                for end in ('navigate', 'close'):
                    crypto.unlock_folder_in_place(root, base / 'metadata', pin='12345678', manifest=manifest)
                    tracker = explorer_sessions.ExplorerSessions()
                    tracker.begin(str(root))
                    explorer_integration.open_directory(root)

                    def find_view():
                        for window in shell.Windows():
                            path = explorer_sessions.file_url_path(window.LocationURL or '')
                            if path and explorer_sessions.inside(str(root), path):
                                return window
                        return None
                    view = wait_for(find_view, 'Explorer opens disposable protected root')
                    opened.append(view)
                    tracker.observe(explorer_sessions.snapshot(), tracker.tokens())
                    view.Navigate(str(child))
                    wait_for(lambda: any(explorer_sessions.path_key(p) == explorer_sessions.path_key(str(child))
                                         for p in explorer_sessions.snapshot()), 'navigate into child')
                    assert not tracker.observe(explorer_sessions.snapshot(), tracker.tokens())
                    file.write_text('edited in ' + end + ' session', encoding='utf-8')
                    if end == 'navigate':
                        view.Navigate(str(base))
                    else:
                        view.Quit()
                        opened.remove(view)
                    wait_for(lambda: tracker.observe(explorer_sessions.snapshot(), tracker.tokens()),
                             'session ends after ' + end)
                    crypto.lock_folder_in_place(root, base / 'metadata', manifest=manifest)
                    crypto.folder_gate.release(root)  # Verify durable ACL rather than sharing handles.
                    try:
                        handle = win32file.CreateFile(str(file), crypto.folder_gate.FILE_READ_DATA,
                                                      crypto.folder_gate.FILE_SHARE_ALL, None, 3, 0x02000000, None)
                        handle.Close()
                    except pywintypes.error as denied:
                        assert denied.winerror == 5, repr(denied)
                    else:
                        raise AssertionError('Locked contents are still readable')
                    crypto.unlock_folder_in_place(root, base / 'metadata', pin='12345678', manifest=manifest)
                    assert file.read_text(encoding='utf-8') == 'edited in ' + end + ' session'
                    print('PASS: actual Explorer ' + end + ', content preservation, persistent Access Denied (5)')
            finally:
                for view in opened:
                    try:
                        view.Quit()
                    except Exception:
                        pass
                # Restore ACLs/data before deleting only this test's temp folder.
                crypto.unprotect_folder_in_place(root, base / 'metadata', '12345678', manifest=manifest)
    finally:
        pythoncom.CoUninitialize()


if __name__ == '__main__':
    main()
