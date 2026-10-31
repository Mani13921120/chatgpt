"""Bound authenticated folder access to Explorer's reported folder views.

No foreground/title guessing: minimising Explorer does not end a session.
The COM probe runs in a disposable process so an unresponsive Shell cannot hang
the GUI. This observes Shell views, not kernel I/O or per-process authorization.
"""
from dataclasses import dataclass
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit
import uuid


def path_key(path):
    return ntpath.normcase(os.path.realpath(path) if os.name == 'nt' else ntpath.abspath(path))


def inside(root, candidate):
    if not candidate:
        return False
    root, candidate = path_key(root), path_key(candidate)
    try:
        return ntpath.commonpath([root, candidate]) == root
    except ValueError:
        return False


def file_url_path(url):
    value = urlsplit(url)
    if value.scheme.lower() != 'file':
        return None
    path = unquote(value.path)
    if value.netloc and value.netloc.lower() != 'localhost':
        return '\\\\' + value.netloc + path.replace('/', '\\')
    if len(path) >= 3 and path[0] == '/' and path[2] == ':':
        path = path[1:]
    return path.replace('/', '\\') if path else None


@dataclass
class Session:
    root: str
    token: str
    started: float
    seen: bool = False
    missing_since: float | None = None
    error_since: float | None = None
    retry_at: float = 0.0
    observed_at: float = 0.0


class ExplorerSessions:
    def __init__(self, launch_timeout=15.0, leave_grace=1.0, error_timeout=5.0):
        self.sessions = {}
        self.launch_timeout = launch_timeout
        self.leave_grace = leave_grace
        self.error_timeout = error_timeout

    def begin(self, root, now=None):
        now = time.monotonic() if now is None else now
        session = Session(str(root), uuid.uuid4().hex, now)
        self.sessions[path_key(root)] = session
        return session.token

    def discard(self, root):
        self.sessions.pop(path_key(root), None)

    def tokens(self):
        return {key: item.token for key, item in self.sessions.items()}

    def reusable(self, root, now=None):
        """Only this process's live authenticated session can reuse access."""
        now = time.monotonic() if now is None else now
        session = self.sessions.get(path_key(root))
        if not session or session.missing_since is not None or session.error_since is not None or session.retry_at:
            return False
        return (now - session.observed_at <= 2.0 if session.seen
                else now - session.started < self.launch_timeout)

    def observe(self, paths, tokens, now=None):
        """Return due roots. None means observation failed, never 'no windows'.

        A failed probe has a short bounded grace, then requests protective relock.
        A probe started before a new authentication cannot expire that new lease.
        """
        now = time.monotonic() if now is None else now
        due = []
        for key, session in self.sessions.items():
            if tokens.get(key) != session.token:
                continue
            if paths is None:
                if session.error_since is None:
                    session.error_since = now
                expired = now - session.error_since >= self.error_timeout
            else:
                session.error_since = None
                if any(inside(session.root, path) for path in paths):
                    session.seen = True
                    session.observed_at = now
                    session.missing_since = None
                    continue
                if session.missing_since is None:
                    session.missing_since = now
                expired = (now - session.missing_since >= self.leave_grace if session.seen
                           else now - session.started >= self.launch_timeout)
            if expired and now >= session.retry_at:
                due.append(session.root)
        return due

    def retry_later(self, root, now=None):
        session = self.sessions.get(path_key(root))
        if session:
            session.retry_at = (time.monotonic() if now is None else now) + 5.0


def enumerate_paths():
    """Call only in the probe process; COM interfaces stay in their apartment."""
    if os.name != 'nt':
        raise RuntimeError('Explorer observation requires Windows.')
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()
    try:
        shell = win32com.client.Dispatch('Shell.Application')
        windows = shell.Windows()
        count = windows.Count
        paths = []
        for index in range(count):
            window = windows.Item(index)
            if window is None:
                raise RuntimeError('Explorer views changed during observation.')
            if ntpath.basename(window.FullName).lower() != 'explorer.exe':
                continue
            if window.Busy:
                raise RuntimeError('Explorer is navigating; retry observation.')
            path = file_url_path(window.LocationURL or '')
            if path:
                paths.append(path)
        if count != windows.Count:
            raise RuntimeError('Explorer view count changed during observation.')
        return paths
    finally:
        pythoncom.CoUninitialize()


def write_snapshot(destination):
    try:
        result = {'paths': enumerate_paths()}
    except Exception as exc:
        result = {'error': str(exc)}
    Path(destination).write_text(json.dumps(result, ensure_ascii=True), encoding='utf-8')


def snapshot():
    """Bound Shell COM calls to four seconds; timeout kills only our probe."""
    with tempfile.TemporaryDirectory(prefix='facegate-shell-') as directory:
        output = Path(directory) / 'views.json'
        if getattr(sys, 'frozen', False):
            command = [sys.executable, '--explorer-snapshot-output', str(output)]
        else:
            executable = Path(sys.executable)
            if executable.name.lower() == 'pythonw.exe':
                executable = executable.with_name('python.exe')
            command = [str(executable), str(Path(__file__).resolve()), str(output)]
        subprocess.run(command, check=True, timeout=4, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if output.stat().st_size > 1024 * 1024:
            raise RuntimeError('Explorer snapshot is too large.')
        value = json.loads(output.read_text(encoding='utf-8'))
        if 'error' in value:
            raise RuntimeError(value['error'])
        paths = value.get('paths')
        if not isinstance(paths, list) or not all(isinstance(p, str) and '\x00' not in p for p in paths):
            raise RuntimeError('Invalid Explorer snapshot.')
        return paths


if __name__ == '__main__':
    write_snapshot(sys.argv[1])
