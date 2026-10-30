"""Per-user Explorer context menu and repair of the legacy default override.

This routes Shell open invocations, not arbitrary filesystem I/O. No test folders,
shortcuts, desktop.ini files, or changes inside selected directories are created.
"""
import ctypes
import json
import os
import subprocess

VERB = 'FaceGateOpen'
SHELL_KEY = r'Software\Classes\Directory\shell'
STATE_KEY = r'Software\FaceGate\ExplorerIntegration'


def _registry():
    if os.name != 'nt':
        raise RuntimeError('این قابلیت فقط روی ویندوز در دسترس است.')
    import winreg
    return winreg


def _read(reg, path, name=None):
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_READ) as key:
            return reg.QueryValueEx(key, name)
    except FileNotFoundError:
        return None


def _write(reg, path, name, value, kind):
    with reg.CreateKeyEx(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_SET_VALUE) as key:
        reg.SetValueEx(key, name, 0, kind, value)


def _delete_value(reg, path, name=None):
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_SET_VALUE) as key:
            reg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def _delete_key(reg, path):
    try:
        reg.DeleteKey(reg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def restore_legacy_default(registry=None):
    reg = registry or _registry()
    current = _read(reg, SHELL_KEY)
    if not current or current[0] != VERB:
        return False
    state = _read(reg, STATE_KEY, 'PreviousDefault')
    previous = json.loads(state[0]) if state else None
    if previous is None or previous[0] == VERB:
        # Remove only our own override; Windows' inherited default becomes active.
        _delete_value(reg, SHELL_KEY)
    else:
        _write(reg, SHELL_KEY, None, previous[0], previous[1])
    if registry is None:
        _notify_shell()
    return True


def install(command, icon, registry=None):
    reg = registry or _registry()
    restore_legacy_default(reg)
    verb_key = SHELL_KEY + '\\' + VERB
    _write(reg, verb_key, None, 'بازکردن با FaceGate', reg.REG_SZ)
    _write(reg, verb_key, 'Icon', icon, reg.REG_SZ)
    _write(reg, verb_key + r'\command', None, command, reg.REG_SZ)
    # Context menu only: never replace the default navigation verb again.
    if registry is None:
        _notify_shell()


def uninstall(registry=None):
    reg = registry or _registry()
    restore_legacy_default(reg)
    # A newer default chosen by the user or another application remains untouched.
    _delete_key(reg, SHELL_KEY + '\\' + VERB + r'\command')
    _delete_key(reg, SHELL_KEY + '\\' + VERB)
    _delete_value(reg, STATE_KEY, 'PreviousDefault')
    _delete_key(reg, STATE_KEY)
    if registry is None:
        _notify_shell()


def _notify_shell():
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.SHChangeNotify.argtypes = [ctypes.c_long, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
    shell.SHChangeNotify.restype = None
    shell.SHChangeNotify(0x08000000, 0, None, None)


def open_directory(path):
    """Explicit Explorer process avoids re-entering our default Shell verb."""
    if os.name != 'nt':
        raise RuntimeError('بازکردن Explorer فقط روی ویندوز ممکن است.')
    from pathlib import Path
    explorer = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'explorer.exe'
    subprocess.Popen([str(explorer), os.path.abspath(path)], close_fds=True)
