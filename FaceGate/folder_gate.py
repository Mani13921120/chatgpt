"""Windows folder gate: persistent root DACL plus live sharing locks.

Applies reversible per-object DACLs and a shared parent deletion guard.
Recovery metadata remains outside the selected folder.
"""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import uuid
import windows_acl_policy as policy

_handles = {}
_verified = set()
DACL = 4
FILE_READ_DATA = 0x0001  # FILE_LIST_DIRECTORY for directory handles
DELETE = 0x00010000
FILE_SHARE_ALL = 0x0007
LOCK_ACCESS = FILE_READ_DATA | DELETE


def _key(root):
    # Windows TEMP, shortcuts and callers can use an 8.3 alias for a path that
    # Path.resolve() elsewhere expands to its long name. Use one identity form.
    return os.path.normcase(os.path.realpath(os.path.abspath(root)))


def _api():
    if os.name != 'nt':
        raise RuntimeError('قفل خود پوشه فقط روی Windows و دیسک دارای ACL پشتیبانی می‌شود.')
    policy.bindings()  # Check the native dependency before changing any data.
    k = C.WinDLL('kernel32', use_last_error=True)
    a = C.WinDLL('advapi32', use_last_error=True)
    k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
    k.CreateFileW.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    k.CloseHandle.restype = W.BOOL
    k.LocalFree.argtypes = [C.c_void_p]
    k.LocalFree.restype = C.c_void_p
    a.GetFileSecurityW.argtypes = [W.LPCWSTR, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    a.GetFileSecurityW.restype = W.BOOL
    a.SetFileSecurityW.argtypes = [W.LPCWSTR, W.DWORD, C.c_void_p]
    a.SetFileSecurityW.restype = W.BOOL
    a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD)]
    a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = W.BOOL
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD)]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = W.BOOL
    return k, a


def _get_dacl(root):
    k, a = _api()
    n = W.DWORD()
    a.GetFileSecurityW(str(root), DACL, None, 0, C.byref(n))
    if not n.value:
        raise C.WinError(C.get_last_error())
    buf = C.create_string_buffer(n.value)
    if not a.GetFileSecurityW(str(root), DACL, buf, n.value, C.byref(n)):
        raise C.WinError(C.get_last_error())
    p = C.c_void_p()
    if not a.ConvertSecurityDescriptorToStringSecurityDescriptorW(buf, 1, DACL, C.byref(p), None):
        raise C.WinError(C.get_last_error())
    try:
        return C.wstring_at(p)
    finally:
        k.LocalFree(p)


def _set_dacl(root, sddl):
    k, a = _api()
    p = C.c_void_p()
    if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(p), None):
        raise C.WinError(C.get_last_error())
    try:
        flags = sddl[2:].split('(', 1)[0]
        inheritance = 0x80000000 if 'P' in flags else 0x20000000
        if not a.SetFileSecurityW(str(root), DACL | inheritance, p):
            raise C.WinError(C.get_last_error())
    finally:
        k.LocalFree(p)


def sidecar(manifest):
    return Path(str(manifest) + '.gate')


def saved(root, manifest):
    p = sidecar(manifest)
    if not p.exists():
        return None
    value = json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(value.get('root'), str) or _key(value['root']) != _key(root) or not isinstance(value.get('original_dacl'), str):
        raise RuntimeError('اطلاعات بازیابی مجوز پوشه نامعتبر است؛ هیچ مجوزی تغییر نکرد.')
    policy.validate(value, root)
    return value


def active(root):
    return _key(root) in _handles and _key(root) in _verified


def _paths(root):
    paths = []
    def fail(exc):
        raise exc
    for current, dirs, files in os.walk(root, onerror=fail, followlinks=False):
        for name in dirs + files:
            p = Path(current) / name
            if p.is_symlink() or p.stat().st_file_attributes & 0x400:
                raise RuntimeError('junction/symlink در قفل پوشه پشتیبانی نمی‌شود.')
            paths.append(p)
    return paths + [Path(root)]


def acquire(root, paths=None):
    """All handles or none; existing incompatible open files cause an error."""
    if _key(root) in _handles:
        return
    k, _ = _api()
    handles = []
    try:
        for path in (paths if paths is not None else _paths(root)):
            # A metadata-only READ_CONTROL handle does not participate in normal
            # data-access sharing checks. Request actual read/list access so that
            # share=0 enforces read/write/delete exclusion, including empty dirs.
            h = k.CreateFileW(str(path), LOCK_ACCESS, 0, None, 3, 0x02000000, None)
            if h == C.c_void_p(-1).value:
                raise C.WinError(C.get_last_error())
            handles.append(h)
        _handles[_key(root)] = handles
    except Exception:
        for h in reversed(handles):
            k.CloseHandle(h)
        raise


def _denied(path, accesses):
    k, _ = _api()
    for access in accesses:
        h = k.CreateFileW(str(path), access, FILE_SHARE_ALL, None, 3, 0x02000000, None)
        if h != C.c_void_p(-1).value:
            k.CloseHandle(h)
            raise RuntimeError('ویندوز هنوز دسترسی خواندن، نوشتن یا حذف را می‌دهد؛ قفل کامل اعمال نشد: ' + str(path))
        error = C.get_last_error()
        if error not in (5, 32):
            raise C.WinError(error)


def verify_exclusion(root, paths=None):
    """Non-destructive access probes; success is based on actual Windows denial."""
    for path in (paths if paths is not None else [root]):
        _denied(path, (FILE_READ_DATA, 0x2, DELETE))


def verify_lock(root, manifest):
    value = saved(root, manifest)
    if not active(root) or not value or value.get('version') != 2 or value.get('state') != 'locked':
        raise RuntimeError('قفل کامل و تأییدشده فعال نیست؛ قفل مجدد یا بازیابی لازم است.')
    paths = [policy.relative_path(root, e['relative']) for e in value['entries']]
    verify_exclusion(root, paths)
    _denied(Path(root).parent, (policy.DELETE_CHILD,))
    return sum(not e['directory'] for e in value['entries'])


def release(root):
    _verified.discard(_key(root))
    handles = _handles.pop(_key(root), [])
    if handles:
        k, _ = _api()
        for h in reversed(handles):
            k.CloseHandle(h)


def _restore_existing(root, manifest, value):
    if value.get('state') == 'unlocked':
        return
    if value.get('version') == 2:
        policy.restore_tree(root, manifest, value)
    else:
        _set_dacl(root, value['original_dacl'])


def engage(root, manifest):
    """Journal all original ACLs, apply tree/parent guards, then verify Windows."""
    root = Path(os.path.realpath(os.path.abspath(root)))
    if active(root):
        verify_lock(root, manifest)
        return
    value = saved(root, manifest)
    if value:
        _restore_existing(root, manifest, value)
        release(root)
    paths = _paths(root)
    value = policy.snapshot(root, paths)
    policy.write_journal(sidecar(manifest), value)
    try:
        acquire(root, paths)
        policy.apply_tree(root, manifest, value)
        verify_exclusion(root, paths)
        _denied(root.parent, (policy.DELETE_CHILD,))
        value['state'] = 'locked'
        policy.write_journal(sidecar(manifest), value)
        _verified.add(_key(root))
    except Exception as exc:
        try:
            policy.restore_tree(root, manifest, value)
            release(root)
            value['state'] = 'unlocked'
            policy.write_journal(sidecar(manifest), value)
        except Exception as recovery:
            # Keep remaining live handles and the durable original ACL journal.
            # Never display a verified lock when rollback was incomplete.
            _verified.discard(_key(root))
            raise RuntimeError('قفل کامل نشد و بازیابی بعضی مجوزها نیازمند بررسی است. اطلاعات بازیابی را حذف نکن.\n' + str(recovery)) from exc
        raise


def disengage(root, manifest):
    """Caller MUST authenticate before changing permissions or releasing handles."""
    value = saved(root, manifest)
    if value:
        _restore_existing(root, manifest, value)
        value['state'] = 'unlocked'
        policy.write_journal(sidecar(manifest), value)
    release(root)
