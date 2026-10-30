"""Windows folder gate: persistent root DACL plus live sharing locks.

Not a kernel security boundary against the account owner/admin. Never modifies
parent or child DACLs. Recovery metadata must remain outside the target folder.
"""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import uuid

_handles = {}
DACL = 4
FILE_READ_DATA = 0x0001  # FILE_LIST_DIRECTORY for directory handles
DELETE = 0x00010000
FILE_SHARE_ALL = 0x0007


def _key(root):
    # Windows TEMP, shortcuts and callers can use an 8.3 alias for a path that
    # Path.resolve() elsewhere expands to its long name. Use one identity form.
    return os.path.normcase(os.path.realpath(os.path.abspath(root)))


def _api():
    if os.name != 'nt':
        raise RuntimeError('قفل خود پوشه فقط روی Windows و دیسک دارای ACL پشتیبانی می‌شود.')
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
    return value


def active(root):
    return _key(root) in _handles


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


def acquire(root):
    """All handles or none; existing incompatible open files cause an error."""
    if active(root):
        return
    k, _ = _api()
    handles = []
    try:
        for path in _paths(root):
            # A metadata-only READ_CONTROL handle does not participate in normal
            # data-access sharing checks. Request actual read/list access so that
            # share=0 enforces read/write/delete exclusion, including empty dirs.
            h = k.CreateFileW(str(path), FILE_READ_DATA, 0, None, 3, 0x02000000, None)
            if h == C.c_void_p(-1).value:
                raise C.WinError(C.get_last_error())
            handles.append(h)
        _handles[_key(root)] = handles
    except Exception:
        for h in reversed(handles):
            k.CloseHandle(h)
        raise


def verify_exclusion(root):
    """Never report a lock if Windows still grants read/list or delete access.

    Probes request handles only; they never read, copy, rename or delete data.
    DELETE checks the parent-permission route too, unlike inspecting the root ACL.
    """
    k, _ = _api()
    for access in (FILE_READ_DATA, DELETE):
        h = k.CreateFileW(str(root), access, FILE_SHARE_ALL, None, 3, 0x02000000, None)
        if h != C.c_void_p(-1).value:
            k.CloseHandle(h)
            raise RuntimeError('ویندوز هنوز دسترسی خواندن یا حذف پوشه را می‌دهد؛ قفل کامل اعمال نشد.')
        error = C.get_last_error()
        if error not in (5, 32):  # ACCESS_DENIED or SHARING_VIOLATION, not missing path/etc.
            raise C.WinError(error)


def release(root):
    handles = _handles.pop(_key(root), [])
    if handles:
        k, _ = _api()
        for h in reversed(handles):
            k.CloseHandle(h)


def engage(root, manifest):
    """Save restoration data before restricting access. No success on partial lock."""
    if active(root):
        return
    value = saved(root, manifest)
    # A previous process may have left the persistent DACL in place. Opening
    # children requires restoring it first; ciphertext remains protected.
    if value:
        _set_dacl(root, value['original_dacl'])
    else:
        original = _get_dacl(root)
        if not original.startswith('D:') or '(' not in original:
            raise RuntimeError('این پوشه DACL معمولی ندارد؛ برای جلوگیری از تغییر ناامن، قفل اعمال نشد.')
        value = {'root': _key(root), 'original_dacl': original}
        dest = sidecar(manifest)
        temp = dest.with_name(dest.name + '.' + uuid.uuid4().hex)
        try:
            with temp.open('x', encoding='utf-8') as f:
                json.dump(value, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, dest)
        finally:
            temp.unlink(missing_ok=True)
    try:
        acquire(root)
        original = value['original_dacl']
        i = original.index('(')
        # No inheritance: only the selected directory DACL changes. Preserve
        # READ_CONTROL/WRITE_DAC for restoration by its owner.
        _set_dacl(root, original[:i] + '(D;;0x00010047;;;WD)' + original[i:])
        verify_exclusion(root)
    except Exception:
        release(root)
        _set_dacl(root, value['original_dacl'])
        raise


def disengage(root, manifest):
    """Caller MUST authenticate before calling this function."""
    value = saved(root, manifest)
    if value:
        _set_dacl(root, value['original_dacl'])
    release(root)
