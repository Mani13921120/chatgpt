"""Reversible NTFS ACL journal for a complete selected tree and its parent.

The parent receives only a non-inheriting DELETE_CHILD denial, shared across
protected siblings. Unrelated parent ACEs are preserved when the guard is removed.
All metadata stays outside the selected tree. No ownership changes are performed.
"""
import json
import os
from pathlib import Path, PureWindowsPath
import sqlite3
import threading
import uuid
from contextlib import closing, contextmanager

_LOCK = threading.RLock()
READ_CONTROL = 0x20000
WRITE_DAC = 0x40000
READ_ATTRIBUTES = 0x80
DELETE_CHILD = 0x40
REPARSE_POINT = 0x400
DENY_FILE = 0x10137
DENY_DIRECTORY = 0x10177


def bindings():
    if os.name != 'nt':
        raise RuntimeError('Windows/NTFS is required.')
    try:
        import win32file
        import win32security
    except ImportError as exc:
        raise RuntimeError('وابستگی pywin32 نصب نیست؛ INSTALL_DEPENDENCIES.bat را اجرا کن.') from exc
    return win32file, win32security


def key(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


@contextmanager
def metadata_handle(path, write=False):
    file, _ = bindings()
    access = READ_CONTROL | READ_ATTRIBUTES | (WRITE_DAC if write else 0)
    handle = file.CreateFile(str(path), access, 7, None, 3, 0x02000000 | 0x00200000, None)
    try:
        yield handle
    finally:
        handle.Close()


def information(handle):
    file, _ = bindings()
    info = file.GetFileInformationByHandle(handle)
    if info[0] & REPARSE_POINT:
        raise RuntimeError('مسیر به junction/symlink تغییر کرده است؛ مجوزی تغییر نکرد.')
    return [int(n) & 0xffffffff for n in (info[4], info[-2], info[-1])], bool(info[0] & 0x10)


def identity(path):
    with metadata_handle(path) as handle:
        return information(handle)[0]


def dacl(path):
    _, security = bindings()
    with metadata_handle(path) as handle:
        information(handle)
        sd = security.GetKernelObjectSecurity(handle, security.DACL_SECURITY_INFORMATION)
    return security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, security.DACL_SECURITY_INFORMATION)


def set_dacl(path, value, expected_identity):
    _, security = bindings()
    sd = security.ConvertStringSecurityDescriptorToSecurityDescriptor(value, 1)
    control, _ = sd.GetSecurityDescriptorControl()
    protection = 0x80000000 if control & 0x1000 else 0x20000000
    with metadata_handle(path, write=True) as handle:
        actual, _ = information(handle)
        if actual != expected_identity:
            raise RuntimeError('هویت فایل یا پوشه تغییر کرده است؛ برای جلوگیری از تغییر مجوز مسیر اشتباه، عملیات متوقف شد.')
        flags = security.DACL_SECURITY_INFORMATION | protection
        # pywin32 parses SECURITY_INFORMATION as a signed Windows LONG, although
        # the native bitmask is unsigned. Preserve the high protection bit.
        if flags >= 0x80000000:
            flags -= 0x100000000
        # Set the complete descriptor on the validated handle. SetSecurityInfo
        # re-evaluates inheritance and can change originally explicit ACEs.
        security.SetKernelObjectSecurity(handle, flags, sd)


def relative_path(root, relative):
    rel = PureWindowsPath(relative)
    if rel.is_absolute() or rel.root or rel.drive or '..' in rel.parts or '\x00' in relative or ':' in relative:
        raise RuntimeError('مسیر فرادادهٔ مجوز نامعتبر است.')
    return Path(root).joinpath(*rel.parts)


def validate(value, root):
    if value.get('version') != 2:
        return
    entries = value.get('entries')
    if not isinstance(entries, list) or not entries:
        raise RuntimeError('فهرست بازیابی مجوزها نامعتبر است.')
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get('relative'), str):
            raise RuntimeError('رکورد مجوز نامعتبر است.')
        relative_path(root, entry['relative'])
        normalized = str(PureWindowsPath(entry['relative'])).casefold()
        if normalized in seen:
            raise RuntimeError('رکورد مجوز تکراری است.')
        seen.add(normalized)
        file_id = entry.get('identity')
        if not isinstance(entry.get('dacl'), str) or type(entry.get('directory')) is not bool or not isinstance(file_id, list) or len(file_id) != 3 or not all(type(n) is int and n >= 0 for n in file_id):
            raise RuntimeError('شناسه یا مجوز ذخیره‌شده نامعتبر است.')
    if entries[0]['relative'] != '.' or key(value.get('parent', '')) != key(Path(root).parent):
        raise RuntimeError('ریشه یا والد فرادادهٔ مجوز نامعتبر است.')
    parent_id = value.get('parent_identity')
    if not isinstance(parent_id, list) or len(parent_id) != 3 or not all(type(n) is int and n >= 0 for n in parent_id):
        raise RuntimeError('شناسهٔ والد نامعتبر است.')


def write_journal(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temp.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def snapshot(root, paths):
    root = Path(root)
    parent = root.parent
    if parent == root or parent == Path(parent.anchor):
        raise RuntimeError('برای محافظت از حذف، پوشه باید داخل یک پوشهٔ شخصی باشد؛ مجوز ریشهٔ درایو تغییر داده نمی‌شود.')
    entries = []
    ordered = sorted(set([root] + [Path(p) for p in paths]), key=lambda p: (len(p.parts), str(p).casefold()))
    for path in ordered:
        with metadata_handle(path, write=True) as handle:
            file_id, directory = information(handle)
            file, security = bindings()
            if not directory and file.GetFileInformationByHandle(handle)[7] > 1:
                raise RuntimeError('فایل دارای hard link است؛ مجوز مسیرهای خارج از پوشه تغییر داده نمی‌شود.')
            sd = security.GetKernelObjectSecurity(handle, security.DACL_SECURITY_INFORMATION)
            acl = security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, security.DACL_SECURITY_INFORMATION)
        if not acl.startswith('D:') or '(' not in acl:
            raise RuntimeError('قفل پوشه با مجوز خالی/نامحدود پشتیبانی نمی‌شود؛ هیچ مجوزی تغییر نکرد.')
        entries.append({'relative': path.relative_to(root).as_posix(), 'identity': file_id,
                        'directory': directory, 'dacl': acl})
    return {'version': 2, 'root': key(root), 'original_dacl': entries[0]['dacl'], 'state': 'locking',
            'parent': str(parent), 'parent_identity': identity(parent), 'entries': entries}


def preflight_parent(root):
    root = Path(os.path.realpath(os.path.abspath(root)))
    parent = root.parent
    if parent == root or parent == Path(parent.anchor):
        raise RuntimeError('برای جلوگیری از تغییر مجوز ریشهٔ درایو، پوشه باید داخل یک پوشهٔ شخصی باشد.')
    # Check permission to install/remove the guard before decrypting, encrypting,
    # or temporarily restoring a legacy root ACL. This call changes nothing.
    with metadata_handle(parent, write=True) as handle:
        information(handle)


def locked_dacl(entry):
    original = entry['dacl']
    mask = DENY_DIRECTORY if entry['directory'] else DENY_FILE
    # Protect each object's ACL from inheritance while locked. Keep original ACEs
    # verbatim; the original protection/inheritance flags are restored from the journal.
    return 'D:P(D;;0x%08x;;;WD)' % mask + original[original.index('('):]


def _parent_database(manifest):
    path = Path(manifest).parent / 'folder_parent_guards.sqlite3'
    con = sqlite3.connect(path, timeout=20)
    con.execute('CREATE TABLE IF NOT EXISTS parents (path TEXT PRIMARY KEY, identity TEXT NOT NULL, original TEXT NOT NULL, inserted INTEGER NOT NULL)')
    con.execute('CREATE TABLE IF NOT EXISTS members (parent TEXT NOT NULL, root TEXT NOT NULL, PRIMARY KEY(parent, root))')
    con.commit()
    return con


def _our_parent_ace(ace, security):
    return (len(ace) == 3 and ace[0] == (security.ACCESS_DENIED_ACE_TYPE, 0)
            and ace[1] == DELETE_CHILD and security.ConvertSidToStringSid(ace[2]) == 'S-1-1-0')


def parent_policy(current, remove=False):
    _, security = bindings()
    sd = security.ConvertStringSecurityDescriptorToSecurityDescriptor(current, 1)
    acl = sd.GetSecurityDescriptorDacl()
    if acl is None:
        raise RuntimeError('مجوز والد نامحدود است؛ برای جلوگیری از تغییر ناامن، قفل اعمال نشد.')
    index = next((i for i in range(acl.GetAceCount()) if _our_parent_ace(acl.GetAce(i), security)), None)
    if remove:
        if index is None:
            return current, False
        acl.DeleteAce(index)
    else:
        if index is not None:
            return current, False
        acl.AddAccessDeniedAceEx(4, 0, DELETE_CHILD, security.ConvertStringSidToSid('S-1-1-0'))
    sd.SetSecurityDescriptorDacl(True, acl, False)
    return security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, security.DACL_SECURITY_INFORMATION), True


def protect_parent(root, manifest, journal):
    parent = Path(root).parent
    parent_key, root_key = key(parent), key(root)
    with _LOCK, closing(_parent_database(manifest)) as con:
        row = con.execute('SELECT identity, original, inserted FROM parents WHERE path=?', (parent_key,)).fetchone()
        if row:
            expected = json.loads(row[0])
            if identity(parent) != expected:
                raise RuntimeError('پوشهٔ والد تغییر کرده است؛ قفل اعمال نشد.')
            current = dacl(parent)
            guarded, _ = parent_policy(current)
        else:
            expected = journal['parent_identity']
            current = dacl(parent)
            guarded, inserted = parent_policy(current)
            con.execute('INSERT INTO parents VALUES (?,?,?,?)', (parent_key, json.dumps(expected), current, int(inserted)))
        con.execute('INSERT OR IGNORE INTO members VALUES (?,?)', (parent_key, root_key))
        # Persist restoration ownership before changing a permission.
        con.commit()
        set_dacl(parent, guarded, expected)


def release_parent(root, manifest):
    parent = Path(root).parent
    parent_key, root_key = key(parent), key(root)
    with _LOCK, closing(_parent_database(manifest)) as con:
        row = con.execute('SELECT identity, original, inserted FROM parents WHERE path=?', (parent_key,)).fetchone()
        if not row:
            return
        member = con.execute('SELECT 1 FROM members WHERE parent=? AND root=?', (parent_key, root_key)).fetchone()
        if not member:
            return
        others = con.execute('SELECT 1 FROM members WHERE parent=? AND root<>? LIMIT 1', (parent_key, root_key)).fetchone()
        if not others and row[2]:
            current = dacl(parent)
            restored, changed = parent_policy(current, remove=True)
            if changed:
                set_dacl(parent, restored, json.loads(row[0]))
        con.execute('DELETE FROM members WHERE parent=? AND root=?', (parent_key, root_key))
        if not others:
            con.execute('DELETE FROM parents WHERE path=?', (parent_key,))
        con.commit()


def apply_tree(root, manifest, journal):
    # Descendants first: inherited permissions from a parent cannot overwrite a
    # child's already-protected ACL. No parent/sibling content ACL is rewritten.
    for entry in reversed(journal['entries']):
        set_dacl(relative_path(root, entry['relative']), locked_dacl(entry), entry['identity'])
    protect_parent(root, manifest, journal)


def restore_tree(root, manifest, journal):
    if journal.get('state') == 'unlocked':
        return
    errors = []
    # Parents first when restoring inheritance, then each exact original child ACL.
    for entry in journal['entries']:
        try:
            set_dacl(relative_path(root, entry['relative']), entry['dacl'], entry['identity'])
        except Exception as exc:
            errors.append(f"{entry['relative']}: {exc}")
    if errors:
        raise RuntimeError('بازگردانی بعضی مجوزها کامل نشد؛ فراداده را نگه دار:\n' + '\n'.join(errors[:10]))
    release_parent(root, manifest)
