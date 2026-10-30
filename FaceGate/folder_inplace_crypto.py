"""FaceGate in-place per-file encryption for Windows folders.

Files keep their names and locations. While locked, their contents are authenticated
AES-GCM ciphertext. This is application-level content protection, not a filesystem
filter: file names/operations can still be visible, and plaintext exists while unlocked.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
import struct
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FGFLOCK2"  # exactly 8 bytes
CHUNK_SIZE = 1024 * 1024
TAG_BYTES = 16
MAX_HEADER = 128 * 1024


def folder_id(folder: str | Path) -> str:
    p = Path(folder).resolve()
    return hashlib.sha256(os.path.normcase(str(p)).casefold().encode("utf-8")).hexdigest()[:32]


def manifest_path(folder: str | Path, metadata_root: str | Path) -> Path:
    return Path(metadata_root) / f"{folder_id(folder)}.json"


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _dpapi_and_pin_helpers():
    try:
        from vault_crypto import _dpapi_protect, _dpapi_unprotect, _derive_pin_key, _pin_aad, _validate_pin
    except Exception as exc:
        raise RuntimeError("ماژول رمزگذاری FaceGate یا وابستگی cryptography در دسترس نیست؛ INSTALL_DEPENDENCIES.bat را اجرا کن.") from exc
    return _dpapi_protect, _dpapi_unprotect, _derive_pin_key, _pin_aad, _validate_pin


def make_key_envelope(pin: str) -> tuple[bytes, dict]:
    _dpapi_protect, _dpapi_unprotect, derive_pin_key, pin_aad, validate_pin = _dpapi_and_pin_helpers()
    validate_pin(pin)
    key = secrets.token_bytes(32)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    pin_key = derive_pin_key(pin, salt)
    wrapped = AESGCM(pin_key).encrypt(nonce, key, pin_aad(salt))
    envelope = {
        "version": 1,
        "dpapi_key": base64.b64encode(_dpapi_protect(key)).decode("ascii"),
        "pin_salt": base64.b64encode(salt).decode("ascii"),
        "pin_nonce": base64.b64encode(nonce).decode("ascii"),
        "pin_wrapped_key": base64.b64encode(wrapped).decode("ascii"),
    }
    return key, envelope


def unwrap_key(envelope: dict, pin: str | None = None) -> bytes:
    _dpapi_protect, dpapi_unprotect, derive_pin_key, pin_aad, validate_pin = _dpapi_and_pin_helpers()
    try:
        if pin is None:
            key = dpapi_unprotect(base64.b64decode(envelope["dpapi_key"], validate=True))
        else:
            validate_pin(pin)
            salt = base64.b64decode(envelope["pin_salt"], validate=True)
            nonce = base64.b64decode(envelope["pin_nonce"], validate=True)
            wrapped = base64.b64decode(envelope["pin_wrapped_key"], validate=True)
            pin_key = derive_pin_key(pin, salt)
            key = AESGCM(pin_key).decrypt(nonce, wrapped, pin_aad(salt))
        if len(key) != 32:
            raise ValueError("طول کلید نامعتبر است")
        return key
    except Exception as exc:
        if pin is None:
            raise RuntimeError("کلید ویندوز (DPAPI) باز نشد. اگر این پوشه متعلق به همین حساب ویندوز نیست، از PIN هشت‌رقمی استفاده کن.") from exc
        raise RuntimeError("PIN نادرست است یا اطلاعات کلید آسیب دیده است.") from exc


def write_manifest(folder: str | Path, metadata_root: str | Path, envelope: dict, backup_path: str | Path | None, state: str) -> Path:
    root = Path(folder).resolve()
    base = Path(metadata_root)
    base.mkdir(parents=True, exist_ok=True)
    dest = manifest_path(root, base)
    record = {
        "format": "FGINPLACE2",
        "root": str(root),
        "state": state,
        "key_envelope": envelope,
        "backup_path": str(backup_path) if backup_path else "",
        "updated_at": int(time.time()),
    }
    temp = dest.with_name(dest.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temp.write_bytes(_json_bytes(record))
        os.replace(temp, dest)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass
    return dest


def read_manifest(path: str | Path) -> dict | None:
    """Read a manifest defensively. ACL backups may intentionally be inaccessible
    to the current user; a status refresh must never crash the whole GUI because
    Windows raises PermissionError even for Path.is_file()/stat().
    """
    try:
        p = Path(path)
        if not p.is_file():
            return None
        value = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None
        if value.get("format") != "FGINPLACE2" or not isinstance(value.get("key_envelope"), dict):
            return None
        return value
    except (OSError, PermissionError, ValueError, TypeError, json.JSONDecodeError):
        return None
    except Exception:
        # Metadata is untrusted input; a bad entry should be reported as unavailable,
        # not allowed to terminate FaceGate during startup/refresh.
        return None


def _path_is_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        fn = getattr(path, "is_junction", None)
        return bool(fn and fn())
    except Exception:
        return True


def _walk_error(exc):
    # Inaccessible directories are errors, never an apparently empty folder.
    raise exc


def _cleanup_stale_temps(root: Path) -> int:
    """Remove only atomic-write temp files left by an interrupted FaceGate operation.

    The original file remains in place until os.replace succeeds, so these temporary
    siblings are incomplete duplicates, not the only copy of a file. Do not run while a
    worker is active; the GUI guards refresh during an active operation.
    """
    import re
    pattern = re.compile(r'^\..+\.(?:fglock-tmp|fgunlock-tmp)-[0-9a-f]{32}$', re.IGNORECASE)
    removed = 0
    for current, dirs, files in os.walk(root, followlinks=False, onerror=_walk_error):
        base = Path(current)
        dirs[:] = [name for name in dirs if not _path_is_link(base / name)]
        for name in files:
            if not pattern.fullmatch(name):
                continue
            temp = base / name
            if _path_is_link(temp):
                continue
            marker = '.fgunlock-tmp-' if '.fgunlock-tmp-' in name else '.fglock-tmp-'
            marker_index = name.rfind(marker)
            original_name = name[1:marker_index] if marker_index > 1 and name.startswith('.') else ''
            original = base / original_name if original_name else None
            # Atomic replacement consumes the temp file only after the original path has
            # been replaced. If the original sibling is absent, keep the temp for manual
            # recovery instead of guessing that it is disposable.
            if not original or not original.is_file():
                raise RuntimeError(f'فایل موقت باقی‌مانده است و فایل اصلی کنار آن پیدا نشد؛ برای جلوگیری از حذف داده، آن را نگه داشتم:\n{temp}')
            try:
                temp.unlink()
                removed += 1
            except OSError as exc:
                raise RuntimeError(f'فایل موقت باقی‌مانده از اجرای قبلی حذف نشد؛ فایل اصلی را حذف نکن:\n{temp}\n{exc}') from exc
    return removed


def walk_regular_files(folder: str | Path) -> list[Path]:
    root = Path(folder).resolve()
    if not root.is_dir() or _path_is_link(root):
        raise RuntimeError("مسیر انتخاب‌شده پوشهٔ معتبر و مستقیم نیست.")
    _cleanup_stale_temps(root)
    result: list[Path] = []
    for current, dirs, files in os.walk(root, followlinks=False, onerror=_walk_error):
        current_path = Path(current)
        for name in list(dirs):
            p = current_path / name
            if _path_is_link(p):
                raise RuntimeError(f"برای جلوگیری از تغییر مسیر ناخواسته، junction/symlink پشتیبانی نمی‌شود:\n{p}")
        for name in files:
            p = current_path / name
            if _path_is_link(p):
                raise RuntimeError(f"برای جلوگیری از تغییر مسیر ناخواسته، junction/symlink پشتیبانی نمی‌شود:\n{p}")
            if p.is_file() and not is_encrypted_file(p):
                if p.stat().st_nlink > 1:
                    raise RuntimeError(f'برای جلوگیری از باقی ماندن مسیر جایگزین خوانا، فایل دارای hard link پشتیبانی نمی‌شود:\n{p}')
                result.append(p)
    return result


def list_encrypted_files(folder: str | Path) -> list[Path]:
    root = Path(folder).resolve()
    result = []
    for current, dirs, files in os.walk(root, followlinks=False, onerror=_walk_error):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if not _path_is_link(current_path / name)]
        for name in files:
            p = current_path / name
            if not _path_is_link(p) and is_encrypted_file(p):
                result.append(p)
    return result


def is_encrypted_file(path: str | Path) -> bool:
    try:
        with open(path, "rb") as stream:
            return stream.read(len(MAGIC)) == MAGIC
    except (OSError, ValueError):
        return False


def read_file_header(path: str | Path) -> tuple[dict, bytes]:
    with open(path, "rb") as stream:
        if stream.read(len(MAGIC)) != MAGIC:
            raise ValueError("فایل رمزگذاری‌شدهٔ FaceGate نیست.")
        raw_len = stream.read(4)
        if len(raw_len) != 4:
            raise ValueError("سرآیند فایل ناقص است.")
        n = struct.unpack(">I", raw_len)[0]
        if n < 2 or n > MAX_HEADER:
            raise ValueError("اندازهٔ سرآیند فایل معتبر نیست.")
        raw = stream.read(n)
        if len(raw) != n:
            raise ValueError("سرآیند فایل ناقص است.")
        try:
            header = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("سرآیند فایل قابل خواندن نیست.") from exc
    if header.get("version") != 2 or header.get("chunk_size") != CHUNK_SIZE:
        raise ValueError("قالب این فایل توسط این نسخه پشتیبانی نمی‌شود.")
    if not isinstance(header.get("key_envelope"), dict):
        raise ValueError("اطلاعات کلید بازیابی در فایل پیدا نشد.")
    if not isinstance(header.get("size"), int) or header["size"] < 0:
        raise ValueError("اندازهٔ فایل نامعتبر است.")
    try:
        nonce_prefix = base64.b64decode(header["nonce_prefix"], validate=True)
        if len(nonce_prefix) != 8:
            raise ValueError("nonce نامعتبر است")
    except Exception as exc:
        raise ValueError("اطلاعات nonce فایل نامعتبر است.") from exc
    return header, raw


def _header_mac(key: bytes, fields: dict) -> str:
    return hmac.new(key, MAGIC + _json_bytes(fields), hashlib.sha256).hexdigest()


def _replace_content(temp: Path, original: Path):
    """Keep Windows file permissions when atomically replacing its contents."""
    if os.name != 'nt':
        os.replace(temp, original)
        return
    import ctypes
    from ctypes import wintypes
    from windows_acl_policy import dacl, identity, set_dacl
    # A freshly created temp file has inherited permissions, which may differ
    # from an original's explicit/protected ACL. Preserve those flags as well.
    original_acl = dacl(original)
    set_dacl(temp, original_acl, identity(temp))
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    replace = kernel.ReplaceFileW
    replace.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    replace.restype = wintypes.BOOL
    # No IGNORE_MERGE_ERRORS fallback: a security/stream merge failure is an error.
    if not replace(str(original), str(temp), None, 0, None, None):
        raise ctypes.WinError(ctypes.get_last_error())
    # ReplaceFile may add SE_DACL_AUTO_INHERITED even to a protected DACL.
    # Restore the recorded control flags as well as the unchanged ACE contents.
    set_dacl(original, original_acl, identity(original))


def encrypt_file_in_place(path: str | Path, key: bytes, envelope: dict) -> bool:
    """Encrypt one plain file atomically. Returns False when it was already encrypted."""
    p = Path(path)
    if is_encrypted_file(p):
        return False
    before = p.stat()
    size = before.st_size
    nonce_prefix = os.urandom(8)
    fields = {
        "version": 2,
        "size": size,
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": base64.b64encode(nonce_prefix).decode("ascii"),
        "atime_ns": getattr(before, "st_atime_ns", int(before.st_atime * 1e9)),
        "mtime_ns": getattr(before, "st_mtime_ns", int(before.st_mtime * 1e9)),
        "mode": stat.S_IMODE(before.st_mode),
        "key_envelope": envelope,
    }
    header = dict(fields)
    header["header_mac"] = _header_mac(key, fields)
    raw_header = _json_bytes(header)
    if len(raw_header) > MAX_HEADER:
        raise ValueError("سرآیند رمزگذاری بیش از حد بزرگ است.")
    aad_base = hashlib.sha256(MAGIC + raw_header).digest()
    temp = p.with_name(f".{p.name}.fglock-tmp-{uuid.uuid4().hex}")
    aes = AESGCM(key)
    try:
        with open(p, "rb") as src, open(temp, "xb") as dst:
            dst.write(MAGIC)
            dst.write(struct.pack(">I", len(raw_header)))
            dst.write(raw_header)
            idx = 0
            read_total = 0
            while read_total < size:
                block = src.read(min(CHUNK_SIZE, size - read_total))
                if not block:
                    raise RuntimeError(f"فایل هنگام رمزگذاری زودتر تمام شد: {p}")
                if idx >= 0xFFFFFFFF:
                    raise ValueError("فایل از اندازهٔ قابل پشتیبانی این نسخه بزرگ‌تر است.")
                aad = aad_base + struct.pack(">I", idx)
                nonce = nonce_prefix + struct.pack(">I", idx)
                ciphertext = aes.encrypt(nonce, block, aad)
                dst.write(struct.pack(">I", len(ciphertext)))
                dst.write(ciphertext)
                read_total += len(block)
                idx += 1
            if src.read(1):
                raise RuntimeError(f"فایل حین رمزگذاری تغییر کرد؛ عملیات متوقف شد: {p}")
            dst.flush()
            os.fsync(dst.fileno())
        original_mode = stat.S_IMODE(before.st_mode)
        original_writable = bool(original_mode & stat.S_IWRITE)
        try:
            if not original_writable:
                os.chmod(p, original_mode | stat.S_IWRITE)
            os.chmod(temp, original_mode | stat.S_IWRITE)
            _replace_content(temp, p)
            os.chmod(p, original_mode)
        except Exception:
            if p.exists() and not original_writable:
                try: os.chmod(p, original_mode)
                except Exception: pass
            raise
        try:
            os.utime(p, ns=(fields["atime_ns"], fields["mtime_ns"]))
        except Exception:
            pass
        return True
    finally:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass


def decrypt_file_in_place(path: str | Path, key: bytes) -> bool:
    """Decrypt one FaceGate file atomically. Returns False for already-plain files."""
    p = Path(path)
    if not is_encrypted_file(p):
        return False
    header, raw_header = read_file_header(p)
    fields = dict(header)
    saved_mac = fields.pop("header_mac", None)
    if not isinstance(saved_mac, str) or not hmac.compare_digest(saved_mac, _header_mac(key, fields)):
        raise RuntimeError(f"اعتبار سرآیند رمزگذاری تأیید نشد؛ فایل دست‌نخورده ماند:\n{p}")
    size = header["size"]
    nonce_prefix = base64.b64decode(header["nonce_prefix"], validate=True)
    aad_base = hashlib.sha256(MAGIC + raw_header).digest()
    temp = p.with_name(f".{p.name}.fgunlock-tmp-{uuid.uuid4().hex}")
    aes = AESGCM(key)
    try:
        with open(p, "rb") as src, open(temp, "xb") as dst:
            src.seek(len(MAGIC) + 4 + len(raw_header))
            idx = 0
            written = 0
            while written < size:
                raw_len = src.read(4)
                if len(raw_len) != 4:
                    raise RuntimeError(f"دادهٔ رمزگذاری‌شده ناقص است؛ فایل اصلی دست‌نخورده ماند:\n{p}")
                cipher_len = struct.unpack(">I", raw_len)[0]
                expected_plain = min(CHUNK_SIZE, size - written)
                if cipher_len != expected_plain + TAG_BYTES:
                    raise RuntimeError(f"اندازهٔ بخش رمزگذاری‌شده نامعتبر است؛ فایل دست‌نخورده ماند:\n{p}")
                ciphertext = src.read(cipher_len)
                if len(ciphertext) != cipher_len:
                    raise RuntimeError(f"دادهٔ رمزگذاری‌شده ناقص است؛ فایل دست‌نخورده ماند:\n{p}")
                aad = aad_base + struct.pack(">I", idx)
                nonce = nonce_prefix + struct.pack(">I", idx)
                try:
                    block = aes.decrypt(nonce, ciphertext, aad)
                except Exception as exc:
                    raise RuntimeError(f"اعتبار رمزنگاری فایل تأیید نشد؛ فایل دست‌نخورده ماند:\n{p}") from exc
                dst.write(block)
                written += len(block)
                idx += 1
            if src.read(1):
                raise RuntimeError(f"پس از دادهٔ رمزگذاری‌شده اطلاعات اضافه پیدا شد؛ فایل دست‌نخورده ماند:\n{p}")
            dst.flush()
            os.fsync(dst.fileno())
        original_mode = stat.S_IMODE(p.stat().st_mode)
        desired_mode = int(header.get("mode", original_mode))
        originally_readonly = not bool(original_mode & stat.S_IWRITE)
        try:
            if originally_readonly:
                os.chmod(p, original_mode | stat.S_IWRITE)
            os.chmod(temp, desired_mode | stat.S_IWRITE)
            _replace_content(temp, p)
            os.chmod(p, desired_mode)
        except Exception:
            if p.exists() and originally_readonly:
                try: os.chmod(p, original_mode)
                except Exception: pass
            raise
        try:
            os.utime(p, ns=(header.get("atime_ns", p.stat().st_atime_ns), header.get("mtime_ns", p.stat().st_mtime_ns)))
        except Exception:
            pass
        return True
    finally:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass


def _backup_before_first_protect(root: Path, backup_root: Path, folder_key_id: str, pin: str) -> Path:
    from vault_crypto import create_encrypted_vault
    backup_root.mkdir(parents=True, exist_ok=True)
    # Unique recovery snapshot per protection attempt. A previous failed attempt must not
    # permanently block retry, and an older recovery copy is never overwritten implicitly.
    backup = backup_root / f"{folder_key_id}_recovery_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.fgvault"
    result = create_encrypted_vault(root, backup, pin=pin, overwrite=False)
    if not result.get("verified") or not backup.is_file() or backup.stat().st_size == 0:
        raise RuntimeError("نسخهٔ پشتیبان رمزگذاری‌شده تأیید نشد؛ فایل‌های اصلی تغییر داده نشدند.")
    return backup


def _read_envelope_from_folder(root: Path) -> dict | None:
    for path in list_encrypted_files(root):
        header, _ = read_file_header(path)
        envelope = header.get("key_envelope")
        if isinstance(envelope, dict):
            return envelope
    return None


def load_folder_record(root: str | Path, metadata_root: str | Path) -> tuple[Path, dict | None]:
    mp = manifest_path(root, metadata_root)
    return mp, read_manifest(mp)


def _transform_folder(root: Path, key: bytes, envelope: dict, to_encrypted: bool) -> int:
    """Transform one folder atomically per file; roll back changed files if any item fails."""
    if to_encrypted:
        targets = walk_regular_files(root)
        changed: list[Path] = []
        try:
            for path in targets:
                if encrypt_file_in_place(path, key, envelope):
                    changed.append(path)
            return len(changed)
        except Exception:
            rollback_errors = []
            for path in reversed(changed):
                try:
                    decrypt_file_in_place(path, key)
                except Exception as rollback_exc:
                    rollback_errors.append(f"{path}: {rollback_exc}")
            detail = ""
            if rollback_errors:
                detail = "\nبازیابی کامل نشد؛ اطلاعات کلید در فایل‌های باقی‌مانده حفظ شده است:\n" + "\n".join(rollback_errors[:10])
            raise RuntimeError("قفل‌کردن پوشه کامل نشد. تغییرات انجام‌شده تا حد امکان به حالت خوانا برگشت داده شدند." + detail)
    targets = list_encrypted_files(root)
    changed = []
    try:
        for path in targets:
            if decrypt_file_in_place(path, key):
                changed.append(path)
        return len(changed)
    except Exception:
        rollback_errors = []
        for path in reversed(changed):
            try:
                encrypt_file_in_place(path, key, envelope)
            except Exception as rollback_exc:
                rollback_errors.append(f"{path}: {rollback_exc}")
        detail = ""
        if rollback_errors:
            detail = "\nبازگشت کامل به وضعیت رمزگذاری‌شده نشد؛ فایل‌های رمزگذاری‌شدهٔ باقی‌مانده حاوی اطلاعات کلید هستند:\n" + "\n".join(rollback_errors[:10])
        raise RuntimeError("بازکردن پوشه کامل نشد. تغییرات انجام‌شده تا حد امکان به حالت رمزگذاری‌شده برگشت داده شدند." + detail)


def protect_folder_in_place(folder: str | Path, pin: str, metadata_root: str | Path, backup_root: str | Path) -> dict:
    raw_root = Path(folder).expanduser().absolute()
    if not raw_root.is_dir() or _path_is_link(raw_root):
        raise RuntimeError("پوشهٔ انتخاب‌شده معتبر نیست یا یک پیوند/junction است.")
    root = raw_root.resolve()
    _cleanup_stale_temps(root)
    _dpapi, _unprotect, _derive, _aad, validate_pin = _dpapi_and_pin_helpers()
    validate_pin(pin)
    current_files = list_encrypted_files(root)
    if current_files:
        raise RuntimeError("در این پوشه فایل‌های رمزگذاری‌شدهٔ FaceGate از قبل پیدا شد؛ برای جلوگیری از دوباره‌رمزگذاری، از عملیات بازیابی/بازکردن استفاده کن.")
    normal_files = walk_regular_files(root)
    # Directory protection is independent of file count. Empty trees still need
    # a key envelope and manifest for authenticated ACL restoration/unprotection.
    key, envelope = make_key_envelope(pin)
    ident = folder_id(root)
    backup = _backup_before_first_protect(root, Path(backup_root), ident, pin)
    mp = write_manifest(root, metadata_root, envelope, backup, "protecting")
    try:
        changed = _transform_folder(root, key, envelope, True)
        # Never report success unless every regular file is now encrypted in place.
        encrypted_after = list_encrypted_files(root)
        plaintext_after = walk_regular_files(root)
        if plaintext_after or len(encrypted_after) != len(normal_files):
            raise RuntimeError(
                "اعتبارسنجی نهایی شکست خورد: همهٔ فایل‌های پوشه رمزگذاری نشده‌اند. "
                "برنامه وضعیت را موفق اعلام نمی‌کند. فایل‌های اصلی را حذف نکن و از بخش بازیابی استفاده کن. "
                f"رمزگذاری‌شده: {len(encrypted_after)}، خوانا: {len(plaintext_after)}، انتظار: {len(normal_files)}"
            )
        # Validate each header and its authentication tag before setting locked state.
        for encrypted_path in encrypted_after:
            header, raw_header = read_file_header(encrypted_path)
            fields = dict(header)
            saved_mac = fields.pop("header_mac", None)
            if not isinstance(saved_mac, str) or not hmac.compare_digest(saved_mac, _header_mac(key, fields)):
                raise RuntimeError(f"اعتبارسنجی رمزگذاری فایل شکست خورد؛ وضعیت موفق اعلام نشد:\n{encrypted_path}")
    except Exception:
        encrypted_left = list_encrypted_files(root)
        if not encrypted_left:
            try:
                mp.unlink(missing_ok=True)
            except Exception:
                pass
        else:
            write_manifest(root, metadata_root, envelope, backup, "recovery-needed")
        raise
    write_manifest(root, metadata_root, envelope, backup, "locked")
    return {"root": str(root), "manifest_path": str(mp), "backup_path": str(backup), "file_count": len(normal_files), "state": "locked"}


def unlock_folder_in_place(folder: str | Path, metadata_root: str | Path, pin: str | None = None, manifest: str | Path | None = None) -> dict:
    raw_root = Path(folder).expanduser().absolute()
    if not raw_root.is_dir() or _path_is_link(raw_root):
        raise RuntimeError("پوشهٔ موردنظر پیدا نشد یا یک پیوند/junction است؛ هیچ فایلی تغییر نکرد.")
    root = raw_root.resolve()
    _cleanup_stale_temps(root)
    mp = Path(manifest) if manifest else manifest_path(root, metadata_root)
    meta = read_manifest(mp)
    envelope = meta.get("key_envelope") if meta else None
    if not isinstance(envelope, dict):
        envelope = _read_envelope_from_folder(root)
    if not isinstance(envelope, dict):
        raise RuntimeError("اطلاعات کلید پوشه پیدا نشد؛ هیچ فایلی تغییر نکرد.")
    key = unwrap_key(envelope, pin=pin)
    count = _transform_folder(root, key, envelope, False)
    backup = meta.get("backup_path", "") if meta else ""
    mp = write_manifest(root, metadata_root, envelope, backup, "unlocked")
    return {"root": str(root), "manifest_path": str(mp), "file_count": count, "state": "unlocked"}


def lock_folder_in_place(folder: str | Path, metadata_root: str | Path, pin: str | None = None, manifest: str | Path | None = None) -> dict:
    raw_root = Path(folder).expanduser().absolute()
    if not raw_root.is_dir() or _path_is_link(raw_root):
        raise RuntimeError("پوشهٔ موردنظر پیدا نشد یا یک پیوند/junction است؛ هیچ فایلی تغییر نکرد.")
    root = raw_root.resolve()
    _cleanup_stale_temps(root)
    mp = Path(manifest) if manifest else manifest_path(root, metadata_root)
    meta = read_manifest(mp)
    envelope = meta.get("key_envelope") if meta else None
    if not isinstance(envelope, dict):
        envelope = _read_envelope_from_folder(root)
    if not isinstance(envelope, dict):
        raise RuntimeError("اطلاعات کلید پوشه پیدا نشد. اگر پوشه باز است، آن را با رمزگذاری دوباره ثبت کن.")
    key = unwrap_key(envelope, pin=pin)
    backup_path = meta.get("backup_path", "") if meta else ""
    # Refresh the separate encrypted recovery snapshot before re-locking changed plaintext.
    # A backup refresh failure is reported but does not discard or destroy source files.
    backup_warning = ""
    encrypted_before = list_encrypted_files(root)
    if backup_path:
        if not Path(backup_path).is_file():
            backup_warning = f"نسخهٔ پشتیبان بازیابی پیدا نشد: {backup_path}. محتوای اصلی رمزگذاری می‌شود، اما قبل از تکیه بر این پوشه یک نسخهٔ پشتیبان مستقل بساز."
        elif not encrypted_before:
            try:
                from vault_crypto import repack_encrypted_vault
                existing = Path(backup_path)
                staged = existing.with_name(existing.name + ".refresh." + uuid.uuid4().hex + ".tmp")
                try:
                    repack_encrypted_vault(root, existing, staged)
                    os.replace(staged, existing)
                finally:
                    staged.unlink(missing_ok=True)
            except Exception as exc:
                backup_warning = f"نسخهٔ پشتیبان قبلی به‌روزرسانی نشد؛ پوشه همچنان رمزگذاری می‌شود، اما نسخهٔ پشتیبان ممکن است تغییرات اخیر را نداشته باشد. جزئیات: {exc}"
        elif walk_regular_files(root):
            backup_warning = "پوشه شامل فایل‌های رمزگذاری‌شده و فایل‌های خوانا بود؛ برای جلوگیری از خراب‌کردن وضعیت مختلط، نسخهٔ پشتیبان خودکار به‌روزرسانی نشد. پس از قفل، یک نسخهٔ پشتیبان تازه و مستقل تهیه کن."
    else:
        backup_warning = "مسیر نسخهٔ پشتیبان در فهرست FaceGate ثبت نشده است؛ محتوای فایل‌ها رمزگذاری می‌شود، اما پشتیبان بازیابی خودکار به‌روزرسانی نشد."
    expected_count = len(walk_regular_files(root)) + len(encrypted_before)
    count = _transform_folder(root, key, envelope, True)
    encrypted_after = list_encrypted_files(root)
    plaintext_after = walk_regular_files(root)
    if plaintext_after or len(encrypted_after) != expected_count:
        write_manifest(root, metadata_root, envelope, backup_path, "recovery-needed")
        raise RuntimeError(
            "اعتبارسنجی نهایی قفل مجدد شکست خورد؛ FaceGate موفقیت را اعلام نمی‌کند. "
            "فایل‌های اصلی را حذف نکن و وضعیت پوشه را از بخش بازیابی بررسی کن. "
            f"رمزگذاری‌شده: {len(encrypted_after)}، خوانا: {len(plaintext_after)}، انتظار: {expected_count}"
        )
    for encrypted_path in encrypted_after:
        header, raw_header = read_file_header(encrypted_path)
        fields = dict(header)
        saved_mac = fields.pop("header_mac", None)
        if not isinstance(saved_mac, str) or not hmac.compare_digest(saved_mac, _header_mac(key, fields)):
            write_manifest(root, metadata_root, envelope, backup_path, "recovery-needed")
            raise RuntimeError(f"اعتبارسنجی رمزگذاری شکست خورد؛ وضعیت نیازمند بازیابی است:\n{encrypted_path}")
    mp = write_manifest(root, metadata_root, envelope, backup_path, "locked")
    return {"root": str(root), "manifest_path": str(mp), "backup_path": str(backup_path), "file_count": len(encrypted_after), "state": "locked", "warning": backup_warning}


def inspect_folder(folder: str | Path) -> dict:
    root = Path(folder).resolve()
    encrypted = list_encrypted_files(root)
    all_files = walk_regular_files(root)
    return {"encrypted_count": len(encrypted), "plain_count": len(all_files)}


# Public operations combine content encryption and the Windows directory gate.
# Keep the existing on-disk FGINPLACE2 format and recovery vault compatibility.
import folder_gate

_content_protect = protect_folder_in_place
_content_lock = lock_folder_in_place
_content_unlock = unlock_folder_in_place


def folder_gate_active(folder):
    return folder_gate.active(folder)


def protect_folder_in_place(folder, pin, metadata_root, backup_root):
    folder_gate.policy.ensure_external_metadata(folder, metadata_root)
    folder_gate.policy.ensure_external_metadata(folder, backup_root)
    folder_gate._api(folder)  # Check parent rights and native support before data changes.
    result = _content_protect(folder, pin, metadata_root, backup_root)
    try:
        folder_gate.engage(result['root'], result['manifest_path'])
    except Exception as exc:
        raise RuntimeError('محتوا رمزگذاری شد، اما قفل خود پوشه کامل نشد. فایل‌ها را حذف نکن؛ برنامه‌های باز روی پوشه را ببند و قفل مجدد را بزن.\n' + str(exc)) from exc
    return result


def unlock_folder_in_place(folder, metadata_root, pin=None, manifest=None):
    mp = Path(manifest) if manifest else manifest_path(folder, metadata_root)
    meta = read_manifest(mp)
    has_gate = folder_gate.saved(folder, mp) is not None
    if has_gate:
        if not meta:
            raise RuntimeError('اطلاعات کلید در دسترس نیست؛ قفل پوشه برداشته نشد.')
        # Wrong PIN must not release even one handle or change any permission.
        unwrap_key(meta['key_envelope'], pin=pin)
        folder_gate.disengage(folder, mp)
    try:
        return _content_unlock(folder, metadata_root, pin=pin, manifest=mp)
    except Exception:
        if has_gate:
            folder_gate.engage(folder, mp)
        raise


def lock_folder_in_place(folder, metadata_root, pin=None, manifest=None):
    mp = Path(manifest) if manifest else manifest_path(folder, metadata_root)
    meta = read_manifest(mp)
    if meta and meta.get('state') == 'unprotected':
        raise RuntimeError('محافظت این پوشه برداشته شده است؛ برای قفل دوباره، آن را مجدداً اضافه کن.')
    if folder_gate.active(folder):
        meta = read_manifest(mp)
        if not meta or meta.get('state') != 'locked':
            raise RuntimeError('وضعیت قفل پوشه ناسازگار است؛ بازیابی لازم است.')
        count = folder_gate.verify_lock(folder, mp)
        return {'root': str(folder), 'manifest_path': str(mp), 'state': 'locked',
                'file_count': count, 'warning': ''}
    folder_gate._api(folder)
    has_gate = folder_gate.saved(folder, mp) is not None
    if has_gate:
        meta = read_manifest(mp)
        if not meta:
            raise RuntimeError('اطلاعات کلید پیدا نشد؛ مجوزهای پوشه تغییر نکرد.')
        unwrap_key(meta['key_envelope'], pin=pin)
        folder_gate.disengage(folder, mp)
    try:
        result = _content_lock(folder, metadata_root, pin=pin, manifest=mp)
    except Exception:
        if has_gate:
            folder_gate.engage(folder, mp)
        raise
    folder_gate.engage(folder, mp)
    return result


def unprotect_folder_in_place(folder, metadata_root, pin, manifest=None):
    """Authenticate, restore data/ACLs, then retire metadata; never delete a folder.

    Keep the recovery vault and retired manifest. A crash before SQLite removal
    must not let startup rediscover/re-lock a folder the user just unprotected.
    """
    mp = Path(manifest) if manifest else manifest_path(folder, metadata_root)
    meta = read_manifest(mp)
    if not meta:
        raise RuntimeError('اطلاعات کلید پوشه پیدا نشد؛ حذف از قفل انجام نشد.')
    unwrap_key(meta['key_envelope'], pin=pin)
    result = unlock_folder_in_place(folder, metadata_root, pin=pin, manifest=mp)
    if list_encrypted_files(folder):
        raise RuntimeError('هنوز فایل رمزگذاری‌شده باقی مانده است؛ پوشه از فهرست حذف نشد.')
    # Traversal must succeed before claiming all contents are accessible again.
    walk_regular_files(folder)
    write_manifest(folder, metadata_root, meta['key_envelope'], meta.get('backup_path', ''), 'unprotected')
    # This file belongs to FaceGate metadata, not the selected folder or its files.
    # Removing it also prevents stale ACLs being reused if the folder is added again.
    folder_gate.sidecar(mp).unlink(missing_ok=True)
    result['state'] = 'unprotected'
    return result
