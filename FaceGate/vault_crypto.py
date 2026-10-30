"""FaceGate encrypted folder vault: AES-256-GCM chunks, user DPAPI and PIN recovery."""
from __future__ import annotations
import base64
import ctypes
import hashlib
import json
import os
import shutil
import stat
import struct
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from ctypes import wintypes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FGVAULT1"  # exactly 8 bytes
CHUNK_SIZE = 1024 * 1024
TAG_LEN = 16
PIN_LENGTH = 8


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes):
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf


def _dpapi_protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("ساخت این نسخه از گاوصندوق فقط روی ویندوز پشتیبانی می‌شود؛ کلید با DPAPI ویندوز نیز محافظت می‌شود.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, keepalive = _blob(data)
    out_blob = DATA_BLOB()
    crypt32.CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.POINTER(DATA_BLOB)]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), "FaceGate encrypted vault key", None, None, None,
                                    0, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))


def _dpapi_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("بازکردن مسیر DPAPI فقط در ویندوز پشتیبانی می‌شود؛ از PIN پشتیبان استفاده کن.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, keepalive = _blob(data)
    out_blob = DATA_BLOB()
    crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR),
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))


def _validate_pin(pin: str):
    if not isinstance(pin, str) or not pin.isdigit() or len(pin) != PIN_LENGTH:
        raise ValueError("PIN پشتیبان گاوصندوق باید دقیقاً ۸ رقم باشد.")


def _derive_pin_key(pin: str, salt: bytes) -> bytes:
    _validate_pin(pin)
    # Scrypt is memory-hard to raise the cost of offline PIN guessing if a vault leaks.
    kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1)
    return kdf.derive(pin.encode("ascii"))


def _pin_aad(salt: bytes) -> bytes:
    return MAGIC + b"|PIN-KEY-WRAP-v1|" + salt


def _read_header(vault_file: Path):
    with open(vault_file, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError("این فایل قالب گاوصندوق FaceGate را ندارد.")
        raw_len = f.read(4)
        if len(raw_len) != 4:
            raise ValueError("سرآیند گاوصندوق ناقص است.")
        header_len = struct.unpack(">I", raw_len)[0]
        if header_len < 2 or header_len > 64 * 1024:
            raise ValueError("طول سرآیند گاوصندوق معتبر نیست.")
        header_bytes = f.read(header_len)
        if len(header_bytes) != header_len:
            raise ValueError("سرآیند گاوصندوق ناقص است.")
        try:
            header = json.loads(header_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError("سرآیند گاوصندوق قابل خواندن نیست.") from exc
    if header.get("version") != 1 or header.get("chunk_size") != CHUNK_SIZE:
        raise ValueError("نسخه یا تنظیمات این گاوصندوق پشتیبانی نمی‌شود.")
    try:
        nonce_prefix = base64.b64decode(header["nonce_prefix"], validate=True)
        if len(nonce_prefix) != 8:
            raise ValueError("شناسه رمزگذاری معتبر نیست.")
        # Check the two wrapped-key records exist and are parseable.
        base64.b64decode(header["dpapi_key"], validate=True)
        salt = base64.b64decode(header["pin_salt"], validate=True)
        pin_nonce = base64.b64decode(header["pin_nonce"], validate=True)
        base64.b64decode(header["pin_wrapped_key"], validate=True)
        if len(salt) != 16 or len(pin_nonce) != 12:
            raise ValueError("اطلاعات بازیابی PIN نامعتبر است.")
    except (KeyError, ValueError) as exc:
        raise ValueError("اطلاعات کلید یا PIN در سرآیند ناقص است.") from exc
    return header_bytes, header, nonce_prefix


def _unwrap_key(vault_file: Path, header: dict, pin: str | None = None) -> bytes:
    if pin is None:
        wrapped = base64.b64decode(header["dpapi_key"], validate=True)
        key = _dpapi_unprotect(wrapped)
    else:
        _validate_pin(pin)
        salt = base64.b64decode(header["pin_salt"], validate=True)
        nonce = base64.b64decode(header["pin_nonce"], validate=True)
        wrapped = base64.b64decode(header["pin_wrapped_key"], validate=True)
        try:
            pin_key = _derive_pin_key(pin, salt)
            key = AESGCM(pin_key).decrypt(nonce, wrapped, _pin_aad(salt))
        except Exception as exc:
            raise ValueError("PIN اشتباه است یا اطلاعات بازیابی گاوصندوق خراب شده است.") from exc
    if len(key) != 32:
        raise ValueError("کلید رمزگذاری بازیابی‌شده معتبر نیست.")
    return key


def _header_and_key(vault_file: Path, pin: str | None = None):
    header_bytes, header, nonce_prefix = _read_header(vault_file)
    key = _unwrap_key(vault_file, header, pin=pin)
    return header_bytes, key, nonce_prefix, header


def _aad(header_bytes: bytes, counter: int, plain_len: int) -> bytes:
    return MAGIC + hashlib.sha256(header_bytes).digest() + struct.pack(">II", counter, plain_len)


def _is_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _walk_files(source: Path):
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if not _is_link(root_path / d)]
        rel_root = root_path.relative_to(source)
        if rel_root != Path(".") and not dirs and not files:
            yield root_path, None, rel_root.as_posix().rstrip("/") + "/"
        for name in files:
            path = root_path / name
            if _is_link(path) or not path.is_file():
                continue
            rel = path.relative_to(source).as_posix()
            yield root_path, path, rel


def _make_zip(source: Path, zip_path: Path):
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as zf:
        for _, item, rel in _walk_files(source):
            if item is None:
                zf.writestr(rel, b"")
            else:
                zf.write(item, rel)


def _wrapped_header(key: bytes, nonce_prefix: bytes, pin: str, existing_header: dict | None = None):
    if existing_header is not None:
        # Keep the PIN recovery wrapper but refresh the DPAPI wrapper for the current Windows user.
        try:
            dpapi_wrapped = base64.b64encode(_dpapi_protect(key)).decode("ascii")
        except Exception:
            # PIN recovery continues to work even if creating a fresh DPAPI wrapper is unavailable.
            dpapi_wrapped = existing_header["dpapi_key"]
        return {
            "version": 1,
            "chunk_size": CHUNK_SIZE,
            "nonce_prefix": base64.b64encode(nonce_prefix).decode("ascii"),
            "dpapi_key": dpapi_wrapped,
            "pin_salt": existing_header["pin_salt"],
            "pin_nonce": existing_header["pin_nonce"],
            "pin_wrapped_key": existing_header["pin_wrapped_key"],
        }
    _validate_pin(pin)
    salt = os.urandom(16)
    pin_nonce = os.urandom(12)
    pin_key = _derive_pin_key(pin, salt)
    pin_wrapped = AESGCM(pin_key).encrypt(pin_nonce, key, _pin_aad(salt))
    return {
        "version": 1,
        "chunk_size": CHUNK_SIZE,
        "nonce_prefix": base64.b64encode(nonce_prefix).decode("ascii"),
        "dpapi_key": base64.b64encode(_dpapi_protect(key)).decode("ascii"),
        "pin_salt": base64.b64encode(salt).decode("ascii"),
        "pin_nonce": base64.b64encode(pin_nonce).decode("ascii"),
        "pin_wrapped_key": base64.b64encode(pin_wrapped).decode("ascii"),
    }


def _encrypt_zip(zip_path: Path, vault_path: Path, key: bytes, pin: str | None = None, existing_header: dict | None = None):
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    nonce_prefix = os.urandom(8)
    header = _wrapped_header(key, nonce_prefix, pin or "", existing_header=existing_header)
    header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    aes = AESGCM(key)
    temp = vault_path.with_name(vault_path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with open(zip_path, "rb") as src, open(temp, "xb") as out:
            out.write(MAGIC)
            out.write(struct.pack(">I", len(header_bytes)))
            out.write(header_bytes)
            counter = 0
            while True:
                block = src.read(CHUNK_SIZE)
                if not block:
                    break
                if counter >= 0xFFFFFFFF:
                    raise ValueError("اندازه فایل از محدودیت این نسخه بیشتر است.")
                nonce = nonce_prefix + struct.pack(">I", counter)
                encrypted = aes.encrypt(nonce, block, _aad(header_bytes, counter, len(block)))
                out.write(struct.pack(">I", len(block)))
                out.write(encrypted)
                counter += 1
            # Authenticated terminal marker detects truncation.
            nonce = nonce_prefix + struct.pack(">I", counter)
            out.write(struct.pack(">I", 0))
            out.write(aes.encrypt(nonce, b"", _aad(header_bytes, counter, 0)))
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, vault_path)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass


def _decrypt_to_zip(vault_file: Path, zip_path: Path, key: bytes | None = None, pin: str | None = None):
    vault_file = Path(vault_file)
    if key is None:
        header_bytes, key, nonce_prefix, header = _header_and_key(vault_file, pin=pin)
    else:
        header_bytes, header, nonce_prefix = _read_header(vault_file)
    aes = AESGCM(key)
    with open(vault_file, "rb") as src, open(zip_path, "wb") as out:
        src.seek(len(MAGIC))
        raw_header_len = src.read(4)
        if len(raw_header_len) != 4:
            raise ValueError("سرآیند ناقص است.")
        header_len = struct.unpack(">I", raw_header_len)[0]
        header_bytes = src.read(header_len)
        counter = 0
        while True:
            raw = src.read(4)
            if len(raw) != 4:
                raise ValueError("گاوصندوق ناقص یا دستکاری‌شده است؛ داده‌ها آزاد نشدند.")
            plain_len = struct.unpack(">I", raw)[0]
            if plain_len > CHUNK_SIZE:
                raise ValueError("قطعه رمزگذاری‌شده اندازه غیرمجاز دارد.")
            expected = TAG_LEN if plain_len == 0 else plain_len + TAG_LEN
            encrypted = src.read(expected)
            if len(encrypted) != expected:
                raise ValueError("محتوای گاوصندوق ناقص است.")
            nonce = nonce_prefix + struct.pack(">I", counter)
            try:
                clear = aes.decrypt(nonce, encrypted, _aad(header_bytes, counter, plain_len))
            except Exception as exc:
                raise ValueError("بررسی صحت رمزگذاری ناموفق بود؛ فایل ممکن است خراب یا دستکاری شده باشد.") from exc
            if plain_len == 0:
                if src.read(1):
                    raise ValueError("پس از پایان گاوصندوق داده اضافی وجود دارد.")
                break
            if len(clear) != plain_len:
                raise ValueError("طول داده بازیابی‌شده معتبر نیست.")
            out.write(clear)
            counter += 1


def _verify_archive(zip_path: Path):
    with zipfile.ZipFile(zip_path, "r") as zf:
        bad = zf.testzip()
        if bad:
            raise ValueError(f"بررسی آرشیو رمزگذاری‌شده در فایل {bad} ناموفق بود.")
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            pp = PurePosixPath(name)
            if pp.is_absolute() or ".." in pp.parts or (pp.parts and ":" in pp.parts[0]):
                raise ValueError("نام مسیر ناامن در آرشیو پیدا شد.")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ValueError("آرشیو شامل پیوندی است که استخراج آن مجاز نیست.")


def _safe_source(source: Path, vault: Path):
    if not source.is_dir():
        raise ValueError("پوشه مبدا پیدا نشد.")
    if vault == source or source in vault.parents:
        raise ValueError("فایل گاوصندوق را داخل پوشه‌ای که در حال رمزگذاری است ذخیره نکن.")


def create_encrypted_vault(source_dir: str | Path, vault_file: str | Path, pin: str, overwrite: bool = False):
    source = Path(source_dir).resolve()
    vault = Path(vault_file).resolve()
    _safe_source(source, vault)
    _validate_pin(pin)
    if vault.exists() and not overwrite:
        raise FileExistsError("فایل گاوصندوق از قبل وجود دارد؛ برای جلوگیری از بازنویسی انتخاب مسیر دیگری لازم است.")
    vault.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fgvault_zip_") as td:
        zip_path = Path(td) / "contents.zip"
        _make_zip(source, zip_path)
        key = os.urandom(32)
        target_temp = vault.with_name(vault.name + ".build." + uuid.uuid4().hex + ".fgvault")
        try:
            _encrypt_zip(zip_path, target_temp, key, pin=pin)
            # Verify both recovery paths (PIN and current Windows user's DPAPI), plus archive integrity.
            pin_check_zip = Path(td) / "verify_pin.zip"
            _decrypt_to_zip(target_temp, pin_check_zip, pin=pin)
            _verify_archive(pin_check_zip)
            dpapi_check_zip = Path(td) / "verify_dpapi.zip"
            _decrypt_to_zip(target_temp, dpapi_check_zip)
            _verify_archive(dpapi_check_zip)
            if vault.exists() and not overwrite:
                raise FileExistsError("مقصد هم‌زمان موجود شد؛ فایل اصلی دست‌نخورده ماند.")
            os.replace(target_temp, vault)
        finally:
            try:
                target_temp.unlink(missing_ok=True)
            except Exception:
                pass
    return {"vault_file": str(vault), "verified": True, "format": "FGVAULT1"}


def repack_encrypted_vault(source_dir: str | Path, existing_vault_file: str | Path, new_vault_file: str | Path, pin: str | None = None):
    """Encrypt updated workspace with the existing data key and preserve PIN recovery."""
    source = Path(source_dir).resolve()
    current = Path(existing_vault_file).resolve()
    staged = Path(new_vault_file).resolve()
    _safe_source(source, staged)
    if not current.is_file():
        raise FileNotFoundError("گاوصندوق قبلی پیدا نشد؛ فضای کاری دست‌نخورده باقی می‌ماند.")
    if staged.exists():
        raise FileExistsError("فایل موقت مقصد از قبل موجود است.")
    _, old_header, _ = _read_header(current)
    key = _unwrap_key(current, old_header, pin=pin)
    with tempfile.TemporaryDirectory(prefix="fgvault_repack_") as td:
        zip_path = Path(td) / "contents.zip"
        _make_zip(source, zip_path)
        try:
            _encrypt_zip(zip_path, staged, key, existing_header=old_header)
            check_zip = Path(td) / "verify.zip"
            try:
                _decrypt_to_zip(staged, check_zip)  # Prefer current Windows DPAPI.
            except Exception:
                if pin is None:
                    raise
                _decrypt_to_zip(staged, check_zip, pin=pin)  # PIN recovery can still preserve user data.
            _verify_archive(check_zip)
            # Validate that the PIN wrapper continues to unwrap the same content key.
            _, _, _, new_header = _header_and_key(staged, pin=pin)
            if new_header["pin_wrapped_key"] != old_header["pin_wrapped_key"]:
                raise ValueError("کلید بازیابی PIN در نسخه جدید با نسخه قبلی مطابقت ندارد.")
        except Exception:
            try: staged.unlink(missing_ok=True)
            except Exception: pass
            raise
    return {"vault_file": str(staged), "verified": True, "format": "FGVAULT1"}


def extract_encrypted_vault(vault_file: str | Path, destination_dir: str | Path, pin: str | None = None):
    vault = Path(vault_file).resolve()
    dest = Path(destination_dir).resolve()
    if not vault.is_file():
        raise FileNotFoundError("فایل گاوصندوق پیدا نشد.")
    if dest.exists():
        raise FileExistsError("پوشه کاری از قبل وجود دارد؛ برای جلوگیری از بازنویسی، استخراج متوقف شد.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fgvault_open_") as td:
        zip_path = Path(td) / "contents.zip"
        _decrypt_to_zip(vault, zip_path, pin=pin)
        _verify_archive(zip_path)
        dest.mkdir(parents=True, exist_ok=False)
        root = dest.resolve()
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for info in zf.infolist():
                    name = info.filename.replace("\\", "/")
                    pp = PurePosixPath(name)
                    if pp.is_absolute() or ".." in pp.parts or (pp.parts and ":" in pp.parts[0]):
                        raise ValueError("مسیر ناامن در آرشیو؛ استخراج متوقف شد.")
                    target = (dest / Path(*pp.parts)).resolve()
                    if target != root and root not in target.parents:
                        raise ValueError("مسیر فایل از محدوده گاوصندوق خارج می‌شود.")
                    if info.is_dir() or name.endswith("/"):
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as src, open(target, "xb") as out:
                        shutil.copyfileobj(src, out, length=1024 * 1024)
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
    return str(dest)


def verify_vault(vault_file: str | Path, pin: str | None = None):
    vault = Path(vault_file)
    with tempfile.TemporaryDirectory(prefix="fgvault_verify_") as td:
        zip_path = Path(td) / "contents.zip"
        _decrypt_to_zip(vault, zip_path, pin=pin)
        _verify_archive(zip_path)
    return True
