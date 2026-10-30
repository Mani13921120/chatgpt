import sys, os, sqlite3, secrets, time, hashlib, ctypes, uuid, subprocess, xml.etree.ElementTree as ET, getpass
import shutil
import traceback
from pathlib import Path
if __name__ == '__main__' and os.name == 'nt':
    try:
        from explorer_integration import restore_legacy_default
        restore_legacy_default()
    except Exception as exc:
        ctypes.windll.user32.MessageBoxW(None, str(exc), 'FaceGate: Explorer restore failed', 0x10)
# Shell invocations for ordinary folders must remain fast and must not create data.
# A protected path is always forwarded to the GUI that owns its Windows handles.
if __name__ == '__main__' and '--explorer-open' in sys.argv:
    try:
        from explorer_router import find_protected_root
        from explorer_integration import open_directory
        idx = sys.argv.index('--explorer-open')
        selected = sys.argv[idx + 1]
        data_dir = Path(os.getenv('LOCALAPPDATA', str(Path.home()))) / 'FaceGate'
        protected = find_protected_root(selected, data_dir / 'users.db')
        if protected is None:
            open_directory(selected)
            raise SystemExit(0)
        sys.argv = [sys.argv[0], '--folder-action', 'open-face', '--folder-path', protected, '--from-explorer']
    except Exception as exc:
        if os.name == 'nt':
            ctypes.windll.user32.MessageBoxW(None, str(exc), 'FaceGate', 0x10)
        raise SystemExit(1)
import psutil
import folder_inplace_crypto as inplace_crypto
import explorer_integration
from folder_auth import FOLDER_AUTH_SECONDS, FolderFaceAttempt
from instance_bridge import InstanceServer, forward_request, instance_name
from ctypes import wintypes
import cv2
import numpy as np
from PySide6.QtCore import QTimer, Qt, QThread, Signal, QFileInfo, QSize
from PySide6.QtGui import QImage, QPixmap, QAction
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QLineEdit, QVBoxLayout, QHBoxLayout, QGridLayout, QMessageBox, QFrame, QInputDialog, QFileDialog, QListWidget, QListWidgetItem, QSystemTrayIcon, QMenu, QStyle, QScrollArea, QDialog, QDialogButtonBox, QAbstractItemView, QComboBox, QFileIconProvider)

APP_DIR = Path(os.getenv('LOCALAPPDATA', str(Path.home()))) / 'FaceGate'
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = APP_DIR / 'users.db'
MODEL_DIR = Path(__file__).resolve().parent / 'models'
YUNET_MODEL = MODEL_DIR / 'face_detection_yunet_2023mar.onnx'
SFACE_MODEL = MODEL_DIR / 'face_recognition_sface_2021dec.onnx'
TEMPLATE_PATH = APP_DIR / 'face_template.npy'  # legacy profile compatibility
FACE_PROFILES_DIR = APP_DIR / 'faces'
FACE_PROFILES_DIR.mkdir(parents=True, exist_ok=True)
MAX_FACE_PROFILES = 3
# SFace cosine similarity threshold. Higher values reduce false accepts but can
# increase false rejects; calibrate with genuine/impostor samples on the target webcam.
COSINE_THRESHOLD = 0.47
ENROLL_SAMPLE_COUNT = 40
ENROLL_SAMPLE_INTERVAL = 0.25
MIN_ENROLL_FACE_SIZE = 120
MIN_ENROLL_SHARPNESS = 35.0
PROTECTED_FOLDERS_DIR = APP_DIR / 'FolderAclBackups'
PROTECTED_FOLDERS_DIR.mkdir(parents=True, exist_ok=True)
FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400



def _windows_file_attributes(path):
    """Return GetFileAttributesW for a path, or INVALID_FILE_ATTRIBUTES on failure."""
    if os.name != 'nt':
        return 0xFFFFFFFF
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    func = kernel32.GetFileAttributesW
    func.argtypes = [wintypes.LPCWSTR]
    func.restype = wintypes.DWORD
    return int(func(str(path)))


def _windows_filesystem_name(path):
    """Return the filesystem name for the volume holding path, using documented Win32 APIs."""
    if os.name != 'nt':
        raise RuntimeError('این تابع فقط روی ویندوز در دسترس است.')
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    get_volume_path = kernel32.GetVolumePathNameW
    get_volume_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume_path.restype = wintypes.BOOL
    volume_root = ctypes.create_unicode_buffer(1024)
    if not get_volume_path(str(path), volume_root, len(volume_root)):
        raise ctypes.WinError(ctypes.get_last_error())
    get_volume_info = kernel32.GetVolumeInformationW
    get_volume_info.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    get_volume_info.restype = wintypes.BOOL
    fs_name = ctypes.create_unicode_buffer(64)
    serial = wintypes.DWORD()
    max_component = wintypes.DWORD()
    flags = wintypes.DWORD()
    if not get_volume_info(volume_root.value, None, 0, ctypes.byref(serial), ctypes.byref(max_component), ctypes.byref(flags), fs_name, len(fs_name)):
        raise ctypes.WinError(ctypes.get_last_error())
    return fs_name.value


def db():
    con = sqlite3.connect(DB_PATH)
    con.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)')
    con.execute('CREATE TABLE IF NOT EXISTS locked_apps (path TEXT PRIMARY KEY COLLATE NOCASE, display_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)')
    con.execute('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    con.execute('CREATE TABLE IF NOT EXISTS protected_folders (path TEXT PRIMARY KEY COLLATE NOCASE, display_name TEXT NOT NULL, acl_backup_path TEXT NOT NULL, is_locked INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP)')
    con.commit()
    return con


def hash_password(password: str, salt: bytes | None = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 310_000)
    return salt.hex() + ':' + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(':', 1)
        candidate = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), 310_000).hex()
        return secrets.compare_digest(candidate, digest_hex)
    except Exception:
        return False


def normalize_embedding(feature):
    feature = np.asarray(feature, dtype=np.float32).reshape(-1)
    norm = float(np.linalg.norm(feature))
    if norm < 1e-8:
        raise ValueError('ویژگی چهره معتبر نیست.')
    return feature / norm


class FolderOperationWorker(QThread):
    """Run potentially long folder crypto operations away from the GUI thread."""
    result_ready = Signal(bool, object)

    def __init__(self, task, parent=None):
        super().__init__(parent)
        self.task = task

    def run(self):
        try:
            self.result_ready.emit(True, self.task())
        except Exception as exc:
            self.result_ready.emit(False, {"error": str(exc), "traceback": traceback.format_exc()})


class FaceTrainingWorker(QThread):
    succeeded = Signal(str)
    failed = Signal(str)

    def __init__(self, samples, template_path):
        super().__init__()
        self.samples = [normalize_embedding(v) for v in samples]
        self.template_path = Path(template_path)

    def run(self):
        try:
            if len(self.samples) < 12:
                raise RuntimeError('نمونه‌های باکیفیت کافی ثبت نشد؛ نور را بهتر کنید، نزدیک‌تر بنشینید و دوباره ثبت کنید.')
            # Robust template: discard embeddings far from the initial median direction,
            # then average the remaining normalized embeddings.
            stack = np.stack(self.samples, axis=0).astype(np.float32)
            seed = normalize_embedding(np.median(stack, axis=0))
            similarities = stack @ seed
            kept = stack[similarities >= max(0.25, float(np.percentile(similarities, 20)))]
            if len(kept) < 10:
                kept = stack
            template = normalize_embedding(np.mean(kept, axis=0))
            self.template_path.parent.mkdir(parents=True, exist_ok=True)
            np.save(self.template_path, template)
            self.succeeded.emit(f'چهره با مدل ویژگی‌محور ثبت شد ({len(self.samples)} نمونه). اکنون آزمایش کنید.')
        except Exception as exc:
            self.failed.emit(str(exc))


class FaceGate(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('FaceGate | قفل برنامه‌ها و رمزگذاری پوشه‌ها')
        self.resize(1050, 690)
        self.setMinimumSize(820, 560)
        self.detector = None
        self.recognizer = None
        self.face_template = None
        self.face_templates = {}
        self.current_face_slot = 1
        self.cap = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_frame)
        # Track already-running processes so FaceGate only gates new launches.
        self._known_processes = set()
        try:
            for proc in psutil.process_iter(['pid', 'create_time']):
                try: self._known_processes.add((proc.info['pid'], proc.info.get('create_time')))
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        except Exception: pass
        self._authorized_launches = {}
        # Keep an app authorized for its whole running session, including child/helper processes.
        self._authorized_app_sessions = set()
        self._authorized_session_last_seen = {}
        self._allow_next_foreground = {}
        self._last_foreground_key = None
        self._last_gate_event = 0.0
        self.app_lock_timer = QTimer(self)
        self.app_lock_timer.timeout.connect(self.check_locked_foreground_app)
        self.app_lock_timer.start(250)
        self.faces = []
        self.labels = []
        self.label_to_name = {}
        self.mode = 'idle'
        self._gate_active = False
        self._app_unlock_until = {}
        self._last_blocked_hwnd = 0
        self._last_gate_prompt = 0.0
        self._pending_app_unlock = None
        self._folder_worker = None
        self._folder_worker_callback = None
        self._folder_unlocking_path = None
        self._folder_face_attempt = None
        self._folder_prompt_active = False
        self._folder_prompt_path = None
        self._folder_open_from_shell = False
        self._queued_shell_requests = []
        self._instance_request_timer = QTimer(self)
        self._instance_request_timer.setSingleShot(True)
        self._instance_request_timer.timeout.connect(self._drain_instance_requests)
        self._folder_auth_timer = QTimer(self)
        self._folder_auth_timer.setSingleShot(True)
        self._folder_auth_timer.setTimerType(Qt.PreciseTimer)
        self._folder_auth_timer.timeout.connect(self._folder_face_failed)
        self._workspace_mode = None
        self._startup_relock_paths = []
        self.challenge = None
        self.challenge_start = 0
        self.challenge_center = None
        self.challenge_done = False
        self.login_start = 0.0
        self.last_enroll_sample = 0.0
        self.login_matches = 0
        self.login_last_label = None
        self.face_profile_id = None
        self._training_worker = None
        self._build_ui()
        self._setup_tray()
        self.load_model()
        self._refresh_face_profiles()
        self.refresh_protected_folders()
        self._recover_folder_acl_state()
        # Privacy-first: do not open the webcam until authentication/enrollment is requested.
        self.stop_camera()
        self.video.setText('دوربین خاموش است؛ هنگام نیاز به احراز هویت فعال می‌شود.')

    def _build_ui(self):
        self.setStyleSheet('''
            QMainWindow, QWidget { background:#0a1020; color:#eaf0fb; font-family:Segoe UI; font-size:14px; }
            QFrame#panel { background:#111b2e; border:1px solid #263956; border-radius:18px; }
            QLabel#title { font-size:30px; font-weight:800; color:#ffffff; }
            QLabel#sub { color:#a8bad4; }
            QLabel#video { background:#050914; border:1px solid #2c4162; border-radius:16px; }
            QLineEdit { background:#0b1424; border:1px solid #354966; border-radius:10px; padding:11px; color:#fff; selection-background-color:#2563eb; }
            QPushButton { background:#356df3; border:0; border-radius:10px; padding:11px 14px; color:white; font-weight:650; }
            QPushButton:hover { background:#4a80ff; }
            QPushButton:pressed { background:#2454c7; }
            QPushButton#secondary { background:#253752; }
            QPushButton#secondary:hover { background:#304968; }
            QPushButton#danger { background:#a93449; }
            QPushButton#danger:hover { background:#c44257; }
            QComboBox { background:#0b1424; border:1px solid #354966; border-radius:9px; padding:8px; }
        ''')
        central = QWidget(); self.setCentralWidget(central)
        root = QHBoxLayout(central); root.setContentsMargins(24,24,24,24); root.setSpacing(20)
        left = QVBoxLayout(); left.setSpacing(14)
        title = QLabel('FaceGate'); title.setObjectName('title')
        subtitle = QLabel('احراز هویت محلی با وب‌کم'); subtitle.setObjectName('sub')
        left.addWidget(title); left.addWidget(subtitle)
        self.video = QLabel('در حال راه‌اندازی دوربین…'); self.video.setObjectName('video'); self.video.setAlignment(Qt.AlignCenter); self.video.setMinimumSize(540, 410)
        left.addWidget(self.video, 1)
        self.status = QLabel('آماده'); self.status.setObjectName('sub'); left.addWidget(self.status)
        root.addLayout(left, 3)
        right_frame = QFrame(); right_frame.setObjectName('panel'); right = QVBoxLayout(right_frame); right.setContentsMargins(22,22,22,22); right.setSpacing(13)
        self.workspace_label = QLabel('حالت کاری'); self.workspace_label.setObjectName('sub'); right.addWidget(self.workspace_label)
        workspace_back = QPushButton('انتخاب بخش دیگر'); workspace_back.setObjectName('secondary'); workspace_back.clicked.connect(self._show_workspace_picker); right.addWidget(workspace_back)
        self._app_mode_widgets = []
        heading = QLabel('قفل با تشخیص چهره'); heading.setStyleSheet('font-size:20px;font-weight:700;')
        right.addWidget(heading); self._app_mode_widgets.append(heading)
        login = QPushButton('آزمایش / تأیید با چهره'); login.clicked.connect(self.begin_login); right.addWidget(login); self._app_mode_widgets.append(login)
        face_heading = QLabel('پروفایل‌های چهره'); face_heading.setStyleSheet('font-size:16px;font-weight:700;')
        right.addWidget(face_heading)
        self.face_profiles_list = QListWidget()
        self.face_profiles_list.setMaximumHeight(118)
        self.face_profiles_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.face_profiles_list.setStyleSheet('QListWidget {background:#0b1424;border:1px solid #30415d;border-radius:9px;padding:4px;} QListWidget::item {padding:8px;border-radius:6px;} QListWidget::item:selected {background:#2563eb;color:white;}')
        self.face_profiles_list.currentRowChanged.connect(self._face_profile_selection_changed)
        right.addWidget(self.face_profiles_list)
        face_buttons = QHBoxLayout()
        enroll = QPushButton('ثبت / ویرایش چهره'); enroll.setObjectName('secondary'); enroll.clicked.connect(self.enroll_user)
        rename_face = QPushButton('تغییر نام'); rename_face.setObjectName('secondary'); rename_face.clicked.connect(self.rename_face_profile)
        remove_face = QPushButton('حذف'); remove_face.setObjectName('danger'); remove_face.clicked.connect(self.remove_face_profile)
        face_buttons.addWidget(enroll); face_buttons.addWidget(rename_face); face_buttons.addWidget(remove_face)
        right.addLayout(face_buttons)
        theme_row = QHBoxLayout()
        theme_label = QLabel('تم رابط کاربری'); theme_row.addWidget(theme_label)
        self.theme_choice = QComboBox(); self.theme_choice.addItems(['تیره', 'روشن']); self.theme_choice.currentTextChanged.connect(self.apply_theme); theme_row.addWidget(self.theme_choice)
        right.addLayout(theme_row)
        self.cancel = QPushButton('لغو عملیات'); self.cancel.setObjectName('danger'); self.cancel.clicked.connect(self.cancel_action); right.addWidget(self.cancel)
        backup_set = QPushButton('تنظیم / تغییر رمز پشتیبان'); backup_set.setObjectName('secondary'); backup_set.clicked.connect(self.set_backup_password); right.addWidget(backup_set)
        login_cred = QPushButton('تغییر رمز ورود / تنظیم PIN'); login_cred.setObjectName('secondary'); login_cred.clicked.connect(self.change_login_credential); right.addWidget(login_cred)
        backup_use = QPushButton('بازکردن برنامهٔ در انتظار با رمز پشتیبان'); backup_use.setObjectName('secondary'); backup_use.clicked.connect(self.use_backup_password); right.addWidget(backup_use); self._app_mode_widgets.append(backup_use)
        right.addStretch(1)
        note = QLabel('اطلاعات روی همین دستگاه ذخیره می‌شود. برای حساب‌های مهم، احراز هویت ویندوز یا کلید امنیتی را هم فعال نگه دارید.')
        note.setWordWrap(True); note.setObjectName('sub'); right.addWidget(note)
        startup_btn = QPushButton('فعال‌سازی اجرای پس‌زمینه و شروع با ویندوز')
        startup_btn.setObjectName('secondary')
        startup_btn.clicked.connect(self.toggle_startup_registration)
        right.addWidget(startup_btn)
        exit_btn = QPushButton('خروج کامل و بستن FaceGate')
        exit_btn.setObjectName('danger')
        exit_btn.clicked.connect(self._exit_application)
        right.addWidget(exit_btn)
        # Folder mode UI: actual content encryption in-place, not a nearby container.
        self._folder_mode_widgets = []
        folder_heading = QLabel('قفل پوشه و رمزگذاری محتوا')
        folder_heading.setStyleSheet('font-size:17px;font-weight:700;margin-top:8px;')
        right.addWidget(folder_heading); self._folder_mode_widgets.append(folder_heading)
        folder_note = QLabel('خود پوشه با مجوزهای ویندوز بسته می‌شود و محتوای فایل‌ها نیز رمزگذاری می‌شود. تا وقتی FaceGate اجراست، قفل‌های اشتراک ویندوز خواندن، کپی، تغییر نام و حذف مسیرهای قفل‌شده را محدود می‌کنند. پیش از قفل، برنامه‌های باز روی پوشه را ببند. در برابر مدیر سیستم، توقف اجباری برنامه، دسترسی خام دیسک یا نسخه‌های قبلی فایل‌ها تضمین مطلق وجود ندارد. مجوزهای قبلی پس از تأیید چهره یا PIN بازگردانده می‌شوند.')
        folder_note.setWordWrap(True); folder_note.setObjectName('sub'); right.addWidget(folder_note); self._folder_mode_widgets.append(folder_note)
        self.protected_folder_list = QListWidget(); self.protected_folder_list.setMaximumHeight(150); self.protected_folder_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.protected_folder_list.setStyleSheet('QListWidget {background:#0b1424;border:1px solid #30415d;border-radius:8px;padding:4px;} QListWidget::item {padding:6px;}')
        right.addWidget(self.protected_folder_list); self._folder_mode_widgets.append(self.protected_folder_list)
        folder_add = QPushButton('انتخاب و قفل پوشه'); folder_add.setObjectName('secondary'); folder_add.clicked.connect(self.choose_and_protect_folder)
        right.addWidget(folder_add); self._folder_mode_widgets.append(folder_add)
        folder_auth_row = QHBoxLayout()
        folder_face = QPushButton('بازکردن با تشخیص چهره'); folder_face.clicked.connect(self.open_selected_folder_with_face)
        folder_pin = QPushButton('بازکردن با PIN پشتیبان'); folder_pin.setObjectName('secondary'); folder_pin.clicked.connect(self.open_selected_folder_with_pin)
        folder_auth_row.addWidget(folder_face); folder_auth_row.addWidget(folder_pin); right.addLayout(folder_auth_row)
        self._folder_mode_widgets.extend([folder_face, folder_pin])
        folder_lock_row = QHBoxLayout()
        folder_lock = QPushButton('قفل مجدد پوشه'); folder_lock.setObjectName('danger'); folder_lock.clicked.connect(self.lock_selected_folder)
        folder_refresh = QPushButton('تازه‌سازی فهرست'); folder_refresh.setObjectName('secondary'); folder_refresh.clicked.connect(self.refresh_protected_folders)
        folder_lock_row.addWidget(folder_lock); folder_lock_row.addWidget(folder_refresh); right.addLayout(folder_lock_row)
        self._folder_mode_widgets.extend([folder_lock, folder_refresh])
        folder_remove = QPushButton('حذف پوشه از قفل (بدون حذف فایل‌ها)')
        folder_remove.setObjectName('danger'); folder_remove.clicked.connect(self.remove_selected_folder_protection)
        right.addWidget(folder_remove); self._folder_mode_widgets.append(folder_remove)
        folder_restore = QPushButton('بازیابی پشتیبان به پوشهٔ جدید'); folder_restore.setObjectName('secondary'); folder_restore.clicked.connect(self.restore_selected_folder_backup)
        right.addWidget(folder_restore); self._folder_mode_widgets.append(folder_restore)
        folder_menu_row = QHBoxLayout()
        folder_menu_install = QPushButton('افزودن گزینهٔ راست‌کلیک FaceGate'); folder_menu_install.setObjectName('secondary'); folder_menu_install.clicked.connect(self.install_folder_context_menu)
        folder_menu_remove = QPushButton('بازگردانی بازکردن عادی Explorer'); folder_menu_remove.setObjectName('secondary'); folder_menu_remove.clicked.connect(self.remove_folder_context_menu)
        folder_menu_row.addWidget(folder_menu_install); folder_menu_row.addWidget(folder_menu_remove); right.addLayout(folder_menu_row)
        self._folder_mode_widgets.extend([folder_menu_install, folder_menu_remove])
        folder_recover = QPushButton('بازیابی مجوزهای نسخهٔ قدیمی FaceGate'); folder_recover.setObjectName('secondary'); folder_recover.clicked.connect(self.recover_legacy_folder_permissions)
        right.addWidget(folder_recover); self._folder_mode_widgets.append(folder_recover)

        # App-lock mode UI; append to the app-only widgets registered above.
        app_heading = QLabel('قفل برنامه‌های ویندوز'); app_heading.setStyleSheet('font-size:17px;font-weight:700;margin-top:8px;')
        right.addWidget(app_heading); self._app_mode_widgets.append(app_heading)
        self.app_list = QListWidget(); self.app_list.setMinimumHeight(135); self.app_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.app_list.setStyleSheet('QListWidget {background:#0b1424;border:1px solid #30415d;border-radius:8px;padding:4px;} QListWidget::item {padding:6px;}')
        right.addWidget(self.app_list); self._app_mode_widgets.append(self.app_list)
        app_buttons = QHBoxLayout()
        add_app = QPushButton('افزودن از فهرست برنامه‌ها'); add_app.setObjectName('secondary'); add_app.clicked.connect(self.add_locked_app)
        choose_exe = QPushButton('انتخاب مسیر فایل اجرایی (.exe)'); choose_exe.setObjectName('secondary'); choose_exe.clicked.connect(self.add_locked_app_by_path)
        remove_app = QPushButton('حذف از فهرست'); remove_app.setObjectName('danger'); remove_app.clicked.connect(self.remove_locked_app)
        app_buttons.addWidget(add_app); app_buttons.addWidget(choose_exe); app_buttons.addWidget(remove_app); right.addLayout(app_buttons)
        self._app_mode_widgets.extend([add_app, choose_exe, remove_app])
        refresh_apps = QPushButton('به‌روزرسانی فهرست'); refresh_apps.setObjectName('secondary'); refresh_apps.clicked.connect(self.load_locked_apps)
        right.addWidget(refresh_apps); self._app_mode_widgets.append(refresh_apps)
        lock_note = QLabel('تشخیص هویت با SFace و YuNet انجام می‌شود. FaceGate باید در حال اجرا باشد؛ قفل برنامه‌ها جایگزین کنترل‌های امنیتی بومی ویندوز نیست.')
        lock_note.setWordWrap(True); lock_note.setObjectName('sub'); right.addWidget(lock_note); self._app_mode_widgets.append(lock_note)
        # Scroll the controls when the window is not maximized / display is short.
        right_scroll = QScrollArea(); right_scroll.setWidgetResizable(True); right_scroll.setFrameShape(QFrame.NoFrame)
        right_scroll.setWidget(right_frame); right_scroll.setMinimumWidth(330)
        root.addWidget(right_scroll, 2)
        self.load_locked_apps()
        self.refresh_protected_folders()
        con = db()
        theme_row = con.execute('SELECT value FROM app_settings WHERE key=?', ('theme',)).fetchone()
        con.close()
        if theme_row:
            self.theme_choice.blockSignals(True)
            self.theme_choice.setCurrentText(theme_row[0])
            self.theme_choice.blockSignals(False)
            self.apply_theme(theme_row[0])
        for widget in getattr(self, '_folder_mode_widgets', []):
            widget.hide()
        for widget in getattr(self, '_app_mode_widgets', []):
            widget.hide()

    def _choose_workspace_mode(self):
        box = QMessageBox()
        box.setWindowTitle('FaceGate')
        box.setText('می‌خواهی کدام بخش را باز کنی؟')
        box.setInformativeText('یک بخش را انتخاب کن تا رابط خلوت‌تر شود.')
        apps = box.addButton('قفل برنامه‌ها', QMessageBox.AcceptRole)
        folders = box.addButton('رمزگذاری فایل‌ها و پوشه‌ها', QMessageBox.AcceptRole)
        box.addButton('خروج کامل', QMessageBox.DestructiveRole)
        box.setDefaultButton(apps)
        box.exec()
        clicked = box.clickedButton()
        if clicked is apps:
            return 'apps'
        if clicked is folders:
            return 'folders'
        return 'exit'

    def set_workspace_mode(self, mode):
        if mode not in {'apps', 'folders'}:
            return
        self._workspace_mode = mode
        for widget in getattr(self, '_app_mode_widgets', []):
            widget.setVisible(mode == 'apps')
        for widget in getattr(self, '_folder_mode_widgets', []):
            widget.setVisible(mode == 'folders')
        label = 'حالت قفل برنامه‌ها' if mode == 'apps' else 'حالت رمزگذاری فایل‌ها و پوشه‌ها'
        self.workspace_label.setText(label)
        self.setWindowTitle('FaceGate | ' + label)

    def _show_workspace_picker(self):
        mode = self._choose_workspace_mode()
        if mode == 'exit':
            self._exit_application()
            return
        self.set_workspace_mode(mode)

    def apply_theme(self, theme):
        dark = theme != 'روشن'
        if dark:
            self.setStyleSheet('''
                QMainWindow, QWidget { background:#0b1220; color:#e5edf9; font-family:Segoe UI; font-size:14px; }
                QFrame#panel { background:#121d30; border:1px solid #263650; border-radius:16px; }
                QLabel#title { font-size:28px; font-weight:700; color:#f8fbff; }
                QLabel#sub { color:#9fb1ca; }
                QLabel#video { background:#050a12; border:1px solid #263650; border-radius:14px; }
                QLineEdit, QListWidget, QComboBox { background:#0b1424; border:1px solid #30415d; border-radius:9px; padding:8px; color:#fff; }
                QPushButton { background:#2563eb; border:0; border-radius:9px; padding:10px 12px; color:white; font-weight:600; }
                QPushButton:hover { background:#3475ff; } QPushButton#secondary { background:#26364f; } QPushButton#danger { background:#b93845; }
            ''')
        else:
            self.setStyleSheet('''
                QMainWindow, QWidget { background:#f4f7fb; color:#172033; font-family:Segoe UI; font-size:14px; }
                QFrame#panel { background:#ffffff; border:1px solid #d9e1ec; border-radius:16px; }
                QLabel#title { font-size:28px; font-weight:700; color:#13213a; }
                QLabel#sub { color:#52627a; }
                QLabel#video { background:#e8edf4; border:1px solid #ccd6e4; border-radius:14px; color:#25344a; }
                QLineEdit, QListWidget, QComboBox { background:#ffffff; border:1px solid #c7d2e2; border-radius:9px; padding:8px; color:#172033; }
                QPushButton { background:#2563eb; border:0; border-radius:9px; padding:10px 12px; color:white; font-weight:600; }
                QPushButton:hover { background:#1d4ed8; } QPushButton#secondary { background:#52627a; } QPushButton#danger { background:#b93845; }
            ''')
        con = db()
        con.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ('theme', theme))
        con.commit(); con.close()

    def _face_profile_name(self, slot):
        con = db()
        try:
            row = con.execute('SELECT value FROM app_settings WHERE key=?', (f'face_profile_name_{slot}',)).fetchone()
            return row[0] if row and row[0].strip() else f'چهره {slot}'
        finally:
            con.close()

    def _refresh_face_profiles(self, preferred_slot=None):
        if not hasattr(self, 'face_profiles_list'):
            return
        self.face_profiles_list.blockSignals(True)
        self.face_profiles_list.clear()
        for slot in range(1, MAX_FACE_PROFILES + 1):
            path = FACE_PROFILES_DIR / f'face_{slot}.npy'
            name = self._face_profile_name(slot)
            status = 'ثبت‌شده' if path.exists() else 'ثبت‌نشده'
            item = QListWidgetItem(f'{name}  ·  {status}')
            item.setData(Qt.UserRole, slot)
            self.face_profiles_list.addItem(item)
        wanted = preferred_slot or getattr(self, 'current_face_slot', 1)
        self.face_profiles_list.setCurrentRow(max(0, min(MAX_FACE_PROFILES - 1, wanted - 1)))
        self.face_profiles_list.blockSignals(False)
        self.current_face_slot = wanted

    def _face_profile_selection_changed(self, row):
        if row >= 0 and hasattr(self, 'face_profiles_list'):
            item = self.face_profiles_list.item(row)
            if item:
                self.current_face_slot = int(item.data(Qt.UserRole))

    def rename_face_profile(self):
        if not self._require_management_password('تأیید تغییر نام چهره'):
            return
        slot = getattr(self, 'current_face_slot', 1)
        old_name = self._face_profile_name(slot)
        name, ok = QInputDialog.getText(self, 'تغییر نام پروفایل', 'نام دلخواه برای این چهره:', QLineEdit.Normal, old_name)
        if not ok:
            return
        name = name.strip()
        if not name or len(name) > 40:
            QMessageBox.warning(self, 'نام نامعتبر', 'نام باید بین ۱ تا ۴۰ نویسه باشد.')
            return
        con = db()
        try:
            con.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                        (f'face_profile_name_{slot}', name))
            con.commit()
        finally:
            con.close()
        self._refresh_face_profiles(slot)

    def change_login_credential(self):
        if not self._require_management_password('تأیید تغییر اطلاعات ورود'):
            return
        choice, ok = QInputDialog.getItem(self, 'روش ورود', 'روش ورود جدید را انتخاب کن:',
                                          ['رمز عبور', 'PIN چهار تا هشت رقمی'], 0, False)
        if not ok:
            return
        is_pin = choice == 'PIN چهار تا هشت رقمی'
        first, ok = QInputDialog.getText(self, 'اطلاعات ورود جدید',
            'PIN جدید (۴ تا ۸ رقم):' if is_pin else 'رمز جدید (حداقل ۸ نویسه):', QLineEdit.Password)
        if not ok:
            return
        if is_pin and (not first.isdigit() or not 4 <= len(first) <= 8):
            QMessageBox.warning(self, 'PIN نامعتبر', 'PIN باید فقط شامل ۴ تا ۸ رقم باشد.')
            return
        if not is_pin and len(first) < 8:
            QMessageBox.warning(self, 'رمز ضعیف', 'رمز عبور باید حداقل ۸ نویسه داشته باشد.')
            return
        second, ok = QInputDialog.getText(self, 'تأیید اطلاعات ورود', 'دوباره وارد کن:', QLineEdit.Password)
        if not ok:
            return
        if first != second:
            QMessageBox.warning(self, 'عدم تطبیق', 'دو مقدار یکسان نیستند.')
            return
        candidate = ('PIN:' + first) if is_pin else first
        con = db()
        con.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                    ('app_login_password_hash', hash_password(candidate)))
        con.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                    ('app_login_credential_type', 'pin' if is_pin else 'password'))
        con.commit()
        con.close()
        QMessageBox.information(self, 'ذخیره شد', 'اطلاعات ورود جدید از اجرای بعدی فعال است.')

    def _verify_current_credential(self, value):
        con = db()
        row = con.execute('SELECT value FROM app_settings WHERE key=?', ('app_login_password_hash',)).fetchone()
        type_row = con.execute('SELECT value FROM app_settings WHERE key=?', ('app_login_credential_type',)).fetchone()
        con.close()
        if not row:
            return False
        credential_type = type_row[0] if type_row else 'password'
        if credential_type == 'pin':
            if not value.isdigit() or not 4 <= len(value) <= 8:
                return False
            value = 'PIN:' + value
        return verify_password(value, row[0])

    def _require_management_password(self, action):
        con = db()
        row = con.execute('SELECT value FROM app_settings WHERE key=?', ('app_login_password_hash',)).fetchone()
        con.close()
        if not row:
            QMessageBox.warning(self, 'رمز لازم است', 'ابتدا رمز ورود FaceGate را تنظیم کنید.')
            return False
        credential_type = 'password'
        con2 = db()
        type_row = con2.execute('SELECT value FROM app_settings WHERE key=?', ('app_login_credential_type',)).fetchone()
        con2.close()
        if type_row and type_row[0] == 'pin':
            prompt = 'PIN فعلی (۴ تا ۸ رقم) را وارد کنید:'
        else:
            prompt = 'رمز ورود فعلی FaceGate را وارد کنید:'
        password, ok = QInputDialog.getText(self, action, prompt, QLineEdit.Password)
        if not ok:
            return False
        if not self._verify_current_credential(password):
            QMessageBox.warning(self, 'اطلاعات نادرست', 'رمز یا PIN نادرست است؛ عملیات انجام نشد.')
            return False
        return True

    def remove_face_profile(self):
        if not self._require_management_password('تأیید حذف چهره'):
            return
        slot = getattr(self, 'current_face_slot', 1)
        path = FACE_PROFILES_DIR / f'face_{slot}.npy'
        if not path.exists():
            QMessageBox.information(self, 'چهره پیدا نشد', f'برای «{self._face_profile_name(slot)}» چهره‌ای ثبت نشده است.')
            return
        if QMessageBox.question(self, 'حذف چهره', f'چهره «{self._face_profile_name(slot)}» حذف شود؟') != QMessageBox.Yes:
            return
        path.unlink(missing_ok=True)
        self.face_templates.pop(slot, None)
        self.face_template = self.face_templates[1] if 1 in self.face_templates else next(iter(self.face_templates.values()), None)
        self._refresh_face_profiles(slot)
        self.status.setText(f'پروفایل «{self._face_profile_name(slot)}» حذف شد.')

    def _is_admin(self):
        if os.name != 'nt':
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _folder_acl_backup_path(self, folder):
        key = hashlib.sha256(str(Path(folder).resolve()).casefold().encode('utf-8')).hexdigest()[:32]
        return PROTECTED_FOLDERS_DIR / f'{key}.acl'

    def _folder_record(self, folder_path):
        con = db()
        try:
            row = con.execute('SELECT path, display_name, acl_backup_path, is_locked FROM protected_folders WHERE path=?',
                              (str(Path(folder_path).resolve()),)).fetchone()
            if not row:
                # case-insensitive fallback for existing records on Windows
                row = con.execute('SELECT path, display_name, acl_backup_path, is_locked FROM protected_folders WHERE lower(path)=lower(?)',
                                  (str(Path(folder_path).resolve()),)).fetchone()
            return {'path': row[0], 'name': row[1], 'backup': row[2], 'locked': bool(row[3])} if row else None
        finally:
            con.close()

    def _sync_orphaned_folder_manifests(self):
        """Recover manifest records written before a crash interrupted the DB update."""
        root = self._metadata_root()
        con = db()
        try:
            registered = {str(row[0]).casefold() for row in con.execute('SELECT path FROM protected_folders').fetchall()}
        finally:
            con.close()
        for mp in root.glob('*.json'):
            meta = inplace_crypto.read_manifest(mp)
            if not meta or meta.get('state') == 'unprotected':
                continue
            try:
                folder = Path(meta.get('root', '')).resolve()
                if not folder.is_dir() or str(folder).casefold() in registered:
                    continue
                # Do not register arbitrary unused metadata unless some ciphertext remains
                # or the manifest explicitly says an operation was interrupted/open.
                state = str(meta.get('state', ''))
                has_gate = inplace_crypto.folder_gate.saved(folder, mp) is not None
                encrypted = [] if has_gate else inplace_crypto.list_encrypted_files(folder)
                if encrypted or state in {'protecting', 'unlocked', 'recovery-needed'} or (state == 'locked' and has_gate):
                    locked = 1 if state == 'locked' else 0
                    con = db()
                    try:
                        con.execute('INSERT OR IGNORE INTO protected_folders(path, display_name, acl_backup_path, is_locked) VALUES(?,?,?,?)',
                                    (str(folder), folder.name, str(mp), locked))
                        con.commit()
                    finally:
                        con.close()
                    registered.add(str(folder).casefold())
            except Exception:
                continue

    def refresh_protected_folders(self):
        if not hasattr(self, 'protected_folder_list'):
            return
        if self._folder_worker is not None and self._folder_worker.isRunning():
            self.status.setText('عملیات پوشه هنوز در حال اجراست؛ پس از اتمام، فهرست را تازه کن.')
            return
        self._sync_orphaned_folder_manifests()
        current = None
        item = self.protected_folder_list.currentItem()
        if item:
            current = item.data(Qt.UserRole)
        self.protected_folder_list.clear()
        con = db()
        try:
            rows = con.execute('SELECT path, display_name, acl_backup_path, is_locked FROM protected_folders ORDER BY display_name COLLATE NOCASE').fetchall()
        finally:
            con.close()
        selected_index = -1
        for folder_path, display_name, metadata_path, is_locked in rows:
            manifest = inplace_crypto.read_manifest(metadata_path) if metadata_path else None
            folder = Path(folder_path)
            if not manifest and folder.is_dir():
                try:
                    encrypted = inplace_crypto.list_encrypted_files(folder)
                    if encrypted:
                        header, _ = inplace_crypto.read_file_header(encrypted[0])
                        manifest_path = inplace_crypto.write_manifest(folder, self._metadata_root(), header['key_envelope'], '', 'locked' if is_locked else 'unlocked')
                        con = db()
                        try:
                            con.execute('UPDATE protected_folders SET acl_backup_path=? WHERE path=?', (str(manifest_path), folder_path))
                            con.commit()
                        finally:
                            con.close()
                        metadata_path = str(manifest_path)
                        manifest = inplace_crypto.read_manifest(metadata_path)
                except Exception:
                    manifest = None
            if manifest and manifest.get('state') == 'unprotected':
                status = 'محافظت برداشته شده — قابل حذف از فهرست'
            elif manifest and inplace_crypto.folder_gate_active(folder):
                status = 'خود پوشه قفل است — ورود، کپی و تغییر نام مسدود'
            elif manifest:
                try:
                    encrypted_count = len(inplace_crypto.list_encrypted_files(folder))
                    plain_count = len(inplace_crypto.walk_regular_files(folder))
                    if encrypted_count and not plain_count:
                        status = 'محتوا رمزگذاری‌شده'
                    elif encrypted_count and plain_count:
                        status = f'هشدار: محتوا ترکیبی است ({encrypted_count} رمزگذاری‌شده، {plain_count} خوانا)؛ قفل مجدد لازم است'
                    elif plain_count:
                        status = 'محتوا خوانا — قفل مجدد لازم است'
                    else:
                        status = 'پوشه خالی'
                except Exception as exc:
                    status = 'وضعیت نامشخص — بررسی لازم است'
            else:
                status = 'نسخهٔ قدیمی EFS/ACL — نیازمند بازیابی' if str(metadata_path).lower().endswith('.acl') else 'اطلاعات محافظت در دسترس نیست'
            item = QListWidgetItem(f'{display_name}  —  {status}\n{folder_path}')
            item.setData(Qt.UserRole, folder_path)
            self.protected_folder_list.addItem(item)
            if current and str(folder_path).casefold() == str(current).casefold():
                selected_index = self.protected_folder_list.count() - 1
        if selected_index >= 0:
            self.protected_folder_list.setCurrentRow(selected_index)

    def _selected_protected_folder(self):
        item = self.protected_folder_list.currentItem() if hasattr(self, 'protected_folder_list') else None
        if not item:
            QMessageBox.information(self, 'پوشه انتخاب نشده', 'ابتدا یک پوشه از فهرست محافظت‌شده انتخاب کن.')
            return None
        record = self._folder_record(item.data(Qt.UserRole))
        if not record:
            QMessageBox.warning(self, 'پوشه پیدا نشد', 'اطلاعات این پوشه در پایگاه داده پیدا نشد. فهرست را تازه‌سازی کن.')
        return record

    def _handoff_folder_action_to_admin(self, action, folder_path):
        """Re-launch a user-selected folder action elevated; the elevated instance still requires FaceGate login."""
        if os.name != 'nt':
            QMessageBox.warning(self, 'فقط ویندوز', 'محافظت EFS فقط روی ویندوز قابل استفاده است.')
            return False
        script_path = str(Path(__file__).resolve())
        if getattr(sys, 'frozen', False):
            executable = str(Path(sys.executable).resolve())
            args = ['--folder-action', action, '--folder-path', str(folder_path)]
        else:
            py = Path(sys.executable).resolve()
            pythonw = py.with_name('pythonw.exe')
            executable = str(pythonw if pythonw.exists() else py)
            args = [script_path, '--folder-action', action, '--folder-path', str(folder_path)]
        params = subprocess.list2cmdline(args)
        try:
            result = ctypes.windll.shell32.ShellExecuteW(None, 'runas', executable, params, str(Path(script_path).parent), 1)
        except Exception as exc:
            QMessageBox.critical(self, 'اجرای مدیر', f'درخواست اجرای FaceGate با دسترسی مدیر ناموفق بود:\n{exc}')
            return False
        if int(result) <= 32:
            QMessageBox.warning(self, 'لغو دسترسی مدیر', 'برای اعمال مجوزهای امن پوشه، اجرای FaceGate با دسترسی مدیر لازم است. تغییراتی اعمال نشد.')
            return False
        self._allow_real_exit = True
        if self.tray:
            self.tray.hide()
        self.stop_camera()
        self.app_lock_timer.stop()
        QApplication.quit()
        return True

    def _require_folder_admin(self, action, folder_path):
        if self._is_admin():
            return True
        answer = QMessageBox.question(
            self, 'دسترسی مدیر لازم است',
            'برای اعمال مجوزهای NTFS که جلوی دسترسی مستقیم برنامه‌های عادی و CMD را در حالت قفل می‌گیرد، FaceGate باید با دسترسی مدیر اجرا شود.\n\n'
            'با تأیید، پنجره UAC ویندوز نمایش داده می‌شود و FaceGate دوباره اجرا خواهد شد. ادامه می‌دهی؟',
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Yes)
        if answer != QMessageBox.Yes:
            return False
        self._handoff_folder_action_to_admin(action, folder_path)
        return False

    def _validate_folder_target(self, folder_path):
        if os.name != 'nt':
            raise RuntimeError('این قابلیت فقط روی Windows/NTFS پشتیبانی می‌شود.')
        folder = Path(os.path.abspath(os.path.expandvars(str(folder_path))))
        if not folder.exists() or not folder.is_dir():
            raise RuntimeError('پوشه انتخاب‌شده پیدا نشد یا پوشه نیست.')
        if folder == Path(folder.anchor) or folder.parent == folder:
            raise RuntimeError('انتخاب ریشه درایو مجاز نیست؛ یک پوشه معمولی را انتخاب کن.')
        # Do not allow system roots or folders whose locking would affect FaceGate itself.
        forbidden_roots = [Path(os.environ.get('WINDIR', r'C:\Windows')).resolve(),
                           Path(os.environ.get('ProgramFiles', r'C:\Program Files')).resolve(),
                           Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')).resolve()]
        for blocked in forbidden_roots:
            try:
                if folder == blocked or blocked in folder.parents or folder in blocked.parents:
                    raise RuntimeError(f'برای جلوگیری از قفل‌شدن ویندوز، این مسیر پشتیبانی نمی‌شود: {folder}')
            except OSError:
                pass
        home_root = Path.home().resolve()
        app_root = APP_DIR.resolve()
        code_root = Path(__file__).resolve().parent
        try:
            if folder == code_root or folder in code_root.parents:
                raise RuntimeError(f'برای جلوگیری از رمزگذاری خود برنامه و فایل‌های نصب، این مسیر پشتیبانی نمی‌شود: {folder}')
        except OSError:
            pass
        if folder == home_root:
            raise RuntimeError('قفل‌کردن ریشه پروفایل کاربر می‌تواند FaceGate و برنامه‌های دیگر را از کار بیندازد؛ یک زیرپوشه را انتخاب کن.')
        try:
            if folder == app_root or folder in app_root.parents:
                raise RuntimeError(f'برای جلوگیری از قفل‌شدن اطلاعات داخلی FaceGate، این مسیر پشتیبانی نمی‌شود: {folder}')
        except OSError:
            pass
        if _windows_filesystem_name(folder).upper() != 'NTFS':
            raise RuntimeError('قفل خود پوشه در این نسخه فقط روی درایو NTFS محلی پشتیبانی می‌شود.')
        if str(folder).startswith('\\\\'):
            raise RuntimeError('مسیر شبکه پشتیبانی نمی‌شود؛ پوشهٔ محلی NTFS انتخاب کن.')
        attrs = _windows_file_attributes(folder)
        if attrs == 0xFFFFFFFF or attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError('پوشه پیدا نشد یا یک junction/symlink است؛ مسیر مستقیم و معمولی انتخاب کن.')
        # Reject nested reparse points so a recursive operation cannot unexpectedly traverse elsewhere.
        for root, dirs, files in os.walk(folder, followlinks=False):
            for name in list(dirs) + list(files):
                p = Path(root) / name
                a = _windows_file_attributes(p)
                if a != 0xFFFFFFFF and a & FILE_ATTRIBUTE_REPARSE_POINT:
                    raise RuntimeError(f'در این پوشه junction/symlink وجود دارد و برای جلوگیری از تغییر مسیر ناخواسته پشتیبانی نمی‌شود:\n{p}')
            # os.walk does not follow symlinks; no extra traversal needed.
        return folder

    def _cipher_command(self, args, timeout=7200):
        exe = shutil.which('cipher.exe') or shutil.which('cipher') or str(Path(os.environ.get('WINDIR', r'C:\Windows')) / 'System32' / 'cipher.exe')
        return subprocess.run([exe, *args], capture_output=True, text=True, encoding='mbcs' if os.name == 'nt' else 'utf-8', errors='replace', timeout=timeout)

    def _file_has_efs(self, path):
        try:
            attrs = _windows_file_attributes(path)
            return attrs != 0xFFFFFFFF and bool(attrs & FILE_ATTRIBUTE_ENCRYPTED)
        except Exception:
            return False

    def _verify_efs_tree(self, folder):
        failures = []
        if not self._file_has_efs(folder):
            failures.append(str(folder))
        for root, dirs, files in os.walk(folder, followlinks=False):
            for name in dirs + files:
                item = Path(root) / name
                attrs = _windows_file_attributes(item)
                if attrs == 0xFFFFFFFF:
                    failures.append(str(item))
                elif attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
                elif not attrs & FILE_ATTRIBUTE_ENCRYPTED:
                    failures.append(str(item))
                if len(failures) >= 20:
                    return failures
        return failures

    def _encrypt_and_verify_folder(self, folder):
        result = self._cipher_command(['/e', f'/s:{folder}', '/h', '/b'])
        if result.returncode != 0:
            return False, 'EFS برای همه محتویات کامل نشد؛ پوشه را فعلاً قفل نکردم تا خطر قفل‌شدن داده کاهش یابد.\n' + (result.stdout or '') + '\n' + (result.stderr or '')
        failures = self._verify_efs_tree(folder)
        if failures:
            return False, 'برخی محتویات هنوز EFS-encrypted نیستند؛ قفل اعمال نشد. مسیرهای نمونه:\n' + '\n'.join(failures[:10])
        return True, ''

    def _secure_acl_backup_directory(self):
        """Keep ACL recovery snapshots away from ordinary non-elevated processes."""
        PROTECTED_FOLDERS_DIR.mkdir(parents=True, exist_ok=True)
        if not self._is_admin():
            raise RuntimeError('برای نگه‌داری امن نسخه پشتیبان مجوزها، FaceGate باید با دسترسی مدیر اجرا شود.')
        exe = shutil.which('icacls.exe') or 'icacls.exe'
        reset = subprocess.run([exe, str(PROTECTED_FOLDERS_DIR), '/reset', '/t', '/c', '/q'],
                               capture_output=True, text=True, errors='replace', timeout=300)
        if reset.returncode != 0:
            raise RuntimeError('مجوزهای قدیمی پوشه پشتیبان بازنشانی نشدند؛ عملیات محافظت متوقف شد.\n' + (reset.stdout or '') + '\n' + (reset.stderr or ''))
        result = subprocess.run([exe, str(PROTECTED_FOLDERS_DIR), '/inheritance:r', '/grant:r',
                                 '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '/t', '/c', '/q'],
                                capture_output=True, text=True, errors='replace', timeout=300)
        if result.returncode != 0:
            raise RuntimeError('پوشه پشتیبان مجوزهای NTFS امن نشد. عملیات محافظت متوقف شد.\n' + (result.stdout or '') + '\n' + (result.stderr or ''))
        owner = subprocess.run([exe, str(PROTECTED_FOLDERS_DIR), '/setowner', '*S-1-5-18', '/t', '/c', '/q'],
                               capture_output=True, text=True, errors='replace', timeout=300)
        if owner.returncode != 0:
            raise RuntimeError('مالکیت پوشه پشتیبان مجوزها به SYSTEM منتقل نشد. عملیات محافظت متوقف شد.\n' + (owner.stdout or '') + '\n' + (owner.stderr or ''))

    def _save_folder_acl(self, folder, backup_path):
        """Back up all DACLs and original owners before applying any restrictions."""
        self._secure_acl_backup_directory()
        owner_manifest = backup_path.with_suffix(backup_path.suffix + '.owners.json')
        owner_tmp = owner_manifest.with_suffix(owner_manifest.suffix + '.pending')
        temp_backup = backup_path.with_suffix(backup_path.suffix + '.pending')
        owner_tmp.unlink(missing_ok=True)
        temp_backup.unlink(missing_ok=True)
        # icacls /save stores DACLs but not owners. Export relative paths and owners through PowerShell.
        powershell = shutil.which('powershell.exe') or 'powershell.exe'
        env = os.environ.copy()
        env['FG_OWNER_ROOT'] = str(folder)
        env['FG_OWNER_OUTPUT'] = str(owner_tmp)
        save_owner_script = r'''$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($env:FG_OWNER_ROOT)
$items = @((Get-Item -LiteralPath $root -Force)) + @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
$rows = foreach ($item in $items) {
  $relative = if ($item.FullName -ieq $root) { '' } else { $item.FullName.Substring($root.Length).TrimStart([char[]]@('\','/')) }
  [PSCustomObject]@{ RelativePath = $relative; Owner = (Get-Acl -LiteralPath $item.FullName).Owner }
}
[System.IO.File]::WriteAllText($env:FG_OWNER_OUTPUT, (ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress), ([System.Text.UTF8Encoding]::new($false)))
'''
        owner_result = subprocess.run([powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', save_owner_script],
                                      capture_output=True, text=True, encoding='utf-8', errors='replace', env=env, timeout=1800)
        if owner_result.returncode != 0 or not owner_tmp.exists() or owner_tmp.stat().st_size == 0:
            owner_tmp.unlink(missing_ok=True)
            raise RuntimeError('نسخه پشتیبان مالکیت فایل‌ها ساخته نشد؛ هیچ محدودیت دسترسی اعمال نشد.\n' + (owner_result.stdout or '') + '\n' + (owner_result.stderr or ''))
        try:
            import json
            owners = json.loads(owner_tmp.read_text(encoding='utf-8'))
            if not isinstance(owners, list) or not owners or not any(entry.get('RelativePath', '') == '' for entry in owners):
                raise ValueError('مالک ریشه پوشه در فهرست پشتیبان نیست.')
        except Exception as exc:
            owner_tmp.unlink(missing_ok=True)
            raise RuntimeError(f'اعتبارسنجی نسخه پشتیبان مالکیت ناموفق بود: {exc}')
        exe = shutil.which('icacls.exe') or 'icacls.exe'
        result = subprocess.run([exe, folder.name, '/save', str(temp_backup), '/t', '/c', '/q'],
                                cwd=str(folder.parent), capture_output=True, text=True, errors='replace', timeout=1800)
        if result.returncode != 0 or not temp_backup.exists() or temp_backup.stat().st_size == 0:
            temp_backup.unlink(missing_ok=True)
            owner_tmp.unlink(missing_ok=True)
            raise RuntimeError('پشتیبان مجوزهای NTFS ساخته نشد؛ هیچ محدودیت دسترسی اعمال نشد.\n' + (result.stdout or '') + '\n' + (result.stderr or ''))
        os.replace(temp_backup, backup_path)
        os.replace(owner_tmp, owner_manifest)
        return backup_path

    def _apply_locked_acl(self, folder):
        """Restrict access to SYSTEM and Administrators, and set SYSTEM ownership on the tree."""
        exe = shutil.which('icacls.exe') or 'icacls.exe'
        reset = subprocess.run([exe, str(folder), '/reset', '/t', '/c', '/q'],
                               capture_output=True, text=True, errors='replace', timeout=1800)
        if reset.returncode != 0:
            return False, 'بازنشانی اولیه مجوزهای NTFS کامل نشد؛ قفل اعمال نشد و باید وضعیت پوشه بررسی شود.\n' + (reset.stdout or '') + '\n' + (reset.stderr or '')
        result = subprocess.run([exe, str(folder), '/inheritance:r', '/grant:r',
                                 '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
                                 '/t', '/c', '/q'], capture_output=True, text=True, errors='replace', timeout=1800)
        if result.returncode != 0:
            return False, 'تنظیم مجوزهای محدود NTFS کامل نشد.\n' + (result.stdout or '') + '\n' + (result.stderr or '')
        owner = subprocess.run([exe, str(folder), '/setowner', '*S-1-5-18', '/t', '/c', '/q'],
                               capture_output=True, text=True, errors='replace', timeout=1800)
        if owner.returncode != 0:
            return False, 'محدودیت دسترسی اعمال شد اما انتقال مالکیت کامل نشد. بازیابی مجوزها را بررسی کن.\n' + (owner.stdout or '') + '\n' + (owner.stderr or '')
        return True, ''

    def _restore_folder_acl(self, folder, backup_path):
        backup = Path(backup_path)
        owner_manifest = backup.with_suffix(backup.suffix + '.owners.json')
        if not backup.is_file():
            return False, f'فایل پشتیبان مجوزها پیدا نشد؛ قفل را تغییر ندادم:\n{backup}'
        if not owner_manifest.is_file():
            return False, f'پشتیبان مالکیت فایل‌ها پیدا نشد؛ برای جلوگیری از تغییر ناقص مجوزها، بازیابی انجام نشد:\n{owner_manifest}'
        exe = shutil.which('icacls.exe') or 'icacls.exe'
        result = subprocess.run([exe, str(folder.parent), '/restore', str(backup), '/c', '/q'],
                                cwd=str(folder.parent), capture_output=True, text=True, errors='replace', timeout=1800)
        if result.returncode != 0:
            return False, 'بازیابی مجوزهای اصلی NTFS کامل نشد. پوشه را حذف نکن و خطا را نگه دار.\n' + (result.stdout or '') + '\n' + (result.stderr or '')
        powershell = shutil.which('powershell.exe') or 'powershell.exe'
        env = os.environ.copy()
        env['FG_OWNER_ROOT'] = str(folder)
        env['FG_OWNER_MANIFEST'] = str(owner_manifest)
        restore_owner_script = r'''$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($env:FG_OWNER_ROOT)
$rows = @(ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($env:FG_OWNER_MANIFEST, [System.Text.Encoding]::UTF8)))
foreach ($entry in $rows) {
  $target = if ([string]::IsNullOrEmpty([string]$entry.RelativePath)) { $root } else { Join-Path $root ([string]$entry.RelativePath) }
  if (!(Test-Path -LiteralPath $target)) { throw "A backed-up path no longer exists: $target" }
  $acl = Get-Acl -LiteralPath $target
  $acl.SetOwner([System.Security.Principal.NTAccount]::new([string]$entry.Owner))
  Set-Acl -LiteralPath $target -AclObject $acl
}
'''
        owners_result = subprocess.run([powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', restore_owner_script],
                                       capture_output=True, text=True, encoding='utf-8', errors='replace', env=env, timeout=7200)
        if owners_result.returncode != 0:
            return False, 'مجوزها بازیابی شدند، اما بازیابی مالکیت بعضی مسیرها کامل نشد؛ دسترسی‌ها را بررسی کن.\n' + (owners_result.stdout or '') + '\n' + (owners_result.stderr or '')
        return True, ''

    def _metadata_root(self):
        path = APP_DIR / 'FolderKeys'
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _backup_root(self):
        path = APP_DIR / 'FolderRecoveryBackups'
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _is_modern_folder_record(self, record):
        if not record:
            return False
        if inplace_crypto.read_manifest(record.get('backup', '')):
            return True
        folder = Path(record['path'])
        try:
            encrypted = inplace_crypto.list_encrypted_files(folder)
            if encrypted:
                header, _ = inplace_crypto.read_file_header(encrypted[0])
                mp = inplace_crypto.write_manifest(folder, self._metadata_root(), header['key_envelope'], '', 'locked' if record.get('locked') else 'unlocked')
                con = db()
                try:
                    con.execute('UPDATE protected_folders SET acl_backup_path=? WHERE path=?', (str(mp), record['path']))
                    con.commit()
                finally:
                    con.close()
                return True
        except Exception:
            pass
        return False

    def _run_folder_worker(self, task, callback, status_text):
        if self._folder_worker is not None and self._folder_worker.isRunning():
            QMessageBox.information(self, 'عملیات در حال انجام است', 'لطفاً تا پایان عملیات فعلی صبر کن.')
            return False
        self.status.setText(status_text)
        worker = FolderOperationWorker(task, self)
        self._folder_worker = worker
        self._folder_worker_callback = callback
        worker.result_ready.connect(lambda ok, result, w=worker: self._folder_worker_done(w, ok, result))
        worker.start()
        return True

    def _folder_worker_done(self, worker, ok, result):
        if self._folder_worker is not worker:
            return
        self._folder_worker = None
        callback = self._folder_worker_callback
        self._folder_worker_callback = None
        if callback:
            try:
                callback(ok, result)
            except Exception as exc:
                self.status.setText('یک خطا هنگام تکمیل عملیات پوشه رخ داد؛ گزارش خطا نمایش داده شد.')
                QMessageBox.critical(self, 'خطا هنگام تکمیل عملیات', f'{exc}\n\n{traceback.format_exc()}')
                try:
                    self.refresh_protected_folders()
                except Exception:
                    pass

    def _folder_error_text(self, result):
        if isinstance(result, dict):
            return str(result.get('error') or result)
        return str(result)

    def choose_and_protect_folder(self):
        # Read-only picker: even the picker's "New folder" action is disabled.
        picker = QFileDialog(self, 'انتخاب پوشهٔ موجود برای قفل', str(Path.home()))
        picker.setOption(QFileDialog.DontUseNativeDialog, True)
        picker.setFileMode(QFileDialog.Directory)
        picker.setOption(QFileDialog.ShowDirsOnly, True)
        picker.setOption(QFileDialog.ReadOnly, True)
        selected = picker.selectedFiles()[0] if picker.exec() == QDialog.Accepted and picker.selectedFiles() else None
        if selected:
            self.protect_folder_path(selected)

    def protect_folder_path(self, folder_path):
        if self._folder_action_busy():
            QMessageBox.information(self, 'عملیات در حال انجام است', 'ابتدا عملیات یا احراز هویت فعلی را تمام کن.')
            return False
        try:
            folder = self._validate_folder_target(folder_path)
        except Exception as exc:
            QMessageBox.warning(self, 'مسیر پوشه مجاز نیست', str(exc))
            return False
        existing = self._folder_record(folder)
        if existing and self._is_modern_folder_record(existing):
            QMessageBox.information(self, 'پوشه از قبل ثبت شده', 'این پوشه قبلاً در FaceGate ثبت شده است. برای پوشهٔ قفل‌شده از «بازکردن با چهره/PIN» و برای محتوای باز از «رمزگذاری مجدد» استفاده کن.')
            return False
        if existing and not self._is_modern_folder_record(existing):
            QMessageBox.warning(self, 'پوشه متعلق به نسخهٔ قدیمی است', 'این پوشه از سیستم قدیمی EFS/ACL ثبت شده است. ابتدا آن را از دکمه «بازیابی مجوزهای نسخهٔ قدیمی FaceGate» انتخاب و بازیابی کن؛ رمزگذاری جدید شروع نشد.')
            return False
        pin, ok = QInputDialog.getText(self, 'PIN پشتیبان پوشه', 'یک PIN دقیقاً ۸ رقمی برای بازیابی این پوشه تعیین کن:', QLineEdit.Password)
        if not ok:
            return False
        if not pin.isdigit() or len(pin) != 8:
            QMessageBox.warning(self, 'PIN نامعتبر', 'PIN باید دقیقاً ۸ رقم باشد.')
            return False
        second, ok = QInputDialog.getText(self, 'تأیید PIN', 'PIN را دوباره وارد کن:', QLineEdit.Password)
        if not ok:
            return False
        if pin != second:
            QMessageBox.warning(self, 'PIN یکسان نیست', 'دو PIN مطابقت ندارند؛ هیچ فایلی تغییر نکرد.')
            return False
        answer = QMessageBox.warning(self, 'رمزگذاری محتوا در محل اصلی',
            'FaceGate ابتدا یک نسخهٔ پشتیبان رمزگذاری‌شده در پوشهٔ دادهٔ خودش می‌سازد و آن را بررسی می‌کند. سپس محتوای هر فایل را در همان مسیر با AES-256-GCM رمزگذاری می‌کند؛ نام‌ها و پوشه‌بندی حفظ می‌شوند و فایل گاوصندوق کنار پوشه ساخته نمی‌شود.\n\n'
            'خود پوشه با مجوزهای ویندوز بسته می‌شود. هنگام اجرای FaceGate، قفل‌های اشتراک نیز کپی، تغییر نام و حذف را محدود می‌کنند. ابتدا برنامه‌های باز روی پوشه را ببند. مدیر سیستم یا توقف اجباری برنامه می‌تواند این محدودیت‌ها را دور بزند. ادامه می‌دهی؟',
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        if answer != QMessageBox.Yes:
            return False
        self._run_folder_worker(
            lambda: inplace_crypto.protect_folder_in_place(folder, pin, self._metadata_root(), self._backup_root()),
            lambda success, result: self._on_folder_protect_done(folder, success, result),
            f'در حال ساخت پشتیبان و رمزگذاری محتوا در همان پوشه: {folder}\nپوشه‌های بزرگ ممکن است چند دقیقه طول بکشند؛ پنجره پاسخ‌گو می‌ماند.')
        return True

    def _on_folder_protect_done(self, folder, success, result):
        if not success:
            self.status.setText('رمزگذاری پوشه کامل نشد؛ وضعیت فایل‌ها بررسی شود.')
            QMessageBox.critical(self, 'رمزگذاری پوشه کامل نشد', self._folder_error_text(result) + '\n\nپوشه را حذف نکن. نسخهٔ پشتیبان رمزگذاری‌شده در پوشهٔ بازیابی FaceGate ممکن است برای بازیابی موجود باشد.')
            self.refresh_protected_folders()
            return
        con = db()
        try:
            con.execute('INSERT INTO protected_folders(path, display_name, acl_backup_path, is_locked) VALUES(?,?,?,1) ON CONFLICT(path) DO UPDATE SET display_name=excluded.display_name, acl_backup_path=excluded.acl_backup_path, is_locked=1',
                        (str(folder), folder.name, result['manifest_path']))
            con.commit()
        except Exception as exc:
            QMessageBox.critical(self, 'خطای ثبت اطلاعات', f'محتوای فایل‌ها رمزگذاری شده است، اما ثبت مسیر در FaceGate کامل نشد. فایل‌ها را حذف نکن؛ از PIN استفاده کن.\n{exc}')
        finally:
            con.close()
        self.refresh_protected_folders()
        self.status.setText(f'محتوای {result["file_count"]} فایل در مسیر اصلی رمزگذاری شد.')
        QMessageBox.information(self, 'رمزگذاری انجام شد',
            f'خود پوشه قفل شد و محتوای {result["file_count"]} فایل نیز رمزگذاری شد. مسیر اصلی حفظ شد.\n\nنسخهٔ پشتیبان رمزگذاری‌شده: {result["backup_path"]}\n\nبرای خواندن فایل‌ها از «بازکردن با تشخیص چهره» یا «بازکردن با PIN» استفاده کن. در حالت باز، فایل‌ها خوانا هستند تا برنامه‌های ویندوز بتوانند آن‌ها را بخوانند؛ برای پایان کار «قفل مجدد پوشه» را بزن.')

    def open_selected_folder_with_face(self):
        record = self._selected_protected_folder()
        if not record:
            return
        if not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'نسخهٔ قدیمی پوشه', 'این پوشه از نسخهٔ قدیمی EFS/ACL است؛ ابتدا گزینهٔ بازیابی مجوزهای نسخهٔ قدیمی را اجرا کن.')
            return
        self._folder_open_from_shell = False
        self._start_folder_face_auth(record)

    def _folder_action_busy(self):
        return (self._folder_worker is not None or self._folder_prompt_active
                or self.mode in {'login', 'enroll'} or self._pending_app_unlock is not None)

    def _start_folder_face_auth(self, record):
        if self._folder_action_busy():
            self._restore_from_tray()
            return
        if not Path(record['path']).is_dir():
            QMessageBox.warning(self, 'پوشه پیدا نشد', f'پوشه موجود نیست: {record["path"]}')
            return
        meta = inplace_crypto.read_manifest(record['backup'])
        if not meta:
            QMessageBox.warning(self, 'اطلاعات پوشه در دسترس نیست', 'کلید پوشه پیدا نشد؛ هیچ قفلی برداشته نشد.')
            return
        if meta.get('state') not in {'locked', 'unlocked'}:
            QMessageBox.warning(self, 'بررسی پوشه لازم است', 'ابتدا وضعیت پوشه را بررسی و در صورت نیاز قفل مجدد کن؛ احراز هویت شروع نشد.')
            return
        # Do not enumerate a directory that our own ACL/handles intentionally block.
        self.set_workspace_mode('folders')
        self._restore_from_tray()
        self._pending_app_unlock = {'kind': 'folder_unlock', 'path': record['path'],
                                    'name': record['name'], 'backup': record['backup']}
        self._gate_active = True
        if self.face_template is None or self.recognizer is None:
            self._folder_face_failed('چهره ثبت نشده یا مدل تشخیص چهره در دسترس نیست.')
            return
        if not self.start_camera():
            self._folder_face_failed('دوربین در دسترس نیست.')
            return
        self.login_start = time.time()
        self.login_matches = 0
        self.login_last_label = None
        self.mode = 'login'
        # Deadline starts when the camera is ready, not while Windows opens it.
        self._folder_face_attempt = FolderFaceAttempt()
        self._folder_auth_timer.start(int(FOLDER_AUTH_SECONDS * 1000))
        self.status.setText(f'بررسی چهره برای «{record["name"]}» — حداکثر ۳ ثانیه')

    def _folder_face_failed(self, reason=''):
        pending = self._pending_app_unlock
        if not pending or pending.get('kind') != 'folder_unlock' or self._folder_prompt_active:
            return
        record = {'path': pending['path'], 'name': pending['name'], 'backup': pending['backup'], 'locked': True}
        self._pending_app_unlock = None
        self.mode = 'idle'
        self.login_matches = 0
        self.login_last_label = None
        self.stop_camera()
        self._folder_prompt_active = True
        self._folder_prompt_path = record['path']
        self.status.setText('تشخیص چهره ناموفق؛ این درخواست تأیید نشد و وضعیت قبلی پوشه تغییر نکرد.')
        box = QMessageBox(self)
        box.setWindowTitle('تشخیص چهره ناموفق')
        box.setText('تشخیص چهره ناموفق بود. مایل هستید مجدداً تلاش کنید یا PIN خود را وارد کنید؟')
        if reason:
            box.setInformativeText(str(reason))
        retry = box.addButton('تلاش مجدد', QMessageBox.AcceptRole)
        pin = box.addButton('ورود PIN', QMessageBox.ActionRole)
        box.addButton('انصراف', QMessageBox.RejectRole)
        box.setDefaultButton(retry)
        try:
            box.exec()
            clicked = box.clickedButton()
        finally:
            self._folder_prompt_active = False
            self._folder_prompt_path = None
            self._gate_active = False
        if clicked is retry:
            QTimer.singleShot(0, lambda: self._start_folder_face_auth(record))
        elif clicked is pin:
            self._open_folder_with_pin(record)
        else:
            self._folder_open_from_shell = False

    def _open_folder_in_explorer(self, path):
        try:
            explorer_integration.open_directory(path)
            if self._folder_open_from_shell:
                self.hide()
            self._folder_open_from_shell = False
        except Exception as exc:
            QMessageBox.warning(self, 'Explorer اجرا نشد', str(exc))

    def set_folder_pin(self):
        QMessageBox.information(self, 'PIN پوشه', 'PIN هشت‌رقمی هنگام رمزگذاری هر پوشه تنظیم می‌شود. برای تغییر آن، پوشه را با PIN فعلی باز کن و دوباره محافظت کن.')

    def open_selected_folder_with_pin(self):
        record = self._selected_protected_folder()
        if not record:
            return
        self._folder_open_from_shell = False
        self._open_folder_with_pin(record)

    def _open_folder_with_pin(self, record):
        if self._folder_worker is not None or self._folder_prompt_active or self.mode == 'enroll':
            QMessageBox.information(self, 'عملیات در حال انجام است', 'ابتدا عملیات فعلی را تمام کن.')
            return
        pending = self._pending_app_unlock
        if pending:
            if pending.get('kind') != 'folder_unlock' or pending['path'] != record['path']:
                QMessageBox.information(self, 'احراز هویت در حال انجام است', 'ابتدا احراز هویت فعلی را تمام یا لغو کن.')
                return
            from_shell = self._folder_open_from_shell
            self.cancel_action()
            self._folder_open_from_shell = from_shell
        if not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'نسخهٔ قدیمی پوشه', 'این پوشه از نسخهٔ قدیمی EFS/ACL است؛ ابتدا گزینهٔ بازیابی مجوزهای نسخهٔ قدیمی را اجرا کن.')
            return
        self._folder_prompt_active = True
        self._folder_prompt_path = record['path']
        self._gate_active = True
        try:
            pin, ok = QInputDialog.getText(self, 'بازکردن پوشه با PIN', f'PIN هشت‌رقمی برای «{record["name"]}» را وارد کن:', QLineEdit.Password)
        finally:
            self._folder_prompt_active = False
            self._folder_prompt_path = None
            self._gate_active = False
        if not ok:
            return
        if not pin.isdigit() or len(pin) != 8:
            QMessageBox.warning(self, 'PIN نامعتبر', 'PIN باید دقیقاً ۸ رقم باشد.')
            return
        folder = Path(record['path'])
        self._folder_unlocking_path = record['path']
        started = self._run_folder_worker(
            lambda: inplace_crypto.unlock_folder_in_place(folder, self._metadata_root(), pin=pin, manifest=record['backup']),
            lambda success, result: self._on_folder_unlock_done(record, success, result),
            f'در حال تأیید PIN و رمزگشایی فایل‌های «{record["name"]}»…')
        if not started:
            self._folder_unlocking_path = None

    def _finish_folder_unlock(self, pending):
        folder = Path(pending['path'])
        if not folder.is_dir():
            QMessageBox.warning(self, 'پوشه پیدا نشد', f'پوشه موجود نیست:\n{folder}')
            return False
        record = self._folder_record(folder)
        if not record or not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'پوشه ثبت نشده', 'اطلاعات رمزگذاری این پوشه پیدا نشد؛ هیچ فایلی تغییر نکرد.')
            return False
        self._folder_unlocking_path = record['path']
        started = self._run_folder_worker(
            lambda: inplace_crypto.unlock_folder_in_place(folder, self._metadata_root(), pin=None, manifest=record['backup']),
            lambda success, result: self._on_folder_unlock_done(record, success, result),
            f'چهره تأیید شد؛ در حال رمزگشایی «{folder.name}» در مسیر اصلی…')
        if not started:
            self._folder_unlocking_path = None
        return started

    def _on_folder_unlock_done(self, record, success, result):
        self._folder_unlocking_path = None
        folder = Path(record['path'])
        if not success:
            self.status.setText('بازکردن پوشه ناموفق بود؛ داده‌ها تا حد امکان به حالت قبلی برگشت داده شدند.')
            QMessageBox.critical(self, 'بازکردن پوشه انجام نشد', self._folder_error_text(result))
            self.refresh_protected_folders()
            return
        con = db()
        try:
            con.execute('UPDATE protected_folders SET is_locked=0 WHERE path=?', (record['path'],))
            con.commit()
        finally:
            con.close()
        self.refresh_protected_folders()
        self.status.setText(f'«{folder.name}» باز شد؛ بعد از پایان کار «قفل مجدد پوشه» را بزن.')
        self._open_folder_in_explorer(folder)

    def remove_selected_folder_protection(self):
        if self._folder_action_busy():
            QMessageBox.information(self, 'عملیات در حال انجام است', 'ابتدا عملیات یا احراز هویت فعلی را تمام کن.')
            return
        record = self._selected_protected_folder()
        if not record:
            return
        if not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'نسخهٔ قدیمی پوشه', 'ابتدا مجوزهای نسخهٔ قدیمی را با گزینهٔ بازیابی برگردان.')
            return
        self._folder_prompt_active = True
        self._folder_prompt_path = record['path']
        self._gate_active = True
        try:
            answer = QMessageBox.question(self, 'حذف از قفل',
                f'محافظت «{record["name"]}» برداشته شود؟ فایل‌ها رمزگشایی می‌شوند و مجوزهای پوشه برمی‌گردند. خود پوشه و فایل‌هایش حذف نمی‌شوند.',
                QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
            if answer != QMessageBox.Yes:
                return
            pin, ok = QInputDialog.getText(self, 'تأیید حذف از قفل', 'PIN هشت‌رقمی همین پوشه را وارد کن:', QLineEdit.Password)
        finally:
            self._folder_prompt_active = False
            self._folder_prompt_path = None
            self._gate_active = False
        if not ok:
            return
        if not pin.isdigit() or len(pin) != 8:
            QMessageBox.warning(self, 'PIN نامعتبر', 'PIN باید دقیقاً ۸ رقم باشد.')
            return

        def remove_protection():
            result = inplace_crypto.unprotect_folder_in_place(record['path'], self._metadata_root(), pin, manifest=record['backup'])
            # SQLite is touched only after decryption, ACL restoration and retirement.
            con = db()
            try:
                con.execute('DELETE FROM protected_folders WHERE path=?', (record['path'],))
                con.commit()
            finally:
                con.close()
            return result

        def complete(success, result):
            self.refresh_protected_folders()
            if not success:
                QMessageBox.critical(self, 'حذف از قفل کامل نشد', self._folder_error_text(result) + '\nپوشه را حذف نکن؛ اطلاعات بازیابی حفظ شده‌اند.')
                return
            self.status.setText(f'«{record["name"]}» از فهرست قفل حذف شد؛ پوشه و فایل‌هایش باقی ماندند.')
            QMessageBox.information(self, 'حذف از قفل انجام شد', 'پوشه به حالت عادی برگشت و دیگر به‌طور خودکار قفل نمی‌شود. فایل‌ها و پشتیبان بازیابی حذف نشده‌اند.')

        self._run_folder_worker(remove_protection, complete, f'در حال بررسی PIN و برداشتن محافظت «{record["name"]}»…')

    def lock_selected_folder(self):
        record = self._selected_protected_folder()
        if not record:
            return
        if not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'نسخهٔ قدیمی پوشه', 'این پوشه از نسخهٔ قدیمی EFS/ACL است؛ ابتدا گزینهٔ بازیابی مجوزهای نسخهٔ قدیمی را اجرا کن.')
            return
        self.lock_folder_path(record['path'])

    def lock_folder_path(self, folder_path):
        record = self._folder_record(folder_path)
        if not record:
            QMessageBox.warning(self, 'پوشه ثبت نشده', 'این مسیر در فهرست FaceGate وجود ندارد.')
            return False
        if not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'نسخهٔ قدیمی پوشه', 'این پوشه از نسخهٔ قدیمی EFS/ACL است؛ ابتدا آن را بازیابی کن.')
            return False
        if inplace_crypto.folder_gate_active(record['path']):
            QMessageBox.information(self, 'پوشه قفل است', 'قفل خود پوشه فعال است.')
            return True
        if record['locked'] and not inplace_crypto.folder_gate.saved(record['path'], record['backup']):
            try:
                encrypted_count = len(inplace_crypto.list_encrypted_files(record['path']))
                plain_count = len(inplace_crypto.walk_regular_files(record['path']))
            except Exception as exc:
                QMessageBox.critical(self, 'بررسی پوشه ناموفق بود', str(exc))
                return False
            # Ciphertext alone does not mean the directory itself is locked.
            # If files were replaced or an earlier operation was interrupted, repair the
            # mixed/plain state by encrypting remaining readable files instead of assuming locked.
        folder = Path(record['path'])
        self._run_folder_worker(
            lambda: inplace_crypto.lock_folder_in_place(folder, self._metadata_root(), pin=None, manifest=record['backup']),
            lambda success, result: self._on_folder_lock_done(record, success, result),
            f'در حال به‌روزرسانی نسخهٔ پشتیبان و رمزگذاری مجدد محتویات «{folder.name}»…')
        return True

    def _on_folder_lock_done(self, record, success, result):
        if not success:
            self.status.setText('رمزگذاری مجدد کامل نشد؛ پوشه را حذف نکن.')
            QMessageBox.critical(self, 'رمزگذاری مجدد کامل نشد', self._folder_error_text(result))
            self.refresh_protected_folders()
            return
        con = db()
        try:
            con.execute('UPDATE protected_folders SET is_locked=1 WHERE path=?', (record['path'],))
            con.commit()
        finally:
            con.close()
        self.refresh_protected_folders()
        warning = result.get('warning', '') if isinstance(result, dict) else ''
        message = f'محتوای {result.get("file_count", 0)} فایل دوباره رمزگذاری شد و در همان مسیر باقی مانده است.'
        if warning:
            message += '\n\nهشدار نسخهٔ پشتیبان:\n' + warning
        self.status.setText(f'محتوا رمزگذاری شد: {record["path"]}')
        QMessageBox.information(self, 'پوشه قفل شد', message)

    def restore_selected_folder_backup(self):
        record = self._selected_protected_folder()
        if not record:
            return
        manifest = inplace_crypto.read_manifest(record.get('backup', ''))
        backup_path = Path(manifest.get('backup_path', '')) if manifest and manifest.get('backup_path') else None
        if not backup_path or not backup_path.is_file():
            QMessageBox.warning(self, 'نسخهٔ پشتیبان موجود نیست',
                'نسخهٔ پشتیبان رمزگذاری‌شده پیدا نشد یا مسیر آن ثبت نشده است. هیچ فایلی تغییر نکرد.')
            return
        parent = QFileDialog.getExistingDirectory(self, 'محل قرارگیری پوشهٔ بازیابی‌شده', str(Path.home()))
        if not parent:
            return
        default_name = f"{Path(record['path']).name}_recovered"
        name, ok = QInputDialog.getText(self, 'نام پوشهٔ بازیابی',
            'یک نام جدید برای پوشهٔ بازیابی‌شده وارد کن؛ پوشهٔ موجود بازنویسی نمی‌شود:', QLineEdit.Normal, default_name)
        if not ok:
            return
        name = name.strip()
        if not name or name in {'.', '..'} or any(ch in name for ch in '<>:"/\\|?*'):
            QMessageBox.warning(self, 'نام نامعتبر', 'نام پوشه خالی است یا شامل نویسهٔ غیرمجاز ویندوز است.')
            return
        destination = Path(parent) / name
        if destination.exists():
            QMessageBox.warning(self, 'مسیر از قبل وجود دارد', f'برای جلوگیری از بازنویسی، بازیابی انجام نشد:\n{destination}')
            return
        pin, ok = QInputDialog.getText(self, 'PIN بازیابی', 'PIN هشت‌رقمی این پوشه را وارد کن:', QLineEdit.Password)
        if not ok:
            return
        if not pin.isdigit() or len(pin) != 8:
            QMessageBox.warning(self, 'PIN نامعتبر', 'PIN باید دقیقاً ۸ رقم باشد.')
            return
        def recover():
            from vault_crypto import extract_encrypted_vault
            return extract_encrypted_vault(backup_path, destination, pin=pin)
        def complete(success, result):
            if not success:
                QMessageBox.critical(self, 'بازیابی ناموفق', self._folder_error_text(result) + '\n\nپوشهٔ مقصد موجود نباید حذف یا بازنویسی شود؛ منبع پشتیبان دست‌نخورده باقی می‌ماند.')
                return
            QMessageBox.information(self, 'بازیابی انجام شد',
                f'نسخهٔ پشتیبان در یک پوشهٔ جدید بازیابی شد:\n{result}\n\nپوشهٔ اصلی و فایل پشتیبان دست‌نخورده باقی ماندند. پوشهٔ بازیابی‌شده هنوز محافظت‌شده نیست؛ برای محافظت مجدد آن را جداگانه به FaceGate معرفی کن.')
        self._run_folder_worker(recover, complete, f'در حال بررسی PIN و بازیابی نسخهٔ پشتیبان به مسیر جدید:\n{destination}')

    def recover_legacy_folder_permissions(self):
        record = self._selected_protected_folder()
        if not record:
            return
        if self._is_modern_folder_record(record):
            QMessageBox.information(self, 'بازیابی لازم نیست', 'این پوشه از روش جدید رمزگذاری درجا استفاده می‌کند.')
            return
        folder = Path(record['path'])
        backup = Path(record['backup'])
        owner_backup = backup.with_suffix(backup.suffix + '.owners.json')
        # Windows can raise PermissionError even for Path.is_file/stat when the
        # backup directory is owned by SYSTEM. Never let a stale legacy ACL
        # backup crash the GUI; report the inaccessible state and stop safely.
        try:
            backup_exists = backup.is_file()
            owner_backup_exists = owner_backup.is_file()
        except (OSError, PermissionError) as exc:
            QMessageBox.warning(
                self, 'پشتیبان در دسترس نیست',
                'ویندوز اجازهٔ بررسی فایل پشتیبان مجوزهای نسخهٔ قدیمی را نمی‌دهد. '
                'برای جلوگیری از آسیب بیشتر، هیچ مجوزی تغییر داده نشد.\n\n'
                f'مسیر: {backup}\nجزئیات: {exc}\n\n'
                'FaceGate را با دسترسی مدیر اجرا کن یا از حساب مدیر، مجوز پوشهٔ '
                'FolderAclBackups را بازیابی کن. تا آن زمان روی Continue کلیک نکن.'
            )
            return
        if not backup_exists or not owner_backup_exists:
            QMessageBox.critical(self, 'پشتیبان بازیابی پیدا نشد', f'فایل‌های پشتیبان مجوزهای نسخهٔ قدیمی پیدا نشدند. مجوزها را به‌صورت خودکار تغییر ندادم.\n\n{backup}')
            return
        answer = QMessageBox.warning(self, 'بازیابی مجوزهای نسخهٔ قدیمی',
            'این گزینه سعی می‌کند مجوزها و مالکیت ذخیره‌شده توسط نسخهٔ قبلی FaceGate را برگرداند. رمزگذاری EFS ویندوز حذف نمی‌شود. پس از بازیابی، می‌توانی پوشه را با روش جدید دوباره محافظت کنی. ادامه می‌دهی؟',
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        if answer != QMessageBox.Yes:
            return
        okay, error = self._restore_folder_acl(folder, backup)
        if not okay:
            QMessageBox.critical(self, 'بازیابی کامل نشد', error)
            return
        con = db()
        try:
            con.execute('DELETE FROM protected_folders WHERE path=?', (record['path'],))
            con.commit()
        finally:
            con.close()
        self.refresh_protected_folders()
        QMessageBox.information(self, 'بازیابی شد', 'مجوزهای ذخیره‌شدهٔ نسخهٔ قبلی بازیابی شدند. حالا می‌توانی همین پوشه را با رمزگذاری محتوای FaceGate دوباره محافظت کنی.')

    def _recover_folder_acl_state(self):
        # Restore live sharing locks after restart and recover interrupted encryption.
        # The root DACL persists across process exit; sharing handles do not.
        self._startup_relock_paths = []
        self._sync_orphaned_folder_manifests()
        con = db()
        try:
            rows = con.execute('SELECT path, acl_backup_path, is_locked FROM protected_folders').fetchall()
        finally:
            con.close()
        seen = set()
        for folder_path, metadata_path, is_locked in rows:
            manifest = inplace_crypto.read_manifest(metadata_path) if metadata_path else None
            if not manifest or manifest.get('state') == 'unprotected':
                continue
            if inplace_crypto.folder_gate_active(folder_path):
                continue
            folder = Path(folder_path)
            if not folder.is_dir():
                continue
            try:
                has_plain = bool(inplace_crypto.walk_regular_files(folder))
                has_encrypted = bool(inplace_crypto.list_encrypted_files(folder))
            except Exception:
                has_plain, has_encrypted = True, True
            if inplace_crypto.folder_gate.saved(folder_path, metadata_path) or (not bool(is_locked)) or manifest.get('state') != 'locked' or (has_plain and (has_encrypted or bool(is_locked))):
                key = str(folder.resolve()).casefold()
                if key not in seen:
                    self._startup_relock_paths.append((folder_path, metadata_path))
                    seen.add(key)

    def start_startup_recovery(self):
        if self._startup_relock_paths:
            self._relock_startup_next()

    def _relock_startup_next(self):
        if self._folder_worker is not None and self._folder_worker.isRunning():
            QTimer.singleShot(500, self._relock_startup_next)
            return
        if not self._startup_relock_paths:
            return
        folder_path, metadata_path = self._startup_relock_paths.pop(0)
        folder = Path(folder_path)
        record = self._folder_record(folder_path)
        if not record or not folder.is_dir():
            QTimer.singleShot(50, self._relock_startup_next)
            return
        self._run_folder_worker(
            lambda: inplace_crypto.lock_folder_in_place(folder, self._metadata_root(), manifest=metadata_path),
            lambda success, result: self._on_startup_relock_done(folder_path, success, result),
            'در حال بازیابی خودکار و رمزگذاری مجدد پوشه‌ای که از اجرای قبلی باز مانده بود…')

    def _on_startup_relock_done(self, folder_path, success, result):
        if success:
            con = db()
            try:
                con.execute('UPDATE protected_folders SET is_locked=1 WHERE path=?', (folder_path,))
                con.commit()
            finally:
                con.close()
        else:
            QMessageBox.warning(self, 'بازیابی خودکار پوشه کامل نشد', self._folder_error_text(result) + '\n\nپوشهٔ مربوطه را در بخش رمزگذاری فایل‌ها بررسی کن.')
        self.refresh_protected_folders()
        QTimer.singleShot(50, self._relock_startup_next)

    def _lock_all_protected_folders(self):
        # This helper is run in FolderOperationWorker; it does not touch GUI widgets.
        failures = []
        con = db()
        try:
            rows = con.execute('SELECT path, acl_backup_path, is_locked FROM protected_folders').fetchall()
        finally:
            con.close()
        for path, metadata_path, is_locked in rows:
            manifest = inplace_crypto.read_manifest(metadata_path) if metadata_path else None
            if not manifest or manifest.get('state') == 'unprotected':
                # Legacy EFS/ACL records require their existing explicit recovery flow.
                continue
            try:
                folder = Path(path)
                if inplace_crypto.folder_gate_active(path):
                    continue
                if folder.is_dir():
                    needs_lock = True  # Includes ciphertext-only folders needing a directory gate.
                    if needs_lock:
                        inplace_crypto.lock_folder_in_place(folder, self._metadata_root(), manifest=metadata_path)
                        con = db()
                        try:
                            con.execute('UPDATE protected_folders SET is_locked=1 WHERE path=?', (path,))
                            con.commit()
                        finally:
                            con.close()
            except Exception as exc:
                failures.append(f'{path}\n{exc}')
        return failures

    def backup_efs_key(self):
        # cipher /x invokes Microsoft's interactive EFS key export dialog in a console window.
        target, ok = QFileDialog.getSaveFileName(self, 'محل ذخیره کلید EFS (خارج از پوشه محافظت‌شده)',
                                                  str(Path.home() / f'FaceGate_EFS_{getpass.getuser()}'),
                                                  'EFS certificate backup prefix (*)')
        if not ok or not target:
            return
        prefix = Path(target)
        if prefix.suffix.lower() in ('.pfx', '.cer'):
            prefix = prefix.with_suffix('')
        if not prefix.parent.exists():
            QMessageBox.warning(self, 'محل نامعتبر', 'پوشه مقصد وجود ندارد.')
            return
        if any(str(prefix.resolve()).casefold().startswith(str(Path(p).resolve()).casefold()) for p in [APP_DIR]):
            QMessageBox.warning(self, 'محل ناامن', 'فایل کلید را داخل پوشه داده‌های FaceGate ذخیره نکن؛ یک USB یا محل امن جداگانه انتخاب کن.')
            return
        con = db()
        try:
            protected_paths = [row[0] for row in con.execute('SELECT path FROM protected_folders').fetchall()]
        finally:
            con.close()
        for protected_path in protected_paths:
            try:
                if Path(protected_path).resolve() in prefix.resolve().parents:
                    QMessageBox.warning(self, 'محل ناامن', 'فایل کلید EFS را داخل هیچ پوشه محافظت‌شده‌ای ذخیره نکن؛ یک USB یا پوشه امن دیگر انتخاب کن.')
                    return
            except OSError:
                pass
        if QMessageBox.question(self, 'پشتیبان‌گیری کلید EFS',
            'یک پنجره کنسول باز می‌شود. دستور رسمی cipher /x از گواهی و کلید خصوصی EFS پشتیبان می‌گیرد و ممکن است برای فایل خروجی رمز عبور بخواهد. فایل خروجی را روی USB یا محل امن جداگانه نگه دار. ادامه می‌دهی؟',
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Yes) != QMessageBox.Yes:
            return
        try:
            command = f'cipher /x "{prefix}"'
            subprocess.Popen(['cmd.exe', '/k', command], cwd=str(prefix.parent))
        except Exception as exc:
            QMessageBox.warning(self, 'اجرای پشتیبان‌گیری ناموفق', str(exc))

    def _folder_context_menu_command(self):
        script_path = str(Path(__file__).resolve())
        if getattr(sys, 'frozen', False):
            executable = str(Path(sys.executable).resolve())
            return f'"{executable}" --explorer-open "%1"'
        py = Path(sys.executable).resolve()
        pythonw = py.with_name('pythonw.exe')
        executable = pythonw if pythonw.exists() else py
        return f'"{executable}" "{script_path}" --explorer-open "%1"'

    def install_folder_context_menu(self):
        if os.name != 'nt':
            QMessageBox.warning(self, 'فقط ویندوز', 'این گزینه فقط در Windows Explorer قابل نصب است.')
            return
        try:
            explorer_integration.install(self._folder_context_menu_command(), str(Path(sys.executable).resolve()))
            QMessageBox.information(self, 'راست‌کلیک FaceGate اضافه شد',
                'گزینهٔ «بازکردن با FaceGate» به راست‌کلیک اضافه شد. بازکردن عادی و دابل‌کلیک پوشه‌ها به Explorer سپرده می‌شود و تنظیم پیش‌فرض آن تغییر نمی‌کند.')
        except Exception as exc:
            QMessageBox.warning(self, 'ثبت اتصال Explorer ناموفق', str(exc))

    def remove_folder_context_menu(self):
        if os.name != 'nt':
            return
        try:
            explorer_integration.uninstall()
            QMessageBox.information(self, 'بازکردن عادی Explorer برگشت', 'تنظیم قبلی بازگردانده شد. فایل‌ها و قفل پوشه‌ها تغییری نکردند.')
        except Exception as exc:
            QMessageBox.warning(self, 'بازگردانی Explorer ناموفق', str(exc))

    def _handle_instance_request(self, request):
        action = request['action']
        if action == 'show':
            self._restore_from_tray()
            return
        path = request['path']
        if self._folder_worker is not None and str(self._folder_unlocking_path).casefold() == str(path).casefold():
            self._restore_from_tray()
            return
        if self._folder_prompt_active and str(self._folder_prompt_path).casefold() == str(path).casefold():
            self._restore_from_tray()
            return
        pending = self._pending_app_unlock
        if (pending and pending.get('kind') == 'folder_unlock'
                and str(pending['path']).casefold() == str(path).casefold()):
            self._restore_from_tray()
            return  # Repeated double-clicks must not extend the three-second deadline.
        if self._folder_action_busy() or self._startup_relock_paths:
            if request not in self._queued_shell_requests and len(self._queued_shell_requests) < 8:
                self._queued_shell_requests.append(request)
            self._instance_request_timer.start(300)
            return
        self.set_workspace_mode('folders')
        self._restore_from_tray()
        if action in {'protect', 'lock'} and not self._require_management_password('تأیید عملیات پوشه'):
            return
        self._folder_open_from_shell = action in {'open-face', 'open-pin'}
        self._dispatch_folder_cli_action(action, path)

    def _drain_instance_requests(self):
        if self._queued_shell_requests:
            self._handle_instance_request(self._queued_shell_requests.pop(0))
        if self._queued_shell_requests:
            self._instance_request_timer.start(300)

    def _dispatch_folder_cli_action(self, action, folder_path):
        if not folder_path or action not in {'protect', 'open-face', 'open-pin', 'lock'}:
            return
        if action == 'protect':
            self.protect_folder_path(folder_path)
        elif action == 'lock':
            self.lock_folder_path(folder_path)
        else:
            record = self._folder_record(folder_path)
            if not record:
                # A queued request may arrive just after the user removed protection.
                if self._folder_open_from_shell and Path(folder_path).is_dir():
                    self._open_folder_in_explorer(folder_path)
                else:
                    QMessageBox.warning(self, 'پوشه ثبت نشده', 'این پوشه در فهرست قفل نیست.')
                return
            self.protected_folder_list.setCurrentRow(next((i for i in range(self.protected_folder_list.count()) if str(self.protected_folder_list.item(i).data(Qt.UserRole)).casefold() == str(folder_path).casefold()), -1))
            if action == 'open-face':
                self._start_folder_face_auth(record)
            else:
                self._open_folder_with_pin(record)

    def _startup_command(self):
        """Build a quoted command for the current EXE or Python script."""
        if getattr(sys, 'frozen', False):
            return f'"{Path(sys.executable).resolve()}" --autostart'
        return f'"{Path(sys.executable).resolve()}" "{Path(__file__).resolve()}" --autostart'

    def _startup_is_enabled(self):
        if os.name != 'nt':
            return False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, 'FaceGate')
            return value == self._startup_command()
        except (OSError, ImportError):
            return False

    def toggle_startup_registration(self):
        """Opt-in, visible per-user startup registration; no stealth persistence."""
        if os.name != 'nt':
            QMessageBox.information(self, 'شروع با ویندوز', 'این گزینه فقط در ویندوز قابل استفاده است.')
            return
        try:
            import winreg
            run_key = r'Software\Microsoft\Windows\CurrentVersion\Run'
            if self._startup_is_enabled():
                with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ) as key:
                    try: winreg.DeleteValue(key, 'FaceGate')
                    except FileNotFoundError: pass
                # Remove the optional scheduled task too.
                subprocess.run(['schtasks', '/Delete', '/TN', 'FaceGateAutoStart', '/F'], capture_output=True, text=True, timeout=10)
                QMessageBox.information(self, 'شروع با ویندوز', 'اجرای خودکار FaceGate غیرفعال شد.')
            else:
                command = self._startup_command()
                with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ) as key:
                    winreg.SetValueEx(key, 'FaceGate', 0, winreg.REG_SZ, command)
                # Task Scheduler logon trigger avoids relying only on the delayed Run-key startup path.
                # The task runs as the current user at normal privilege, not hidden or elevated.
                task = subprocess.run(['schtasks', '/Create', '/SC', 'ONLOGON', '/TN', 'FaceGateAutoStart', '/TR', command, '/F', '/RL', 'LIMITED'], capture_output=True, text=True, timeout=15)
                if task.returncode != 0:
                    QMessageBox.warning(self, 'شروع با ویندوز', 'ثبت اجرای خودکار انجام شد، اما زمان‌بند ویندوز فعال نشد؛ ممکن است شروع با تأخیر باشد.\n' + (task.stderr or task.stdout or ''))
                else:
                    QMessageBox.information(self, 'شروع با ویندوز', 'FaceGate هنگام ورود به حساب ویندوز بدون درخواست رمز شروع می‌شود. زمان‌بند ورود هم فعال شد. توجه: این برنامه قفل امنیتیِ سطح ویندوز نیست و تا وقتی واقعاً اجرا نشده، مانع اجرای برنامه‌ها نمی‌شود.')
        except Exception as exc:
            QMessageBox.warning(self, 'خطای شروع با ویندوز', f'ثبت تنظیم شروع خودکار انجام نشد:\n{exc}')

    def _setup_tray(self):
        self._allow_real_exit = False
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(QApplication.style().standardIcon(QStyle.SP_ComputerIcon), self)
        self.tray.setToolTip('FaceGate — محافظت فعال تا زمانی که برنامه در حال اجراست')
        menu = QMenu()
        show_action = QAction('باز کردن FaceGate', self)
        show_action.triggered.connect(self._restore_from_tray)
        menu.addAction(show_action)
        startup_action = QAction('شروع خودکار با ویندوز', self)
        startup_action.setCheckable(True)
        startup_action.setChecked(self._startup_is_enabled())
        startup_action.triggered.connect(self.toggle_startup_registration)
        menu.addAction(startup_action)
        menu.addSeparator()
        exit_action = QAction('خروج کامل (محافظت متوقف می‌شود)', self)
        exit_action.triggered.connect(self._exit_application)
        menu.addAction(exit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self._restore_from_tray() if reason == QSystemTrayIcon.DoubleClick else None)
        self.tray.show()

    def _restore_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _exit_application(self):
        if not self._require_management_password('تأیید خروج کامل'):
            return
        answer = QMessageBox.warning(self, 'خروج کامل از FaceGate',
            'با خروج کامل، پایش برنامه‌ها متوقف می‌شود. پیش از خروج، FaceGate تلاش می‌کند محتوای تمام پوشه‌های باز را دوباره رمزگذاری کند. ممکن است چند دقیقه طول بکشد. خارج می‌شوی؟',
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel)
        if answer != QMessageBox.Yes:
            return
        self._run_folder_worker(self._lock_all_protected_folders, self._finish_exit_after_lock,
                                'در حال رمزگذاری مجدد همهٔ پوشه‌های باز پیش از خروج کامل…')

    def _finish_exit_after_lock(self, success, result):
        if not success:
            QMessageBox.critical(self, 'خروج ایمن انجام نشد', self._folder_error_text(result))
            return
        failures = result or []
        if failures:
            QMessageBox.critical(self, 'خروج ایمن انجام نشد', 'FaceGate نتوانست همهٔ پوشه‌های باز را رمزگذاری کند؛ برنامه برای جلوگیری از باقی‌ماندن فایل خوانا بسته نمی‌شود.\n\n' + '\n\n'.join(failures))
            return
        self._allow_real_exit = True
        if self.tray:
            self.tray.hide()
        self.stop_camera()
        self.app_lock_timer.stop()
        self.close()
        QApplication.quit()

    def set_backup_password(self):
        first, ok = QInputDialog.getText(self, 'رمز پشتیبان', 'رمز پشتیبان جدید را وارد کنید (حداقل 8 نویسه):', QLineEdit.Password)
        if not ok:
            return
        if len(first) < 8:
            QMessageBox.warning(self, 'رمز ضعیف', 'رمز پشتیبان باید حداقل ۸ نویسه داشته باشد.')
            return
        second, ok = QInputDialog.getText(self, 'تأیید رمز', 'رمز را دوباره وارد کنید:', QLineEdit.Password)
        if not ok:
            return
        if first != second:
            QMessageBox.warning(self, 'عدم تطبیق', 'دو رمز یکسان نیستند.')
            return
        con = db()
        con.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                    ('backup_password_hash', hash_password(first)))
        con.commit(); con.close()
        QMessageBox.information(self, 'رمز پشتیبان', 'رمز پشتیبان ذخیره شد. آن را در جای امن نگه دار.')

    def use_backup_password(self):
        pending = self._pending_app_unlock
        if pending and pending.get('kind') == 'folder_unlock':
            self._open_folder_with_pin({'path': pending['path'], 'name': pending['name'],
                                        'backup': pending['backup'], 'locked': True})
            return
        con = db()
        row = con.execute('SELECT value FROM app_settings WHERE key=?', ('backup_password_hash',)).fetchone()
        con.close()
        if not row:
            QMessageBox.warning(self, 'رمز پشتیبان تنظیم نشده', 'ابتدا «تنظیم / تغییر رمز پشتیبان» را انتخاب کن.')
            return
        password, ok = QInputDialog.getText(self, 'تأیید با رمز پشتیبان', 'رمز پشتیبان را وارد کن:', QLineEdit.Password)
        if not ok:
            return
        if not verify_password(password, row[0]):
            QMessageBox.warning(self, 'رمز اشتباه', 'رمز پشتیبان نادرست است؛ برنامهٔ محافظت‌شده قفل می‌ماند.')
            return
        pending = self._pending_app_unlock
        if not pending:
            QMessageBox.information(self, 'رمز تأیید شد', 'رمز درست است؛ این گزینه برای بازکردن برنامهٔ در انتظار احراز هویت است.')
            return
        self._pending_app_unlock = None
        self.mode = 'idle'
        self.stop_camera()
        if pending.get('kind') == 'folder_unlock':
            self._finish_folder_unlock(pending)
        else:
            self._launch_pending_app(pending)

    def _launch_pending_app(self, pending):
        key = pending['key']
        try:
            # Face auth grants one session for this app path; switching/minimizing or
            # creating documents won't re-prompt while any instance of the app is alive.
            normalized_exe = str(Path(pending['exe']).resolve()).lower()
            self._authorized_app_sessions.add(normalized_exe)
            self._authorized_app_sessions.add(Path(normalized_exe).name.casefold())
            now = time.time()
            self._authorized_session_last_seen[normalized_exe] = now
            self._authorized_session_last_seen[Path(normalized_exe).name.casefold()] = now
            # If a protected app window was already open, restore it only after auth.
            hwnd = int(pending.get('hwnd') or 0)
            if hwnd and os.name == 'nt' and ctypes.windll.user32.IsWindow(hwnd):
                ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                ctypes.windll.user32.SetForegroundWindow(hwnd)
            else:
                child = subprocess.Popen(pending['command'], cwd=str(Path(pending['exe']).parent), close_fds=True)
                self._authorized_launches[key] = time.time() + 3
                self._allow_next_foreground[key] = time.time() + 3
            # Release the webcam immediately. Keep only the background monitor alive,
            # so the next protected-app launch can trigger a fresh authentication.
            self.stop_camera()
            self.mode = 'idle'
            self._pending_app_unlock = None
            self._gate_active = False
            self.status.setText(f'احراز هویت موفق؛ «{pending["name"]}» باز شد. دوربین خاموش شد.')
            self.hide()
        except Exception as launch_error:
            self.status.setText(f'احراز هویت موفق بود، اما اجرای برنامه ناموفق بود: {launch_error}')
            self.stop_camera()

    def load_locked_apps(self):
        if not hasattr(self, 'app_list'):
            return
        self.app_list.clear()
        con = db()
        rows = sorted(con.execute('SELECT path, display_name, enabled FROM locked_apps').fetchall(), key=lambda row: row[1].casefold())
        con.close()
        icon_provider = QFileIconProvider()
        for path, name, enabled in rows:
            item = QListWidgetItem(('🔒  ' if enabled else '○  ') + name)
            item.setData(Qt.UserRole, path)  # internal only; never displayed
            try:
                item.setIcon(icon_provider.icon(QFileInfo(path)))
            except Exception:
                pass
            self.app_list.addItem(item)

    def _discover_installed_apps(self):
        """Return installed desktop apps from Windows uninstall registry entries."""
        found = {}
        if os.name != 'nt':
            return found
        try:
            import winreg
            roots = [
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'),
                (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
            ]
            for hive, subkey in roots:
                try: parent = winreg.OpenKey(hive, subkey)
                except OSError: continue
                with parent:
                    for i in range(winreg.QueryInfoKey(parent)[0]):
                        try:
                            child_name = winreg.EnumKey(parent, i)
                            with winreg.OpenKey(parent, child_name) as child:
                                vals = {}
                                for name in ('DisplayName','DisplayIcon','InstallLocation','UninstallString'):
                                    try: vals[name] = winreg.QueryValueEx(child, name)[0]
                                    except OSError: pass
                            display = str(vals.get('DisplayName','')).strip()
                            icon = str(vals.get('DisplayIcon','')).strip().strip('"')
                            if ',' in icon and icon.rsplit(',',1)[-1].strip('-').isdigit(): icon = icon.rsplit(',',1)[0].strip('"')
                            candidate = Path(os.path.expandvars(icon)) if icon else None
                            if candidate and candidate.is_file() and candidate.suffix.lower()=='.exe' and display:
                                found[str(candidate.resolve()).lower()] = (display, str(candidate.resolve()))
                        except (OSError, ValueError): continue
        except Exception:
            pass
        # Resolve Start Menu shortcuts (.lnk) through Windows Script Host so apps
        # such as Edge/Chrome appear even when the shortcut itself is not an EXE.
        if os.name == 'nt':
            try:
                roots = [Path(os.getenv('APPDATA',''))/'Microsoft/Windows/Start Menu',
                         Path(os.getenv('PROGRAMDATA',''))/'Microsoft/Windows/Start Menu',
                         Path(os.getenv('USERPROFILE',''))/'Desktop',
                         Path(os.getenv('PUBLIC',r'C:\\Users\\Public'))/'Desktop']
                ps = r'''$ErrorActionPreference='SilentlyContinue'; $w=New-Object -ComObject WScript.Shell; Get-ChildItem -LiteralPath $env:FACEGATE_SCAN_ROOT -Filter *.lnk -Recurse -Force | ForEach-Object { $s=$w.CreateShortcut($_.FullName); if ($s.TargetPath) { [PSCustomObject]@{Name=$_.BaseName;Target=$s.TargetPath} } } | ConvertTo-Json -Compress'''
                import json
                for root in roots:
                    if not root.exists(): continue
                    env = os.environ.copy()
                    env['FACEGATE_SCAN_ROOT'] = str(root)
                    run = subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',ps],
                                         env=env, capture_output=True, text=True, timeout=30, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                    if run.returncode == 0 and run.stdout.strip():
                        data = json.loads(run.stdout)
                        if isinstance(data, dict): data = [data]
                        for entry in data:
                            target = str(Path(entry.get('Target','')).resolve())
                            if target.lower().endswith('.exe') and Path(target).is_file():
                                found[target.lower()] = (entry.get('Name') or Path(target).stem, target)
            except Exception:
                pass
        # Also include common app executables from Start Menu's Programs folder.
        try:
            roots = [Path(os.getenv('APPDATA',''))/'Microsoft/Windows/Start Menu', Path(os.getenv('PROGRAMDATA',''))/'Microsoft/Windows/Start Menu', Path(os.getenv('USERPROFILE',''))/'Desktop', Path(os.getenv('PUBLIC',r'C:\\Users\\Public'))/'Desktop']
            for root in roots:
                if not root.exists(): continue
                for exe in root.rglob('*.exe'):
                    if exe.is_file(): found.setdefault(str(exe.resolve()).lower(), (exe.stem, str(exe.resolve())))
        except Exception: pass
        return found

    def add_locked_app(self):
        if not self._require_management_password('تأیید افزودن برنامه محافظت‌شده'): return
        apps = self._discover_installed_apps()
        dialog = QDialog(self); dialog.setWindowTitle('انتخاب برنامه‌ها — شبیه منوی Start'); dialog.resize(650, 650)
        layout = QVBoxLayout(dialog)
        hint = QLabel('برنامه‌ها را بر اساس نام پیدا کن و انتخاب کن. فقط نام و نماد نمایش داده می‌شود؛ مسیرها پنهان هستند.'); hint.setWordWrap(True); layout.addWidget(hint)
        search = QLineEdit(); search.setPlaceholderText('جست‌وجوی برنامه‌ها…'); layout.addWidget(search)
        listing = QListWidget(); listing.setSelectionMode(QAbstractItemView.ExtendedSelection); listing.setIconSize(QSize(32, 32)); listing.setSpacing(3)
        listing.setStyleSheet('QListWidget {background:#f7f7f7;color:#171717;border:0;border-radius:10px;padding:8px;} QListWidget::item {padding:10px 8px; min-height:34px;} QListWidget::item:selected {background:#dceafe;color:#111;} QListWidget::item:hover {background:#eaeaea;}')
        layout.addWidget(listing, 1)
        items = sorted(apps.values(), key=lambda x: x[0].casefold())
        icon_provider = QFileIconProvider()
        for name, path in items:
            item = QListWidgetItem(name); item.setData(Qt.UserRole, path); item.setData(Qt.UserRole + 1, name)
            try: item.setIcon(icon_provider.icon(QFileInfo(path)))
            except Exception: pass
            listing.addItem(item)
        def filter_items(text):
            needle = text.casefold().strip()
            for i in range(listing.count()):
                item = listing.item(i); item.setHidden(needle not in item.text().casefold())
        search.textChanged.connect(filter_items)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText('تأیید انتخاب')
        buttons.button(QDialogButtonBox.Cancel).setText('لغو')
        buttons.accepted.connect(dialog.accept); buttons.rejected.connect(dialog.reject); layout.addWidget(buttons)
        if not items:
            QMessageBox.information(self, 'برنامه‌ها پیدا نشدند', 'از فهرست فایل‌های EXE استفاده کنید.');
            paths, _ = QFileDialog.getOpenFileNames(self, 'انتخاب چند فایل اجرایی', str(Path.home()), 'برنامه‌های ویندوز (*.exe)')
        else:
            if dialog.exec() != QDialog.Accepted: return
            paths = [listing.item(i).data(Qt.UserRole) for i in range(listing.count()) if listing.item(i).isSelected()]
            if not paths: return
        con = db()
        try:
            if items:
                selected = [(listing.item(i).data(Qt.UserRole), listing.item(i).data(Qt.UserRole + 1)) for i in range(listing.count()) if listing.item(i).isSelected()]
            else:
                selected = [(path, Path(path).stem) for path in paths]
            for path, name in selected:
                path = str(Path(path).resolve())
                con.execute('INSERT INTO locked_apps(path, display_name, enabled) VALUES(?,?,1) ON CONFLICT(path) DO UPDATE SET display_name=excluded.display_name, enabled=1', (path, name or Path(path).stem))
            con.commit()
        finally: con.close()
        self.load_locked_apps()
        self.status.setText(f'{len(paths)} برنامه به فهرست محافظت اضافه شد.')

    def add_locked_app_by_path(self):
        """Manually choose one or more EXE paths when Start-menu discovery misses an app."""
        if not self._require_management_password('تأیید افزودن برنامه محافظت‌شده'): return
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            'انتخاب فایل اجرایی برنامه(ها)',
            str(Path.home()),
            'فایل‌های اجرایی ویندوز (*.exe);;همه فایل‌ها (*.*)'
        )
        if not paths:
            return
        added = 0
        con = db()
        try:
            for raw_path in paths:
                try:
                    exe_path = Path(raw_path).expanduser().resolve()
                    if not exe_path.is_file() or exe_path.suffix.lower() != '.exe':
                        continue
                    # Use the executable filename as the default display name; keep the full
                    # canonical path as the identity used by the monitor.
                    con.execute(
                        'INSERT INTO locked_apps(path, display_name, enabled) VALUES(?,?,1) '
                        'ON CONFLICT(path) DO UPDATE SET display_name=excluded.display_name, enabled=1',
                        (str(exe_path), exe_path.stem)
                    )
                    added += 1
                except (OSError, ValueError):
                    continue
            con.commit()
        finally:
            con.close()
        self.load_locked_apps()
        if added:
            self.status.setText(f'{added} فایل اجرایی به فهرست محافظت اضافه شد.')
            QMessageBox.information(self, 'فهرست محافظت', f'{added} برنامه اضافه شد. برای اعمال پایش، FaceGate باید در حال اجرا باشد.')
        else:
            QMessageBox.warning(self, 'فایل اجرایی نامعتبر', 'فایل EXE معتبری انتخاب نشد.')

    def remove_locked_app(self):
        if not self._require_management_password('تأیید حذف برنامه محافظت‌شده'): return
        items = self.app_list.selectedItems() if hasattr(self, 'app_list') else []
        if not items:
            QMessageBox.information(self, 'قفل برنامه‌ها', 'ابتدا یک یا چند برنامه از فهرست انتخاب کنید.')
            return
        con = db()
        try:
            for item in items:
                path = item.data(Qt.UserRole)
                con.execute('DELETE FROM locked_apps WHERE path=?', (path,))
                self._app_unlock_until.pop(path.lower(), None)
                self._authorized_app_sessions.discard(path.lower())
            con.commit()
        finally: con.close()
        self.load_locked_apps()

    @staticmethod
    def _foreground_process_path():
        """Return (window handle, executable path) for the foreground Windows process."""
        if os.name != 'nt':
            return 0, None
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            user32.GetForegroundWindow.restype = wintypes.HWND
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return 0, None
            pid = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not pid.value:
                return int(hwnd), None
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
            if not handle:
                return int(hwnd), None
            try:
                size = wintypes.DWORD(32768)
                buffer = ctypes.create_unicode_buffer(size.value)
                if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                    return int(hwnd), str(Path(buffer.value).resolve())
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            pass
        return 0, None

    def check_locked_foreground_app(self):
        """Best-effort gate for new processes and foreground re-activations."""
        if self._gate_active or self._folder_worker is not None or self._folder_prompt_active:
            return
        con = db()
        rows = con.execute('SELECT path, display_name FROM locked_apps WHERE enabled=1').fetchall()
        con.close()
        locked = {str(Path(p).resolve()).lower(): n for p, n in rows}
        locked_by_basename = {Path(p).name.casefold(): (str(Path(p).resolve()).lower(), n) for p, n in rows}
        if not locked:
            self._last_foreground_key = None
            try:
                for proc in psutil.process_iter(['pid', 'create_time']):
                    try: self._known_processes.add((proc.info['pid'], proc.info.get('create_time')))
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            except Exception: pass
            return

        # Foreground changes (minimize/restore, switching windows, creating a document)
        # must NOT request face auth again. Only newly launched app sessions are gated.
        hwnd, fg_exe = self._foreground_process_path()
        fg_key = str(Path(fg_exe).resolve()).lower() if fg_exe else None
        if self.mode == 'login' and fg_key in locked and hwnd and os.name == 'nt':
            try:
                ctypes.windll.user32.ShowWindow(int(hwnd), 6)
                self.showNormal(); self.raise_(); self.activateWindow()
            except Exception: pass
            return

        # An authorized path remains authorized while at least one process for it is alive.
        live_locked_paths = set()
        live_locked_basenames = set()
        try:
            for proc in psutil.process_iter(['exe']):
                try:
                    exe = proc.info.get('exe')
                    if exe:
                        k = str(Path(exe).resolve()).lower()
                        if k in locked or Path(k).name.casefold() in locked_by_basename:
                            live_locked_paths.add(k)
                            live_locked_basenames.add(Path(k).name.casefold())
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError): pass
        except Exception: pass
        # Keep authorization for the entire app session. Newly spawned helper processes can
        # appear a moment after the parent launch, so don't revoke it just because the first
        # process scan briefly sees no matching executable. Clear it only after the app has
        # been absent for a short grace period.
        now = time.time()
        live_authorized_keys = live_locked_paths | live_locked_basenames
        for auth_key in list(self._authorized_app_sessions):
            if auth_key in live_authorized_keys:
                self._authorized_session_last_seen[auth_key] = now
            elif now - self._authorized_session_last_seen.get(auth_key, now) > 5.0:
                self._authorized_app_sessions.discard(auth_key)
                self._authorized_session_last_seen.pop(auth_key, None)

        # Detect newly created processes, stop them before requesting authentication.
        now = time.time()
        for proc in psutil.process_iter(['pid', 'exe', 'cmdline', 'create_time']):
            try:
                info = proc.info
                identity = (info.get('pid'), info.get('create_time'))
                if identity in self._known_processes:
                    continue
                self._known_processes.add(identity)
                exe = info.get('exe')
                if not exe:
                    continue
                key = str(Path(exe).resolve()).lower()
                base_key = Path(key).name.casefold()
                if key in self._authorized_app_sessions or base_key in self._authorized_app_sessions:
                    continue
                if self._authorized_launches.get(key, 0) > now:
                    self._authorized_launches.pop(key, None)
                    continue
                matched_key = key if key in locked else (locked_by_basename.get(base_key, (None, None))[0])
                if matched_key is None:
                    continue
                display_for_lock = locked.get(matched_key, locked_by_basename.get(base_key, (None, Path(key).stem))[1])
                own_path = str(Path(sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]).resolve()).lower()
                if key == own_path:
                    continue
                command = info.get('cmdline') or [exe]
                try:
                    proc.terminate()
                    try: proc.wait(timeout=0.8)
                    except psutil.TimeoutExpired: proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                    self.status.setText(f'نتوانستم فرایند {display_for_lock} را متوقف کنم؛ مجوز تأیید نشد.')
                    continue
                if self.mode in ('enroll', 'training'):
                    self.status.setText(f'«{display_for_lock}» هنگام ثبت چهره متوقف شد؛ پس از پایان ثبت دوباره اجرا و احراز هویت کنید.')
                    return
                self._begin_app_gate(matched_key, display_for_lock, command=command, exe=exe, existing=False)
                return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

    def _begin_app_gate(self, key, display_name, hwnd=0, command=None, exe=None, existing=False):
        if self.mode in ('enroll', 'login', 'training'):
            return
        if existing and hwnd and os.name == 'nt':
            try: ctypes.windll.user32.ShowWindow(int(hwnd), 6)  # SW_MINIMIZE
            except Exception: pass
        self._gate_active = True
        try:
            self.showNormal(); self.raise_(); self.activateWindow()
            self._pending_app_unlock = {'key': key, 'name': display_name,
                'command': command or [exe], 'exe': exe or key,
                'hwnd': int(hwnd or 0) if existing else 0}
            con = db()
            row = con.execute('SELECT id FROM users ORDER BY id LIMIT 1').fetchone()
            con.close()
            if not row or not self.face_templates and (not TEMPLATE_PATH.exists() or self.face_template is None):
                self.status.setText(f'مجوز «{display_name}» داده نشد؛ ابتدا چهره را ثبت کنید.')
                QMessageBox.warning(self, 'مجوز اجرا داده نشد', f'«{display_name}» قفل ماند. ابتدا چهره را در FaceGate ثبت کنید.')
                self.stop_camera()
                self._pending_app_unlock = None
                return
            self.login_user_id = int(row[0])
            if not self.start_camera():
                self.status.setText(f'وب‌کم در دسترس نیست؛ «{display_name}» قفل ماند.')
                QMessageBox.warning(self, 'وب‌کم در دسترس نیست', f'برای باز کردن «{display_name}» دوربین لازم است. برنامه قفل ماند.')
                self._pending_app_unlock = None
                self.mode = 'idle'
                return
            self.login_start = time.time()
            self.login_matches = 0
            self.login_last_label = None
            self.mode = 'login'
            self.status.setText(f'مجوز «{display_name}» هنوز داده نشده؛ چهره را روبه‌روی دوربین نگه دارید…')
        finally:
            self._gate_active = False

    def start_camera(self):
        """Open the webcam only for an explicit authentication/enrollment session."""
        if self.cap is not None and self.cap.isOpened():
            if not self.timer.isActive():
                self.timer.start(33)
            return True
        try:
            self.cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
            if not self.cap.isOpened():
                self.cap.release()
                self.cap = cv2.VideoCapture(0)
        except Exception:
            self.cap = None
        if self.cap is not None and self.cap.isOpened():
            self.timer.start(33)
            self.status.setText('دوربین فقط برای احراز هویت فعال است • پردازش محلی')
            return True
        if self.cap is not None:
            try: self.cap.release()
            except Exception: pass
        self.cap = None
        self.timer.stop()
        self.video.clear()
        self.video.setText('وب‌کم در دسترس نیست')
        self.status.setText('دوربین پیدا نشد؛ اتصال وب‌کم را بررسی کنید.')
        return False

    def stop_camera(self):
        """Stop frame processing and release the webcam immediately."""
        self._folder_auth_timer.stop()
        self._folder_face_attempt = None
        try:
            self.timer.stop()
        except Exception:
            pass
        if self.cap is not None:
            try:
                self.cap.release()
            except Exception:
                pass
        self.cap = None
        if hasattr(self, 'video'):
            self.video.clear()
            self.video.setText('دوربین خاموش است؛ هنگام نیاز به احراز هویت فعال می‌شود.')
        if hasattr(self, 'status'):
            self.status.setText('دوربین خاموش شد.')

    def load_model(self):
        try:
            if not hasattr(cv2, 'FaceDetectorYN') or not hasattr(cv2, 'FaceRecognizerSF'):
                raise RuntimeError('نسخهٔ OpenCV نصب‌شده از YuNet/SFace پشتیبانی نمی‌کند؛ opencv-contrib-python را نصب کنید.')
            if not YUNET_MODEL.exists() or not SFACE_MODEL.exists():
                raise RuntimeError('مدل‌های YuNet/SFace پیدا نشدند. install_and_run.bat را با اینترنت اجرا کنید تا مدل‌ها دریافت شوند.')
            self.detector = cv2.FaceDetectorYN.create(str(YUNET_MODEL), '', (320, 320), 0.85, 0.3, 5000)
            self.recognizer = cv2.FaceRecognizerSF.create(str(SFACE_MODEL), '')
            self.face_templates = {}
            for slot in range(1, MAX_FACE_PROFILES + 1):
                profile = FACE_PROFILES_DIR / f'face_{slot}.npy'
                if profile.exists():
                    self.face_templates[slot] = normalize_embedding(np.load(profile))
            if not self.face_templates and TEMPLATE_PATH.exists():
                self.face_templates[1] = normalize_embedding(np.load(TEMPLATE_PATH))
            self.face_template = self.face_templates[1] if 1 in self.face_templates else next(iter(self.face_templates.values()), None)
        except Exception as e:
            QMessageBox.warning(self, 'راه‌اندازی تشخیص چهره', str(e))

    def get_face(self, frame):
        if self.detector is None or self.recognizer is None:
            return None
        h, w = frame.shape[:2]
        self.detector.setInputSize((w, h))
        _, found = self.detector.detect(frame)
        if found is None or len(found) == 0:
            return None
        # Prefer a clearly detected, reasonably large face. Reject weak detections.
        candidates = [r for r in found if len(r) >= 15 and float(r[14]) >= 0.85]
        if not candidates:
            return None
        row = max(candidates, key=lambda r: float(r[2] * r[3]) * float(r[14]))
        x, y, fw, fh = [int(v) for v in row[:4]]
        try:
            aligned = self.recognizer.alignCrop(frame, row)
            feature = normalize_embedding(self.recognizer.feature(aligned))
        except Exception:
            return None
        return (x, y, fw, fh, feature)

    def update_frame(self):
        if not self.cap or not self.cap.isOpened(): return
        if self._folder_face_attempt is not None and self._folder_face_attempt.expired():
            self._folder_face_failed()
            return
        ok, frame = self.cap.read()
        if not ok: return
        frame = cv2.flip(frame, 1)
        face = self.get_face(frame)
        if face:
            x,y,w,h,crop = face
            color = (40,220,130) if self.mode == 'idle' else (20,190,255)
            cv2.rectangle(frame,(x,y),(x+w,y+h),color,2)
            if self.mode == 'enroll':
                now = time.time()
                # Only retain samples with enough face pixels and reasonable sharpness.
                face_roi = frame[max(0, y):max(0, y)+h, max(0, x):max(0, x)+w]
                face_size_ok = min(w, h) >= MIN_ENROLL_FACE_SIZE
                sharpness = cv2.Laplacian(face_roi, cv2.CV_64F).var() if face_roi.size else 0.0
                quality_ok = face_size_ok and sharpness >= MIN_ENROLL_SHARPNESS
                if quality_ok and now - self.last_enroll_sample >= ENROLL_SAMPLE_INTERVAL:
                    self.faces.append(crop.copy())
                    self.last_enroll_sample = now
                quality_msg = 'نمونه مناسب' if quality_ok else 'کمی نزدیک‌تر شوید و دوربین را ثابت نگه دارید'
                self.status.setText(f'ثبت نمونه‌های باکیفیت: {len(self.faces)}/{ENROLL_SAMPLE_COUNT} • {quality_msg} • سر را آرام در چند جهت بچرخانید')
                if len(self.faces) >= ENROLL_SAMPLE_COUNT: self.finish_enroll()
            elif self.mode == 'login':
                self.check_liveness(frame, face)
        else:
            if self._folder_face_attempt is not None:
                self._folder_face_attempt.no_face()
            if self.mode in ('enroll','login'):
                self.status.setText('صورت را در محدوده دوربین نگه دارید؛ نور مستقیم و شدید پشت سر نباشد.')
        if self.cap is None:
            return  # Do not display an old camera frame after success/failure/cancel.
        if self.mode == 'login' and time.time() - self.login_start > 8.0:
            pending = self._pending_app_unlock
            self.mode = 'idle'
            self.login_matches = 0
            self.login_last_label = None
            self.stop_camera()
            self.status.setText(f'چهره تأیید نشد؛ {"برنامه قفل ماند. برای تلاش دوباره دکمه تأیید با چهره را بزنید یا از رمز پشتیبان استفاده کنید." if pending else "تأیید ناموفق بود؛ دوباره تلاش کنید."}')
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB).copy()
        h,w,ch = rgb.shape
        qimg = QImage(rgb.data, w, h, ch*w, QImage.Format_RGB888).copy()
        self.video.setPixmap(QPixmap.fromImage(qimg).scaled(self.video.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def enroll_user(self):
        if not self._require_management_password('تأیید افزودن / تغییر چهره'):
            return
        slot = getattr(self, 'current_face_slot', 1)
        if not self.start_camera():
            QMessageBox.warning(self, 'دوربین', 'وب‌کم فعال نیست.'); return
        con = db()
        row = con.execute('SELECT id FROM users ORDER BY id LIMIT 1').fetchone()
        if row:
            user_id = int(row[0])
        else:
            # Internal profile only: no username/password prompt is shown to the user.
            internal_password = secrets.token_urlsafe(48)
            cur = con.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',
                              ('local-face-profile', hash_password(internal_password)))
            user_id = int(cur.lastrowid)
        con.commit(); con.close()
        self.current_enroll_id = user_id
        self.face_profile_id = user_id
        self.current_face_slot = slot
        self.faces = []
        self.last_enroll_sample = 0.0
        self.mode = 'enroll'
        self.status.setText('ثبت دقیق چهره شروع شد؛ نور یکنواخت، فاصله مناسب و چرخش آرام سر در چند جهت لازم است. عینک را در استفاده روزمره ثابت نگه دارید.')

    def finish_enroll(self):
        if not self.faces or (self._training_worker is not None and self._training_worker.isRunning()):
            return
        samples = [im.copy() for im in self.faces]
        self.mode = 'training'
        self.status.setText('نمونه‌ها ثبت شد؛ در حال ساخت الگوی چهره…')
        self._training_worker = FaceTrainingWorker(samples, FACE_PROFILES_DIR / f'face_{self.current_face_slot}.npy')
        self._training_worker.succeeded.connect(self._finish_enroll_success)
        self._training_worker.failed.connect(self._finish_enroll_error)
        self._training_worker.start()

    def _finish_enroll_success(self, message):
        try:
            self.face_templates[self.current_face_slot] = normalize_embedding(np.load(FACE_PROFILES_DIR / f'face_{self.current_face_slot}.npy'))
            self.face_template = self.face_templates[1] if 1 in self.face_templates else next(iter(self.face_templates.values()), None)
            self._refresh_face_profiles(self.current_face_slot)
            self.mode = 'idle'
            self.status.setText(message)
            QMessageBox.information(self, 'ثبت چهره', message)
        except Exception as exc:
            self._finish_enroll_error(str(exc))

    def _finish_enroll_error(self, message):
        self.mode = 'idle'
        self.status.setText('ثبت چهره انجام نشد؛ دوباره تلاش کنید.')
        QMessageBox.critical(self, 'خطا در ثبت چهره', message)

    def begin_login(self):
        pending = self._pending_app_unlock
        if pending and pending.get('kind') == 'folder_unlock':
            record = {'path': pending['path'], 'name': pending['name'],
                      'backup': pending['backup'], 'locked': True}
            self.cancel_action()
            self._start_folder_face_auth(record)
            return
        if self.face_template is None or (not self.face_templates and not TEMPLATE_PATH.exists()) or self.recognizer is None:
            QMessageBox.warning(self, 'چهره ثبت نشده', 'ابتدا دکمه «ثبت یا بازثبت چهره من» را بزنید.')
            return
        if not self.start_camera():
            QMessageBox.warning(self, 'وب‌کم در دسترس نیست', 'دوربین برای تأیید چهره در دسترس نیست.')
            return
        self.login_start = time.time()
        self.login_matches = 0
        self.login_last_label = None
        self.mode = 'login'
        self.status.setText('چهره را روبه‌روی دوربین نگه دارید؛ برای نتیجه بهتر نور یکنواخت و تصویر واضح داشته باشید.')

    def check_liveness(self, frame, face):
        pending = self._pending_app_unlock
        if pending and pending.get('kind') == 'folder_unlock':
            attempt = self._folder_face_attempt
            if attempt is None or self.mode != 'login':
                return
            if attempt.expired():
                self._folder_face_failed()
                return
            try:
                feature = normalize_embedding(face[4])
                templates = list(self.face_templates.values()) or [self.face_template]
                similarity = max(float(np.dot(feature, normalize_embedding(template))) for template in templates)
                if attempt.observe(similarity, COSINE_THRESHOLD):
                    self._pending_app_unlock = None
                    self.mode = 'idle'
                    self._gate_active = False
                    self.stop_camera()
                    self._finish_folder_unlock(pending)
                elif attempt.expired():
                    self._folder_face_failed()
                else:
                    self.status.setText(f'بررسی چهره تا ۳ ثانیه — تطبیق {attempt.matches}/5')
            except Exception as exc:
                self._folder_face_failed(str(exc))
            return
        if time.time() - self.login_start > 8.0:
            pending = self._pending_app_unlock
            self.mode = 'idle'
            self.login_matches = 0
            self.login_last_label = None
            if pending and pending.get('kind') == 'folder_unlock':
                self.status.setText('چهره تأیید نشد؛ پوشه قفل ماند. برای تلاش دوباره از چهره یا PIN استفاده کن.')
            else:
                self.status.setText(f'چهره تأیید نشد؛ {"برنامه قفل ماند. برای رمز پشتیبان از دکمه مربوطه استفاده کنید." if pending else "تأیید ناموفق بود؛ دوباره تلاش کنید."}')
            self.stop_camera()
            return
        _, _, _, _, feature = face
        try:
            if self.face_template is None:
                raise RuntimeError('الگوی چهره ثبت نشده است.')
            templates = list(self.face_templates.values()) or ([self.face_template] if self.face_template is not None else [])
            if not templates:
                raise RuntimeError('الگوی چهره ثبت نشده است.')
            similarity = max(float(np.dot(normalize_embedding(feature), normalize_embedding(template))) for template in templates)
            if similarity >= COSINE_THRESHOLD:
                if self.login_last_label == 'match':
                    self.login_matches += 1
                else:
                    self.login_last_label = 'match'
                    self.login_matches = 1
                self.status.setText(f'تطبیق چهره… {self.login_matches}/5 • شباهت {similarity:.3f}')
                if self.login_matches >= 5:
                    pending = self._pending_app_unlock
                    self.mode = 'idle'
                    self._pending_app_unlock = None
                    self.login_matches = 0
                    if pending:
                        # The camera is only required for face verification; stop it before
                        # changing files so frame updates do not compete with the crypto worker.
                        self.stop_camera()
                        if pending.get('kind') == 'folder_unlock':
                            self._finish_folder_unlock(pending)
                        else:
                            self._launch_pending_app(pending)
                    else:
                        self.stop_camera()
                        self.status.setText('چهره تأیید شد؛ دوربین خاموش شد.')
            else:
                self.login_matches = 0
                self.login_last_label = None
                self.status.setText(f'چهره تأیید نشد؛ شباهت {similarity:.3f} (حد شروع {COSINE_THRESHOLD:.2f})')
        except Exception as exc:
            self.mode = 'idle'
            self.status.setText(f'خطا در تشخیص چهره؛ برنامه محافظت‌شده باز نشد: {exc}')

    def cancel_action(self):
        pending = self._pending_app_unlock
        self._pending_app_unlock = None
        self.mode='idle'; self.faces=[]; self.login_matches=0
        self._gate_active = False
        self._folder_open_from_shell = False
        self.stop_camera()
        if pending and pending.get('kind') == 'folder_unlock':
            self.status.setText(f'عملیات لغو شد؛ وضعیت قبلی پوشهٔ «{pending["name"]}» تغییر نکرد.')
        elif pending:
            self.status.setText(f'عملیات لغو شد؛ «{pending["name"]}» قفل ماند. برای رمز پشتیبان از دکمه مربوطه استفاده کنید.')
        else:
            self.status.setText('عملیات لغو شد.')

    def closeEvent(self, event):
        # Closing the window hides it to the tray so the monitor keeps running.
        # This is not a security boundary: terminating the process still stops monitoring.
        if self.tray is not None and not self._allow_real_exit:
            if self._pending_app_unlock is not None or self.mode in {'login', 'enroll'}:
                self.cancel_action()
            self.hide()
            self.tray.showMessage('FaceGate در پس‌زمینه فعال است', 'پایش برنامه‌ها ادامه دارد تا وقتی FaceGate در حال اجرا باشد.', QSystemTrayIcon.Information, 3500)
            event.ignore()
            return
        self.stop_camera()
        self.app_lock_timer.stop()
        event.accept()


def authenticate_startup(app):
    """Require master password or optional 4–8 digit PIN before starting monitor."""
    con = db()
    row = con.execute('SELECT value FROM app_settings WHERE key=?', ('app_login_password_hash',)).fetchone()
    con.close()
    if not row:
        choice, ok = QInputDialog.getItem(None, 'روش ورود FaceGate', 'روش ورود را انتخاب کنید:',
                                          ['رمز عبور', 'PIN چهار تا هشت رقمی'], 0, False)
        if not ok:
            return False
        is_pin = choice == 'PIN چهار تا هشت رقمی'
        while True:
            first, ok = QInputDialog.getText(None, 'ساخت اطلاعات ورود',
                'PIN جدید (۴ تا ۸ رقم):' if is_pin else 'رمز جدید (حداقل ۸ نویسه):', QLineEdit.Password)
            if not ok:
                return False
            if is_pin and (not first.isdigit() or not 4 <= len(first) <= 8):
                QMessageBox.warning(None, 'PIN نامعتبر', 'PIN باید فقط شامل ۴ تا ۸ رقم باشد.')
                continue
            if not is_pin and len(first) < 8:
                QMessageBox.warning(None, 'رمز ضعیف', 'رمز باید حداقل ۸ نویسه داشته باشد.')
                continue
            second, ok = QInputDialog.getText(None, 'تأیید اطلاعات ورود', 'دوباره وارد کنید:', QLineEdit.Password)
            if not ok:
                return False
            if first != second:
                QMessageBox.warning(None, 'عدم تطبیق', 'مقادیر یکسان نیستند.')
                continue
            candidate = ('PIN:' + first) if is_pin else first
            con = db()
            con.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                        ('app_login_password_hash', hash_password(candidate)))
            con.execute('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                        ('app_login_credential_type', 'pin' if is_pin else 'password'))
            con.commit()
            con.close()
            return True

    con = db()
    type_row = con.execute('SELECT value FROM app_settings WHERE key=?', ('app_login_credential_type',)).fetchone()
    con.close()
    credential_type = type_row[0] if type_row else 'password'
    for attempt in range(3):
        prompt = 'PIN (۴ تا ۸ رقم)' if credential_type == 'pin' else 'رمز ورود'
        value, ok = QInputDialog.getText(None, 'ورود به FaceGate',
            f'{prompt} را وارد کنید (تلاش {attempt + 1} از ۳):', QLineEdit.Password)
        if not ok:
            return False
        if credential_type == 'pin' and (not value.isdigit() or not 4 <= len(value) <= 8):
            QMessageBox.warning(None, 'PIN نامعتبر', 'PIN باید ۴ تا ۸ رقم باشد.')
            continue
        candidate = ('PIN:' + value) if credential_type == 'pin' else value
        if verify_password(candidate, row[0]):
            return True
        QMessageBox.warning(None, 'رمز اشتباه', 'اطلاعات ورود نادرست است.')
    QMessageBox.critical(None, 'دسترسی رد شد', 'سه تلاش ناموفق؛ FaceGate بسته می‌شود.')
    return False


def _command_line_value(flag):
    try:
        idx = sys.argv.index(flag)
        return sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
    except ValueError:
        return None


def _choose_initial_workspace_mode():
    box = QMessageBox()
    box.setWindowTitle('FaceGate')
    box.setText('ابتدا بخش موردنظر را انتخاب کن')
    box.setInformativeText('برای خلوت ماندن رابط، فقط ابزارهای همان بخش نمایش داده می‌شوند.')
    apps = box.addButton('قفل برنامه‌ها', QMessageBox.AcceptRole)
    folders = box.addButton('رمزگذاری فایل‌ها و پوشه‌ها', QMessageBox.AcceptRole)
    box.addButton('خروج کامل', QMessageBox.DestructiveRole)
    box.setDefaultButton(apps)
    box.exec()
    clicked = box.clickedButton()
    if clicked is apps:
        return 'apps'
    if clicked is folders:
        return 'folders'
    return 'exit'


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    action = _command_line_value('--folder-action')
    folder_path = _command_line_value('--folder-path')
    request = {'action': action, 'path': folder_path} if action and folder_path else {'action': 'show', 'path': ''}
    name = instance_name(APP_DIR.resolve())
    try:
        if forward_request(name, request):
            return
        instance = InstanceServer(name, app)
    except (RuntimeError, ValueError) as exc:
        QMessageBox.warning(None, 'FaceGate', str(exc))
        return
    # Keep requests received during startup dialogs until the primary GUI is ready.
    queued = []
    instance.request_received.connect(queued.append)
    folder_auth_action = action in {'open-face', 'open-pin'} and bool(folder_path)
    is_autostart = '--autostart' in sys.argv[1:]
    if action and folder_path:
        mode = 'folders'
    elif is_autostart:
        mode = 'apps'
    else:
        mode = _choose_initial_workspace_mode()
    if mode == 'exit' or mode is None:
        instance.server.close()
        return
    if not is_autostart and not folder_auth_action and not authenticate_startup(app):
        instance.server.close()
        return
    win = FaceGate()
    win.set_workspace_mode(mode)
    # Keep Python ownership for the entire application lifetime.
    win._instance = instance
    instance.request_received.disconnect(queued.append)
    instance.request_received.connect(win._handle_instance_request)
    if is_autostart and win.tray is not None:
        win.hide()
    else:
        win.show()
    QTimer.singleShot(0, win.start_startup_recovery)
    if action and folder_path:
        queued.insert(0, request)
    for pending in queued:
        QTimer.singleShot(0, lambda pending=pending: win._handle_instance_request(pending))
    sys.exit(app.exec())

if __name__ == '__main__': main()
