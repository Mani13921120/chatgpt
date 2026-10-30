from pathlib import Path
p = Path(__file__).with_name('main.py')
s = p.read_text(encoding='utf-8')

# Imports + worker state
s = s.replace('import shutil\nimport psutil\n', 'import shutil\nimport traceback\nimport psutil\nimport folder_inplace_crypto as inplace_crypto\n', 1)
needle = 'class FaceTrainingWorker(QThread):\n'
insert = '''class FolderOperationWorker(QThread):
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


'''
assert needle in s
s = s.replace(needle, insert + needle, 1)
needle = '        self._pending_app_unlock = None\n        self.challenge = None\n'
repl = '        self._pending_app_unlock = None\n        self._folder_worker = None\n        self._folder_worker_callback = None\n        self._workspace_mode = None\n        self._startup_relock_paths = []\n        self.challenge = None\n'
assert needle in s
s = s.replace(needle, repl, 1)
s = s.replace("self.setWindowTitle('FaceGate | محافظت پوشه‌ها و قفل برنامه‌ها')", "self.setWindowTitle('FaceGate | قفل برنامه‌ها و رمزگذاری پوشه‌ها')", 1)
s = s.replace('self.setMinimumSize(900, 600)', 'self.setMinimumSize(820, 560)', 1)

# Workspace selector controls
needle = "        right_frame = QFrame(); right_frame.setObjectName('panel'); right = QVBoxLayout(right_frame); right.setContentsMargins(22,22,22,22); right.setSpacing(13)\n        heading = QLabel('قفل با تشخیص چهره');"
repl = "        right_frame = QFrame(); right_frame.setObjectName('panel'); right = QVBoxLayout(right_frame); right.setContentsMargins(22,22,22,22); right.setSpacing(13)\n        self.workspace_label = QLabel('حالت کاری'); self.workspace_label.setObjectName('sub'); right.addWidget(self.workspace_label)\n        workspace_back = QPushButton('انتخاب بخش دیگر'); workspace_back.setObjectName('secondary'); workspace_back.clicked.connect(self._show_workspace_picker); right.addWidget(workspace_back)\n        heading = QLabel('قفل با تشخیص چهره');"
assert needle in s
s = s.replace(needle, repl, 1)

# Replace UI feature section with mode-specific widgets.
start = s.index("        folder_heading = QLabel('محافظت از خود پوشه با رمزگذاری ویندوز (EFS)')")
end = s.index('        # Scroll the controls when the window is not maximized / display is short.', start)
ui_block = r'''        # Folder mode UI: actual content encryption in-place, not a nearby container.
        self._folder_mode_widgets = []
        folder_heading = QLabel('رمزگذاری محتوا در همان پوشه')
        folder_heading.setStyleSheet('font-size:17px;font-weight:700;margin-top:8px;')
        right.addWidget(folder_heading); self._folder_mode_widgets.append(folder_heading)
        folder_note = QLabel('محتوای فایل‌ها در همان مسیر با AES-256-GCM رمزگذاری می‌شود؛ نام‌ها و ساختار پوشه باقی می‌مانند و فایل کانتینر کنار پوشه ساخته نمی‌شود. یک نسخهٔ پشتیبان رمزگذاری‌شده جدا از مسیر اصلی نگه‌داری می‌شود. هنگام قفل، برنامه‌های معمولی محتوای فایل‌ها را نمی‌توانند بخوانند. نام‌ها همچنان دیده می‌شوند و با مجوز کافی امکان حذف فایل وجود دارد. هنگام بازبودن، فایل‌ها برای برنامه‌های همین حساب ویندوز خوانا هستند؛ بدون درایور نمی‌توان همهٔ عملیات Explorer/CMD را پیش از اجرا با FaceGate متوقف کرد.')
        folder_note.setWordWrap(True); folder_note.setObjectName('sub'); right.addWidget(folder_note); self._folder_mode_widgets.append(folder_note)
        self.protected_folder_list = QListWidget(); self.protected_folder_list.setMaximumHeight(150); self.protected_folder_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.protected_folder_list.setStyleSheet('QListWidget {background:#0b1424;border:1px solid #30415d;border-radius:8px;padding:4px;} QListWidget::item {padding:6px;}')
        right.addWidget(self.protected_folder_list); self._folder_mode_widgets.append(self.protected_folder_list)
        folder_add = QPushButton('انتخاب پوشه و رمزگذاری محتوا'); folder_add.setObjectName('secondary'); folder_add.clicked.connect(self.choose_and_protect_folder)
        right.addWidget(folder_add); self._folder_mode_widgets.append(folder_add)
        folder_auth_row = QHBoxLayout()
        folder_face = QPushButton('بازکردن با تشخیص چهره'); folder_face.clicked.connect(self.open_selected_folder_with_face)
        folder_pin = QPushButton('بازکردن با PIN پشتیبان'); folder_pin.setObjectName('secondary'); folder_pin.clicked.connect(self.open_selected_folder_with_pin)
        folder_auth_row.addWidget(folder_face); folder_auth_row.addWidget(folder_pin); right.addLayout(folder_auth_row)
        self._folder_mode_widgets.extend([folder_face, folder_pin])
        folder_lock_row = QHBoxLayout()
        folder_lock = QPushButton('رمزگذاری مجدد / قفل محتوا'); folder_lock.setObjectName('danger'); folder_lock.clicked.connect(self.lock_selected_folder)
        folder_refresh = QPushButton('تازه‌سازی فهرست'); folder_refresh.setObjectName('secondary'); folder_refresh.clicked.connect(self.refresh_protected_folders)
        folder_lock_row.addWidget(folder_lock); folder_lock_row.addWidget(folder_refresh); right.addLayout(folder_lock_row)
        self._folder_mode_widgets.extend([folder_lock, folder_refresh])
        folder_menu_row = QHBoxLayout()
        folder_menu_install = QPushButton('افزودن «بازکردن با FaceGate» به راست‌کلیک'); folder_menu_install.setObjectName('secondary'); folder_menu_install.clicked.connect(self.install_folder_context_menu)
        folder_menu_remove = QPushButton('حذف گزینه راست‌کلیک'); folder_menu_remove.setObjectName('secondary'); folder_menu_remove.clicked.connect(self.remove_folder_context_menu)
        folder_menu_row.addWidget(folder_menu_install); folder_menu_row.addWidget(folder_menu_remove); right.addLayout(folder_menu_row)
        self._folder_mode_widgets.extend([folder_menu_install, folder_menu_remove])
        folder_recover = QPushButton('بازیابی مجوزهای نسخهٔ قدیمی FaceGate'); folder_recover.setObjectName('secondary'); folder_recover.clicked.connect(self.recover_legacy_folder_permissions)
        right.addWidget(folder_recover); self._folder_mode_widgets.append(folder_recover)

        # App-lock mode UI.
        self._app_mode_widgets = []
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
'''
s = s[:start] + ui_block + s[end:]
# Hide mode-specific areas until user chooses.
needle = "            self.apply_theme(theme_row[0])\n\n    def apply_theme(self, theme):"
repl = "            self.apply_theme(theme_row[0])\n        for widget in getattr(self, '_folder_mode_widgets', []):\n            widget.hide()\n        for widget in getattr(self, '_app_mode_widgets', []):\n            widget.hide()\n\n    def _choose_workspace_mode(self):\n        box = QMessageBox()\n        box.setWindowTitle('FaceGate')\n        box.setText('می‌خواهی کدام بخش را باز کنی؟')\n        box.setInformativeText('یک بخش را انتخاب کن تا رابط خلوت‌تر شود.')\n        apps = box.addButton('قفل برنامه‌ها', QMessageBox.AcceptRole)\n        folders = box.addButton('رمزگذاری فایل‌ها و پوشه‌ها', QMessageBox.AcceptRole)\n        box.addButton('خروج کامل', QMessageBox.DestructiveRole)\n        box.setDefaultButton(apps)\n        box.exec()\n        clicked = box.clickedButton()\n        if clicked is apps:\n            return 'apps'\n        if clicked is folders:\n            return 'folders'\n        return 'exit'\n\n    def set_workspace_mode(self, mode):\n        if mode not in {'apps', 'folders'}:\n            return\n        self._workspace_mode = mode\n        for widget in getattr(self, '_app_mode_widgets', []):\n            widget.setVisible(mode == 'apps')\n        for widget in getattr(self, '_folder_mode_widgets', []):\n            widget.setVisible(mode == 'folders')\n        label = 'حالت قفل برنامه‌ها' if mode == 'apps' else 'حالت رمزگذاری فایل‌ها و پوشه‌ها'\n        self.workspace_label.setText(label)\n        self.setWindowTitle('FaceGate | ' + label)\n\n    def _show_workspace_picker(self):\n        mode = self._choose_workspace_mode()\n        if mode == 'exit':\n            self._exit_application()\n            return\n        self.set_workspace_mode(mode)\n\n    def apply_theme(self, theme):"
assert needle in s
s = s.replace(needle, repl, 1)

# Replace EFS/NTFS dependency check in path validation with a direct folder check.
old = """        fs_name = _windows_filesystem_name(folder)
        if fs_name.upper() != 'NTFS':
            raise RuntimeError(f'EFS ویندوز به NTFS نیاز دارد؛ فایل‌سیستم این مسیر {fs_name or "نامشخص"} است.')
        attrs = _windows_file_attributes(folder)
"""
new = """        # In-place AES encryption works on regular writable folders; it does not depend on EFS/NTFS.
        attrs = _windows_file_attributes(folder)
"""
assert old in s
s = s.replace(old, new, 1)

# Refresh modern statuses and repair missing manifest from encrypted file headers.
start = s.index('    def refresh_protected_folders(self):')
end = s.index('    def _selected_protected_folder(self):', start)
refresh = r'''    def refresh_protected_folders(self):
        if not hasattr(self, 'protected_folder_list'):
            return
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
            if manifest:
                status = 'محتوا رمزگذاری‌شده' if bool(is_locked) else 'محتوا باز / خوانا'
            else:
                status = 'نسخهٔ قدیمی EFS/ACL — نیازمند بازیابی' if str(metadata_path).lower().endswith('.acl') else 'اطلاعات محافظت در دسترس نیست'
            item = QListWidgetItem(f'{display_name}  —  {status}\n{folder_path}')
            item.setData(Qt.UserRole, folder_path)
            self.protected_folder_list.addItem(item)
            if current and str(folder_path).casefold() == str(current).casefold():
                selected_index = self.protected_folder_list.count() - 1
        if selected_index >= 0:
            self.protected_folder_list.setCurrentRow(selected_index)

'''
s = s[:start] + refresh + s[end:]

# Replace folder control operations through the next unrelated method (backup_efs_key).
start = s.index('    def choose_and_protect_folder(self):')
end = s.index('    def backup_efs_key(self):', start)
ops = r'''    def _metadata_root(self):
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
            callback(ok, result)

    def _folder_error_text(self, result):
        if isinstance(result, dict):
            return str(result.get('error') or result)
        return str(result)

    def choose_and_protect_folder(self):
        selected = QFileDialog.getExistingDirectory(self, 'انتخاب پوشه برای رمزگذاری محتوا در همان مسیر', str(Path.home()))
        if selected:
            self.protect_folder_path(selected)

    def protect_folder_path(self, folder_path):
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
            'هنگام قفل، برنامه‌های معمولی محتوای فایل‌ها را نمی‌توانند بخوانند، اما نام‌ها قابل مشاهده‌اند و کاربری با مجوز کافی هنوز می‌تواند فایل را حذف کند. بدون درایور نمی‌توان همهٔ عملیات ویندوز را قبل از اجرا با FaceGate متوقف کرد. ادامه می‌دهی؟',
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
            f'محتوای {result["file_count"]} فایل در همان پوشه رمزگذاری شد. نام فایل‌ها و مسیرها حفظ شدند.\n\nنسخهٔ پشتیبان رمزگذاری‌شده: {result["backup_path"]}\n\nبرای خواندن فایل‌ها از «بازکردن با تشخیص چهره» یا «بازکردن با PIN» استفاده کن. در حالت باز، فایل‌ها خوانا هستند تا برنامه‌های ویندوز بتوانند آن‌ها را بخوانند؛ برای پایان کار «رمزگذاری مجدد / قفل محتوا» را بزن.')

    def open_selected_folder_with_face(self):
        record = self._selected_protected_folder()
        if not record:
            return
        if not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'نسخهٔ قدیمی پوشه', 'این پوشه از نسخهٔ قدیمی EFS/ACL است؛ ابتدا گزینهٔ بازیابی مجوزهای نسخهٔ قدیمی را اجرا کن.')
            return
        self._start_folder_face_auth(record)

    def _start_folder_face_auth(self, record):
        if not Path(record['path']).is_dir():
            QMessageBox.warning(self, 'پوشه پیدا نشد', f'این مسیر پیدا نشد:\n{record["path"]}')
            return
        try:
            encrypted = inplace_crypto.list_encrypted_files(record['path'])
        except Exception as exc:
            QMessageBox.warning(self, 'بررسی پوشه ناموفق بود', str(exc))
            return
        if not encrypted and not record.get('locked'):
            try:
                os.startfile(record['path'])
            except Exception as exc:
                QMessageBox.warning(self, 'Explorer اجرا نشد', str(exc))
            return
        if self.face_template is None or (not self.face_templates and not TEMPLATE_PATH.exists()) or self.recognizer is None:
            QMessageBox.warning(self, 'چهره ثبت نشده', 'ابتدا در بخش مدیریت چهره، چهره‌ات را ثبت کن یا از PIN پشتیبان استفاده کن.')
            return
        self._pending_app_unlock = {'kind': 'folder_unlock', 'path': record['path'], 'name': record['name'], 'backup': record['backup'], 'pin': None}
        if not self.start_camera():
            self._pending_app_unlock = None
            QMessageBox.warning(self, 'وب‌کم در دسترس نیست', 'دوربین برای احراز هویت در دسترس نیست؛ فایل‌ها در حالت فعلی باقی ماندند.')
            return
        self.login_start = time.time()
        self.login_matches = 0
        self.login_last_label = None
        self.mode = 'login'
        self.status.setText(f'برای رمزگشایی محتویات «{record["name"]}»، چهره را روبه‌روی دوربین نگه دار…')

    def set_folder_pin(self):
        QMessageBox.information(self, 'PIN پوشه', 'PIN هشت‌رقمی هنگام رمزگذاری هر پوشه تنظیم می‌شود. برای تغییر آن، پوشه را با PIN فعلی باز کن و دوباره محافظت کن.')

    def open_selected_folder_with_pin(self):
        record = self._selected_protected_folder()
        if not record:
            return
        if not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'نسخهٔ قدیمی پوشه', 'این پوشه از نسخهٔ قدیمی EFS/ACL است؛ ابتدا گزینهٔ بازیابی مجوزهای نسخهٔ قدیمی را اجرا کن.')
            return
        pin, ok = QInputDialog.getText(self, 'بازکردن پوشه با PIN', f'PIN هشت‌رقمی برای «{record["name"]}» را وارد کن:', QLineEdit.Password)
        if not ok:
            return
        if not pin.isdigit() or len(pin) != 8:
            QMessageBox.warning(self, 'PIN نامعتبر', 'PIN باید دقیقاً ۸ رقم باشد.')
            return
        folder = Path(record['path'])
        self._run_folder_worker(
            lambda: inplace_crypto.unlock_folder_in_place(folder, self._metadata_root(), pin=pin, manifest=record['backup']),
            lambda success, result: self._on_folder_unlock_done(record, success, result),
            f'در حال تأیید PIN و رمزگشایی فایل‌های «{record["name"]}»…')

    def _finish_folder_unlock(self, pending):
        folder = Path(pending['path'])
        if not folder.is_dir():
            QMessageBox.warning(self, 'پوشه پیدا نشد', f'پوشه موجود نیست:\n{folder}')
            return False
        record = self._folder_record(folder)
        if not record or not self._is_modern_folder_record(record):
            QMessageBox.warning(self, 'پوشه ثبت نشده', 'اطلاعات رمزگذاری این پوشه پیدا نشد؛ هیچ فایلی تغییر نکرد.')
            return False
        self._run_folder_worker(
            lambda: inplace_crypto.unlock_folder_in_place(folder, self._metadata_root(), pin=None, manifest=record['backup']),
            lambda success, result: self._on_folder_unlock_done(record, success, result),
            f'چهره تأیید شد؛ در حال رمزگشایی «{folder.name}» در مسیر اصلی…')
        return True

    def _on_folder_unlock_done(self, record, success, result):
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
        try:
            os.startfile(str(folder))
            self.status.setText(f'محتوای «{folder.name}» باز شد؛ بعد از پایان کار «رمزگذاری مجدد / قفل محتوا» را بزن.')
        except Exception as exc:
            QMessageBox.warning(self, 'محتوا باز شد، اما Explorer اجرا نشد', f'فایل‌ها رمزگشایی شدند؛ Explorer اجرا نشد:\n{exc}\n\n{folder}')

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
        if record['locked'] and inplace_crypto.list_encrypted_files(record['path']):
            QMessageBox.information(self, 'پوشه قفل است', 'محتوای این پوشه از قبل رمزگذاری‌شده است.')
            return True
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

    def recover_legacy_folder_permissions(self):
        record = self._selected_protected_folder()
        if not record:
            return
        if self._is_modern_folder_record(record):
            QMessageBox.information(self, 'بازیابی لازم نیست', 'این پوشه از روش جدید رمزگذاری درجا استفاده می‌کند.')
            return
        folder = Path(record['path'])
        backup = Path(record['backup'])
        if not backup.is_file() or not backup.with_suffix(backup.suffix + '.owners.json').is_file():
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
        # Do not silently rewrite NTFS ACLs. Only queue modern in-place folders left open.
        self._startup_relock_paths = []
        con = db()
        try:
            rows = con.execute('SELECT path, acl_backup_path, is_locked FROM protected_folders').fetchall()
        finally:
            con.close()
        for folder_path, metadata_path, is_locked in rows:
            manifest = inplace_crypto.read_manifest(metadata_path) if metadata_path else None
            if manifest and not bool(is_locked):
                self._startup_relock_paths.append((folder_path, metadata_path))

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
            if not manifest:
                # Old EFS/ACL folders are left alone; we no longer re-lock them by changing ACLs.
                continue
            try:
                folder = Path(path)
                if folder.is_dir() and (not is_locked or not inplace_crypto.list_encrypted_files(folder)):
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

'''
s = s[:start] + ops + s[end:]

# Fix old EFS invocation if ever used; include explicit target path so cipher can't act on current directory.
s = s.replace("return self._cipher_command(['/e', f'/s:{folder}', '/h', '/b'])", "return self._cipher_command(['/e', f'/s:{folder}', '/h', '/b', str(folder)])")

# Replace exit operation with background re-lock.
start = s.index('    def _exit_application(self):')
end = s.index('    def set_backup_password(self):', start)
exit_code = r'''    def _exit_application(self):
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

'''
s = s[:start] + exit_code + s[end:]

# Remove administrator elevation from open/lock/protect context actions.
old_snippet = """        if not folder_path or action not in {'protect', 'open-face', 'open-pin', 'lock'}:
            return
        if not self._is_admin():
            self._handoff_folder_action_to_admin(action, folder_path)
            return
        if action == 'protect':
"""
new_snippet = """        if not folder_path or action not in {'protect', 'open-face', 'open-pin', 'lock'}:
            return
        if action == 'protect':
"""
assert old_snippet in s
s = s.replace(old_snippet, new_snippet, 1)

# Startup mode chooser
old = """def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    action = _command_line_value('--folder-action')
    folder_path = _command_line_value('--folder-path')
    # Face/PIN folder-unlock actions perform folder-specific auth below. Other elevated actions still require FaceGate login;
    # UAC approval alone is not treated as app authentication.
    folder_auth_action = action in {'open-face', 'open-pin'} and bool(folder_path)
    if '--autostart' not in sys.argv[1:] and not folder_auth_action and not authenticate_startup(app):
        return
    win = FaceGate()
    win.show()
    if action and folder_path:
        QTimer.singleShot(1500, lambda: win._dispatch_folder_cli_action(action, folder_path))
    sys.exit(app.exec())
"""
new = """def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    action = _command_line_value('--folder-action')
    folder_path = _command_line_value('--folder-path')
    folder_auth_action = action in {'open-face', 'open-pin'} and bool(folder_path)
    if '--autostart' not in sys.argv[1:] and not folder_auth_action and not authenticate_startup(app):
        return
    win = FaceGate()
    if action and folder_path:
        mode = 'folders'
    elif '--autostart' in sys.argv[1:]:
        mode = 'apps'
    else:
        mode = win._choose_workspace_mode()
    if mode == 'exit' or mode is None:
        win.stop_camera()
        win.app_lock_timer.stop()
        if win.tray:
            win.tray.hide()
        win._allow_real_exit = True
        return
    win.set_workspace_mode(mode)
    win.show()
    QTimer.singleShot(250, win.start_startup_recovery)
    if action and folder_path:
        QTimer.singleShot(1000, lambda: win._dispatch_folder_cli_action(action, folder_path))
    sys.exit(app.exec())
"""
assert old in s
s = s.replace(old, new, 1)

p.write_text(s, encoding='utf-8', newline='')
print('patched', p)
