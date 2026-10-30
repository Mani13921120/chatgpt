from pathlib import Path
import re
p = Path(__file__).with_name('main.py')
s = p.read_text(encoding='utf-8')
# Create mode-aware list before app-only heading, and mark app-only widgets.
old = "        heading = QLabel('قفل با تشخیص چهره'); heading.setStyleSheet('font-size:20px;font-weight:700;')\n        right.addWidget(heading)\n        login = QPushButton('آزمایش / تأیید با چهره'); login.clicked.connect(self.begin_login); right.addWidget(login)"
new = "        self._app_mode_widgets = []\n        heading = QLabel('قفل با تشخیص چهره'); heading.setStyleSheet('font-size:20px;font-weight:700;')\n        right.addWidget(heading); self._app_mode_widgets.append(heading)\n        login = QPushButton('آزمایش / تأیید با چهره'); login.clicked.connect(self.begin_login); right.addWidget(login); self._app_mode_widgets.append(login)"
assert old in s
s = s.replace(old, new, 1)
# The app backup password action only makes sense in app mode.
old = "        backup_use = QPushButton('بازکردن با رمز پشتیبان'); backup_use.setObjectName('secondary'); backup_use.clicked.connect(self.use_backup_password); right.addWidget(backup_use)"
new = "        backup_use = QPushButton('بازکردن برنامهٔ در انتظار با رمز پشتیبان'); backup_use.setObjectName('secondary'); backup_use.clicked.connect(self.use_backup_password); right.addWidget(backup_use); self._app_mode_widgets.append(backup_use)"
assert old in s
s = s.replace(old, new, 1)
# Do not reset the list after app-only face buttons have already been added.
old = "        # App-lock mode UI.\n        self._app_mode_widgets = []\n        app_heading = QLabel('قفل برنامه‌های ویندوز')"
new = "        # App-lock mode UI; append to the app-only widgets registered above.\n        app_heading = QLabel('قفل برنامه‌های ویندوز')"
assert old in s
s = s.replace(old, new, 1)
# Exclude installed code directory and its parent from targets, preventing accidental self-encryption.
needle = "        home_root = Path.home().resolve()\n        app_root = APP_DIR.resolve()\n"
repl = "        home_root = Path.home().resolve()\n        app_root = APP_DIR.resolve()\n        code_root = Path(__file__).resolve().parent\n        try:\n            if folder == code_root or code_root in folder.parents or folder in code_root.parents:\n                raise RuntimeError(f'برای جلوگیری از رمزگذاری خود برنامه و فایل‌های نصب، این مسیر پشتیبانی نمی‌شود: {folder}')\n        except OSError:\n            pass\n"
assert needle in s
s = s.replace(needle, repl, 1)
# Replace main with mode chooser before master-authentication, so first prompt is the requested choice.
start = s.index('def main():')
end = s.index("\nif __name__ == '__main__': main()", start)
new_main = r'''def _choose_initial_workspace_mode():
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
    folder_auth_action = action in {'open-face', 'open-pin'} and bool(folder_path)
    is_autostart = '--autostart' in sys.argv[1:]
    if action and folder_path:
        mode = 'folders'
    elif is_autostart:
        mode = 'apps'
    else:
        mode = _choose_initial_workspace_mode()
    if mode == 'exit' or mode is None:
        return
    # Choosing a workspace is not authentication. Normal manual startup still authenticates.
    if not is_autostart and not folder_auth_action and not authenticate_startup(app):
        return
    win = FaceGate()
    win.set_workspace_mode(mode)
    win.show()
    QTimer.singleShot(250, win.start_startup_recovery)
    if action and folder_path:
        QTimer.singleShot(1000, lambda: win._dispatch_folder_cli_action(action, folder_path))
    sys.exit(app.exec())
'''
s = s[:start] + new_main + s[end:]
p.write_text(s, encoding='utf-8', newline='\n')

# Patch the crypto recovery backup to use unique filenames and warn if a recovery snapshot went missing.
cp = Path(__file__).with_name('folder_inplace_crypto.py')
c = cp.read_text(encoding='utf-8')
old = '''    backup_root.mkdir(parents=True, exist_ok=True)
    backup = backup_root / f"{folder_key_id}_recovery.fgvault"
    result = create_encrypted_vault(root, backup, pin=pin, overwrite=False)
'''
new = '''    backup_root.mkdir(parents=True, exist_ok=True)
    # Unique recovery snapshot per protection attempt. A previous failed attempt must not
    # permanently block retry, and an older recovery copy is never overwritten implicitly.
    backup = backup_root / f"{folder_key_id}_recovery_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.fgvault"
    result = create_encrypted_vault(root, backup, pin=pin, overwrite=False)
'''
assert old in c
c = c.replace(old, new, 1)
old = '''    backup_warning = ""
    if backup_path and Path(backup_path).is_file() and list_encrypted_files(root) == []:
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
'''
new = '''    backup_warning = ""
    if backup_path:
        if not Path(backup_path).is_file():
            backup_warning = f"نسخهٔ پشتیبان بازیابی پیدا نشد: {backup_path}. محتوای اصلی رمزگذاری می‌شود، اما قبل از تکیه بر این پوشه یک نسخهٔ پشتیبان مستقل بساز."
        elif list_encrypted_files(root) == []:
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
'''
assert old in c
c = c.replace(old, new, 1)
cp.write_text(c, encoding='utf-8', newline='\n')
