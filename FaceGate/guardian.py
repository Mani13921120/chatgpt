"""Visible, independently stoppable user-session guardian. No Task Manager hooks."""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sqlite3
import time

import app_runtime
from app_monitor import Monitor
import guardian_state as state


class Guardian:
    def __init__(self, directory, main_script, wake=None):
        self.directory = Path(directory)
        self.main_script = Path(main_script)
        self.monitor = Monitor(main_script)
        self.sessions = app_runtime.Sessions()
        self.wake = wake or (lambda: state.spawn(self.main_script, '--guardian-wake'))
        self.launch = None
        self.next_launch = 0.0
        self.last_error = ''
        self.last_gui = None
        self.last_gui_update = None

    def tick(self):
        if not state.enabled(self.directory):
            return False
        gui = state.read(self.directory, 'gui', self.main_script, allow_exited=True)
        if gui and gui['updated'] != self.last_gui_update:
            self.sessions.authorized = dict(gui.get('sessions') or {})
            self.monitor.known = {tuple(item) for item in gui.get('known', ())}
            self.last_gui = gui['pid']
            self.last_gui_update = gui['updated']
        if not gui or not gui['alive']:
            targets = state.load_targets(self.directory)
            requests, errors = self.monitor.scan(targets, self.sessions, state.pending_keys(self.directory))
            self.last_error = '\n'.join(errors)
            for request in requests:
                state.queue(self.directory, request)
            if state.pending_keys(self.directory) and time.monotonic() >= self.next_launch:
                if self.launch is None or self.launch.poll() is not None:
                    self.launch = self.wake()
                    self.next_launch = time.monotonic() + 5
        # The GUI uses the snapshot to preserve already authenticated sessions.
        # The PID/create-time check prevents reusing a dead or recycled owner.
        state.publish(self.directory, 'guardian', self.sessions, self.last_error, self.monitor.known)
        return True


def run(directory, main_script):
    from PySide6.QtCore import QLockFile, QTimer
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import QApplication, QMenu, QStyle, QSystemTrayIcon

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    app = QApplication(['FaceGate Guardian'])
    app.setQuitOnLastWindowClosed(False)
    lock = QLockFile(str(directory / 'guardian.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        return 0
    logger = logging.getLogger('FaceGate.Guardian')
    handler = RotatingFileHandler(directory / 'guardian.log', maxBytes=256000, backupCount=1, encoding='utf-8')
    logger.addHandler(handler); logger.setLevel(logging.INFO)
    guardian = Guardian(directory, main_script)
    tray = QSystemTrayIcon(app.style().standardIcon(QStyle.SP_ComputerIcon))
    menu = QMenu()
    show = QAction('بازکردن FaceGate', menu)
    show.triggered.connect(lambda: state.spawn(main_script))
    menu.addAction(show)
    settings = QAction('تنظیم / توقف نگهبان با احراز هویت', menu)
    settings.triggered.connect(lambda: state.spawn(main_script))
    menu.addAction(settings)
    tray.setContextMenu(menu)
    tray.setToolTip('FaceGate — نگهبان مستقل فعال است')
    tray.activated.connect(lambda reason: state.spawn(main_script) if reason == QSystemTrayIcon.DoubleClick else None)
    tray.show()
    timer = QTimer()
    timer.setInterval(300)

    def tick():
        try:
            if not guardian.tick():
                app.quit()
            elif guardian.last_error:
                tray.setToolTip('FaceGate — خطای پایش؛ برنامه را باز کنید')
                logger.warning(guardian.last_error)
            else:
                tray.setToolTip('FaceGate — نگهبان مستقل فعال است')
        except (OSError, sqlite3.Error, ValueError):
            logger.exception('Guardian scan failed')
            tray.setToolTip('FaceGate — خطای پایش؛ guardian.log را بررسی کنید')

    def finish():
        timer.stop(); tray.hide()
        try:
            state.clear(directory, 'guardian')
        except (OSError, sqlite3.Error):
            logger.exception('Could not clear guardian state')
        lock.unlock()
    app.aboutToQuit.connect(finish)
    timer.timeout.connect(tick)
    timer.start(); tick()
    return app.exec()
