"""Shared GUI/guardian app monitor. Pending prompts never exempt another launch."""
from pathlib import Path

import psutil

import app_catalog
import app_runtime


class Monitor:
    def __init__(self, main_script=None):
        self.main_script = main_script or Path(__file__).with_name('main.py')
        self.known = set()
        self.identities = {}
        self.seed()

    def seed(self):
        self.known = {(p.info['pid'], p.info.get('create_time'))
                      for p in psutil.process_iter(['pid', 'create_time'], ad_value=None)}

    def scan(self, targets, sessions, pending_keys=(), foreground=None):
        if not targets:
            return [], []
        hwnd, _ = foreground if foreground is not None else app_runtime.foreground_window()
        foreground_pid = app_runtime.window_pid(hwnd, True) if hwnd else 0
        paths = {a.key: {app_catalog.path_key(p) for p in a.process_paths} for a in targets.values()}
        packaged = any(a.packaged for a in targets.values())
        package_paths = set().union(*(paths[a.key] for a in targets.values() if a.packaged)) if packaged else set()
        snapshots = []; live = set(); live_keys = set()
        for proc in psutil.process_iter(['pid', 'exe', 'cmdline', 'create_time'], ad_value=None):
            try:
                info = proc.info
                pid = info['pid']; identity = (pid, info.get('create_time'))
                live.add(identity)
                if app_catalog.internal_pid(pid):
                    continue
                exe = info.get('exe') or ''
                command = info.get('cmdline') or [exe]
                if not exe or app_catalog.internal_command(command, self.main_script):
                    continue
                normalized = app_catalog.path_key(exe)
                app_id = self.identities.get(identity, '')
                if packaged and (identity not in self.identities or (not app_id and pid == foreground_pid)) and (
                        identity not in self.known or pid == foreground_pid or normalized in package_paths):
                    app_id = app_runtime.process_app_id(pid)
                    self.identities[identity] = app_id
                matches = [a for a in targets.values() if app_runtime.matches(a, exe, command, app_id, paths[a.key], normalized)]
                live_keys.update(a.key for a in matches)
                if matches:
                    snapshots.append((proc, info, identity, matches))
            except (psutil.Error, OSError):
                continue
        sessions.observe(live_keys)
        self.identities = {key: value for key, value in self.identities.items() if key in live}
        requests = []; errors = []; queued = set(pending_keys)
        for proc, info, identity, matches in snapshots:
            keys = {a.key for a in matches}
            if sessions.allows(keys):
                continue
            new = identity not in self.known
            if not new and info['pid'] != foreground_pid:
                continue
            app = matches[0]
            request = {'key': app.key, 'name': app.name, 'exe': info['exe'], 'pid': info['pid'],
                       'started': identity[1],
                       'command': None if app.packaged else (info.get('cmdline') or [info['exe']]),
                       'hwnd': 0, 'cwd': app.working_directory}
            if not new:
                request['hwnd'] = int(hwnd)
                app_runtime.show_window(hwnd, False)
            else:
                try:
                    if proc.create_time() != identity[1]:
                        continue
                    try:
                        request['cwd'] = proc.cwd()
                    except (psutil.Error, OSError):
                        pass
                    proc.terminate()
                except (psutil.Error, OSError):
                    errors.append(f'ویندوز اجازهٔ توقف «{app.name}» را نداد؛ قفل این اجرا تأیید نشد.')
                    continue
            # Stop/minimize every unauthorized attempt, including launches made
            # while the camera or a modal dialog is already waiting for this app.
            if not queued.intersection(keys) and len(requests) < 16:
                requests.append(request)
                queued.add(app.key)
        self.known = live
        return requests, errors
