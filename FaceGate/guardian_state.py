"""Current-user monitor handoff and authentication requests, never unlock commands."""
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import psutil

import app_catalog
import app_runtime


@contextmanager
def connection(directory):
    con = sqlite3.connect(Path(directory) / 'users.db', timeout=2)
    try:
        con.execute('CREATE TABLE IF NOT EXISTS guardian_runtime (role TEXT PRIMARY KEY,pid INTEGER,started REAL,updated REAL,payload TEXT)')
        con.execute('CREATE TABLE IF NOT EXISTS guardian_pending (key TEXT PRIMARY KEY,payload TEXT,created REAL)')
        yield con
        con.commit()
    finally:
        con.close()


def enabled(directory):
    with connection(directory) as con:
        con.execute('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        row = con.execute("SELECT value FROM app_settings WHERE key='guardian_enabled'").fetchone()
    return row is None or row[0] == '1'


def set_enabled(directory, value):
    with connection(directory) as con:
        con.execute('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        con.execute("INSERT INTO app_settings VALUES('guardian_enabled',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ('1' if value else '0',))


def publish(directory, role, sessions, error='', known=None):
    process = psutil.Process()
    payload = json.dumps({'boot': psutil.boot_time(), 'sessions': sessions.authorized, 'error': error,
                          'known': list(known or ())}, ensure_ascii=True)
    with connection(directory) as con:
        con.execute('INSERT INTO guardian_runtime VALUES(?,?,?,?,?) ON CONFLICT(role) DO UPDATE SET pid=excluded.pid,started=excluded.started,updated=excluded.updated,payload=excluded.payload',
                    (role, process.pid, process.create_time(), time.time(), payload))


def read(directory, role, main_script=None, allow_exited=False):
    with connection(directory) as con:
        row = con.execute('SELECT pid,started,updated,payload FROM guardian_runtime WHERE role=?', (role,)).fetchone()
    if not row:
        return None
    try:
        try:
            process = psutil.Process(row[0])
            alive = process.create_time() == row[1] and process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            alive = False
        if not alive and (not allow_exited or time.time() - row[2] > 5):
            return None
        if alive and main_script and not getattr(sys, 'frozen', False):
            command = process.cmdline()
            if not app_catalog.internal_command(command, main_script):
                return None
            if (role == 'guardian') != ('--guardian' in command[2:]):
                return None
        payload = json.loads(row[3])
        if not isinstance(payload, dict):
            return None
        if abs(payload.get('boot', 0) - psutil.boot_time()) > 1:
            return None
        sessions = payload.get('sessions')
        known = payload.get('known')
        if not isinstance(sessions, dict) or not all(isinstance(key, str) and isinstance(stamp, (float, int)) and math.isfinite(stamp) for key, stamp in sessions.items()):
            return None
        if not isinstance(known, list) or not all(isinstance(item, list) and len(item) == 2 and isinstance(item[0], int) and isinstance(item[1], (float, int, type(None))) for item in known):
            return None
        return {**payload, 'pid': row[0], 'updated': row[2], 'alive': alive}
    except (psutil.Error, OSError, ValueError, TypeError):
        return None


def clear(directory, role):
    with connection(directory) as con:
        con.execute('DELETE FROM guardian_runtime WHERE role=? AND pid=?', (role, os.getpid()))


def queue(directory, request):
    payload = json.dumps(request, ensure_ascii=True)
    if not isinstance(request.get('key'), str) or len(payload) > 16000:
        return False
    with connection(directory) as con:
        con.execute('DELETE FROM guardian_pending WHERE created<?', (time.time() - 300,))
        count = con.execute('SELECT COUNT(*) FROM guardian_pending').fetchone()[0]
        if count >= 16:
            return False
        con.execute('INSERT OR IGNORE INTO guardian_pending VALUES(?,?,?)', (request['key'], payload, time.time()))
    return True


def pending_keys(directory):
    with connection(directory) as con:
        return {row[0] for row in con.execute('SELECT key FROM guardian_pending')}


def take_requests(directory, targets):
    result = []
    with connection(directory) as con:
        con.execute('BEGIN IMMEDIATE')
        rows = con.execute('SELECT payload,created FROM guardian_pending ORDER BY created LIMIT 16').fetchall()
        con.execute('DELETE FROM guardian_pending')
    for raw, created in rows:
        try:
            value = json.loads(raw)
            app = targets.get(value.get('key'))
            if app is None or created < time.time() - 300:
                continue
            command = value.get('command')
            if command is not None and (not isinstance(command, list) or not command or not all(isinstance(s, str) and '\x00' not in s for s in command)
                    or not app_runtime.matches(app, command[0], command)):
                continue
            if not isinstance(value.get('pid'), int) or not isinstance(value.get('hwnd'), int):
                continue
            if value.get('cwd') and (not isinstance(value['cwd'], str) or '\x00' in value['cwd']):
                continue
            result.append({'key': app.key, 'name': app.name, 'exe': app.executable,
                           'pid': value['pid'], 'hwnd': value['hwnd'], 'started': value.get('started'),
                           'command': command, 'cwd': value.get('cwd') or ''})
        except (ValueError, TypeError, AttributeError):
            continue
    return result


def load_targets(directory):
    with connection(directory) as con:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='locked_apps'").fetchone():
            return {}
        return app_runtime.load_apps(con)


def spawn(main_script, *arguments):
    executable = Path(sys.executable).resolve()
    if os.name == 'nt' and executable.name.lower() == 'python.exe' and executable.with_name('pythonw.exe').is_file():
        executable = executable.with_name('pythonw.exe')
    command = [str(executable)]
    if not getattr(sys, 'frozen', False):
        command.append(str(Path(main_script).resolve()))
    command.extend(arguments)
    flags = (getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)) if os.name == 'nt' else 0
    return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            close_fds=True, creationflags=flags, cwd=str(Path(main_script).resolve().parent))
