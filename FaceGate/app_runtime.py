"""Exact app identity matching and safe launch helpers; never match by basename alone."""
import ctypes
from ctypes import wintypes
import json
import ntpath
import os
from pathlib import Path
import subprocess
import time
from dataclasses import replace

from app_catalog import App, path_key, SHARED_HOSTS, internal_pid


def ensure_schema(con):
    con.execute('CREATE TABLE IF NOT EXISTS locked_app_details (path TEXT PRIMARY KEY COLLATE NOCASE, payload TEXT NOT NULL)')


def save_app(con, app):
    if not app.monitorable:
        raise ValueError('این مورد میزبان مستقل قابل پایش ندارد.')
    ensure_schema(con)
    con.execute('INSERT INTO locked_apps(path,display_name,enabled) VALUES(?,?,1) ON CONFLICT(path) DO UPDATE SET display_name=excluded.display_name,enabled=1', (app.key,app.name))
    con.execute('INSERT INTO locked_app_details VALUES(?,?) ON CONFLICT(path) DO UPDATE SET payload=excluded.payload', (app.key,app.to_json()))


def load_apps(con):
    ensure_schema(con)
    result = {}
    for key,name,payload in con.execute('SELECT a.path,a.display_name,d.payload FROM locked_apps a LEFT JOIN locked_app_details d ON d.path=a.path WHERE a.enabled=1'):
        if payload:
            try: app=App.from_json(payload)
            except (ValueError,TypeError): continue
            if app.key.casefold() != key.casefold(): continue
            app = replace(app,key=key,name=name)
        elif not key.startswith('start:'):
            app=App.desktop(key,name)
            app=App(key=key,name=name,executable=app.executable,process_paths=app.process_paths,sources=('legacy',))
        else: continue
        if app.monitorable: result[key]=app
    return result


def process_app_id(pid):
    if os.name != 'nt': return ''
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    query=kernel.GetApplicationUserModelId
    query.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.UINT),wintypes.LPWSTR];query.restype=wintypes.LONG
    handle=kernel.OpenProcess(0x1000,False,int(pid))
    if not handle:return ''
    try:
        length=wintypes.UINT()
        if query(handle,ctypes.byref(length),None)!=122 or not 0<length.value<4096:return ''
        value=ctypes.create_unicode_buffer(length.value)
        return value.value if query(handle,ctypes.byref(length),value)==0 else ''
    finally:kernel.CloseHandle(handle)


def matches(app, executable, command=(), app_id='', normalized_paths=None, normalized_executable=None):
    if executable and ntpath.basename(executable).casefold() in SHARED_HOSTS:return False
    if app_id and app.app_id and app_id.casefold()==app.app_id.casefold():return True
    # A real, different package identity must not fall back to a shared exe.
    if app.packaged and app_id:return False
    if not executable:return False
    paths = normalized_paths if normalized_paths is not None else {path_key(p) for p in app.process_paths}
    if (normalized_executable if normalized_executable is not None else path_key(executable)) not in paths:return False
    if app.arguments:
        args=tuple(command[1:])
        return len(args)>=len(app.arguments) and args[:len(app.arguments)]==app.arguments
    return True


def launch(app, override=None, cwd=None):
    if override and not app.packaged:
        if not isinstance(override,(list,tuple)) or not override or path_key(override[0]) not in {path_key(p) for p in app.process_paths}:
            raise ValueError('مسیر راه‌اندازی با برنامهٔ انتخاب‌شده مطابقت ندارد.')
        return subprocess.Popen(list(override),cwd=cwd or app.working_directory or str(Path(override[0]).parent),close_fds=True)
    if os.name=='nt' and app.app_id and not ntpath.isabs(app.app_id) and not app.app_id.lower().startswith(('exe:','lnk:')):
        os.startfile('shell:AppsFolder\\'+app.app_id)
        return None
    if os.name=='nt' and app.shortcut:
        os.startfile(app.shortcut)
        return None
    return subprocess.Popen([app.executable,*app.arguments],cwd=app.working_directory or str(Path(app.executable).parent),close_fds=True)


class Sessions:
    def __init__(self,clock=time.monotonic):self.clock=clock;self.authorized={}
    def grant(self,key):self.authorized[key]=self.clock()
    def revoke(self,key):self.authorized.pop(key,None)
    def observe(self,live_keys):
        now=self.clock()
        for key,last in list(self.authorized.items()):
            if key in live_keys:self.authorized[key]=now
            elif now-last>5:self.revoke(key)
    def allows(self,keys):return any(key in self.authorized for key in keys)


def window_pid(hwnd, resolve_host=False):
    if os.name != 'nt' or not hwnd:return 0
    user=ctypes.WinDLL('user32',use_last_error=True)
    user.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
    pid=wintypes.DWORD();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
    if resolve_host:
        callback=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HWND,wintypes.LPARAM)
        user.GetClassNameW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
        user.EnumChildWindows.argtypes=[wintypes.HWND,callback,wintypes.LPARAM]
        def visit(child,param):
            name=ctypes.create_unicode_buffer(256)
            user.GetClassNameW(child,name,len(name))
            if name.value=='Windows.UI.Core.CoreWindow':
                user.GetWindowThreadProcessId(child,ctypes.byref(pid));return False
            return True
        user.EnumChildWindows(hwnd,callback(visit),0)
    return int(pid.value)


def show_window(hwnd,restore):
    if os.name!='nt' or not hwnd:return
    user=ctypes.WinDLL('user32',use_last_error=True)
    user.ShowWindow.argtypes=[wintypes.HWND,ctypes.c_int]
    user.SetForegroundWindow.argtypes=[wintypes.HWND]
    user.ShowWindow(hwnd,9 if restore else 6)
    if restore:user.SetForegroundWindow(hwnd)


def foreground_window():
    if os.name != 'nt':
        return 0, None
    user = ctypes.WinDLL('user32', use_last_error=True)
    user.GetForegroundWindow.restype = wintypes.HWND
    hwnd = user.GetForegroundWindow()
    pid = window_pid(hwnd, True)
    if not pid:
        return int(hwnd or 0), None
    try:
        import psutil
        return int(hwnd), psutil.Process(pid).exe()
    except (psutil.Error, OSError):
        return int(hwnd), None
