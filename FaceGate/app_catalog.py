"""Current-user Windows Start catalog. IDs, launch arguments and providers survive merging."""
from dataclasses import dataclass, asdict
import base64
import json
import ntpath
import os
from pathlib import Path
import subprocess
import threading
import unicodedata

_INTERNAL_PIDS = set()
_INTERNAL_LOCK = threading.Lock()
SHARED_HOSTS = {'explorer.exe','applicationframehost.exe','runtimebroker.exe','svchost.exe',
                'rundll32.exe','dllhost.exe','sihost.exe','taskhostw.exe','winlogon.exe','csrss.exe',
                'lsass.exe','services.exe','smss.exe','dwm.exe','startmenuexperiencehost.exe',
                'shellexperiencehost.exe','searchhost.exe'}


def path_key(path):
    if not path:
        return ''
    return ntpath.normcase(os.path.realpath(os.path.abspath(path))) if os.name == 'nt' else ntpath.normcase(path)


def internal_pid(pid):
    with _INTERNAL_LOCK:
        return pid in _INTERNAL_PIDS or pid == os.getpid()


def internal_command(command, main_script=None):
    if not command:return False
    name=ntpath.basename(command[0]).casefold()
    if name=='powershell.exe' and len(command)==7:
        expected=['-nologo','-noprofile','-noninteractive','-sta','-encodedcommand']
        if [s.casefold() for s in command[1:6]]==expected:
            return command[6]==base64.b64encode(CATALOG_SCRIPT.encode('utf-16le')).decode('ascii')
    if name in {'python.exe','pythonw.exe'} and len(command)>1 and main_script:
        return path_key(command[1])==path_key(str(main_script))
    return False


def search_key(text):
    text = unicodedata.normalize('NFKC', text).casefold().replace('ي','ی').replace('ك','ک')
    return ''.join(c for c in text if unicodedata.category(c) != 'Cf').strip()


def split_arguments(value):
    """Windows command-line argument rules (without an executable argv[0])."""
    result = []; i = 0
    while i < len(value):
        while i < len(value) and value[i] in ' \t': i += 1
        if i == len(value): break
        out = []; quoted = False
        while i < len(value):
            if not quoted and value[i] in ' \t': break
            slashes = 0
            while i < len(value) and value[i] == '\\': slashes += 1; i += 1
            if i < len(value) and value[i] == '"':
                out.extend('\\' * (slashes // 2))
                if slashes % 2: out.append('"'); i += 1
                elif quoted and i + 1 < len(value) and value[i + 1] == '"': out.append('"'); i += 2
                else: quoted = not quoted; i += 1
            else:
                out.extend('\\' * slashes)
                if i < len(value) and (quoted or value[i] not in ' \t'):
                    out.append(value[i]); i += 1
        result.append(''.join(out))
    return tuple(result)


@dataclass(frozen=True)
class App:
    key: str
    name: str
    app_id: str = ''
    executable: str = ''
    arguments: tuple = ()
    shortcut: str = ''
    working_directory: str = ''
    process_paths: tuple = ()
    sources: tuple = ()

    @property
    def packaged(self):
        return '!' in self.app_id and not self.app_id.lower().startswith(('exe:', 'lnk:'))

    @property
    def monitorable(self):
        if self.executable and ntpath.basename(self.executable).casefold() in SHARED_HOSTS:
            return False
        return self.packaged or any(ntpath.basename(p).casefold() not in SHARED_HOSTS for p in self.process_paths)

    def to_json(self):
        return json.dumps(asdict(self), ensure_ascii=True)

    @classmethod
    def from_json(cls, value):
        data = json.loads(value) if isinstance(value, str) else dict(value)
        for key in ('arguments','process_paths','sources'):
            data[key] = tuple(data.get(key) or ())
        return cls(**data)

    @classmethod
    def desktop(cls, path, name=None):
        return cls(key=path_key(path), name=name or ntpath.splitext(ntpath.basename(path))[0],
                   executable=path, process_paths=(path,), sources=('manual',))


def parse_catalog(value):
    if not isinstance(value, dict) or not isinstance(value.get('apps'), list):
        raise RuntimeError('پاسخ فهرست برنامه‌های ویندوز معتبر نیست.')
    found = {}
    for row in value['apps']:
        if not isinstance(row, dict): continue
        app_id = str(row.get('id') or '').strip()
        name = str(row.get('name') or '').strip()
        if not app_id or not name or '\x00' in app_id: continue
        executable = str(row.get('executable') or '')
        paths = [str(p) for p in (row.get('process_paths') or []) if isinstance(p,str) and p]
        if executable and executable not in paths and row.get('path_unique', True): paths.append(executable)
        sources = tuple(str(s) for s in (row.get('sources') or []))
        candidate = App(key='start:' + app_id.casefold(), name=name, app_id=app_id,
                        executable=executable, arguments=split_arguments(str(row.get('arguments') or '')),
                        shortcut=str(row.get('shortcut') or ''), working_directory=str(row.get('working_directory') or ''),
                        process_paths=tuple(dict.fromkeys(paths)), sources=sources)
        old = found.get(candidate.key)
        if old:
            candidate = App(key=old.key, name=old.name,
                            app_id=old.app_id, executable=old.executable or candidate.executable,
                            arguments=old.arguments or candidate.arguments, shortcut=old.shortcut or candidate.shortcut,
                            working_directory=old.working_directory or candidate.working_directory,
                            process_paths=tuple(dict.fromkeys(old.process_paths+candidate.process_paths)),
                            sources=tuple(dict.fromkeys(old.sources+candidate.sources)))
        found[candidate.key] = candidate
    # Merge extra shortcut copies only if the actual name, executable AND args
    # match. Different app IDs, profiles and same-name products remain distinct.
    result = []
    primary = [app for app in found.values() if not app.app_id.lower().startswith('lnk:')]
    for app in found.values():
        duplicate = app.app_id.lower().startswith('lnk:') and any(
            search_key(other.name) == search_key(app.name) and app.executable
            and path_key(other.executable) == path_key(app.executable) and other.arguments == app.arguments
            for other in primary)
        if not duplicate: result.append(app)
    return sorted(result, key=lambda a: (search_key(a.name), a.key)), value.get('warnings') or []


def discover(cancel=None):
    if os.name != 'nt':
        return [], ['این فهرست فقط روی ویندوز در دسترس است.']
    encoded = base64.b64encode(CATALOG_SCRIPT.encode('utf-16le')).decode('ascii')
    command = ['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-STA','-EncodedCommand',encoded]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    with _INTERNAL_LOCK: _INTERNAL_PIDS.add(process.pid)
    try:
        for _ in range(120):
            if cancel is not None and cancel.is_set():
                process.terminate(); process.communicate(timeout=5)
                return [], ['دریافت فهرست لغو شد.']
            try:
                output, error = process.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired: pass
        else:
            process.kill(); process.communicate()
            raise RuntimeError('دریافت فهرست ویندوز بیش از حد طول کشید؛ دوباره تلاش کن.')
        if process.returncode:
            raise RuntimeError('ویندوز نتوانست فهرست برنامه‌ها را برگرداند؛ دوباره تلاش کن.')
        try:
            return parse_catalog(json.loads(output.decode('utf-8-sig')))
        except (ValueError, UnicodeError) as exc:
            raise RuntimeError('پاسخ فهرست ویندوز خوانا نبود؛ دوباره تلاش کن.') from exc
    finally:
        with _INTERNAL_LOCK: _INTERNAL_PIDS.discard(process.pid)
        if process.poll() is None:
            process.kill(); process.wait(timeout=5)


CATALOG_SCRIPT = r'''
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $WarningPreference='SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$apps=@{}; $warnings=[System.Collections.Generic.List[string]]::new()
function Add-App($id,$name,$exe,$argsText,$shortcut,$working,$source) {
  if ([string]::IsNullOrWhiteSpace($id) -or [string]::IsNullOrWhiteSpace($name)) { return }
  if (-not $apps.ContainsKey($id)) {
    $apps[$id]=@{id=$id;name=$name;executable='';arguments='';shortcut='';working_directory='';process_paths=@();sources=@();path_unique=$true}
  }
  $a=$apps[$id]
  if ($exe -and -not $a.executable) {$a.executable=$exe}
  if ($argsText -and -not $a.arguments) {$a.arguments=$argsText}
  if ($shortcut -and -not $a.shortcut) {$a.shortcut=$shortcut}
  if ($working -and -not $a.working_directory) {$a.working_directory=$working}
  if ($source -notin $a.sources) {$a.sources+=@($source)}
}
try {Get-StartApps | ForEach-Object {Add-App ([string]$_.AppID) ([string]$_.Name) '' '' '' '' 'Start'}}
catch {$warnings.Add('Get-StartApps unavailable')}
$shell=$null
try {
 $shell=New-Object -ComObject Shell.Application
 $folder=$shell.Namespace('shell:AppsFolder')
 if ($null -eq $folder) {throw 'AppsFolder unavailable'}
 foreach ($item in $folder.Items()) {
  $id=[string]$item.ExtendedProperty('System.AppUserModel.ID'); if (-not $id) {$id=[string]$item.Path}
  $target=[string]$item.ExtendedProperty('System.Link.TargetParsingPath')
  $arg=[string]$item.ExtendedProperty('System.Link.Arguments')
  if ($target -and -not $target.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)) {$target=''}
  Add-App $id ([string]$item.Name) $target $arg '' '' 'AppsFolder'
 }
} catch {$warnings.Add('AppsFolder unavailable')}
try {
 $wsh=New-Object -ComObject WScript.Shell
 $roots=@([Environment]::GetFolderPath('Programs'),[Environment]::GetFolderPath('CommonPrograms')) | Select-Object -Unique
 foreach ($root in $roots) {
  if (-not $root -or -not (Test-Path -LiteralPath $root)) {continue}
  Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
   $link=$wsh.CreateShortcut($_.FullName); $target=[Environment]::ExpandEnvironmentVariables([string]$link.TargetPath)
   if (-not $target.EndsWith('.exe',[StringComparison]::OrdinalIgnoreCase)) {return}
   $id=''; $display=$_.BaseName
   if ($shell) {
    $parent=$shell.Namespace($_.DirectoryName)
    if ($parent) {$item=$parent.ParseName($_.Name); $id=[string]$item.ExtendedProperty('System.AppUserModel.ID'); if ($item.Name) {$display=[string]$item.Name}}
   }
   if (-not $id) {
    $matches=@($apps.Values | Where-Object {$_.name -eq $display})
    if ($matches.Count -eq 1) {$id=$matches[0].id} else {$id='lnk:'+ $_.FullName}
   }
   Add-App $id $display $target ([string]$link.Arguments) $_.FullName ([string]$link.WorkingDirectory) 'Shortcut'
  }
 }
} catch {$warnings.Add('Start shortcuts unavailable')}
try {
 foreach ($package in Get-AppxPackage) {
  $prefix=$package.PackageFamilyName+'!'
  $selected=@($apps.Keys | Where-Object {$_.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)})
  if (-not $selected.Count) {continue}
  try {
   $manifest=Get-AppxPackageManifest -Package $package.PackageFullName
   $all=@($manifest.Package.Applications.Application)
   foreach ($entry in $all) {
    $id=$prefix+[string]$entry.Id
    if (-not $apps.ContainsKey($id)) {continue}
    $exe=[Environment]::ExpandEnvironmentVariables([string]$entry.Executable)
    if (-not $exe -or $exe -match '\$') {continue}
    if (-not [IO.Path]::IsPathRooted($exe)) {$exe=Join-Path $package.InstallLocation $exe}
    $shared=@($all | Where-Object {[string]$_.Executable -eq [string]$entry.Executable}).Count -gt 1
    if (-not $shared) {$apps[$id].process_paths=@($exe)} else {$apps[$id].path_unique=$false}
    if (-not $apps[$id].executable) {$apps[$id].executable=$exe}
   }
  } catch {}
 }
} catch {$warnings.Add('Package metadata unavailable')}
@{apps=@($apps.Values);warnings=@($warnings)} | ConvertTo-Json -Depth 6 -Compress
'''
