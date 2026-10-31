"""Explicit, reversible current-user logon/unlock startup and Explorer routing."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

NS = 'http://schemas.microsoft.com/windows/2004/02/mit/task'


def task_xml(sid, executable, script):
    ET.register_namespace('', NS)
    def child(parent, name, text=None, **attrs):
        node = ET.SubElement(parent, '{'+NS+'}'+name, attrs)
        if text is not None:
            node.text = text
        return node
    root = ET.Element('{'+NS+'}Task', version='1.2')
    triggers = child(root, 'Triggers')
    logon = child(triggers, 'LogonTrigger')
    child(logon, 'Enabled', 'true'); child(logon, 'UserId', sid)
    unlock = child(triggers, 'SessionStateChangeTrigger')
    child(unlock, 'Enabled', 'true'); child(unlock, 'StateChange', 'SessionUnlock'); child(unlock, 'UserId', sid)
    principal = child(child(root, 'Principals'), 'Principal', id='CurrentUser')
    child(principal, 'UserId', sid); child(principal, 'LogonType', 'InteractiveToken'); child(principal, 'RunLevel', 'LeastPrivilege')
    settings = child(root, 'Settings')
    child(settings, 'MultipleInstancesPolicy', 'IgnoreNew')
    child(settings, 'DisallowStartIfOnBatteries', 'false'); child(settings, 'StopIfGoingOnBatteries', 'false')
    child(settings, 'ExecutionTimeLimit', 'PT0S'); child(settings, 'StartWhenAvailable', 'true')
    action = child(child(root, 'Actions', Context='CurrentUser'), 'Exec')
    child(action, 'Command', str(executable))
    child(action, 'Arguments', subprocess.list2cmdline([str(script), '--guardian']))
    child(action, 'WorkingDirectory', str(Path(script).parent))
    return ET.tostring(root, encoding='unicode')


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--remove', action='store_true')
    mode.add_argument('--explorer-only', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows only')
    import explorer_integration as shell
    import guardian_state as state
    directory = Path(os.environ['LOCALAPPDATA']) / 'FaceGate'
    directory.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve().with_name('main.py')
    executable = Path(sys.executable).resolve()
    pythonw = executable.with_name('pythonw.exe')
    if pythonw.is_file():
        executable = pythonw
    command = subprocess.list2cmdline([str(executable), str(script), '--explorer-open']) + ' "%1"'
    if args.explorer_only:
        shell.install_double_click(command, str(executable))
        print('Explorer double-click authentication enabled. RESTORE_EXPLORER.bat restores navigation.')
        return
    sid = subprocess.check_output(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'], text=True).strip()
    if not sid.startswith('S-1-') or not all(c in 'S-0123456789' for c in sid):
        raise RuntimeError('Invalid current user SID')
    task_name = 'FaceGateSession-' + sid
    if args.remove:
        result = subprocess.run(['schtasks.exe', '/Delete', '/TN', task_name, '/F'], capture_output=True, text=True)
        shell.uninstall()
        print('Explorer routing removed. Task deletion result:', result.returncode, result.stdout, result.stderr)
        print('Folder protection and guardian settings were not changed. Stop guardian in FaceGate with your PIN.')
        return
    xml = task_xml(sid, executable, script)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / 'startup.xml'
        path.write_text(xml, encoding='utf-16')
        subprocess.run(['schtasks.exe', '/Create', '/TN', task_name, '/XML', str(path), '/F'], check=True)
    shell.install_double_click(command, str(executable))
    state.set_enabled(directory, True)
    state.spawn(script, '--guardian')
    print('Installed: current-user logon + session unlock task, independent guardian, Explorer double-click routing.')
    print('Keep this installation folder in place. RESTORE_EXPLORER.bat can restore Explorer navigation.')


if __name__ == '__main__':
    main()
