$ErrorActionPreference = 'Stop'
$shellPath = 'Software\Classes\Directory\shell'
$statePath = 'Software\FaceGate\ExplorerIntegration'
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($shellPath, $true)
try {
    if ($null -ne $key -and $key.GetValue('') -eq 'FaceGateOpen') {
        $state = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($statePath)
        try {
            $raw = if ($null -ne $state) { $state.GetValue('PreviousDefault') } else { $null }
            $previous = if ($null -ne $raw) { ConvertFrom-Json -InputObject $raw } else { $null }
            if ($null -eq $previous -or $previous[0] -eq 'FaceGateOpen') {
                $key.DeleteValue('', $false)
            } else {
                $key.SetValue('', $previous[0], [Microsoft.Win32.RegistryValueKind][int]$previous[1])
            }
        } finally { if ($null -ne $state) { $state.Dispose() } }
    }
} finally { if ($null -ne $key) { $key.Dispose() } }
$state = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($statePath, $true)
try {
    if ($null -ne $state) { $state.DeleteValue('DoubleClickEnabled', $false) }
} finally { if ($null -ne $state) { $state.Dispose() } }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FaceGateShellRefresh {
    [DllImport("shell32.dll")] public static extern void SHChangeNotify(int e, uint f, IntPtr a, IntPtr b);
}
'@
[FaceGateShellRefresh]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host 'FaceGate default-folder override restored. Close and reopen Explorer windows.'
