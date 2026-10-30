# FaceGate: deliberately manual policy deployment helper.
# Run only after reviewing the XML and testing it on a non-critical device.
# Requires an elevated PowerShell session and a Windows edition/configuration supporting AppLocker.
$ErrorActionPreference = 'Stop'
$policy = Join-Path $PSScriptRoot 'FaceGate-AppLocker-Enforce.xml'
if (-not (Test-Path $policy)) {
  Write-Host 'Place your reviewed FaceGate-AppLocker-Enforce.xml next to this script.' -ForegroundColor Yellow
  exit 2
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error 'Open PowerShell as Administrator, then run this script again.'
  exit 3
}
$confirm = Read-Host 'This applies AppLocker rules and can block selected EXEs. Type APPLY to continue'
if ($confirm -cne 'APPLY') { Write-Host 'Cancelled; no policy was changed.'; exit 0 }
$backup = Join-Path $PSScriptRoot ('AppLocker-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.xml')
try {
  Get-AppLockerPolicy -Local -Xml | Set-Content -LiteralPath $backup -Encoding Unicode
} catch {
  Write-Warning "Could not export existing local policy: $($_.Exception.Message)"
  $continue = Read-Host 'Continue without a policy backup? Type YES to continue'
  if ($continue -cne 'YES') { exit 4 }
}
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc
Set-AppLockerPolicy -XmlPolicy $policy -Merge
Write-Host "Policy imported. Backup (if created): $backup" -ForegroundColor Green
Write-Host 'Review Event Viewer > Applications and Services Logs > Microsoft > Windows > AppLocker.'
Write-Host 'To restore, use the saved backup XML with Set-AppLockerPolicy -XmlPolicy <backup.xml> -Merge, after reviewing it.'
