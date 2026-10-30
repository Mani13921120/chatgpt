@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0RESTORE_EXPLORER.ps1"
if errorlevel 1 (
  echo Explorer restoration failed. Keep this window open and report the error.
  pause
  exit /b 1
)
echo Close and reopen existing Explorer windows.
pause
exit /b 0
