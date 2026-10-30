@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import explorer_integration; explorer_integration.uninstall(); print('Previous Explorer setting restored.')"
) else (
  py -3.13 -c "import explorer_integration; explorer_integration.uninstall(); print('Previous Explorer setting restored.')"
)
if errorlevel 1 (
  echo Explorer restore failed. Keep this folder and the registry recovery settings.
  pause
  exit /b 1
)
pause
exit /b 0
