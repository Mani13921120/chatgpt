@echo off
setlocal
cd /d "%~dp0"
set "VPY=%~dp0.venv\Scripts\python.exe"
if not exist "%VPY%" (
  echo FaceGate virtual environment not found. Run install_and_run.bat first.
  pause
  exit /b 1
)
"%VPY%" "%~dp0main.py" %*
if errorlevel 1 (
  echo FaceGate exited with an error. Keep this window open to read the message.
  pause
  exit /b 1
)
exit /b 0
