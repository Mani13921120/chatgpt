@echo off
setlocal
cd /d "%~dp0"
py -3.13 "%~dp0main.py" %*
if errorlevel 1 (
  echo.
  echo FaceGate exited with an error. Keep this window open to read the message.
  pause
)
