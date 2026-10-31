@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo First run install_and_run.bat and configure your face, PIN and protected folders.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" session_setup.py --explorer-only
if errorlevel 1 echo Explorer registration failed. Copy the error displayed above.
pause
