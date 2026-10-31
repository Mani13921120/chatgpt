@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo First run install_and_run.bat and configure your face, PIN and protected items.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" session_setup.py
if errorlevel 1 echo Setup failed. If Task Scheduler says access denied, run this file as administrator for the SAME Windows account.
pause
