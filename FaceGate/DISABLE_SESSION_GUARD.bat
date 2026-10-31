@echo off
setlocal
cd /d "%~dp0"
".venv\Scripts\python.exe" session_setup.py --remove
pause
