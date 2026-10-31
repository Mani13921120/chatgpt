@echo off
setlocal
cd /d "%~dp0"
".venv\Scripts\python.exe" -u validate_explorer_session.py
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" echo Explorer session validation FAILED. Copy the error displayed above.
pause
exit /b %RESULT%
