@echo off
setlocal
cd /d "%~dp0"
set "VPY=%~dp0.venv\Scripts\python.exe"
if not exist "%VPY%" (
  py -3.13 -m venv "%~dp0.venv"
  if errorlevel 1 goto failed
)
"%VPY%" -m pip install --disable-pip-version-check --prefer-binary -r "%~dp0requirements.txt"
if errorlevel 1 goto failed
echo Dependencies installed in the FaceGate virtual environment.
echo Run RUN_FACEGATE.bat to start the app.
pause
exit /b 0
:failed
echo Dependency installation failed. Python 3.13 x64 and internet access are required.
pause
exit /b 1
