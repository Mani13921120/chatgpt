@echo off
setlocal
cd /d "%~dp0"
echo Installing FaceGate dependencies for Python 3.13...
py -3.13 -m pip install --upgrade pip
if errorlevel 1 goto fallback
py -3.13 -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 goto failed
goto success
:fallback
echo Python launcher for 3.13 was not available; trying the active Python.
python -m pip install --upgrade pip
if errorlevel 1 goto failed
python -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 goto failed
:success
echo.
echo Dependencies installed. Run DOWNLOAD_MODELS.bat next if models are missing.
pause
exit /b 0
:failed
echo.
echo Dependency installation failed. Check Python and internet access.
pause
exit /b 1
