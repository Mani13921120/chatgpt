@echo off
setlocal
cd /d "%~dp0"
echo Downloading and verifying FaceGate ONNX models...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0DOWNLOAD_MODELS.ps1"
if errorlevel 1 goto failed
echo.
echo Model download and SHA256 verification completed successfully.
pause
exit /b 0
:failed
echo.
echo ERROR: Model download or SHA256 verification failed.
echo Check your internet connection and try again.
pause
exit /b 1
