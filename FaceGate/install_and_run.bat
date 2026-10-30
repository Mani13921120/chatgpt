@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
title FaceGate - Diagnostic Run
pushd "%~dp0" || (echo ERROR: Cannot open project folder.& pause & exit /b 1)
set "PROJECT=%CD%"
set "LOG=%PROJECT%\install_log.txt"
>"%LOG%" echo FaceGate log - %DATE% %TIME%
>>"%LOG%" echo Project: %PROJECT%
echo [1/6] Checking Python and project...
if not exist "%PROJECT%\main.py" (echo ERROR: main.py is missing.& >>"%LOG%" echo ERROR: main.py missing& pause& exit /b 1)
where py >nul 2>&1 || (echo ERROR: Python Launcher not found.& >>"%LOG%" echo ERROR: Python Launcher not found& pause& exit /b 1)
py -3.13 --version >>"%LOG%" 2>&1 || (echo ERROR: Python 3.13 x64 not found.& >>"%LOG%" echo ERROR: Python 3.13 x64 not found& pause& exit /b 1)
if not exist ".venv\Scripts\python.exe" (
  echo [2/6] Creating local Python environment...
  >>"%LOG%" echo Creating .venv at %DATE% %TIME%
  py -3.13 -m venv .venv >>"%LOG%" 2>&1
  if errorlevel 1 (echo ERROR: Could not create .venv. See install_log.txt.& pause& exit /b 1)
)
set "VPY=%PROJECT%\.venv\Scripts\python.exe"
echo [3/6] Checking runtime libraries...
"%VPY%" -c "import PySide6.QtWidgets, cv2, numpy, psutil, cryptography; print('Runtime imports OK')" >>"%LOG%" 2>&1
if errorlevel 1 (
  echo Installing runtime packages. First run may take several minutes...
  >>"%LOG%" echo Installing runtime dependencies at %DATE% %TIME%
  "%VPY%" -m pip install --disable-pip-version-check --prefer-binary --no-warn-script-location -r requirements.txt >>"%LOG%" 2>&1
  if errorlevel 1 (echo ERROR: Package installation failed. See install_log.txt.& pause& exit /b 1)
  "%VPY%" -c "import PySide6.QtWidgets, cv2, numpy, psutil, cryptography; print('Runtime imports OK after install')" >>"%LOG%" 2>&1
  if errorlevel 1 (echo ERROR: Packages installed but imports still fail. See install_log.txt.& pause& exit /b 1)
) else (
  echo Runtime packages are ready.
)
echo [4/6] Checking face models...
>>"%LOG%" echo Checking model files at %DATE% %TIME%
if not exist "models" mkdir "models" 2>nul
if not exist "models\face_detection_yunet_2023mar.onnx" (
  echo Downloading YuNet model...
  >>"%LOG%" echo Downloading YuNet model at %DATE% %TIME%
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 -Uri 'https://huggingface.co/opencv/opencv_zoo/resolve/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx' -OutFile 'models\face_detection_yunet_2023mar.onnx'; if ((Get-Item 'models\face_detection_yunet_2023mar.onnx').Length -lt 100000) { throw 'YuNet model download incomplete' }" >>"%LOG%" 2>&1
  if errorlevel 1 (echo ERROR: YuNet download failed or timed out. Check internet and install_log.txt.& >>"%LOG%" echo ERROR: YuNet download failed& pause& exit /b 1)
) else (echo YuNet model already exists.)
if not exist "models\face_recognition_sface_2021dec.onnx" (
  echo Downloading SFace model (about 39 MB)...
  >>"%LOG%" echo Downloading SFace model at %DATE% %TIME%
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 240 -Uri 'https://huggingface.co/opencv/opencv_zoo/resolve/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx' -OutFile 'models\face_recognition_sface_2021dec.onnx'; if ((Get-Item 'models\face_recognition_sface_2021dec.onnx').Length -lt 30000000) { throw 'SFace model download incomplete' }" >>"%LOG%" 2>&1
  if errorlevel 1 (echo ERROR: SFace download failed or timed out. Check internet and install_log.txt.& >>"%LOG%" echo ERROR: SFace download failed& pause& exit /b 1)
) else (echo SFace model already exists.)
echo [5/6] Launching FaceGate now...
>>"%LOG%" echo Launching app at %DATE% %TIME%
"%VPY%" -u "%PROJECT%\main.py" >>"%LOG%" 2>&1
set "APP_RC=%ERRORLEVEL%"
>>"%LOG%" echo App exited with code %APP_RC% at %DATE% %TIME%
if not "%APP_RC%"=="0" (echo ERROR: FaceGate exited with code %APP_RC%. Check install_log.txt.& pause& exit /b %APP_RC%)
echo [6/6] FaceGate closed normally.
pause
popd
endlocal
