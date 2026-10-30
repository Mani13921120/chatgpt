@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
title FaceGate - Build EXE
pushd "%~dp0" || (echo ERROR: Cannot open project folder.& pause & exit /b 1)
set "PROJECT=%CD%"
set "VPY=%PROJECT%\.venv\Scripts\python.exe"
set "LOG=%PROJECT%\build_log.txt"
if not exist "%VPY%" (
  echo ERROR: Virtual environment not found. Run install_and_run.bat first.
  pause
  popd
  exit /b 1
)
if not exist "main.py" (
  echo ERROR: main.py is missing.
  pause
  popd
  exit /b 1
)
if not exist "models\face_detection_yunet_2023mar.onnx" (
  echo ERROR: YuNet model missing. Run install_and_run.bat first.
  pause
  popd
  exit /b 1
)
if not exist "models\face_recognition_sface_2021dec.onnx" (
  echo ERROR: SFace model missing. Run install_and_run.bat first.
  pause
  popd
  exit /b 1
)
>"%LOG%" echo FaceGate build log - %DATE% %TIME%
echo Checking PyInstaller...
"%VPY%" -m pip install --disable-pip-version-check --no-cache-dir --prefer-binary "pyinstaller>=6.11,<7" >>"%LOG%" 2>&1
if errorlevel 1 (
  echo ERROR: PyInstaller installation failed. See build_log.txt
  pause
  popd
  exit /b 1
)
echo Building FaceGate. This may take several minutes...
"%VPY%" -m PyInstaller --noconfirm --clean --windowed --name FaceGate --collect-all cv2 --collect-all PySide6 --add-data "models;models" main.py >>"%LOG%" 2>&1
if errorlevel 1 (
  echo ERROR: Build failed. See build_log.txt
  pause
  popd
  exit /b 1
)
if not exist "dist\FaceGate\FaceGate.exe" (
  echo ERROR: EXE not found after build. See build_log.txt
  pause
  popd
  exit /b 1
)
echo.
echo Build successful: %PROJECT%\dist\FaceGate\FaceGate.exe
pause
popd
endlocal
