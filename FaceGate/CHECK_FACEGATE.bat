@echo off
setlocal
cd /d "%~dp0"
echo Checking FaceGate Python dependencies...
"%~dp0.venv\Scripts\python.exe" -c "import PySide6.QtNetwork, cv2, numpy, psutil, cryptography, win32file, win32security; print('Dependencies: OK')"
if errorlevel 1 goto failed
echo Checking Python syntax...
"%~dp0.venv\Scripts\python.exe" -m py_compile "%~dp0main.py" "%~dp0folder_inplace_crypto.py" "%~dp0vault_crypto.py" "%~dp0folder_gate.py" "%~dp0folder_auth.py" "%~dp0instance_bridge.py" "%~dp0explorer_integration.py" "%~dp0explorer_router.py" "%~dp0windows_acl_policy.py"
if errorlevel 1 goto failed
echo Checking face models...
if not exist "%~dp0models\face_detection_yunet_2023mar.onnx" echo MISSING: models\face_detection_yunet_2023mar.onnx
if not exist "%~dp0models\face_recognition_sface_2021dec.onnx" echo MISSING: models\face_recognition_sface_2021dec.onnx
echo.
echo Code syntax and dependency imports passed. Missing model files must be downloaded separately.
pause
exit /b 0
:failed
echo.
echo FaceGate preflight check failed. Read the error above and run INSTALL_DEPENDENCIES.bat if needed.
pause
exit /b 1
