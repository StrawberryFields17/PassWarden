@echo off
REM Build PassWarden as a single-file Windows EXE with icon
set SCRIPT_NAME=main.py
set APP_NAME=PassWarden
set ICON_PATH=assets\passwarden.ico

REM install pyinstaller if needed:
REM   python -m pip install pyinstaller

pyinstaller ^
  --name %APP_NAME% ^
  --onefile ^
  --windowed ^
  --icon %ICON_PATH% ^
  %SCRIPT_NAME%

echo.
echo Build complete. EXE is in the dist folder.
pause
