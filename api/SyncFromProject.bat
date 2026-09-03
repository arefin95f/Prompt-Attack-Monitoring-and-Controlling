@echo off
cd /d "%~dp0\.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sync_from_project.ps1"
if errorlevel 1 (
  echo Sync failed.
  pause
  exit /b 1
)
echo.
pause
