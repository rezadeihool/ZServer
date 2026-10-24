@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-windows.ps1" %*
set "BUILD_EXIT=%ERRORLEVEL%"
if not "%BUILD_EXIT%"=="0" (
  echo.
  echo BUILD FAILED with exit code %BUILD_EXIT%.
  pause
  exit /b %BUILD_EXIT%
)
echo.
echo BUILD SUCCEEDED.
pause
exit /b 0
