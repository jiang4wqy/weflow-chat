@echo off
setlocal

if not "%~1"=="" (
    exit /b 2
)

chcp 65001 >nul
set "PYTHONUTF8=1"
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.."
set "REPO_ROOT=%CD%"
set "PYTHONPATH=%REPO_ROOT%\src"

"C:\Windows\py.exe" -3.12 -B -m weflow_chat.desktop_refresh
set "EXIT_CODE=%ERRORLEVEL%"
popd

echo.
echo Task finished with exit code %EXIT_CODE%. No data processing is still running.
echo Press any key to close this window.
pause >nul
exit /b %EXIT_CODE%
