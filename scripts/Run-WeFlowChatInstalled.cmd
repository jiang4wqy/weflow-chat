@echo off
setlocal

if not "%~1"=="" (
    exit /b 2
)

chcp 65001 >nul
set "INSTALL_ROOT=%~dp0.."
set "PYTHONUTF8=1"
set "PYTHONPATH=%INSTALL_ROOT%\src"
set "PATH=%INSTALL_ROOT%\runtime\node;%PATH%"

if not exist "%INSTALL_ROOT%\runtime\python\python.exe" exit /b 3
if not exist "%INSTALL_ROOT%\runtime\node\node.exe" exit /b 3

"%INSTALL_ROOT%\runtime\python\python.exe" -B -m weflow_chat.desktop_refresh
set "EXIT_CODE=%ERRORLEVEL%"

echo.
echo Task finished with exit code %EXIT_CODE%. No data processing is still running.
echo Press any key to close this window.
pause >nul
exit /b %EXIT_CODE%
