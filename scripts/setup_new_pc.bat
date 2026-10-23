@echo off
setlocal
echo ============================================================================
echo   8BitDo Retro 18 Mechanical Numpad - New PC Setup ^& Auto-Start Installer
echo ============================================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not installed or not on PATH!
    echo Please install Python 3.10+ from https://www.python.org/ or run:
    echo   winget install Python.Python.3.12
    pause
    exit /b 1
)

echo [1/3] Installing required USB HID and YouTube Music Lyrics libraries...
python -m pip install --upgrade hidapi syncedlyrics winrt-runtime winrt-Windows.Media.Control winrt-Windows.Foundation winrt-Windows.Foundation.Collections
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install hidapi!
    pause
    exit /b 1
)

echo.
echo [2/3] Installing Windows Startup script (runs silently on login)...
python "%~dp0install_startup.py"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install Startup script!
    pause
    exit /b 1
)

echo.
echo [3/3] Starting 8BitDo Retro 18 Display Daemon in background now...
wscript.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\8BitDo_Retro18_Display.vbs"

echo.
echo ============================================================================
echo   Setup Complete! Your Retro 18 Numpad display is now running and will
echo   start automatically every time you log into Windows.
echo ============================================================================
pause
