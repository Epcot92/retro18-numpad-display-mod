@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
cd /d "%~dp0.."

REM If Rust / Cargo is installed, use the native Ratatui crate; otherwise run the instant zero-dependency TUI Studio
where cargo >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo Launching Rust Ratatui TUI Studio...
    cd /d "%~dp0..\retro18-tui"
    cargo run --release
) else (
    python "%~dp0..\src\retro18_tui.py"
)
