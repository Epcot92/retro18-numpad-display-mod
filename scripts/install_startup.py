"""Install or update the Windows Startup launcher for the 8BitDo Retro 18 Numpad Display Daemon."""
import os
import pathlib
import sys


def install_startup() -> pathlib.Path:
    project_root = pathlib.Path(__file__).resolve().parent.parent
    display_script = project_root / "src" / "retro18_display.py"
    if not display_script.exists():
        raise FileNotFoundError(f"Could not find {display_script}")

    python_exe = pathlib.Path(sys.executable)
    pythonw_exe = python_exe.with_name("pythonw.exe")
    runner = pythonw_exe if pythonw_exe.exists() else python_exe

    vbs_content = (
        "' 8BitDo Retro 18 Mechanical Numpad Display Daemon Auto-Start\n"
        'Set WshShell = CreateObject("WScript.Shell")\n'
        f'WshShell.CurrentDirectory = "{project_root}"\n'
        f'WshShell.Run """{runner}"" ""{display_script}"" clock --format dashes", 0, False\n'
    )

    # Save a copy in scripts/ for reference
    local_vbs = project_root / "scripts" / "start_retro18_display.vbs"
    local_vbs.write_text(vbs_content, encoding="utf-8")

    # Install into the current user's Windows Startup folder
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA environment variable is not set")

    startup_dir = pathlib.Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    startup_vbs = startup_dir / "8BitDo_Retro18_Display.vbs"
    startup_vbs.write_text(vbs_content, encoding="utf-8")

    print(f"Created local launcher:   {local_vbs}")
    print(f"Installed Startup script: {startup_vbs}")
    print(f"Using Python runner:      {runner}")
    print(f"Target display script:    {display_script}")
    return startup_vbs


if __name__ == "__main__":
    install_startup()
