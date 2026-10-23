' 8BitDo Retro 18 Mechanical Numpad Display Daemon Auto-Start
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "D:\GEMINI_ANTI\retro18-numpad-display-mod"
WshShell.Run """C:\Program Files\Python311\pythonw.exe"" ""D:\GEMINI_ANTI\retro18-numpad-display-mod\src\retro18_display.py"" clock --format dashes", 0, False
