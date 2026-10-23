# 8BitDo Retro 18 Mechanical Numpad Display Hack & Mod

*THIS IS A FIRMWARE LEVEL HACK. AS-IS/NO WARRANTY. THIS COULD POSSIBLY VOID YOUR WARRANTY*

Reverse engineering, custom firmware injection, and multi-mode host display driver for the **8BitDo Retro 18 Mechanical Numpad** (`USB\VID_2DC8&PID_5203`).

Turns the stock 9-digit 7-segment LED screen into an active, multi-mode smart display with an interactive TUI studio, live lyrics sync, stock tickers, and hardware button intercepting.

---

## Features

- **Live 24-Hour / 12-Hour Clock**: Stream real-time `HH-MM-SS` or `HH.MM.SS` clock to the 7-segment display.
- **Hardware Calculator Button Hijacking**: The physical Windows Calculator shortcut key on the numpad is intercepted at the firmware level (`*0x00844d50` bit 3), suppressing `calc.exe` and cycling display modes instead.
- **Live YouTube Music Synced Lyrics**: Listens to Windows Media Transport Controls (`Windows.Media.Control`), auto-fetches millisecond-synced `.lrc` lyrics, and punches in words dynamically across the 9 digits with micro-timing adjustment (`[` and `]`).
- **Live Stock & Crypto Ticker**: Real-time quote ticker (`DIS`, `FUN`, `SPY`, `VOO`, `VXX`, `RCL`, `NVDA`, `KO`) smoothly scrolling across the screen.
- **Interactive TUI Studio (Ratatui / Python)**: Built with Rust `ratatui` (0.30) & zero-dep Python fallback:
  - Live 9-digit ASCII 7-segment preview (`━━`, `┃`, `•`)
  - Marquee repeat modes (`Static`, `1x`, `2x`, `3x`, `5x`, `Continuous`)
  - Customizable hotkey triggers (`F1`–`F9` / `Ctrl+S`)
- **System Resource Monitor**: Live CPU% and RAM% (`C 18 r 45`).
- **Priority Notification API**: Push instant scrolling messages from any script or terminal over local UDP:
  ```powershell
  python src/retro18_display.py notify "HELLO WORLD"
  ```
- **Firmware Patch & Flasher**:
  - Injects a 64-byte vendor USB command (`0x81 0xD0`) at Flash `0x21200`
  - Telink IEEE CRC32 trailer calculation
  - Custom OTA flasher leveraging the 8BitDo bootloader protocol (`0x00C1`–`0x00C4`)

---

## Project Structure

```
├── src/
│   ├── retro18_display.py       # Core HID interface & daemon
│   ├── retro18_tui.py           # Zero-dependency Python TUI Studio
│   ├── retro18_lyrics.py        # YouTube Music / Windows Media synced lyrics engine
│   ├── patch_retro18_fw.py      # TC32 firmware binary patcher & Yichip encryptor
│   └── flash_retro18_fw.py      # USB OTA flasher for Telink MCU
├── retro18-tui/                 # Native Rust Ratatui (v0.30) TUI Studio
│   ├── Cargo.toml
│   └── src/main.rs
├── scripts/
│   ├── setup_new_pc.bat         # Automated one-click setup script
│   ├── launch_tui.bat           # Launcher for TUI Studio
│   └── install_startup.py       # Windows Startup daemon installer
└── tests/
    └── test_retro18_display.py  # Unit tests
```

---

## Quick Start

### 1. Requirements
- Windows 10/11
- Python 3.10+
- `pip install hidapi winrt-runtime winrt-Windows.Media.Control winrt-Windows.Foundation winrt-Windows.Foundation.Collections syncedlyrics`

### 2. Run the Display Daemon
```powershell
python src/retro18_display.py clock --format dashes
```

Press the **Windows Calculator** key on the numpad to cycle modes:
1. Live Clock (`HH-MM-SS`)
2. Current Date (`MM-DD-YY`)
3. Live CPU & RAM % (`C xx r yy`)
4. Scrolling Stock Ticker
5. YouTube Music Live Synced Lyrics
6. Display Off / Stealth

### 3. Launch TUI Studio
```powershell
python src/retro18_display.py tui
# or double click scripts\launch_tui.bat
```

---

## License
Apache 2.0
