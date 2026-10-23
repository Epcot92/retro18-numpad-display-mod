"""Host controller and multi-mode display daemon for the 8BitDo Retro 18 Mechanical Numpad (VID 0x2DC8, PID 0x5203).

Supports:
  - Encoding arbitrary strings, numbers, dates, system stats, and live clocks (`HH-MM-SS`, `HH.MM.SS`) into the
    exact 9-byte 7-segment framebuffer format (`0x00844644`) used by the Retro 18 Numpad's TM16xx/AIP16xx LED driver.
  - Sending real-time display updates over USB HID (`UsagePage 0xFFA0`, Report ID `0x81`, Command `0xD0`).
  - Intercepting the physical Windows Calculator shortcut button (`VK_LAUNCH_APP2` / `0xB7`) via a Win32 low-level
    keyboard hook so pressing it cycles the numpad screen through:
      1. 24-Hour Live Clock (` 20-24-00`)
      2. Current Date (` 10-22-26`)
      3. Live CPU & RAM Usage (`C 18 r 45`)
      4. Display Off / Stealth Mode
    (Hold Shift + Calculator button if you still want to launch the Windows Calculator app.)
"""
from __future__ import annotations

import argparse
from collections import deque
import ctypes
from ctypes import wintypes
import datetime
import json
import socket
import threading
import time
import urllib.request
from typing import Callable, Sequence

import hid

VID_8BITDO = 0x2DC8
PID_RETRO18 = 0x5203
VENDOR_USAGE_PAGE = 0xFFA0
REPORT_ID_OUT = 0x81
REPORT_ID_IN = 0x02
CMD_DISPLAY = 0xD0
NOTIFY_UDP_PORT = 18818
DEFAULT_TICKERS: tuple[str, ...] = ("DIS", "FUN", "SPY", "VOO", "VXX", "RCL", "NVDA", "KO")

# 7-segment bit mapping confirmed from firmware functions 0x14bcc, 0x14c20, and 0x14b14:
#   Bit 0 (0x01): Segment A (Top)
#   Bit 1 (0x02): Segment B (Top-Right)
#   Bit 2 (0x04): Segment C (Bottom-Right)
#   Bit 3 (0x08): Segment D (Bottom)
#   Bit 4 (0x10): Segment E (Bottom-Left)
#   Bit 5 (0x20): Segment F (Top-Left)
#   Bit 6 (0x40): Segment G (Middle)
#   Bit 7 (0x80): Segment DP (Decimal Point)
SEG7_FONT: dict[str, int] = {
    " ": 0x00,
    "0": 0x3F,
    "1": 0x06,
    "2": 0x5B,
    "3": 0x4F,
    "4": 0x66,
    "5": 0x6D,
    "6": 0x7D,
    "7": 0x07,
    "8": 0x7F,
    "9": 0x6F,
    "-": 0x40,
    "_": 0x08,
    "=": 0x48,
    "A": 0x77,
    "a": 0x77,
    "B": 0x7C,
    "b": 0x7C,
    "C": 0x39,
    "c": 0x58,
    "D": 0x5E,
    "d": 0x5E,
    "E": 0x79,
    "e": 0x79,
    "F": 0x71,
    "f": 0x71,
    "G": 0x3D,
    "g": 0x6F,
    "H": 0x76,
    "h": 0x74,
    "I": 0x06,
    "i": 0x04,
    "J": 0x1E,
    "j": 0x1E,
    "K": 0x75,
    "k": 0x75,
    "L": 0x38,
    "l": 0x30,
    "M": 0x37,
    "m": 0x54,
    "N": 0x54,
    "n": 0x54,
    "O": 0x3F,
    "o": 0x5C,
    "P": 0x73,
    "p": 0x73,
    "Q": 0x67,
    "q": 0x67,
    "R": 0x50,
    "r": 0x50,
    "S": 0x6D,
    "s": 0x6D,
    "T": 0x78,
    "t": 0x78,
    "U": 0x3E,
    "u": 0x1C,
    "V": 0x3E,
    "v": 0x1C,
    "W": 0x3E,
    "w": 0x1C,
    "X": 0x76,
    "x": 0x76,
    "Y": 0x6E,
    "y": 0x6E,
    "Z": 0x5B,
    "z": 0x5B,
    ":": 0x48,
    "/": 0x52,
    "!": 0x86,
    "?": 0x53,
}


def encode_7seg_sequence(text: str) -> list[int]:
    """Encode a string of arbitrary length into a sequence of 7-segment bytes (with '.' merging)."""
    digits: list[int] = []
    for ch in text:
        if ch == ".":
            if digits and not (digits[-1] & 0x80):
                digits[-1] |= 0x80
            else:
                digits.append(0x80)
        else:
            digits.append(SEG7_FONT.get(ch, 0x00))
    return digits


def generate_scroll_frames(text: str, pad_lead: int = 9, pad_trail: int = 9) -> list[bytes]:
    """Generate 9-byte sliding window frames for scrolling `text` right-to-left across the 9-digit screen."""
    seq = [0x00] * pad_lead + encode_7seg_sequence(text) + [0x00] * pad_trail
    if len(seq) < 9:
        seq = seq + [0x00] * (9 - len(seq))
    return [bytes(seq[i : i + 9]) for i in range(len(seq) - 9 + 1)]


def encode_7seg_text(text: str, align: str = "right") -> bytes:
    """Encode a string into 9 bytes for the Retro 18's 9-digit 7-segment display."""
    if align not in ("left", "right", "center"):
        raise ValueError(f"Invalid align {align!r}; must be 'left', 'right', or 'center'")

    digits: list[int] = []
    for ch in text:
        if ch == ".":
            if digits and not (digits[-1] & 0x80):
                digits[-1] |= 0x80
            else:
                digits.append(0x80)
        else:
            digits.append(SEG7_FONT.get(ch, 0x00))

    if len(digits) > 9:
        digits = digits[:9]
    elif len(digits) < 9:
        pad = 9 - len(digits)
        if align == "left":
            digits = digits + [0x00] * pad
        elif align == "right":
            digits = [0x00] * pad + digits
        else:
            left_pad = pad // 2
            right_pad = pad - left_pad
            digits = [0x00] * left_pad + digits + [0x00] * right_pad

    return bytes(digits)


def format_ascii_preview(seg_bytes: Sequence[int]) -> str:
    """Return a compact human-readable representation of a 9-byte 7-segment buffer."""
    inv = {v: k for k, v in SEG7_FONT.items() if k.isupper() or k in " -_="}
    for d in "0123456789":
        inv[SEG7_FONT[d]] = d
    inv[0x50] = "r"
    inv[0x5C] = "o"
    inv[0x74] = "h"
    inv[0x54] = "n"
    inv[0x78] = "t"
    inv[0x1C] = "u"
    parts = []
    for b in seg_bytes:
        base = b & 0x7F
        dot = "." if (b & 0x80) else ""
        ch = inv.get(base, "?")
        parts.append(f"{ch}{dot}")
    return "[" + "|".join(parts) + "]"


def format_cpu_ram_text(cpu_percent: int, ram_percent: int) -> str:
    """Format CPU and RAM usage percentages into a 9-character 7-segment string (`C 18 r 45`)."""
    c = max(0, min(100, int(cpu_percent)))
    r = max(0, min(100, int(ram_percent)))
    return f"C{c:3d} r{r:3d}"


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


class SystemStatsMonitor:
    """Zero-dependency Windows CPU & RAM usage monitor using kernel32 APIs."""

    def __init__(self) -> None:
        self._kernel32 = ctypes.windll.kernel32
        self._prev_idle = 0
        self._prev_total = 0
        self._last_cpu = 0
        self.sample()

    @staticmethod
    def _ft_to_int(ft: _FILETIME) -> int:
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    def sample(self) -> tuple[int, int]:
        """Return `(cpu_percent, ram_percent)`."""
        idle_ft = _FILETIME()
        kernel_ft = _FILETIME()
        user_ft = _FILETIME()
        if self._kernel32.GetSystemTimes(
            ctypes.byref(idle_ft), ctypes.byref(kernel_ft), ctypes.byref(user_ft)
        ):
            idle = self._ft_to_int(idle_ft)
            total = self._ft_to_int(kernel_ft) + self._ft_to_int(user_ft)
            d_total = total - self._prev_total
            d_idle = idle - self._prev_idle
            self._prev_total = total
            self._prev_idle = idle
            if d_total > 0:
                busy = max(0, d_total - d_idle)
                self._last_cpu = int(round((busy * 100.0) / d_total))

        mem = _MEMORYSTATUSEX()
        mem.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        ram_pct = 0
        if self._kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
            ram_pct = int(mem.dwMemoryLoad)

        return self._last_cpu, ram_pct


def format_ticker_item(symbol: str, price: float) -> str:
    """Format a stock/crypto symbol and price into a clean 7-segment ticker item (`NVDA 142.50`)."""
    clean_sym = symbol.upper().replace("-USD", "")
    if price >= 1000.0:
        return f"{clean_sym} {price:.0f}"
    return f"{clean_sym} {price:.2f}"


class StockTickerMonitor:
    """Background live stock & crypto quote fetcher (NVDA, AAPL, MSFT, SPY, BTC) with caching."""

    def __init__(self, symbols: Sequence[str] = DEFAULT_TICKERS, refresh_sec: float = 60.0) -> None:
        self.symbols = list(symbols)
        self.refresh_sec = refresh_sec
        self._lock = threading.Lock()
        self._banner_text = "   ".join(s.replace("-USD", "") for s in self.symbols)
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._started = False

    def start(self) -> None:
        if not self._started:
            self._started = True
            self._thread.start()

    def get_banner(self) -> str:
        with self._lock:
            return self._banner_text

    def fetch_once(self) -> dict[str, float]:
        """Fetch latest quotes from Yahoo Finance v8 chart endpoint (or Coinbase for BTC-USD fallback)."""
        quotes: dict[str, float] = {}
        headers = {"User-Agent": "Mozilla/5.0"}
        for sym in self.symbols:
            try:
                url = f"https://query1.finance.yahoo.com/v8/finance/chart/{sym}?interval=1d&range=1d"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    price = float(data["chart"]["result"][0]["meta"]["regularMarketPrice"])
                    quotes[sym] = price
            except Exception:
                if sym.upper().startswith("BTC"):
                    try:
                        req = urllib.request.Request("https://api.coinbase.com/v2/prices/BTC-USD/spot", headers=headers)
                        with urllib.request.urlopen(req, timeout=4.0) as resp:
                            data = json.loads(resp.read().decode("utf-8"))
                            quotes[sym] = float(data["data"]["amount"])
                    except Exception:
                        pass
        if quotes:
            parts = [format_ticker_item(sym, quotes[sym]) for sym in self.symbols if sym in quotes]
            if parts:
                with self._lock:
                    self._banner_text = "   ".join(parts)
        return quotes

    def _run_loop(self) -> None:
        while True:
            try:
                self.fetch_once()
            except Exception:
                pass
            time.sleep(self.refresh_sec)


class NotificationListener:
    """Local UDP listener (`127.0.0.1:18818`) so `retro18_display.py notify` or external scripts can push alerts."""

    def __init__(self, on_message: Callable[[str], None], port: int = NOTIFY_UDP_PORT) -> None:
        self.port = port
        self._on_message = on_message
        self._thread = threading.Thread(target=self._run_server, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run_server(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", self.port))
                while True:
                    data, _ = sock.recvfrom(2048)
                    msg = data.decode("utf-8", errors="replace").strip()
                    if msg:
                        self._on_message(msg)
        except OSError:
            pass


def send_daemon_notification(message: str, port: int = NOTIFY_UDP_PORT) -> bool:
    """Send a priority scrolling notification message to a running `retro18_display.py clock` daemon."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message.encode("utf-8"), ("127.0.0.1", port))
    return True


class _KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class CalcButtonInterceptor:
    """Intercepts the Windows Calculator key (VK_LAUNCH_APP2 = 0xB7) to cycle numpad display modes."""

    WH_KEYBOARD_LL = 13
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101
    WM_SYSKEYDOWN = 0x0104
    WM_SYSKEYUP = 0x0105
    VK_LAUNCH_APP2 = 0xB7
    VK_SHIFT = 0x10

    def __init__(self, on_press: Callable[[], None]) -> None:
        self._on_press = on_press
        self._thread: threading.Thread | None = None
        self._hook_id = None
        self._thread_id: int | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_message_loop, daemon=True)
        self._thread.start()

    def _run_message_loop(self) -> None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        self._thread_id = kernel32.GetCurrentThreadId()

        CMPFUNC = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM
        )
        user32.SetWindowsHookExW.argtypes = [
            ctypes.c_int,
            CMPFUNC,
            wintypes.HINSTANCE,
            wintypes.DWORD,
        ]
        user32.SetWindowsHookExW.restype = ctypes.c_void_p
        user32.CallNextHookEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        user32.CallNextHookEx.restype = ctypes.c_ssize_t

        def _ll_keyboard_proc(n_code: int, w_param: int, l_param: int) -> int:
            if n_code == 0 and l_param:
                kbd = ctypes.cast(l_param, ctypes.POINTER(_KBDLLHOOKSTRUCT)).contents
                if kbd.vkCode == self.VK_LAUNCH_APP2:
                    # Allow Shift + Calculator button to still open Windows Calculator
                    if user32.GetAsyncKeyState(self.VK_SHIFT) & 0x8000:
                        return user32.CallNextHookEx(self._hook_id, n_code, w_param, l_param)
                    if w_param in (self.WM_KEYDOWN, self.WM_SYSKEYDOWN):
                        try:
                            self._on_press()
                        except Exception:
                            pass
                    # Swallow the key event so Windows does not open calc.exe
                    return 1
            return user32.CallNextHookEx(self._hook_id, n_code, w_param, l_param)

        # Keep reference to callback alive
        self._cb_ref = CMPFUNC(_ll_keyboard_proc)
        self._hook_id = user32.SetWindowsHookExW(self.WH_KEYBOARD_LL, self._cb_ref, None, 0)

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))


class Retro18Display:
    """USB HID interface for the 8BitDo Retro 18 Mechanical Numpad."""

    def __init__(self) -> None:
        self._dev: hid.device | None = None
        self.path: bytes | None = None

    def open(self) -> None:
        for d in hid.enumerate(VID_8BITDO, PID_RETRO18):
            if d.get("usage_page") == VENDOR_USAGE_PAGE:
                self.path = d["path"]
                break
        if not self.path:
            raise RuntimeError(
                f"8BitDo Retro 18 Numpad (VID 0x{VID_8BITDO:04X}, PID 0x{PID_RETRO18:04X}, "
                f"UsagePage 0x{VENDOR_USAGE_PAGE:04X}) not found."
            )
        self._dev = hid.device()
        self._dev.open_path(self.path)
        self._dev.set_nonblocking(False)

    def close(self) -> None:
        if self._dev is not None:
            self._dev.close()
            self._dev = None

    def __enter__(self) -> Retro18Display:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def get_firmware_version(self) -> float | None:
        """Query the active firmware version using stock command 81 05 00 21 01."""
        if self._dev is None:
            raise RuntimeError("Device is not open")
        pkt = bytearray(64)
        pkt[0] = REPORT_ID_OUT
        pkt[1] = 0x05
        pkt[2] = 0x00
        pkt[3] = 0x21
        pkt[4] = 0x01
        self._dev.write(bytes(pkt))
        resp = self._dev.read(64, timeout_ms=500)
        if resp and len(resp) >= 3 and resp[0] == REPORT_ID_IN and resp[1] == 0x22:
            return resp[2] / 100.0
        return None

    def poll_calc_button_event(self) -> bool:
        """Non-blockingly check for firmware Input Report 0x02 0xD1 (Calc shortcut button press)."""
        if self._dev is None:
            return False
        pressed = False
        while True:
            try:
                pkt = self._dev.read(64, timeout_ms=1)
            except OSError:
                break
            if not pkt:
                break
            if len(pkt) >= 2 and pkt[0] == REPORT_ID_IN and pkt[1] == 0xD1:
                pressed = True
        return pressed

    def send_raw_segments(self, seg_bytes: bytes, force_in_calc_mode: bool = False) -> None:
        """Send 9 raw 7-segment bytes via custom command 0x81 0xD0."""
        if self._dev is None:
            raise RuntimeError("Device is not open")
        if len(seg_bytes) != 9:
            raise ValueError(f"Expected 9 segment bytes, got {len(seg_bytes)}")
        pkt = bytearray(64)
        pkt[0] = REPORT_ID_OUT
        pkt[1] = CMD_DISPLAY
        pkt[2] = 0x02 if force_in_calc_mode else 0x01
        pkt[3:12] = seg_bytes
        self._dev.write(bytes(pkt))

    def show_text(self, text: str, align: str = "right", force_in_calc_mode: bool = False) -> bytes:
        """Encode `text` and display it on the 9-digit 7-segment display."""
        seg_bytes = encode_7seg_text(text, align=align)
        self.send_raw_segments(seg_bytes, force_in_calc_mode=force_in_calc_mode)
        return seg_bytes

    def turn_off(self) -> None:
        """Turn off the 7-segment display via custom command 0x81 0xD0 0x00."""
        if self._dev is None:
            raise RuntimeError("Device is not open")
        pkt = bytearray(64)
        pkt[0] = REPORT_ID_OUT
        pkt[1] = CMD_DISPLAY
        pkt[2] = 0x00
        self._dev.write(bytes(pkt))


def run_interactive_daemon(
    dev: Retro18Display,
    fmt: str = "dashes",
    use_12h: bool = False,
    tickers: Sequence[str] = DEFAULT_TICKERS,
    scroll_speed: float = 0.16,
) -> None:
    """Run the live display daemon with Windows Calculator button mode-cycling & priority notifications."""
    from retro18_lyrics import LiveLyricsSynchronizer

    modes = ["clock", "date", "sys", "stocks", "lyrics", "off"]
    mode_names = {
        "clock": "24h/12h Live Clock",
        "date": "Current Date (MM-DD-YY)",
        "sys": "Live CPU & RAM Usage",
        "stocks": f"Scrolling Stock & Crypto Ticker ({', '.join(s.replace('-USD', '') for s in tickers)})",
        "lyrics": "YouTube Music Live Synced Lyrics (Word/Phrase Punch-In)",
        "off": "Display Off / Stealth",
    }
    state = {"idx": 0}
    wake_event = threading.Event()
    stats = SystemStatsMonitor()
    ticker_monitor = StockTickerMonitor(symbols=tickers)
    ticker_monitor.start()
    lyrics_sync = LiveLyricsSynchronizer()
    lyrics_sync.start()

    # Priority scrolling notification queue (populated via `retro18_display.py notify "MSG"` or JSON UDP commands)
    notify_frames: deque[bytes] = deque()
    notify_lock = threading.Lock()
    continuous_state: dict[str, object] = {"active": False, "frames": [], "idx": 0}

    def on_notification(msg: str) -> None:
        nonlocal stock_frame_idx
        if msg.startswith("{"):
            try:
                cmd = json.loads(msg)
                kind = cmd.get("cmd")
                if kind == "stop":
                    with notify_lock:
                        notify_frames.clear()
                        continuous_state["active"] = False
                    wake_event.set()
                    return
                if kind == "mode":
                    target = str(cmd.get("mode", "clock"))
                    if target in modes:
                        with notify_lock:
                            notify_frames.clear()
                            continuous_state["active"] = False
                        state["idx"] = modes.index(target)
                        if target == "stocks":
                            stock_frame_idx = 0
                        wake_event.set()
                    return
                if kind == "lyrics_offset":
                    delta = float(cmd.get("delta", 0.0))
                    new_off = lyrics_sync.adjust_offset(delta)
                    print(f"[Lyrics Sync Offset] -> {new_off:+.2f}s", flush=True)
                    wake_event.set()
                    return
                if kind == "static":
                    text = str(cmd.get("text", "")).upper()
                    align = str(cmd.get("align", "right"))
                    seg = encode_7seg_text(text, align=align if align in ("left", "right", "center") else "right")
                    with notify_lock:
                        notify_frames.clear()
                        continuous_state["active"] = True
                        continuous_state["frames"] = [seg]
                        continuous_state["idx"] = 0
                    wake_event.set()
                    return
                if kind == "scroll":
                    text = str(cmd.get("text", "")).upper()
                    loops = int(cmd.get("loops", 1))
                    if loops == 0:
                        # Continuous loop!
                        frames = generate_scroll_frames(text, pad_lead=9, pad_trail=4)
                        with notify_lock:
                            notify_frames.clear()
                            continuous_state["active"] = True
                            continuous_state["frames"] = frames
                            continuous_state["idx"] = 0
                    else:
                        with notify_lock:
                            continuous_state["active"] = False
                            for i in range(max(1, loops)):
                                trail = 9 if i == loops - 1 else 4
                                notify_frames.extend(generate_scroll_frames(text, pad_lead=9, pad_trail=trail))
                    wake_event.set()
                    return
            except Exception:
                pass

        print(f"[Priority Notification] Scrolling: {msg!r}", flush=True)
        frames = generate_scroll_frames(msg.upper(), pad_lead=9, pad_trail=9)
        with notify_lock:
            continuous_state["active"] = False
            notify_frames.extend(frames)
        wake_event.set()

    listener = NotificationListener(on_notification)
    listener.start()

    # State for continuous stock ticker scrolling
    stock_frames: list[bytes] = []
    stock_banner_cached = ""
    stock_frame_idx = 0
    last_scroll_step = 0.0

    def on_calc_button() -> None:
        nonlocal stock_frame_idx
        with notify_lock:
            if notify_frames or continuous_state["active"]:
                # Pressing the button during a priority notification or continuous scroll dismisses it immediately
                notify_frames.clear()
                continuous_state["active"] = False
                print("[Calc Button Pressed] -> Dismissed active notification/override", flush=True)
                wake_event.set()
                return
        state["idx"] = (state["idx"] + 1) % len(modes)
        new_mode = modes[state["idx"]]
        if new_mode == "stocks":
            stock_frame_idx = 0
        print(f"[Calc Button Pressed] -> Switched mode to: {mode_names[new_mode]}", flush=True)
        wake_event.set()

    interceptor = CalcButtonInterceptor(on_calc_button)
    interceptor.start()

    print(
        "Streaming to 8BitDo Retro 18 Numpad!\n"
        "  * Press the [Windows Calculator] shortcut button on the numpad to cycle:\n"
        "      1. Live Clock (HH-MM-SS)\n"
        "      2. Current Date (MM-DD-YY)\n"
        "      3. Live CPU & RAM % (C xx r yy)\n"
        f"      4. Scrolling Stock Ticker ({', '.join(tickers)})\n"
        "      5. YouTube Music Live Synced Lyrics (Word/Phrase Punch-In)\n"
        "      6. Display Off (Stealth)\n"
        "  * Push a priority scrolling alert anytime from any terminal:\n"
        '      python src/retro18_display.py notify "HELLO NIKO"\n'
        "  * Press [CAL] anytime to use the built-in standalone calculator.",
        flush=True,
    )

    last_sent_bytes = b""
    last_sys_sample = 0.0
    cpu_pct, ram_pct = stats.sample()

    try:
        while True:
            try:
                if dev.poll_calc_button_event():
                    on_calc_button()

                t_now = time.monotonic()

                # 1. Priority Scrolling Notification Banner or Continuous Custom Override
                has_notify = False
                with notify_lock:
                    if notify_frames:
                        has_notify = True
                        if t_now - last_scroll_step >= scroll_speed:
                            frame = notify_frames.popleft()
                            dev.send_raw_segments(frame)
                            last_sent_bytes = frame
                            last_scroll_step = t_now
                    elif continuous_state["active"]:
                        has_notify = True
                        c_frames = continuous_state["frames"]
                        if isinstance(c_frames, list) and c_frames:
                            c_idx = int(continuous_state["idx"]) % len(c_frames)
                            if len(c_frames) == 1:
                                frame = c_frames[0]
                                if frame != last_sent_bytes or wake_event.is_set():
                                    dev.send_raw_segments(frame)
                                    last_sent_bytes = frame
                            elif t_now - last_scroll_step >= scroll_speed or wake_event.is_set():
                                frame = c_frames[c_idx]
                                dev.send_raw_segments(frame)
                                last_sent_bytes = frame
                                continuous_state["idx"] = (c_idx + 1) % len(c_frames)
                                last_scroll_step = t_now
                if has_notify:
                    wake_event.wait(timeout=0.03)
                    wake_event.clear()
                    continue

                mode = modes[state["idx"]]
                now = datetime.datetime.now()

                if mode == "off":
                    if last_sent_bytes != b"__OFF__":
                        dev.turn_off()
                        last_sent_bytes = b"__OFF__"
                elif mode == "stocks":
                    banner = ticker_monitor.get_banner()
                    if banner != stock_banner_cached or not stock_frames:
                        stock_banner_cached = banner
                        stock_frames = generate_scroll_frames(banner, pad_lead=9, pad_trail=4)
                        stock_frame_idx = stock_frame_idx % max(1, len(stock_frames))
                    if t_now - last_scroll_step >= scroll_speed or wake_event.is_set():
                        frame = stock_frames[stock_frame_idx]
                        dev.send_raw_segments(frame)
                        last_sent_bytes = frame
                        stock_frame_idx = (stock_frame_idx + 1) % len(stock_frames)
                        last_scroll_step = t_now
                elif mode == "lyrics":
                    frame = lyrics_sync.get_current_frame()
                    if frame != last_sent_bytes or wake_event.is_set():
                        dev.send_raw_segments(frame)
                        last_sent_bytes = frame
                else:
                    if mode == "clock":
                        hour = now.strftime("%I" if use_12h else "%H")
                        if fmt == "dashes":
                            s = f" {hour}-{now:%M-%S}"
                        elif fmt == "dots":
                            s = f"   {hour}.{now:%M.%S}"
                        else:
                            s = f" {hour} {now:%M %S}"
                    elif mode == "date":
                        s = f" {now:%m-%d-%y}"
                    elif mode == "sys":
                        if t_now - last_sys_sample >= 0.9 or len(last_sent_bytes) != 9:
                            cpu_pct, ram_pct = stats.sample()
                            last_sys_sample = t_now
                        s = format_cpu_ram_text(cpu_pct, ram_pct)
                    else:
                        s = "         "

                    seg = encode_7seg_text(s, align="right")
                    if seg != last_sent_bytes or wake_event.is_set():
                        dev.send_raw_segments(seg)
                        last_sent_bytes = seg

                wake_event.wait(timeout=0.03)
                wake_event.clear()
            except OSError:
                # Device unplugged or asleep — wait and automatically reconnect when available
                dev.close()
                last_sent_bytes = b""
                while True:
                    time.sleep(2.0)
                    try:
                        dev.open()
                        wake_event.set()
                        break
                    except Exception:
                        pass
    except KeyboardInterrupt:
        print("\nStopped display daemon.")


def main() -> None:
    parser = argparse.ArgumentParser(description="8BitDo Retro 18 Mechanical Numpad Display Controller")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info", help="Query connected Retro 18 Numpad firmware version")

    p_text = sub.add_parser("text", help="Display custom text or numbers on the 9-digit screen")
    p_text.add_argument("value", help="String to display (up to 9 digits, '.' merges with previous digit)")
    p_text.add_argument("--align", choices=["left", "right", "center"], default="right")
    p_text.add_argument("--force", action="store_true", help="Override display even in Calculator mode")

    p_notify = sub.add_parser(
        "notify",
        help="Push a priority scrolling notification banner to the running daemon (or scroll directly if no daemon)",
    )
    p_notify.add_argument("message", help="Notification message to scroll across the 9-digit screen")
    p_notify.add_argument("--speed", type=float, default=0.15, help="Seconds per scroll step (default: 0.15)")

    p_clock = sub.add_parser(
        "clock",
        help="Run live display daemon (cycles Clock / Date / CPU+RAM / Stock Ticker / Off with Calc shortcut key)",
    )
    p_clock.add_argument(
        "--format",
        choices=["dashes", "dots", "compact"],
        default="dashes",
        help="Clock style: 'dashes' (HH-MM-SS), 'dots' (HH.MM.SS), or 'compact' (HH MM SS)",
    )
    p_clock.add_argument("--12h", dest="use_12h", action="store_true", help="Use 12-hour clock format")
    p_clock.add_argument(
        "--tickers",
        nargs="+",
        default=list(DEFAULT_TICKERS),
        help="Ticker symbols to track (default: DIS FUN SPY VOO VXX RCL NVDA KO)",
    )
    p_clock.add_argument("--speed", type=float, default=0.16, help="Scroll step interval in seconds (default: 0.16)")

    sub.add_parser("tui", help="Launch interactive TUI Studio & Trigger Manager for custom text and scroll modes")
    sub.add_parser("off", help="Turn off the 7-segment display")

    args = parser.parse_args()

    if args.cmd == "tui":
        from retro18_tui import Retro18TuiApp

        Retro18TuiApp().run()
        return

    if args.cmd == "notify":
        # Push to running daemon via UDP; also support standalone scrolling if device is not locked by daemon
        send_daemon_notification(args.message)
        print(f"Sent priority scrolling notification to daemon: {args.message!r}")
        return

    if args.cmd == "clock":
        dev = Retro18Display()
        while True:
            try:
                dev.open()
                break
            except Exception:
                time.sleep(2.0)
        try:
            run_interactive_daemon(
                dev, fmt=args.format, use_12h=args.use_12h, tickers=args.tickers, scroll_speed=args.speed
            )
        finally:
            dev.close()
        return

    with Retro18Display() as dev:
        if args.cmd == "info":
            ver = dev.get_firmware_version()
            print(f"Connected 8BitDo Retro 18 Numpad on {dev.path!r} (Firmware: v{ver:.2f})" if ver else "Connected")
        elif args.cmd == "text":
            seg = dev.show_text(args.value, align=args.align, force_in_calc_mode=args.force)
            print(f"Sent {args.value!r} -> {seg.hex(' ')} {format_ascii_preview(seg)}")
        elif args.cmd == "off":
            dev.turn_off()
            print("Sent Display OFF command.")


if __name__ == "__main__":
    main()
