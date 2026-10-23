"""Interactive TUI Studio & Trigger Manager for the 8BitDo Retro 18 Mechanical Numpad.

Allows you to:
  - Type custom text with a live 9-digit 7-segment LED preview (static or animated scrolling).
  - Choose how long it scrolls for: Static (9 Digits), Scroll 1x, Scroll 2x, Scroll 3x, Scroll 5x, or Continuous Loop.
  - Add, save, delete, and fire custom text triggers on demand (with F1-F9 hotkeys or Enter).
  - Switch the numpad's base display mode (Clock, Date, CPU & RAM %, Stock Ticker, or Display Off).
"""
from __future__ import annotations

import ctypes
import json
import msvcrt
import os
import pathlib
import shutil
import socket
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from retro18_display import DEFAULT_TICKERS, NOTIFY_UDP_PORT, encode_7seg_sequence, encode_7seg_text

TRIGGERS_FILE = pathlib.Path(__file__).resolve().parent.parent / "triggers.json"

SCROLL_MODES: list[tuple[str, str, int]] = [
    ("static", "Static (9 Digits)", -1),
    ("1x", "Scroll 1x", 1),
    ("2x", "Scroll 2x", 2),
    ("3x", "Scroll 3x", 3),
    ("5x", "Scroll 5x", 5),
    ("continuous", "Continuous Loop", 0),
]

DAEMON_MODES: list[tuple[str, str]] = [
    ("clock", "24h Clock"),
    ("date", "Date (MM-DD-YY)"),
    ("sys", "CPU & RAM %"),
    ("stocks", "Stock Ticker"),
    ("lyrics", "YouTube Music Lyrics"),
    ("off", "Display Off"),
]


def enable_vt_mode() -> None:
    """Enable ANSI escape sequences and hide cursor in Windows console."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
    mode = ctypes.c_uint32()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    sys.stdout.write("\x1b[?25l\x1b[2J")
    sys.stdout.flush()


def restore_console() -> None:
    sys.stdout.write("\x1b[?25h\x1b[0m\n")
    sys.stdout.flush()


def render_digit_lines(seg: int) -> tuple[str, str, str]:
    """Render a 7-segment byte into a 3-row-tall retro LED glyph."""
    a = bool(seg & 0x01)
    b = bool(seg & 0x02)
    c = bool(seg & 0x04)
    d = bool(seg & 0x08)
    e = bool(seg & 0x10)
    f = bool(seg & 0x20)
    g = bool(seg & 0x40)
    dp = bool(seg & 0x80)

    top = f" {'━━' if a else '  '}  "
    mid = f"{'┃' if f else ' '}{'━━' if g else '  '}{'┃' if b else ' '} "
    bot = f"{'┃' if e else ' '}{'━━' if d else '  '}{'┃' if c else ' '}{'•' if dp else ' '}"
    return top, mid, bot


def load_triggers() -> list[dict[str, str]]:
    if TRIGGERS_FILE.exists():
        try:
            data = json.loads(TRIGGERS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                return data
        except Exception:
            pass
    return [
        {"name": "Greeting", "text": "HELLO WORLD", "mode": "1x"},
        {"name": "Focus Mode", "text": "DEEP WORK DO NOT DISTURB", "mode": "2x"},
        {"name": "Market Check", "text": "CHECK DIS FUN SPY VOO VXX RCL NVDA KO", "mode": "3x"},
        {"name": "Coffee Break", "text": "COFFEE", "mode": "static"},
        {"name": "Alert Loop", "text": "BUILD COMPLETE", "mode": "continuous"},
    ]


def save_triggers(triggers: list[dict[str, str]]) -> None:
    try:
        TRIGGERS_FILE.write_text(json.dumps(triggers, indent=2), encoding="utf-8")
    except Exception:
        pass


def send_daemon_json(payload: dict) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(json.dumps(payload).encode("utf-8"), ("127.0.0.1", NOTIFY_UDP_PORT))
        return True
    except OSError:
        return False


class Retro18TuiApp:
    def __init__(self) -> None:
        self.input_text = "HELLO WORLD"
        self.scroll_idx = 1  # Default: Scroll 1x
        self.triggers = load_triggers()
        self.selected_trigger = 0
        self.daemon_mode_idx = 0
        self.focus = 0  # 0=Input, 1=Scroll Duration, 2=Triggers, 3=Base Mode
        self.status = "Ready! Type custom text and press [Enter] to send, or [F1-F9] to fire a trigger."
        self.preview_offset = 0
        self.last_tick = time.monotonic()

    def current_scroll_mode(self) -> tuple[str, str, int]:
        return SCROLL_MODES[self.scroll_idx % len(SCROLL_MODES)]

    def mode_label(self, mode_id: str) -> str:
        for mid, label, _ in SCROLL_MODES:
            if mid == mode_id:
                return label
        return mode_id

    def send_custom(self, text: str, mode_id: str) -> None:
        loops = 1
        for mid, _, lp in SCROLL_MODES:
            if mid == mode_id:
                loops = lp
                break
        if mode_id == "static" or loops == -1:
            payload = {"cmd": "static", "text": text, "align": "right"}
        else:
            payload = {"cmd": "scroll", "text": text, "loops": loops}
        send_daemon_json(payload)
        self.status = f"Sent {text!r} ({self.mode_label(mode_id)}) -> 8BitDo Numpad!"

    def stop_active(self) -> None:
        send_daemon_json({"cmd": "stop"})
        self.status = "Stopped active scroll / override — returned to base display mode."

    def switch_daemon_mode(self, idx: int) -> None:
        self.daemon_mode_idx = idx % len(DAEMON_MODES)
        mode_id, label = DAEMON_MODES[self.daemon_mode_idx]
        send_daemon_json({"cmd": "mode", "mode": mode_id})
        self.status = f"Switched Numpad base mode to: {label}"

    def save_current_as_trigger(self) -> None:
        txt = self.input_text.strip()
        if not txt:
            self.status = "Cannot save an empty text trigger."
            return
        mode_id, label, _ = self.current_scroll_mode()
        name = f"Trigger #{len(self.triggers) + 1}"
        self.triggers.append({"name": name, "text": txt, "mode": mode_id})
        self.selected_trigger = len(self.triggers) - 1
        save_triggers(self.triggers)
        self.status = f"Saved {txt!r} ({label}) as {name}!"

    def delete_selected_trigger(self) -> None:
        if not self.triggers:
            return
        removed = self.triggers.pop(self.selected_trigger)
        if self.triggers:
            self.selected_trigger = min(self.selected_trigger, len(self.triggers) - 1)
        else:
            self.selected_trigger = 0
        save_triggers(self.triggers)
        self.status = f"Deleted trigger {removed['text']!r}."

    def compute_preview_9(self) -> bytes:
        upper = self.input_text.upper()
        mode_id, _, _ = self.current_scroll_mode()
        if mode_id == "static":
            return encode_7seg_text(upper, align="right")
        seq = [0x00] * 9 + encode_7seg_sequence(upper) + [0x00] * 4
        total = max(1, len(seq) - 8)
        start = self.preview_offset % total
        window = seq[start : start + 9]
        if len(window) < 9:
            window += [0x00] * (9 - len(window))
        return bytes(window)

    def draw(self) -> None:
        cols = max(84, min(110, shutil.get_terminal_size((96, 28)).columns - 2))
        inner = cols - 2

        RESET = "\x1b[0m"
        BOLD = "\x1b[1m"
        RED = "\x1b[91m"
        BG_RED = "\x1b[41;97;1m"
        YELLOW = "\x1b[93m"
        CYAN = "\x1b[96m"
        GREEN = "\x1b[92m"
        GRAY = "\x1b[90m"
        WHITE = "\x1b[97m"
        REV = "\x1b[7m"

        def box_top(title: str, active: bool) -> str:
            color = CYAN + BOLD if active else GRAY
            t = f" {title} "
            bar = "─" * max(0, inner - len(t))
            return f"{color}┌{t}{bar}┐{RESET}"

        def box_bot(active: bool) -> str:
            color = CYAN + BOLD if active else GRAY
            return f"{color}└{'─' * inner}┘{RESET}"

        def box_line(content: str, vis_len: int, active: bool) -> str:
            color = CYAN + BOLD if active else GRAY
            pad = " " * max(0, inner - vis_len)
            return f"{color}│{RESET}{content}{pad}{color}│{RESET}"

        lines: list[str] = ["\x1b[H"]

        # Header
        hdr_title = " 8BitDo Retro 18 Mechanical Numpad "
        hdr_sub = "  Custom Display & Trigger TUI Studio"
        vis = len(hdr_title) + len(hdr_sub)
        lines.append(f"{RED}┏{'━' * inner}┓{RESET}")
        lines.append(
            f"{RED}┃{RESET}{BG_RED}{hdr_title}{RESET}{YELLOW}{BOLD}{hdr_sub}{RESET}{' ' * max(0, inner - vis)}{RED}┃{RESET}"
        )
        lines.append(f"{RED}┗{'━' * inner}┛{RESET}")

        # Live 9-digit 7-Segment LED Preview
        _, scroll_label, _ = self.current_scroll_mode()
        p_title = f" Live 9-Digit 7-Segment LED Preview ({scroll_label}) "
        lines.append(f"{RED}┌{p_title}{'─' * max(0, inner - len(p_title))}┐{RESET}")
        segs = self.compute_preview_9()
        r0, r1, r2 = "   ", "   ", "   "
        for b in segs:
            t, m, bo = render_digit_lines(b)
            r0 += t + "  "
            r1 += m + "  "
            r2 += bo + "  "
        for row_str in (r0, r1, r2):
            lines.append(
                f"{RED}│{BOLD}{row_str}{RESET}{' ' * max(0, inner - len(row_str))}{RED}│{RESET}"
            )
        lines.append(f"{RED}└{'─' * inner}┘{RESET}")

        # Pane 1: Custom Text Input
        lines.append(box_top("1. Custom Text Input [Enter = Send Now | Ctrl+S = Save as Trigger]", self.focus == 0))
        inp_disp = f"  > {self.input_text}█"
        lines.append(box_line(f"{WHITE}{BOLD}{inp_disp}{RESET}", len(inp_disp), self.focus == 0))
        lines.append(box_bot(self.focus == 0))

        # Pane 2: Scroll Duration Selector
        lines.append(
            box_top(
                "2. Scroll Duration / Repeat Mode [Left/Right or Alt+Left/Right to Change]",
                self.focus == 1,
            )
        )
        mode_pills = []
        vis_m = 2
        for idx, (_, label, _) in enumerate(SCROLL_MODES):
            if idx == self.scroll_idx:
                tok = f"[{label}]"
                mode_pills.append(f"{GREEN}{BOLD}{REV} {tok} {RESET}")
                vis_m += len(tok) + 2
            else:
                mode_pills.append(f" {GRAY}{label}{RESET} ")
                vis_m += len(label) + 2
        lines.append(box_line("  " + " ".join(mode_pills), vis_m + len(SCROLL_MODES) - 1, self.focus == 1))
        lines.append(box_bot(self.focus == 1))

        # Pane 3: Saved Text Triggers
        lines.append(
            box_top(
                "3. Saved Text Triggers [F1-F9 = Instant Fire | Up/Down + Enter = Fire | Del = Remove]",
                self.focus == 2,
            )
        )
        max_rows = 7
        for i in range(max_rows):
            if i < len(self.triggers):
                trig = self.triggers[i]
                hk = f"[F{i+1}]" if i < 9 else "[--]"
                mlabel = self.mode_label(trig.get("mode", "1x"))
                raw_txt = f" {hk:<5} {trig['name']:<15} {trig['text'][:34]:<35} ({mlabel})"
                if i == self.selected_trigger:
                    content = f"{REV}{CYAN}{BOLD}▶{raw_txt:<{inner-1}}{RESET}"
                    lines.append(box_line(content, inner, self.focus == 2))
                else:
                    content = (
                        f"  {YELLOW}{BOLD}{hk:<5}{RESET} "
                        f"{CYAN}{trig['name']:<15}{RESET} "
                        f"{WHITE}{BOLD}{trig['text'][:34]:<35}{RESET} "
                        f"{GREEN}({mlabel}){RESET}"
                    )
                    vis_l = 2 + 5 + 1 + 15 + 1 + 35 + 1 + len(mlabel) + 2
                    lines.append(box_line(content, vis_l, self.focus == 2))
            else:
                lines.append(box_line("", 0, self.focus == 2))
        lines.append(box_bot(self.focus == 2))

        # Pane 4: Base Numpad Mode Switcher
        lines.append(box_top("4. Base Numpad Display Mode [Left/Right + Enter]", self.focus == 3))
        m_parts = []
        vis_dm = 2
        for idx, (_, label) in enumerate(DAEMON_MODES):
            short_lbl = label if len(label) <= 22 else "Stock Ticker (8 syms)"
            if idx == self.daemon_mode_idx:
                t_s = f"[{short_lbl}]"
                m_parts.append(f"{YELLOW}{BOLD}{REV} {t_s} {RESET}")
                vis_dm += len(t_s) + 2
            else:
                m_parts.append(f" {GRAY}{short_lbl}{RESET} ")
                vis_dm += len(short_lbl) + 2
        lines.append(box_line("  " + " ".join(m_parts), vis_dm + len(DAEMON_MODES) - 1, self.focus == 3))
        lines.append(box_bot(self.focus == 3))

        # Footer
        st_text = self.status[: inner - 10]
        lines.append(f" {YELLOW}{BOLD}Status:{RESET} {WHITE}{st_text:<{inner-8}}{RESET}")
        lines.append(
            f" {CYAN}{BOLD}Keys:{RESET}   [Tab] Next Pane  [Enter] Send/Fire  [Ctrl+S] Save Trigger  [F1-F9] Fire Trigger  [Esc] Stop Scroll  [Ctrl+Q] Quit"
        )

        sys.stdout.write("\n".join(lines))
        sys.stdout.flush()

    def run(self) -> None:
        enable_vt_mode()
        try:
            while True:
                now = time.monotonic()
                if now - self.last_tick >= 0.16:
                    self.preview_offset += 1
                    self.last_tick = now
                self.draw()

                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    # Check special / function / arrow keys
                    if ch in ("\x00", "\xe0"):
                        k2 = msvcrt.getwch()
                        code = ord(k2)
                        # F1..F9 are 59..67
                        if 59 <= code <= 67:
                            idx = code - 59
                            if idx < len(self.triggers):
                                t = self.triggers[idx]
                                self.send_custom(t["text"], t.get("mode", "1x"))
                        elif code == 72:  # Up
                            if self.focus == 2 and self.triggers:
                                self.selected_trigger = max(0, self.selected_trigger - 1)
                            elif self.focus == 1:
                                self.scroll_idx = (self.scroll_idx - 1) % len(SCROLL_MODES)
                                self.preview_offset = 0
                        elif code == 80:  # Down
                            if self.focus == 2 and self.triggers:
                                self.selected_trigger = min(len(self.triggers) - 1, self.selected_trigger + 1)
                            elif self.focus == 1:
                                self.scroll_idx = (self.scroll_idx + 1) % len(SCROLL_MODES)
                                self.preview_offset = 0
                        elif code == 75:  # Left
                            if self.focus in (0, 1):
                                self.scroll_idx = (self.scroll_idx - 1) % len(SCROLL_MODES)
                                self.preview_offset = 0
                            elif self.focus == 3:
                                self.daemon_mode_idx = (self.daemon_mode_idx - 1) % len(DAEMON_MODES)
                        elif code == 77:  # Right
                            if self.focus in (0, 1):
                                self.scroll_idx = (self.scroll_idx + 1) % len(SCROLL_MODES)
                                self.preview_offset = 0
                            elif self.focus == 3:
                                self.daemon_mode_idx = (self.daemon_mode_idx + 1) % len(DAEMON_MODES)
                        elif code == 83:  # Delete
                            if self.focus == 2:
                                self.delete_selected_trigger()
                        continue

                    if ch == "\x11":  # Ctrl+Q
                        break
                    if ch == "\x13":  # Ctrl+S
                        self.save_current_as_trigger()
                        continue
                    if ch == "\x1b":  # Esc
                        self.stop_active()
                        continue
                    if ch == "\t":  # Tab
                        self.focus = (self.focus + 1) % 4
                        continue
                    if ch == "\r":  # Enter
                        if self.focus in (0, 1):
                            mode_id, _, _ = self.current_scroll_mode()
                            self.send_custom(self.input_text, mode_id)
                        elif self.focus == 2 and self.triggers:
                            t = self.triggers[self.selected_trigger]
                            self.send_custom(t["text"], t.get("mode", "1x"))
                        elif self.focus == 3:
                            self.switch_daemon_mode(self.daemon_mode_idx)
                        continue
                    if ch == "\x08":  # Backspace
                        if self.focus == 0:
                            self.input_text = self.input_text[:-1]
                            self.preview_offset = 0
                        elif self.focus == 2:
                            self.delete_selected_trigger()
                        continue
                    if ch == "[":
                        send_daemon_json({"cmd": "lyrics_offset", "delta": -0.10})
                        self.status = "Nudged Lyrics Sync Offset -100ms (later)"
                        continue
                    if ch == "]":
                        send_daemon_json({"cmd": "lyrics_offset", "delta": 0.10})
                        self.status = "Nudged Lyrics Sync Offset +100ms (earlier)"
                        continue
                    if ch.isprintable() and self.focus == 0:
                        self.input_text += ch
                        self.preview_offset = 0
                else:
                    time.sleep(0.03)
        except KeyboardInterrupt:
            pass
        finally:
            restore_console()


if __name__ == "__main__":
    Retro18TuiApp().run()
