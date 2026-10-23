"""Disassemble 0x1644c..0x166c0, 0x10550..0x10d00, and 0x18380..0x18650 in retro18_fw_v107.bin."""
import sys
from tc32_disasm import disasm_tc32, FW_PATH

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    disasm_tc32(fw, 0x1644C, 0x166C0, "USB Commands 0x1644c..0x166c0")
    disasm_tc32(fw, 0x18380, 0x18650, "USB Endpoint 5 Receiver & 0x185cc (0x18380..0x18650)")
    disasm_tc32(fw, 0x10580, 0x10720, "Main Mode / Battery Display Callers (0x10580..0x10720)")
    disasm_tc32(fw, 0x10A90, 0x10CE0, "Calculator / Numpad Mode Switch (0x10a90..0x10ce0)")


if __name__ == "__main__":
    main()
