"""Locate the 18-key Numpad keymap table and Windows Calculator button handler in retro18_fw_v107.bin."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()

    # Search for HID keypad usage codes (0x54='/', 0x55='*', 0x56='-', 0x57='+') near each other
    print("=== Searching for HID Keypad Usage Codes (0x54, 0x55, 0x56, 0x57) ===")
    for i in range(len(fw) - 32):
        window = fw[i : i + 32]
        if 0x54 in window and 0x55 in window and 0x56 in window and 0x57 in window and 0x59 in window:
            print(f"  Candidate at f:0x{i:05x} (Flash 0x{LOAD_BASE+i:05x}): {fw[i:i+32].hex(' ')}")

    disasm_tc32(fw, 0x13600, 0x13900, "Key Matrix Scan & Action Handler (0x13600..0x13900)")


if __name__ == "__main__":
    main()
