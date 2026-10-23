"""Inspect the key matrix, keymap tables (0x20200..0x20290), and key handler (0x107f0..0x10a90) in retro18_fw_v107.bin."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()

    print("=== RoData Keymap / Macro Tables (Flash 0x20200..0x20290 / f:0x1b200..0x1b290) ===")
    for off in range(0x1B200, 0x1B290, 16):
        chunk = fw[off : off + 16]
        print(f"  f:0x{off:05x} (Flash 0x{LOAD_BASE+off:05x}): {chunk.hex(' ')}")

    disasm_tc32(fw, 0x107F0, 0x10A90, "Key Matrix & Shortcut Handler (0x107f0..0x10a90)")


if __name__ == "__main__":
    main()
