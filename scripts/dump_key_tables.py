"""Dump the key tables at Flash 0x20700..0x20b00 and find code referencing them."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    print("=== Flash 0x20700..0x20b00 (f:0x1b700..0x1bb00) ===")
    for off in range(0x1B700, 0x1BB00, 16):
        chunk = fw[off : off + 16]
        print(f"  f:0x{off:05x} (Flash 0x{LOAD_BASE+off:05x}): {chunk.hex(' ')}")

    print("\n=== Literal Pool References to 0x20600..0x20c00 ===")
    for off in range(0, len(fw) - 4, 2):
        val = struct.unpack_from("<I", fw, off)[0]
        if 0x00020600 <= val <= 0x00020C00:
            print(f"  Word @ Flash 0x{LOAD_BASE+off:05x} (f:0x{off:05x}) -> 0x{val:08x}")

    disasm_tc32(fw, 0x13980, 0x13D00, "Key Matrix Scanner & Consumer Key Handler (0x13980..0x13d00)")


if __name__ == "__main__":
    main()
