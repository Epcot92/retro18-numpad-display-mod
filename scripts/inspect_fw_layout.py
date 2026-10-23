"""Inspect the memory layout, startup code (0x5000..0x5160), and end of image in retro18_fw_v107.bin."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    disasm_tc32(fw, 0x05000, 0x05160, "Telink Vector Table & Startup (0x05000..0x05160)")

    # Check bytes from 0x1bf00 to 0x1c3b4 (Flash 0x20f00..0x213b4)
    print("\n=== End of Firmware Image (f:0x1bf00..0x1c3b4 / Flash 0x20f00..0x213b4) ===")
    for off in range(0x1BF00, 0x1C3C0, 16):
        chunk = fw[off : off + 16]
        print(f"  f:0x{off:05x} (Flash 0x{LOAD_BASE+off:05x}): {chunk.hex(' ')}")


if __name__ == "__main__":
    main()
