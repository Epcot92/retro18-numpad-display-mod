"""Disassemble 0x18640..0x18760 and find all references to 0x16b38/0x16b39 in retro18_fw_v107.bin."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    disasm_tc32(fw, 0x18640, 0x18760, "USB Endpoint 5 OUT Handler (0x18640..0x18760)")

    for val in (0x00016B38, 0x00016B39):
        pat = struct.pack("<I", val)
        idx = fw.find(pat)
        while idx != -1:
            print(f"Found 0x{val:08x} at Flash 0x{LOAD_BASE+idx:05x} (f:0x{idx:05x})")
            idx = fw.find(pat, idx + 1)

    # Also check where 0x00845520..0x00845600 or USB EP5 buffer is referenced
    disasm_tc32(fw, 0x13700, 0x139B0, "Main Loop & USB Polling (0x13700..0x139b0)")


if __name__ == "__main__":
    main()
