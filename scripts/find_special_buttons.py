"""Find all references to 0x00844d50 (special buttons bitmap) and disassemble 0x13d00..0x14300."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    pat = struct.pack("<I", 0x00844D50)
    idx = 0
    hits = []
    while True:
        idx = fw.find(pat, idx)
        if idx == -1:
            break
        hits.append(f"0x{LOAD_BASE+idx:05x} (f:0x{idx:05x})")
        idx += 1
    print(f"References to 0x00844d50: {hits}")

    disasm_tc32(fw, 0x13D00, 0x142E0, "Rest of Key Matrix Scanner & Special Button Handlers (0x13d00..0x142e0)")


if __name__ == "__main__":
    main()
