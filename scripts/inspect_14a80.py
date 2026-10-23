"""Disassemble 0x14a40..0x14bc0 in retro18_fw_v107.bin and check all references to 0x14a80."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    disasm_tc32(fw, 0x14A40, 0x14BC0, "7-Seg Display Core Functions (0x14a40..0x14bc0)")

    # Check if any 16-bit branch (tbcc / tjmp) or literal targets 0x14a80..0x14ac2
    hits = []
    for off in range(0, len(fw) - 2, 2):
        pc = LOAD_BASE + off
        hw = struct.unpack_from("<H", fw, off)[0]
        hi = hw >> 8
        lo = hw & 0xFF
        if 0xC0 <= hi <= 0xDF:
            simm8 = lo if lo < 128 else lo - 256
            target = pc + 2 + (simm8 << 1)
            if 0x14A80 <= target < 0x14AC4:
                hits.append(f"tbcc @ 0x{pc:05x} -> 0x{target:05x}")
        elif 0xE0 <= hi <= 0xE7:
            simm11 = hw & 0x7FF
            if simm11 & 0x400:
                simm11 -= 0x800
            target = pc + 2 + (simm11 << 1)
            if 0x14A80 <= target < 0x14AC4:
                hits.append(f"tjmp @ 0x{pc:05x} -> 0x{target:05x}")
    for off in range(0, len(fw) - 4, 2):
        val = struct.unpack_from("<I", fw, off)[0]
        if 0x14A80 <= (val & ~1) < 0x14AC4:
            hits.append(f"word @ 0x{LOAD_BASE+off:05x} -> 0x{val:08x}")
    print(f"\nReferences to 0x14a80..0x14ac2 outside function: {hits}")


if __name__ == "__main__":
    main()
