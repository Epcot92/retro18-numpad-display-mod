"""Inspect USB hardware registers, vendor command dispatcher, and display callers in retro18_fw_v107.bin."""
import pathlib
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def find_literal_refs(fw: bytes, min_val: int, max_val: int) -> list[tuple[int, int]]:
    hits = []
    for off in range(0, len(fw) - 4, 4):
        val = struct.unpack_from("<I", fw, off)[0]
        if min_val <= val <= max_val:
            hits.append((LOAD_BASE + off, val))
    return hits


def main() -> None:
    fw = FW_PATH.read_bytes()

    # 1. Disassemble 0x14d40..0x14f20 (battery/status display formatter and mode handlers)
    disasm_tc32(fw, 0x14D40, 0x14F20, "Display Formatters & Mode Switch (0x14d40..0x14f20)")

    # 2. Disassemble 0x15a40..0x15c00 and 0x16cc0..0x17050 (callers of display functions)
    disasm_tc32(fw, 0x15A40, 0x15B40, "Display Caller at 0x15a7c")
    disasm_tc32(fw, 0x16CC0, 0x17040, "Display Callers at 0x16d34..0x16fac")

    # 3. Find all literal pool references to Telink USB registers (0x00800100..0x008001ff)
    print("\n=== Literal Pool References to Telink USB Registers (0x00800100..0x008001ff) ===")
    usb_refs = find_literal_refs(fw, 0x00800100, 0x008001FF)
    for flash_addr, reg_val in usb_refs:
        print(f"  Literal @ 0x{flash_addr:05x} (f:0x{flash_addr-LOAD_BASE:05x}) -> 0x{reg_val:08x}")

    # 4. Also search for comparison with 0x81 (Report ID 0x81) or 0xc1 / 0xc3 (`tcmp rN, #0x81` = a881..af81)
    print("\n=== Search for `tcmp rN, #0x81` / `#0xc1` / `#0xc3` in Firmware ===")
    for imm, label in [(0x81, "0x81 (Report ID)"), (0xC1, "0xC1 (Init cmd)"), (0xC3, "0xC3 (CRC cmd)")]:
        locs = []
        for off in range(0, len(fw) - 2, 2):
            hw = struct.unpack_from("<H", fw, off)[0]
            hi = hw >> 8
            lo = hw & 0xFF
            if 0xA8 <= hi <= 0xAF and lo == imm:
                locs.append(f"0x{LOAD_BASE+off:05x}(r{hi-0xA8})")
            elif 0x20 <= hi <= 0x27 and lo == imm:
                locs.append(f"0x{LOAD_BASE+off:05x}(2x_r{hi-0x20})")
        print(f"  {label}: {locs}")


if __name__ == "__main__":
    main()
