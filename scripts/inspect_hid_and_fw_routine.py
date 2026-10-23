"""Disassemble the 8BitDoAdvance.dll functions handling PID 0x5203 and enumerate live HID interfaces."""
import pathlib
import struct
import sys
import capstone
import hid

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ADVANCE_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDoAdvance.dll"
)


def parse_pe_sections(data: bytes):
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    opt_off = pe_off + 24
    image_base = int.from_bytes(data[opt_off + 28 : opt_off + 32], "little")
    num_sec = int.from_bytes(data[pe_off + 6 : pe_off + 8], "little")
    opt_size = int.from_bytes(data[pe_off + 20 : pe_off + 22], "little")
    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sec):
        s = data[sec_off + i * 40 : sec_off + (i + 1) * 40]
        name = s[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", s, 8)
        sections.append((name, va, vsize, roff, rsize))
    return image_base, sections


def off_to_rva(off: int, sections) -> int:
    for _, va, vsize, roff, rsize in sections:
        if roff <= off < roff + rsize:
            return va + (off - roff)
    return -1


def rva_to_off(rva: int, sections) -> int:
    for _, va, vsize, roff, rsize in sections:
        if va <= rva < va + max(vsize, rsize):
            return roff + (rva - va)
    return -1


def enumerate_live_retro18() -> None:
    print("=== Live 8BitDo HID Devices Connected (VID 0x2DC8) ===")
    for d in hid.enumerate(0x2DC8):
        print(
            f"  PID=0x{d['product_id']:04x} ({d['product_id']}) | "
            f"Interface={d['interface_number']} | "
            f"UsagePage=0x{d['usage_page']:04x} Usage=0x{d['usage']:04x} | "
            f"Product={d['product_string']!r} | "
            f"Path={d['path'].decode('ascii', errors='replace')}"
        )


def disasm_range(adv: bytes, image_base: int, sections, start_off: int, length: int, title: str) -> None:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    start_va = image_base + off_to_rva(start_off, sections)
    print(f"\n=== {title} (File Off 0x{start_off:x}, VA 0x{start_va:x}) ===")
    for insn in md.disasm(adv[start_off : start_off + length], start_va):
        print(f"  0x{insn.address:08x}: {insn.bytes.hex():<20} {insn.mnemonic:<8} {insn.op_str}")


if __name__ == "__main__":
    enumerate_live_retro18()
    adv = ADVANCE_PATH.read_bytes()
    image_base, sections = parse_pe_sections(adv)
    # 1. Disassemble 0x103fb053 (file off 0x49453) - where 0x5203 firmware update jumps!
    disasm_range(adv, image_base, sections, 0x49453, 800, "Firmware Update Loop for 0x5203 (at 0x103fb053)")
    # 2. Disassemble 0x1041857b (file off 0x6697b) - where second 0x5203 check jumps!
    disasm_range(adv, image_base, sections, 0x6697B, 500, "Second 0x5203 Handler (at 0x1041857b)")
    # 3. Disassemble 0x1044417a (file off 0x9257a) - HID UsagePage check for 0x5203!
    disasm_range(adv, image_base, sections, 0x9257A, 400, "HID UsagePage Check for 0x5203 (at 0x1044417a)")
