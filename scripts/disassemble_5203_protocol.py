"""Follow ILT jump thunks in 8BitDoAdvance.dll and disassemble the Retro 18 (0x5203) HID protocol."""
import pathlib
import struct
import sys
import capstone

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


def rva_to_off(rva: int, sections) -> int:
    for _, va, vsize, roff, rsize in sections:
        if va <= rva < va + max(vsize, rsize):
            return roff + (rva - va)
    return -1


def resolve_thunk(adv: bytes, va: int, image_base: int, sections) -> int:
    rva = va - image_base
    off = rva_to_off(rva, sections)
    if adv[off] == 0xE9:  # jmp rel32
        rel = struct.unpack_from("<i", adv, off + 1)[0]
        return va + 5 + rel
    return va


def disasm_func(adv: bytes, va: int, image_base: int, sections, name: str, max_bytes: int = 600) -> None:
    real_va = resolve_thunk(adv, va, image_base, sections)
    rva = real_va - image_base
    off = rva_to_off(rva, sections)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    print(f"\n=== {name}: Thunk 0x{va:08x} -> Real VA 0x{real_va:08x} (File Off 0x{off:x}) ===")
    for insn in md.disasm(adv[off : off + max_bytes], real_va):
        target_note = ""
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            c_va = int(insn.op_str, 16)
            c_real = resolve_thunk(adv, c_va, image_base, sections)
            if c_real != c_va:
                target_note = f" ; -> 0x{c_real:08x}"
        print(f"  0x{insn.address:08x}: {insn.bytes.hex():<20} {insn.mnemonic:<8} {insn.op_str}{target_note}")
        if insn.mnemonic in ("ret", "retn") and (insn.address - real_va) > 32:
            break


if __name__ == "__main__":
    adv = ADVANCE_PATH.read_bytes()
    image_base, sections = parse_pe_sections(adv)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for file_off, length, label in [
        (0x946E0, 600, "PID check at 0x946e0"),
        (0x949E0, 600, "PID check at 0x949e0"),
        (0x95DC0, 500, "HID Read/Write at 0x95dc0"),
        (0x95FA0, 500, "HID Read/Write at 0x95fa0"),
        (0x9A8B0, 800, "PID dispatch at 0x9a8b0"),
    ]:
        rva = off_to_rva(file_off, sections) if "off_to_rva" in globals() else (file_off - 0x400 + 0x3B2000)
        # Compute exact VA from sections
        va = 0
        for _, sva, svsize, sroff, srsize in sections:
            if sroff <= file_off < sroff + srsize:
                va = image_base + sva + (file_off - sroff)
                break
        print(f"\n=== {label} (File Off 0x{file_off:x}, VA 0x{va:x}) ===")
        for insn in md.disasm(adv[file_off : file_off + length], va):
            print(f"  0x{insn.address:08x}: {insn.bytes.hex():<20} {insn.mnemonic:<8} {insn.op_str}")
