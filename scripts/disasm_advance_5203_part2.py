"""Disassemble 8BitDoAdvance.dll around 0x103fa8b0..0x103fb100."""
from disassemble_5203_protocol import ADVANCE_PATH, parse_pe_sections, rva_to_off, resolve_thunk
import capstone


def main() -> None:
    adv = ADVANCE_PATH.read_bytes()
    image_base, sections = parse_pe_sections(adv)
    va = 0x103FA8B0
    off = rva_to_off(va - image_base, sections)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for insn in md.disasm(adv[off : off + 0x700], va):
        target_note = ""
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            c_va = int(insn.op_str, 16)
            c_real = resolve_thunk(adv, c_va, image_base, sections)
            if c_real != c_va:
                target_note = f" ; -> 0x{c_real:08x}"
        print(f"  0x{insn.address:08x}: {insn.bytes.hex():<20} {insn.mnemonic:<8} {insn.op_str}{target_note}")


if __name__ == "__main__":
    main()
