"""Disassemble 0x1042ee30 and 0x1042e8a0 in 8BitDoAdvance.dll."""
from disassemble_5203_protocol import ADVANCE_PATH, parse_pe_sections, disasm_func


def main() -> None:
    adv = ADVANCE_PATH.read_bytes()
    image_base, sections = parse_pe_sections(adv)
    disasm_func(adv, 0x1042EE30, image_base, sections, "sub_1042ee30 (post-verify)", 300)
    disasm_func(adv, 0x1042E8A0, image_base, sections, "sub_1042e8a0 (finalize/reboot)", 300)


if __name__ == "__main__":
    main()
