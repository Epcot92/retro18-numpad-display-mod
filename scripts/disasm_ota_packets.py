"""Disassemble the exact USB HID OTA packet builders in 8BitDoAdvance.dll for PID 0x5203."""
from disassemble_5203_protocol import ADVANCE_PATH, parse_pe_sections, disasm_func


def main() -> None:
    adv = ADVANCE_PATH.read_bytes()
    image_base, sections = parse_pe_sections(adv)
    for va, name, size in [
        (0x10414ED0, "send_ota_cmd (0x10414ed0)", 450),
        (0x10426320, "initDevice (0x10426320)", 250),
        (0x10424540, "eraseFlash (0x10424540)", 250),
        (0x10427F80, "verifyBlockCRC (0x10427f80)", 450),
        (0x104325F0, "writeFirmwareBlock (0x104325f0)", 700),
    ]:
        disasm_func(adv, va, image_base, sections, name, size)


if __name__ == "__main__":
    main()
