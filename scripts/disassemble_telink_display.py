"""Disassemble the 7-segment display driver and USB HID vendor handler in retro18_fw_v107.bin."""
import pathlib
import struct
import sys
import capstone

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107.bin")
LOAD_BASE = 0x5000


def disasm_thumb_region(fw: bytes, file_start: int, length: int, title: str) -> None:
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    va_start = LOAD_BASE + file_start
    print(f"\n=== {title} (file 0x{file_start:05x}, flash 0x{va_start:05x}) ===")
    for insn in md.disasm(fw[file_start : file_start + length], va_start):
        note = ""
        # Annotate PC-relative LDR (ldr rX, [pc, #imm])
        if insn.mnemonic == "ldr" and "[pc," in insn.op_str:
            try:
                imm_str = insn.op_str.split("#")[1].rstrip("]")
                imm = int(imm_str, 0)
                target_va = ((insn.address + 4) & ~3) + imm
                target_foff = target_va - LOAD_BASE
                if 0 <= target_foff <= len(fw) - 4:
                    val = struct.unpack_from("<I", fw, target_foff)[0]
                    note = f" ; [0x{target_va:05x}] = 0x{val:08x}"
            except Exception:
                pass
        print(f"  0x{insn.address:05x} (f:0x{insn.address-LOAD_BASE:05x}): {insn.bytes.hex():<10} {insn.mnemonic:<8} {insn.op_str}{note}")


def main() -> None:
    fw = FW_PATH.read_bytes()
    # 1. Disassemble the 7-segment digit lookup & display buffer routine (0x0fa40..0x0fe60)
    disasm_thumb_region(fw, 0x0FA40, 0x420, "7-Segment Digit Encoder / Display Buffer Writer")
    # 2. Disassemble Calculator / Display state machine (0x0c560..0x0c840)
    disasm_thumb_region(fw, 0x0C560, 0x2E0, "Calculator / Display State Machine")


if __name__ == "__main__":
    main()
