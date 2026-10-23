"""Find how the Windows Calculator shortcut button (HID Consumer Usage 0x0192) is handled in retro18_fw_v107.bin."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    # Search for 0x0192 (AL Calculator) in firmware
    for pat, label in [(b"\x92\x01", "0x0192 (16-bit LE)"), (b"\x92\x01\x00\x00", "0x00000192 (32-bit LE)")]:
        idx = 0
        hits = []
        while True:
            idx = fw.find(pat, idx)
            if idx == -1:
                break
            hits.append(f"0x{LOAD_BASE+idx:05x} (f:0x{idx:05x})")
            idx += 1
        print(f"{label}: {hits}")

    # Disassemble around 0x10790..0x10a90 (key handling / mode buttons)
    disasm_tc32(fw, 0x10720, 0x10800, "Key / Mode Handling (0x10720..0x10800)")


if __name__ == "__main__":
    main()
