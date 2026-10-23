"""Disassemble Flash/NVRAM routines 0x11350..0x11530 in retro18_fw_v107.bin."""
import sys
from tc32_disasm import disasm_tc32, FW_PATH

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    disasm_tc32(fw, 0x11350, 0x11530, "Flash & NVRAM Routines (0x11350..0x11530)")


if __name__ == "__main__":
    main()
