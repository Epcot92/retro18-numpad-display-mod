"""Disassemble all USB HID command handlers (0x16300..0x16cc0) and find callers of 0x16ff0 and 0x14a80."""
import struct
import sys
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE
from find_display_callers_and_usb import scan_all_tjl_calls

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    fw = FW_PATH.read_bytes()
    calls = scan_all_tjl_calls(fw)

    for target in [0x14A44, 0x14A80, 0x14AC4, 0x14AFC, 0x14B14, 0x14B38, 0x14B88, 0x14D40, 0x14E18, 0x16FF0, 0x16DA4]:
        c_list = [f"0x{c:05x}" for c in calls.get(target, [])]
        print(f"Callers of 0x{target:05x}: {c_list}")

    disasm_tc32(fw, 0x16360, 0x16CC0, "USB Command Dispatcher & Handlers (0x16360..0x16cc0)")


if __name__ == "__main__":
    main()
