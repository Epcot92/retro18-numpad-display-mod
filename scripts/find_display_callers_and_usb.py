"""Find all callers of 7-segment display functions and locate USB HID vendor command handlers in retro18_fw_v107.bin."""
import pathlib
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107.bin")
LOAD_BASE = 0x5000


def scan_all_tjl_calls(fw: bytes) -> dict[int, list[int]]:
    calls: dict[int, list[int]] = {}
    for off in range(0, len(fw) - 4, 2):
        hw = struct.unpack_from("<H", fw, off)[0]
        hi = hw >> 8
        if 0x90 <= hi <= 0x97:
            hw2 = struct.unpack_from("<H", fw, off + 2)[0]
            hi2 = hw2 >> 8
            if 0x98 <= hi2 <= 0x9F:
                pc = LOAD_BASE + off
                s = (hw >> 10) & 1
                imm10 = hw & 0x3FF
                imm11 = hw2 & 0x7FF
                off22 = (s << 21) | (imm10 << 11) | imm11
                if s:
                    off22 -= 1 << 22
                target = (pc + 4 + (off22 << 1)) & 0xFFFFFFFF
                calls.setdefault(target, []).append(pc)
    return calls


def main() -> None:
    fw = FW_PATH.read_bytes()
    calls = scan_all_tjl_calls(fw)

    print("=== Callers of 7-Segment Display Functions (0x14900..0x14f00) ===")
    for target in sorted(calls.keys()):
        if 0x14900 <= target <= 0x14F00:
            callers = [f"0x{c:05x} (f:0x{c-LOAD_BASE:05x})" for c in calls[target]]
            print(f"  Target 0x{target:05x} (f:0x{target-LOAD_BASE:05x}) <- called from {callers}")

    # Also find all literal pool references to 0x00844d80 and 0x00844644
    print("\n=== All Literal Pool References to 0x00844644 (Framebuffer) and 0x00844d80 ===")
    for name, addr in [
        ("0x00844644 (9-byte 7-seg framebuffer)", 0x00844644),
        ("0x00844640 (display state)", 0x00844640),
        ("0x00844d80 (display flag/buffer)", 0x00844D80),
        ("0x00844d70 (calc state)", 0x00844D70),
    ]:
        pat = struct.pack("<I", addr)
        hits = []
        idx = 0
        while True:
            idx = fw.find(pat, idx)
            if idx == -1:
                break
            hits.append(f"0x{LOAD_BASE+idx:05x} (f:0x{idx:05x})")
            idx += 1
        print(f"  {name}: {hits}")


if __name__ == "__main__":
    main()
