"""Analyze the decrypted 8BitDo Retro 18 Mechanical Numpad firmware (retro18_fw_v107.bin)."""
import pathlib
import re
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107.bin")


def dump_hex(data: bytes, start: int = 0, length: int = 256) -> None:
    for off in range(start, min(start + length, len(data)), 16):
        chunk = data[off : off + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {off:05x}: {hex_str:<48} {ascii_str}")


def main() -> None:
    fw = FW_PATH.read_bytes()
    print(f"=== Decrypted Retro 18 Firmware: {FW_PATH.name} ({len(fw)} bytes, load addr 0x5000) ===")
    print("\n[1] First 256 bytes:")
    dump_hex(fw, 0, 256)

    print("\n[2] Embedded Strings (len >= 5):")
    for m in re.finditer(rb"[\x20-\x7e]{5,}", fw):
        s = m.group(0).decode("ascii")
        print(f"  0x{m.start():05x} (mem 0x{0x5000 + m.start():05x}): {s!r}")

    print("\n[3] USB Descriptors & VID/PID (2DC8:5203) & HID UsagePage 0xFFA0:")
    for name, pat in [
        ("VID:PID 2DC8:5203", b"\xc8\x2d\x03\x52"),
        ("HID UsagePage 0xFFA0 (06 A0 FF)", b"\x06\xa0\xff"),
        ("7-seg standard cathode (3F 06 5B 4F 66 6D 7D 07 7F 6F)", bytes([0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07, 0x7F, 0x6F])),
        ("7-seg standard anode (C0 F9 A4 B0 99 92 82 F8 80 90)", bytes([0xC0, 0xF9, 0xA4, 0xB0, 0x99, 0x92, 0x82, 0xF8, 0x80, 0x90])),
    ]:
        idx = 0
        hits = []
        while True:
            idx = fw.find(pat, idx)
            if idx == -1:
                break
            hits.append(f"0x{idx:05x} (mem 0x{0x5000 + idx:05x})")
            idx += 1
        print(f"  {name}: {hits}")

    # Also search for any 10-byte table where popcount of each byte matches 7-segment digit segment counts!
    # Digit segment counts for 0..9:
    # '0': 6 segs
    # '1': 2 segs
    # '2': 5 segs
    # '3': 5 segs
    # '4': 4 segs
    # '5': 5 segs
    # '6': 6 (or 5) segs
    # '7': 3 (or 4) segs
    # '8': 7 segs
    # '9': 6 (or 5) segs
    print("\n[4] Searching for 7-segment digit lookup tables (by segment popcount signature):")
    for i in range(len(fw) - 10):
        window = fw[i : i + 10]
        # Check cathode-like (bit=1 means segment ON, bit 7=0 or constant)
        pops = [bin(b & 0x7F).count("1") for b in window]
        if (
            pops[0] == 6
            and pops[1] == 2
            and pops[2] == 5
            and pops[3] == 5
            and pops[4] == 4
            and pops[5] == 5
            and pops[6] in (5, 6)
            and pops[7] in (3, 4)
            and pops[8] == 7
            and pops[9] in (5, 6)
        ):
            # Also check that '8' (window[8]) is a superset of all other digits!
            mask8 = window[8] & 0x7F
            if all((b & 0x7F) & ~mask8 == 0 for b in window) and (window[1] & window[0]) == window[1]:
                hex_b = " ".join(f"{b:02x}" for b in window)
                extra = " ".join(f"{b:02x}" for b in fw[i + 10 : i + 20])
                print(f"  CANDIDATE 7-SEG TABLE at file 0x{i:05x} (mem 0x{0x5000+i:05x}): [{hex_b}] + [{extra}]")


if __name__ == "__main__":
    main()
