"""Extract #Strings and #US from UltimateV2_code_only.dll and 8BitDo Ultimate Software V2.pdb."""
import pathlib
import re
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DLL_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\UltimateV2_code_only.dll")
PDB_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo Ultimate Software V2.pdb"
)


def parse_bsjb_streams(data: bytes, base_off: int) -> dict[str, bytes]:
    sig, maj, min_v, reserved, ver_len = struct.unpack_from("<IHHII", data, base_off)
    assert sig == 0x424A5342, f"Bad BSJB magic at 0x{base_off:x}"
    cur = base_off + 16 + ver_len
    flags, num_streams = struct.unpack_from("<HH", data, cur)
    cur += 4
    streams = {}
    for _ in range(num_streams):
        off, size = struct.unpack_from("<II", data, cur)
        cur += 8
        name = bytearray()
        while data[cur] != 0:
            name.append(data[cur])
            cur += 1
        cur += 1
        while (cur - base_off) % 4 != 0:
            cur += 1
        streams[name.decode("ascii")] = data[base_off + off : base_off + off + size]
    return streams


def inspect_dll_metadata() -> None:
    data = DLL_PATH.read_bytes()
    meta_off = 0x00222F1C
    streams = parse_bsjb_streams(data, meta_off)
    print("=== UltimateV2_code_only.dll Metadata Streams ===")
    for k, v in streams.items():
        print(f"  {k:<10}: {len(v)} bytes")

    # 1. Extract all identifiers from #Strings
    raw_strings = streams["#Strings"].split(b"\x00")
    idents = [s.decode("utf-8", errors="replace") for s in raw_strings if s]
    print(f"\nTotal #Strings identifiers: {len(idents)}")
    keywords = (
        "5203",
        "20995",
        "5200",
        "20992",
        "numpad",
        "calc",
        "retro",
        "jp",
        "keyboard",
        "led",
        "display",
        "screen",
        "hid",
        "rtk",
        "dfu",
    )
    matches = [
        s
        for s in idents
        if any(k in s.lower() for k in keywords)
        and not s.startswith("<")
        and len(s) < 100
    ]
    print(f"Matching #Strings ({len(matches)}):")
    for m in sorted(set(matches))[:200]:
        print(" ", m)

    # 2. Extract #US (User Strings - UTF-16LE with 7-bit compressed length)
    us = streams["#US"]
    cur = 1
    user_strings = []
    while cur < len(us):
        b0 = us[cur]
        if b0 == 0:
            cur += 1
            continue
        if (b0 & 0x80) == 0:
            length = b0
            cur += 1
        elif (b0 & 0xC0) == 0x80:
            length = ((b0 & 0x3F) << 8) | us[cur + 1]
            cur += 2
        else:
            length = ((b0 & 0x1F) << 24) | (us[cur + 1] << 16) | (us[cur + 2] << 8) | us[cur + 3]
            cur += 4
        if length > 1:
            s_bytes = us[cur : cur + length - 1]
            s_val = s_bytes.decode("utf-16le", errors="replace")
            user_strings.append(s_val)
        cur += length

    print(f"\nTotal #US literals: {len(user_strings)}")
    for s in user_strings:
        if any(k in s.lower() for k in ("5203", "20995", "5200", "20992", "numpad", "calc", "retro", "dfu", "rtk", "108", "87", "18")):
            if len(s) < 200:
                print("  US:", repr(s))


if __name__ == "__main__":
    inspect_dll_metadata()
