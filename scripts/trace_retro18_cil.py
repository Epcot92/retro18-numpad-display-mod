"""Trace PID 0x5203 (20995) and 'Retro 18 Mechanical Numpad' in UltimateV2_code_only.dll and 8BitDoAdvance.dll."""
import pathlib
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DLL_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\UltimateV2_code_only.dll")
ADVANCE_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDoAdvance.dll"
)


def find_us_tokens(data: bytes, meta_off: int) -> None:
    sig, maj, min_v, reserved, ver_len = struct.unpack_from("<IHHII", data, meta_off)
    cur = meta_off + 16 + ver_len
    flags, num_streams = struct.unpack_from("<HH", data, cur)
    cur += 4
    us_off = 0
    us_size = 0
    for _ in range(num_streams):
        off, size = struct.unpack_from("<II", data, cur)
        cur += 8
        name = bytearray()
        while data[cur] != 0:
            name.append(data[cur])
            cur += 1
        cur += 1
        while (cur - meta_off) % 4 != 0:
            cur += 1
        if name == b"#US":
            us_off = meta_off + off
            us_size = size

    us = data[us_off : us_off + us_size]
    pos = 1
    while pos < len(us):
        start_pos = pos
        b0 = us[pos]
        if b0 == 0:
            pos += 1
            continue
        if (b0 & 0x80) == 0:
            length = b0
            pos += 1
        elif (b0 & 0xC0) == 0x80:
            length = ((b0 & 0x3F) << 8) | us[pos + 1]
            pos += 2
        else:
            length = ((b0 & 0x1F) << 24) | (us[pos + 1] << 16) | (us[pos + 2] << 8) | us[pos + 3]
            pos += 4
        if length > 1:
            s_val = us[pos : pos + length - 1].decode("utf-16le", errors="replace")
            if any(k in s_val for k in ("Retro 18", "Numpad", "5203", "20995")):
                token = 0x70000000 | start_pos
                # Search for ldstr (0x72 + little-endian token) in CIL code
                pat = b"\x72" + struct.pack("<I", token)
                hits = []
                idx = 0
                while True:
                    idx = data.find(pat, idx, meta_off)
                    if idx == -1:
                        break
                    hits.append(hex(idx))
                    idx += 1
                print(f"US Token 0x{token:08x}: {s_val!r} -> ldstr hits at {hits}")
        pos += length

    # Also search for ldc.i4 20995 (0x20 03 52 00 00) in CIL code
    pat_pid = b"\x20\x03\x52\x00\x00"
    idx = 0
    pid_hits = []
    while True:
        idx = data.find(pat_pid, idx, meta_off)
        if idx == -1:
            break
        pid_hits.append(hex(idx))
        idx += 1
    print(f"\nCIL ldc.i4 0x5203 (20995) hits ({len(pid_hits)}): {pid_hits}")


def search_advance_dll() -> None:
    adv = ADVANCE_PATH.read_bytes()
    # Search for 0x5203 in 8BitDoAdvance.dll
    pat32 = struct.pack("<I", 0x5203)
    hits = []
    idx = 0
    while True:
        idx = adv.find(pat32, idx)
        if idx == -1:
            break
        hits.append(hex(idx))
        idx += 1
    print(f"\n8BitDoAdvance.dll 32-bit 0x00005203 hits ({len(hits)}): {hits[:30]}")


if __name__ == "__main__":
    data = DLL_PATH.read_bytes()
    find_us_tokens(data, 0x00222F1C)
    search_advance_dll()
