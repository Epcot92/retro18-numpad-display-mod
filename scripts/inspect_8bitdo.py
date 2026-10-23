"""Inspect 8BitDo Retro 18 firmware binary, logs, and extract .NET single-file bundle assemblies."""
import pathlib
import struct
import sys

# Ensure UTF-8 stdout on Windows
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ULTIMATE_DIR = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37"
)
EXTRACT_DIR = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies")


def inspect_firmware_header() -> None:
    dat_path = ULTIMATE_DIR / "Config" / "updateFile" / "1d4ff454c1ae61ac4fb3b9dc3c978e42.dat"
    raw = dat_path.read_bytes()
    version, addr, payload_len, pid, crc, z1, z2 = struct.unpack("<IIIIIII", raw[:28])
    print("=== Retro 18 Numpad Firmware Header (1d4ff454c1ae61ac4fb3b9dc3c978e42.dat) ===")
    print(f"  Version:        {version} (v{version / 100:.2f})")
    print(f"  Target Address: 0x{addr:08x}")
    print(f"  Payload Length: {payload_len} bytes (0x{payload_len:x})")
    print(f"  USB PID:        0x{pid:04x} ({pid})")
    print(f"  Field 4 (CRC?): 0x{crc:08x}")
    print(f"  Actual Payload: {len(raw) - 28} bytes")


def inspect_log_gbk() -> None:
    log_path = ULTIMATE_DIR / "Log" / "2026-10-22-18.txt"
    if log_path.exists():
        raw = log_path.read_bytes()
        text = raw.decode("gbk", errors="replace")
        print("\n=== Log File Decoded (GBK) ===")
        for line in text.splitlines()[:60]:
            print(" ", line)


def extract_dotnet_single_file_bundle() -> None:
    """Locate the .NET single-file bundle manifest inside 8BitDo Ultimate Software V2.exe."""
    exe_path = ULTIMATE_DIR / "8BitDo Ultimate Software V2.exe"
    data = exe_path.read_bytes()
    # Standard .NET single-file bundle signature (32 bytes):
    # 8b 12 02 b9 6a 61 20 38 72 7b 93 02 14 d7 a0 32 13 f5 b9 e6 9c 3f 33 4f a1 34 c5 8b b2 c4 a8 74
    sig = bytes.fromhex(
        "8b1202b96a612038727b930214d7a03213f5b9e69c3f334fa134c58bb2c4a874"
    )
    pos = data.find(sig)
    print(f"\n=== .NET Single-File Bundle Check ({exe_path.name}) ===")
    if pos == -1:
        print("  Bundle signature not found via standard marker.")
        return

    # The 8-byte int64 right before the 32-byte signature is the manifest offset!
    manifest_offset = struct.unpack_from("<q", data, pos - 8)[0]
    print(f"  Found bundle signature at 0x{pos:x}, manifest offset = 0x{manifest_offset:x}")

    cur = manifest_offset
    major, minor, file_count = struct.unpack_from("<IIi", data, cur)
    cur += 12
    # Read bundle ID string (7-bit encoded length + UTF-8)
    strlen = data[cur]
    cur += 1
    bundle_id = data[cur : cur + strlen].decode("utf-8", errors="replace")
    cur += strlen
    print(f"  Bundle v{major}.{minor}, ID={bundle_id}, files={file_count}")
    if major >= 2:
        # Skip depsJsonOffset, depsJsonSize, runtimeconfigOffset, runtimeconfigSize, flags (8*4 + 8 = 40 bytes)
        cur += 40

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    target_keywords = ("8BitDo", "Advance", "DriverLibrary", "GenericHid", "HID")
    for _ in range(file_count):
        offset, size = struct.unpack_from("<qq", data, cur)
        cur += 16
        compressed_size = 0
        if major >= 6:
            compressed_size = struct.unpack_from("<q", data, cur)[0]
            cur += 8
        ftype = data[cur]
        cur += 1
        # Read 7-bit encoded string length
        path_len = 0
        shift = 0
        while True:
            b = data[cur]
            cur += 1
            path_len |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        rel_path = data[cur : cur + path_len].decode("utf-8", errors="replace")
        cur += path_len
        if any(k.lower() in rel_path.lower() for k in target_keywords):
            print(
                f"  -> Found embedded file: {rel_path} (offset=0x{offset:x}, size={size}, compressed={compressed_size}, type={ftype})"
            )
            out_file = EXTRACT_DIR / pathlib.Path(rel_path).name
            if compressed_size == 0 and size > 0:
                out_file.write_bytes(data[offset : offset + size])
                print(f"     Extracted to {out_file}")


if __name__ == "__main__":
    inspect_firmware_header()
    inspect_log_gbk()
    extract_dotnet_single_file_bundle()
