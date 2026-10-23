"""Check references to 0x14a80 and inspect firmware header/CRC structure in retro18_fw_v107.bin and .dat file."""
import pathlib
import struct
import sys
import zlib
from tc32_disasm import disasm_tc32, FW_PATH, LOAD_BASE

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DAT_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\Config\updateFile\1d4ff454c1ae61ac4fb3b9dc3c978e42.dat"
)


def main() -> None:
    fw = FW_PATH.read_bytes()
    dat = DAT_PATH.read_bytes()

    print("=== 1. .dat Header Analysis ===")
    hdr = struct.unpack_from("<7I", dat, 0)
    for i, val in enumerate(hdr):
        print(f"  hdr[{i}] (offset 0x{i*4:02x}): 0x{val:08x} ({val})")

    print("\n=== 2. End of Decrypted Firmware (last 64 bytes of retro18_fw_v107.bin) ===")
    for off in range(len(fw) - 64, len(fw), 16):
        chunk = fw[off : off + 16]
        print(f"  f:0x{off:05x} (Flash 0x{LOAD_BASE+off:05x}): {chunk.hex(' ')}")

    # Find last non-0xFF byte in fw
    last_non_ff = len(fw) - 1
    while last_non_ff >= 0 and fw[last_non_ff] == 0xFF:
        last_non_ff -= 1
    print(f"  Last non-0xFF byte at f:0x{last_non_ff:05x} (Flash 0x{LOAD_BASE+last_non_ff:05x})")
    start_tail = max(0, (last_non_ff - 32) & ~0xF)
    for off in range(start_tail, min(len(fw), last_non_ff + 16), 16):
        chunk = fw[off : off + 16]
        print(f"  f:0x{off:05x} (Flash 0x{LOAD_BASE+off:05x}): {chunk.hex(' ')}")

    print("\n=== 3. Check Telink Header (first 64 bytes of retro18_fw_v107.bin) ===")
    for off in range(0, 64, 16):
        chunk = fw[off : off + 16]
        print(f"  f:0x{off:05x} (Flash 0x{LOAD_BASE+off:05x}): {chunk.hex(' ')}")
    tl_size = struct.unpack_from("<I", fw, 0x18)[0]
    print(f"  Telink bin size field at 0x18: 0x{tl_size:08x} ({tl_size} bytes)")
    if tl_size <= len(fw):
        print(f"  Bytes around 0x{tl_size:05x}: {fw[tl_size-16:tl_size+16].hex(' ')}")

    print("\n=== 4. Check How Firmware Update Commands (0x1644c..0x16974) Validate Firmware ===")
    # Disassemble 0x160c0 (CRC function called at 0x16870 and 0x165fe!)
    disasm_tc32(fw, 0x160C0, 0x16360, "Firmware Flash/CRC Helpers (0x160c0..0x16360)")


if __name__ == "__main__":
    main()
