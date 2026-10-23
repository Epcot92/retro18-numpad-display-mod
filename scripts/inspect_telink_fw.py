"""Inspect Telink TLSR825x memory map, SRAM variables, and USB HID handlers in retro18_fw_v107.bin."""
import pathlib
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107.bin")


def main() -> None:
    fw = FW_PATH.read_bytes()

    # Check Telink startup header values at 0x00d0..0x0100
    print("=== Telink Startup Pointers (0x00d0..0x0100) ===")
    for off in range(0xD0, 0x100, 4):
        val = struct.unpack_from("<I", fw, off)[0]
        print(f"  0x{off:04x} (flash 0x{0x5000+off:05x}): 0x{val:08x}")

    # Map .data section: Flash 0x00020f24 (file offset 0x1bf24) -> SRAM 0x00844600..0x00844788
    flash_data_start = 0x00020F24
    file_data_start = flash_data_start - 0x5000  # 0x1bf24
    sram_data_start = 0x00844600
    sram_data_end = 0x00844788
    data_len = sram_data_end - sram_data_start

    print(f"\n=== Initialized SRAM .data Section (0x{sram_data_start:08x}..0x{sram_data_end:08x}, {data_len} bytes) ===")
    for off in range(0, data_len, 16):
        f_off = file_data_start + off
        s_addr = sram_data_start + off
        chunk = fw[f_off : f_off + 16]
        h = " ".join(f"{b:02x}" for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  SRAM 0x{s_addr:08x} (file 0x{f_off:05x}): {h:<48} {a}")

    # Search for references to SRAM addresses 0x00844630..0x00844680 in the firmware literal pools!
    print("\n=== Literal Pool References to SRAM 0x00844600..0x00844680 ===")
    for addr in range(0x00844600, 0x00844680):
        pat = struct.pack("<I", addr)
        idx = 0
        hits = []
        while True:
            idx = fw.find(pat, idx)
            if idx == -1:
                break
            hits.append(f"file 0x{idx:05x} (flash 0x{0x5000+idx:05x})")
            idx += 1
        if hits:
            s_off = file_data_start + (addr - sram_data_start)
            preview = fw[s_off : s_off + 12].hex(" ")
            print(f"  SRAM 0x{addr:08x} [{preview}] -> referenced at {hits}")

    # Also dump the USB descriptors around 0x1aa80..0x1b680
    print("\n=== USB Descriptors Region (0x1aa80..0x1b680) ===")
    for off in range(0x1AA80, 0x1B680, 16):
        chunk = fw[off : off + 16]
        h = " ".join(f"{b:02x}" for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  0x{off:05x} (flash 0x{0x5000+off:05x}): {h:<48} {a}")


if __name__ == "__main__":
    main()
