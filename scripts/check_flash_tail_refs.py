"""Check references to 0x00844788..0x00844a90 and 0x210ac..0x213b0 in retro18_fw_v107.bin."""
import struct
from tc32_disasm import FW_PATH, LOAD_BASE


def main() -> None:
    fw = FW_PATH.read_bytes()
    for off in range(0, len(fw) - 4, 2):
        val = struct.unpack_from("<I", fw, off)[0]
        if 0x00020F00 <= val <= 0x00021400 or 0x00844780 <= val <= 0x00844A90:
            print(f"  Word @ Flash 0x{LOAD_BASE+off:05x} (f:0x{off:05x}): 0x{val:08x}")


if __name__ == "__main__":
    main()
