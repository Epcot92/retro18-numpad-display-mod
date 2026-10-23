"""Verify the exact checksum/CRC algorithms for Telink trailer (0x013c7bc3) and .dat header (0x1560a90c)."""
import pathlib
import struct
import zlib

FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107.bin")
DAT_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V2_1.37\1d4ff454c1ae61ac4fb3b9dc3c978e42.dat"
)
# Use the actual path from earlier
DAT_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\Config\updateFile\1d4ff454c1ae61ac4fb3b9dc3c978e42.dat"
)


def main() -> None:
    fw = FW_PATH.read_bytes()
    dat = DAT_PATH.read_bytes()
    enc_payload = dat[0x1C:]

    tl_size = struct.unpack_from("<I", fw, 0x18)[0]  # 0x1c3b4
    tl_trailer = struct.unpack_from("<I", fw, tl_size - 4)[0]
    dat_crc = struct.unpack_from("<I", dat, 0x10)[0]

    print(f"Telink size: 0x{tl_size:x}, trailer @ 0x{tl_size-4:x}: 0x{tl_trailer:08x}")
    print(f".dat header[4] @ 0x10: 0x{dat_crc:08x}")

    # Test sums and CRCs on fw[:tl_size-4], fw, and enc_payload
    for name, buf in [
        ("fw[:tl_size-4]", fw[: tl_size - 4]),
        ("fw[:tl_size]", fw[:tl_size]),
        ("fw (full)", fw),
        ("enc_payload (dat[0x1c:])", enc_payload),
        ("dat[0x1c:0x1c+tl_size]", enc_payload[:tl_size]),
    ]:
        crc32 = zlib.crc32(buf) & 0xFFFFFFFF
        sum8 = sum(buf) & 0xFFFFFFFF
        sum32 = sum(struct.unpack(f"<{len(buf)//4}I", buf)) & 0xFFFFFFFF
        print(
            f"  {name:<28} -> crc32=0x{crc32:08x} (~crc32=0x{(~crc32)&0xFFFFFFFF:08x}), sum8=0x{sum8:08x}, sum32=0x{sum32:08x}"
        )


if __name__ == "__main__":
    main()
