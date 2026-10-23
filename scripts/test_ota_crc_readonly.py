"""Read-only test of 0x00C1 (initDevice) and 0x00C3 (readCRC) on the connected 8BitDo Retro 18 Numpad."""
import pathlib
import struct
import hid

VID = 0x2DC8
PID = 0x5203
USAGE_PAGE = 0xFFA0

ORIG_DAT_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\Config\updateFile\1d4ff454c1ae61ac4fb3b9dc3c978e42.dat"
)


def crc16_modbus(data: bytes) -> int:
    """Compute CRC-16 (poly=0xA001, init=0xFFFF) matching 0x160c0 in firmware and 0x10411070 in 8BitDoAdvance.dll."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def build_ota_packet(
    cmd_id: int,
    hdr_len: int = 0,
    total_len: int = 0,
    offset: int = 0,
    payload: bytes | None = None,
) -> bytes:
    pkt = bytearray(64)
    pkt[0] = 0x81
    pkt[1] = 0x05
    pay_crc = 0
    if payload is not None:
        pkt[18 : 18 + len(payload)] = payload
        pay_crc = crc16_modbus(payload)
    struct.pack_into("<HHIII", pkt, 2, cmd_id, 0, (pay_crc << 16) | hdr_len, total_len, offset)
    return bytes(pkt)


def main() -> None:
    orig_dat = ORIG_DAT_PATH.read_bytes()
    enc_fw = orig_dat[0x1C:]

    target_path = next(d["path"] for d in hid.enumerate(VID, PID) if d["usage_page"] == USAGE_PAGE)
    dev = hid.device()
    dev.open_path(target_path)
    dev.set_nonblocking(False)

    # 1. Send 0x00C1 (initDevice)
    pkt_c1 = build_ota_packet(0x00C1)
    dev.write(pkt_c1)
    resp_c1 = bytes(dev.read(64, timeout_ms=1000))
    print(f"0x00C1 response ({len(resp_c1)}B): {resp_c1[:24].hex(' ')}")

    # 2. Send 0x00C3 (readCRC for offset=0x0000, len=0x1000)
    payload_c3 = struct.pack("<III", 0x0000, 0x1000, 0)
    pkt_c3 = build_ota_packet(0x00C3, hdr_len=12, total_len=0, offset=0, payload=payload_c3)
    dev.write(pkt_c3)
    resp_c3 = bytes(dev.read(64, timeout_ms=1000))
    print(f"0x00C3 response ({len(resp_c3)}B): {resp_c3[:24].hex(' ')}")
    if len(resp_c3) >= 20:
        dev_crc = struct.unpack_from("<H", resp_c3, 18)[0]
        file_crc = crc16_modbus(enc_fw[0:0x1000])
        print(f"Device staging sector 0x0000 CRC: 0x{dev_crc:04x} | Official v1.07 .dat sector 0x0000 CRC: 0x{file_crc:04x}")

    dev.close()


if __name__ == "__main__":
    main()
