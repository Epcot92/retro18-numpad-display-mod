"""Atomic OTA Firmware Flasher for the 8BitDo Retro 18 Mechanical Numpad (VID 0x2DC8, PID 0x5203).

Flashes `retro18_fw_v107_clock_mod.dat` to the Telink MCU's staging partition (0x40000..0x5c400),
verifies every 4KB sector using hardware CRC-16 (0x00C3) before committing the OTA header (0x00C4),
and reboots the numpad into the patched firmware (0x0007).
"""
from __future__ import annotations

import pathlib
import struct
import sys
import time
import hid

VID = 0x2DC8
PID = 0x5203
USAGE_PAGE = 0xFFA0

DEFAULT_DAT_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107_clock_mod.dat")


def crc16_modbus(data: bytes) -> int:
    """Compute CRC-16 (poly=0xA001, init=0xFFFF) matching 0x160c0 in firmware."""
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


def send_and_check(
    dev: hid.device,
    cmd_id: int,
    hdr_len: int = 0,
    total_len: int = 0,
    offset: int = 0,
    payload: bytes | None = None,
    timeout_ms: int = 2000,
) -> bytes:
    pkt = build_ota_packet(cmd_id, hdr_len, total_len, offset, payload)
    for attempt in range(3):
        dev.write(pkt)
        resp = bytes(dev.read(64, timeout_ms=timeout_ms))
        if len(resp) >= 6 and resp[0] == 0x02 and resp[1] == 0x05:
            status, echoed_cmd = struct.unpack_from("<HH", resp, 2)
            if status == 0 and echoed_cmd == cmd_id:
                return resp
        time.sleep(0.05)
    raise RuntimeError(f"OTA command 0x{cmd_id:04X} at offset 0x{offset:05X} failed (last resp: {resp.hex(' ') if resp else 'timeout'})")


def flash_firmware(dat_path: pathlib.Path = DEFAULT_DAT_PATH) -> None:
    dat = dat_path.read_bytes()
    version, base_addr, payload_len, pid = struct.unpack_from("<IIII", dat, 0)
    enc_fw = dat[0x1C:]
    if pid != PID or base_addr != 0x5000 or len(enc_fw) != payload_len:
        raise ValueError(f"Invalid .dat header: version={version}, addr=0x{base_addr:x}, len={payload_len}, pid=0x{pid:x}")

    print(f"Loaded {dat_path.name}: version={version} (v{version/100:.2f}), payload_len={payload_len} bytes (0x{payload_len:x})")

    target_path = next((d["path"] for d in hid.enumerate(VID, PID) if d["usage_page"] == USAGE_PAGE), None)
    if not target_path:
        raise RuntimeError("8BitDo Retro 18 Numpad (VID 0x2DC8, PID 0x5203, UsagePage 0xFFA0) not found!")

    dev = hid.device()
    dev.open_path(target_path)
    dev.set_nonblocking(False)

    try:
        # Step 1: Initialize OTA session (0x00C1)
        print("[1/5] Initializing OTA session (0x00C1)...")
        send_and_check(dev, 0x00C1)

        # Step 2: Erase and write all 4KB sectors sequentially from 0x00000 to payload_len
        # (Sequential writing from 0 ensures the on-chip Yichip 512-byte block counter stays synchronized.)
        total_sectors = (payload_len + 0xFFF) // 0x1000
        print(f"[2/5] Flashing {total_sectors} sectors ({payload_len} bytes) to staging partition (0x40000)...")
        t0 = time.time()
        for sec_idx, sec_off in enumerate(range(0, payload_len, 0x1000)):
            sec_len = min(0x1000, payload_len - sec_off)
            # Erase 4KB sector in staging partition
            send_and_check(dev, 0x0004, hdr_len=0, total_len=0, offset=sec_off)

            # Write sector in 46-byte (0x2E) chunks
            pos = 0
            while pos < sec_len:
                chunk_len = min(0x2E, sec_len - pos)
                chunk = enc_fw[sec_off + pos : sec_off + pos + chunk_len]
                send_and_check(
                    dev,
                    0x0003,
                    hdr_len=chunk_len,
                    total_len=chunk_len,
                    offset=sec_off + pos,
                    payload=chunk,
                )
                pos += chunk_len

            if (sec_idx + 1) % 5 == 0 or (sec_idx + 1) == total_sectors:
                elapsed = time.time() - t0
                print(f"      Flashed sector {sec_idx + 1:2d}/{total_sectors} (offset 0x{sec_off:05x}, {elapsed:.1f}s)")

        # Step 3: Verify every 4KB sector in staging Flash using hardware CRC-16 (0x00C3)
        print(f"[3/5] Verifying all {total_sectors} sectors in staging Flash via hardware CRC-16 (0x00C3)...")
        for sec_idx, sec_off in enumerate(range(0, payload_len, 0x1000)):
            sec_len = min(0x1000, payload_len - sec_off)
            payload_c3 = struct.pack("<III", sec_off, sec_len, 0)
            resp = send_and_check(dev, 0x00C3, hdr_len=12, total_len=0, offset=0, payload=payload_c3)
            dev_crc = struct.unpack_from("<H", resp, 18)[0]
            expected_crc = crc16_modbus(enc_fw[sec_off : sec_off + sec_len])
            if dev_crc != expected_crc:
                raise RuntimeError(
                    f"CRC mismatch at sector 0x{sec_off:05x}: device=0x{dev_crc:04x}, expected=0x{expected_crc:04x}! Aborting before commit."
                )
        print(f"      All {total_sectors} sectors verified 100% match!")

        # Step 4: Finalize OTA staging header at 0x7E000 (0x00C4)
        print("[4/5] Committing OTA staging metadata (0x00C4)...")
        payload_c4 = struct.pack("<II", payload_len, version)
        send_and_check(dev, 0x00C4, hdr_len=8, total_len=8, offset=0, payload=payload_c4)

        # Step 5: Reboot MCU into bootloader to apply staging image (0x0007)
        print("[5/5] Rebooting Retro 18 Numpad to apply firmware (0x0007)...")
        send_and_check(dev, 0x0007, hdr_len=8, total_len=8, offset=0, payload=None)
        print("Firmware flash complete! Waiting for device to reboot and re-enumerate...")
    finally:
        dev.close()


if __name__ == "__main__":
    flash_firmware()
