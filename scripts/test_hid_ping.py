"""Non-destructive read-only HID test with the connected 8BitDo Retro 18 Mechanical Numpad (VID 0x2DC8, PID 0x5203)."""
import hid

VID = 0x2DC8
PID = 0x5203
USAGE_PAGE = 0xFFA0


def main() -> None:
    target_path = None
    for d in hid.enumerate(VID, PID):
        print(
            f"Found interface: MI_{d['interface_number']:02d} "
            f"usage_page=0x{d['usage_page']:04x} usage=0x{d['usage']:04x} path={d['path']}"
        )
        if d["usage_page"] == USAGE_PAGE:
            target_path = d["path"]

    if not target_path:
        print("Vendor HID interface (0xFFA0) not found!")
        return

    dev = hid.device()
    dev.open_path(target_path)
    dev.set_nonblocking(False)
    print(f"\nOpened vendor interface: {target_path}")
    print(f"Manufacturer: {dev.get_manufacturer_string()}")
    print(f"Product:      {dev.get_product_string()}")

    # Send read-only query 81 05 00 21 01 (handled by 0x16db8 in firmware)
    pkt = bytearray(64)
    pkt[0] = 0x81
    pkt[1] = 0x05
    pkt[2] = 0x00
    pkt[3] = 0x21
    pkt[4] = 0x01
    written = dev.write(bytes(pkt))
    print(f"Sent 81 05 00 21 01 ({written} bytes)")

    resp = dev.read(64, timeout_ms=1000)
    if resp:
        raw = bytes(resp)
        print(f"Received ({len(raw)} bytes): {raw[:16].hex(' ')}")
        if len(raw) >= 3 and raw[0] == 0x02 and raw[1] == 0x22:
            fw_ver = raw[2] - 0x10
            print(f"Decoded firmware version from 0x16db8 response: v{fw_ver / 100:.2f} (raw 0x{raw[2]:02x})")
    else:
        print("No response within 1000ms")

    dev.close()


if __name__ == "__main__":
    main()
