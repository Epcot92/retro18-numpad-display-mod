"""Build the patched 8BitDo Retro 18 Mechanical Numpad v1.07 firmware (clock/custom display mod).

Adds USB HID vendor command 0xD0 on Interface 2 (MI_02, UsagePage 0xFFA0, Report ID 0x81):
  Packet format (64 bytes):
    byte[0] = 0x81  (Report ID)
    byte[1] = 0xD0  (Custom 7-Segment Display Command)
    byte[2] = mode:
              0x00 -> Turn OFF 7-segment display (calls 0x14b88)
              0x01 -> Turn ON & update 9 digits if not in Calculator mode (*0x00844ca8 != 1)
              0x02 -> Force Turn ON & update 9 digits regardless of mode
    byte[3..11] = 9 raw 7-segment bytes (left-to-right, digits 0..8)
"""
import pathlib
import struct
import sys
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools" / "8cryptdo" / "8cryptdo-main"))
from tc32_disasm import disasm_tc32, LOAD_BASE
from cryptdo8 import Yichip, words, encrypt_payload

ORIG_FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107.bin")
ORIG_DAT_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\Config\updateFile\1d4ff454c1ae61ac4fb3b9dc3c978e42.dat"
)
PATCHED_FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107_clock_mod.bin")
PATCHED_DAT_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107_clock_mod.dat")


def encode_tjl(pc: int, target: int) -> bytes:
    """Encode a 32-bit TC32 `tjl target` instruction at `pc`."""
    off22 = ((target - (pc + 4)) >> 1) & 0x3FFFFF
    s = (off22 >> 21) & 1
    imm10 = (off22 >> 11) & 0x3FF
    imm11 = off22 & 0x7FF
    hw1 = 0x9000 | (s << 10) | imm10
    hw2 = 0x9800 | imm11
    return struct.pack("<HH", hw1, hw2)


def encode_tbcc(cond: int, pc: int, target: int) -> bytes:
    """Encode a 16-bit TC32 conditional branch `tbcc_cond target` at `pc`."""
    simm8 = (target - (pc + 4)) >> 1
    assert -128 <= simm8 <= 127, f"Branch offset out of range: {simm8}"
    hw = 0xC000 | ((cond & 0xF) << 8) | (simm8 & 0xFF)
    return struct.pack("<H", hw)


def encode_tloadr_pc(rd: int, pc: int, lit_addr: int) -> bytes:
    """Encode a 16-bit TC32 `tloadr rD, [pc, #imm8*4]` instruction at `pc`."""
    base = (pc + 4) & ~3
    diff = lit_addr - base
    assert diff >= 0 and diff % 4 == 0 and (diff // 4) <= 255, f"Bad literal offset: {diff}"
    hw = ((0x08 + rd) << 8) | (diff // 4)
    return struct.pack("<H", hw)


def build_patch_stub(stub_base: int = 0x21200) -> bytes:
    """Assemble the custom USB HID 0xD0 display handler & Calc button interceptor at `stub_base` (0x21200)."""
    # Layout of stub at 0x21200:
    #   0x21200: tpush  {lr}                        (2B)
    #   0x21202: tjl    0x16e4c                     (4B) ; original handler
    #   0x21206: tldrb  r3, [r4, #0x0]              (2B) ; packet[0]
    #   0x21208: tcmp   r3, #0x81                   (2B)
    #   0x2120a: bne    ret_label (0x21244)         (2B)
    #   0x2120c: tldrb  r3, [r4, #0x1]              (2B) ; packet[1]
    #   0x2120e: tcmp   r3, #0xd0                   (2B)
    #   0x21210: bne    ret_label (0x21244)         (2B)
    #   0x21212: tldrb  r3, [r4, #0x2]              (2B) ; packet[2] = mode
    #   0x21214: tcmp   r3, #0x00                   (2B)
    #   0x21216: bne    check_calc (0x2121e)        (2B)
    #   0x21218: tjl    0x14b88                     (4B) ; Display_Power_Off()
    #   0x2121c: tpop   {pc}                        (2B)
    # check_calc (0x2121e):
    #   0x2121e: tcmp   r3, #0x02                   (2B) ; mode 2 = force even in calc mode
    #   0x21220: beq    do_update (0x2122a)         (2B)
    #   0x21222: tloadr r3, [pc, ->lit_ca8]         (2B) ; 0x00844ca8
    #   0x21224: tldrb  r3, [r3, #0x0]              (2B)
    #   0x21226: tcmp   r3, #0x01                   (2B) ; in calculator mode?
    #   0x21228: beq    ret_label (0x21244)         (2B)
    # do_update (0x2122a):
    #   0x2122a: tmovs  r2, #0x00                   (2B)
    #   0x2122c: tloadr r3, [pc, ->lit_d80]         (2B) ; 0x00844d80
    #   0x2122e: tstrb  r2, [r3, #0x0]              (2B) ; *0x00844d80 = 0
    #   0x21230: tjl    0x14b38                     (4B) ; Display_Power_On()
    #   0x21234: tloadr r0, [pc, ->lit_644]         (2B) ; r0 = 0x00844644
    #   0x21236: tmov   r1, r4                      (2B) ; r1 = packet
    #   0x21238: tadds  r1, #0x03                   (2B) ; r1 = packet + 3
    #   0x2123a: tmovs  r2, #0x09                   (2B) ; r2 = 9
    #   0x2123c: tjl    0x181b4                     (4B) ; memcpy(0x00844644, packet + 3, 9)
    #   0x21240: tjl    0x14a44                     (4B) ; Flush_7Seg_Display()
    # ret_label (0x21244):
    #   0x21244: tpop   {pc}                        (2B)
    #   0x21246: nop/pad (c0 46)                    (2B)
    # Literal pool (4-byte aligned at 0x21248):
    #   0x21248: .word 0x00844ca8
    #   0x2124c: .word 0x00844d80
    #   0x21250: .word 0x00844644
    #
    # Sub-stub 2 at 0x21254: Windows Calculator Shortcut Button Hook (hooks 0x1113e..0x1114c)
    #   Pressing the Windows Calculator shortcut button sets *0x00844d50 bit 3 (0x08).
    #   Instead of sending Consumer Usage 0x0192 (AL Calculator) to Windows—which launches calc.exe—
    #   this hook suppresses Usage 0x0192 and sends a 63-byte Vendor Input Report on MI_02
    #   (UsagePage 0xFFA0, Report ID 0x02): [0x02, 0xD1, 0x01, 0x00, ...] via 0x16b50 on rising edge!
    #
    #   0x21254: tpush  {r0, r1, r2, r3, lr}        (2B) ; 0f 65
    #   0x21256: tloadr r3, [pc, ->lit_btn]         (2B) ; r3 = 0x00844d90 (prev state byte)
    #   0x21258: tldrb  r1, [r3, #0x0]              (2B) ; r1 = prev_pressed (0 or 1)
    #   0x2125a: tmovs  r0, #0x08                   (2B) ; bit 3 mask
    #   0x2125c: tand   r0, r2                      (2B) ; r0 = (*0x00844d50) & 0x08
    #   0x2125e: beq    not_pressed (0x21276)       (2B)
    #   0x21260: tcmp   r1, #0x00                   (2B) ; was it already pressed?
    #   0x21262: bne    done_btn (0x2127a)          (2B)
    #   0x21264: tmovs  r0, #0x01                   (2B)
    #   0x21266: tstrb  r0, [r3, #0x0]              (2B) ; *0x00844d90 = 1
    #   0x21268: tloadr r0, [pc, ->lit_pkt]         (2B) ; r0 = 0x21288 (63-byte payload in Flash)
    #   0x2126a: tmovs  r1, #0x3f                   (2B) ; len = 63
    #   0x2126c: tmovs  r2, #0x02                   (2B) ; report_id = 0x02 (MI_02 IN)
    #   0x2126e: tmovs  r3, #0x04                   (2B) ; ep = 4
    #   0x21270: tjl    0x16b50                     (4B) ; Send_MI02_Report(buf, 63, 2, 4)
    #   0x21274: tjmp   done_btn (0x2127a)          (2B)
    # not_pressed (0x21276):
    #   0x21276: tmovs  r0, #0x00                   (2B)
    #   0x21278: tstrb  r0, [r3, #0x0]              (2B) ; *0x00844d90 = 0
    # done_btn (0x2127a):
    #   0x2127a: tpop   {r0, r1, r2, r3, pc}        (2B) ; 0f 6d
    #   0x2127c: nop/pad (c0 46)                    (2B)
    #   0x2127e: nop/pad (c0 46)                    (2B)
    #   0x21280: .word  0x00844d90                  (4B) ; lit_btn
    #   0x21284: .word  0x00021288                  (4B) ; lit_pkt
    #   0x21288: d1 01 00 ... (64 bytes)            (64B)

    ret_label = stub_base + 0x44
    check_calc = stub_base + 0x1E
    do_update = stub_base + 0x2A
    lit_ca8 = stub_base + 0x48
    lit_d80 = stub_base + 0x4C
    lit_644 = stub_base + 0x50

    not_pressed = stub_base + 0x76
    done_btn = stub_base + 0x7A
    lit_btn = stub_base + 0x80
    lit_pkt = stub_base + 0x84
    pkt_addr = stub_base + 0x88

    out = bytearray()

    def emit(b: bytes, expected_off: int) -> None:
        assert len(out) == expected_off, f"Offset mismatch: got 0x{len(out):x}, expected 0x{expected_off:x}"
        out.extend(b)

    emit(bytes.fromhex("0065"), 0x00)                                      # tpush {lr}
    emit(encode_tjl(stub_base + 0x02, 0x16E4C), 0x02)                      # tjl 0x16e4c
    emit(bytes.fromhex("2348"), 0x06)                                      # tldrb r3, [r4, #0x0]
    emit(bytes.fromhex("81ab"), 0x08)                                      # tcmp r3, #0x81
    emit(encode_tbcc(1, stub_base + 0x0A, ret_label), 0x0A)                # bne ret_label
    emit(bytes.fromhex("6348"), 0x0C)                                      # tldrb r3, [r4, #0x1]
    emit(bytes.fromhex("d0ab"), 0x0E)                                      # tcmp r3, #0xd0
    emit(encode_tbcc(1, stub_base + 0x10, ret_label), 0x10)                # bne ret_label
    emit(bytes.fromhex("a348"), 0x12)                                      # tldrb r3, [r4, #0x2]
    emit(bytes.fromhex("00ab"), 0x14)                                      # tcmp r3, #0x00
    emit(encode_tbcc(1, stub_base + 0x16, check_calc), 0x16)               # bne check_calc
    emit(encode_tjl(stub_base + 0x18, 0x14B88), 0x18)                      # tjl 0x14b88 (Display OFF)
    emit(bytes.fromhex("006d"), 0x1C)                                      # tpop {pc}

    # check_calc:
    emit(bytes.fromhex("02ab"), 0x1E)                                      # tcmp r3, #0x02
    emit(encode_tbcc(0, stub_base + 0x20, do_update), 0x20)                # beq do_update
    emit(encode_tloadr_pc(3, stub_base + 0x22, lit_ca8), 0x22)             # tloadr r3, =0x00844ca8
    emit(bytes.fromhex("1b48"), 0x24)                                      # tldrb r3, [r3, #0x0]
    emit(bytes.fromhex("01ab"), 0x26)                                      # tcmp r3, #0x01
    emit(encode_tbcc(0, stub_base + 0x28, ret_label), 0x28)                # beq ret_label

    # do_update:
    emit(bytes.fromhex("00a2"), 0x2A)                                      # tmovs r2, #0x00
    emit(encode_tloadr_pc(3, stub_base + 0x2C, lit_d80), 0x2C)             # tloadr r3, =0x00844d80
    emit(bytes.fromhex("1a40"), 0x2E)                                      # tstrb r2, [r3, #0x0]
    emit(encode_tjl(stub_base + 0x30, 0x14B38), 0x30)                      # tjl 0x14b38 (Display ON)
    emit(encode_tloadr_pc(0, stub_base + 0x34, lit_644), 0x34)             # tloadr r0, =0x00844644
    emit(bytes.fromhex("21ec"), 0x36)                                      # tmov r1, r4
    emit(bytes.fromhex("03b1"), 0x38)                                      # tadds r1, #0x03
    emit(bytes.fromhex("09a2"), 0x3A)                                      # tmovs r2, #0x09
    emit(encode_tjl(stub_base + 0x3C, 0x181B4), 0x3C)                      # tjl 0x181b4 (memcpy)
    emit(encode_tjl(stub_base + 0x40, 0x14A44), 0x40)                      # tjl 0x14a44 (Flush_7Seg_Display)

    # ret_label:
    emit(bytes.fromhex("006d"), 0x44)                                      # tpop {pc}
    emit(bytes.fromhex("c046"), 0x46)                                      # pad

    # Literal pool 1:
    emit(struct.pack("<I", 0x00844CA8), 0x48)
    emit(struct.pack("<I", 0x00844D80), 0x4C)
    emit(struct.pack("<I", 0x00844644), 0x50)

    # Sub-stub 2 (0x21254): Calc Shortcut Button Handler
    emit(bytes.fromhex("0f65"), 0x54)                                      # tpush {r0, r1, r2, r3, lr}
    emit(encode_tloadr_pc(3, stub_base + 0x56, lit_btn), 0x56)             # tloadr r3, =0x00844d90
    emit(bytes.fromhex("1948"), 0x58)                                      # tldrb r1, [r3, #0x0]
    emit(bytes.fromhex("08a0"), 0x5A)                                      # tmovs r0, #0x08
    emit(bytes.fromhex("1002"), 0x5C)                                      # tand r0, r2
    emit(encode_tbcc(0, stub_base + 0x5E, not_pressed), 0x5E)              # beq not_pressed
    emit(bytes.fromhex("00a9"), 0x60)                                      # tcmp r1, #0x00
    emit(encode_tbcc(1, stub_base + 0x62, done_btn), 0x62)                 # bne done_btn
    emit(bytes.fromhex("01a0"), 0x64)                                      # tmovs r0, #0x01
    emit(bytes.fromhex("1840"), 0x66)                                      # tstrb r0, [r3, #0x0]
    emit(encode_tloadr_pc(0, stub_base + 0x68, lit_pkt), 0x68)             # tloadr r0, =0x21288
    emit(bytes.fromhex("3fa1"), 0x6A)                                      # tmovs r1, #0x3f (63)
    emit(bytes.fromhex("02a2"), 0x6C)                                      # tmovs r2, #0x02 (Report ID 2)
    emit(bytes.fromhex("04a3"), 0x6E)                                      # tmovs r3, #0x04 (EP 4)
    emit(encode_tjl(stub_base + 0x70, 0x16B50), 0x70)                      # tjl 0x16b50 (Send_MI02_Report)
    emit(bytes.fromhex("0180"), 0x74)                                      # tjmp done_btn (0x2127a)

    # not_pressed (0x21276):
    emit(bytes.fromhex("00a0"), 0x76)                                      # tmovs r0, #0x00
    emit(bytes.fromhex("1840"), 0x78)                                      # tstrb r0, [r3, #0x0]

    # done_btn (0x2127a):
    emit(bytes.fromhex("0f6d"), 0x7A)                                      # tpop {r0, r1, r2, r3, pc}
    emit(bytes.fromhex("c046"), 0x7C)                                      # pad
    emit(bytes.fromhex("c046"), 0x7E)                                      # pad

    # Literal pool 2:
    emit(struct.pack("<I", 0x00844D90), 0x80)
    emit(struct.pack("<I", pkt_addr), 0x84)

    # 63-byte Vendor Input Report payload at 0x21288 (0x16b50 prepends Report ID 0x02):
    report_pkt = bytearray(64)
    report_pkt[0] = 0xD1  # Custom Calc Shortcut Button Event (becomes pkt[1] on host!)
    report_pkt[1] = 0x01  # Pressed = 1 (becomes pkt[2] on host!)
    emit(bytes(report_pkt), 0x88)

    return bytes(out)


def yichip_encrypt(fw: bytes) -> bytes:
    """Encrypt firmware using the 512-byte block Yichip cipher from cryptdo8.py."""
    cipher = Yichip()
    p_words, _ = words(fw)
    c_words = encrypt_payload(p_words, cipher)
    return struct.pack(f"<{len(c_words)}I", *c_words)


def main() -> None:
    fw = bytearray(ORIG_FW_PATH.read_bytes())
    orig_dat = ORIG_DAT_PATH.read_bytes()

    stub_flash_addr = 0x21200
    stub_file_off = stub_flash_addr - LOAD_BASE  # 0x1c200
    stub = build_patch_stub(stub_flash_addr)

    # Verify target region in original firmware is all zeros
    assert all(b == 0 for b in fw[stub_file_off : stub_file_off + len(stub)]), "Stub region not empty!"

    # 1. Write stub to 0x21200 (f:0x1c200)
    fw[stub_file_off : stub_file_off + len(stub)] = stub

    # 2. Patch `tjl 0x16e4c` at Flash 0x17016 (f:0x12016) -> `tjl 0x21200`
    hook_flash_addr = 0x17016
    hook_file_off = hook_flash_addr - LOAD_BASE
    assert fw[hook_file_off : hook_file_off + 4] == bytes.fromhex("ff97199f"), "Unexpected bytes at hook site!"
    fw[hook_file_off : hook_file_off + 4] = encode_tjl(hook_flash_addr, stub_flash_addr)

    # 2b. Patch Windows Calculator button handler at Flash 0x1113E..0x1114C (f:0x0c13e..0x0c14c)
    #     Replaces Consumer Usage 0x0192 (AL Calculator) write with `tjl 0x21254` + `tjmp 0x1114e`
    calc_btn_flash_addr = 0x1113E
    calc_btn_file_off = calc_btn_flash_addr - LOAD_BASE
    assert fw[calc_btn_file_off : calc_btn_file_off + 16] == bytes.fromhex(
        "11f705c5c9a252f0690602b10a201a20"
    ), "Unexpected bytes at Calc button hook site!"
    calc_btn_patch = (
        encode_tjl(calc_btn_flash_addr, stub_flash_addr + 0x54)
        + bytes.fromhex("0480")  # tjmp 0x1114e
        + bytes.fromhex("c046") * 5  # padding
    )
    assert len(calc_btn_patch) == 16
    fw[calc_btn_file_off : calc_btn_file_off + 16] = calc_btn_patch

    # 3. Recompute Telink IEEE CRC32 trailer at f:0x1c3b0
    tl_size = struct.unpack_from("<I", fw, 0x18)[0]  # 0x1c3b4
    new_crc32 = (~zlib.crc32(fw[: tl_size - 4])) & 0xFFFFFFFF
    struct.pack_into("<I", fw, tl_size - 4, new_crc32)
    assert (zlib.crc32(fw[:tl_size]) & 0xFFFFFFFF) == 0xFFFFFFFF, "Telink CRC32 check failed!"

    PATCHED_FW_PATH.write_bytes(fw)
    print(f"Saved patched plaintext firmware ({len(fw)} bytes) to {PATCHED_FW_PATH}")
    print(f"Updated Telink CRC32 trailer @ f:0x{tl_size-4:05x} -> 0x{new_crc32:08x}")

    # 4. Encrypt into 8BitDo .dat format using Yichip cipher
    orig_fw = ORIG_FW_PATH.read_bytes()
    assert yichip_encrypt(orig_fw) == orig_dat[0x1C:], "Yichip self-test failed!"

    enc_patched = yichip_encrypt(bytes(fw))
    patched_dat = orig_dat[:0x1C] + enc_patched
    PATCHED_DAT_PATH.write_bytes(patched_dat)
    print(f"Saved encrypted 8BitDo .dat package ({len(patched_dat)} bytes) to {PATCHED_DAT_PATH}")

    # Show which 4KB sectors differ between original .dat and patched .dat
    changed_sectors = []
    for off in range(0, len(fw), 0x1000):
        if orig_dat[0x1C + off : 0x1C + off + 0x1000] != patched_dat[0x1C + off : 0x1C + off + 0x1000]:
            changed_sectors.append(f"0x{off:05x} (Flash 0x{LOAD_BASE+off:05x})")
    print(f"Changed 4KB sectors ({len(changed_sectors)} of {(len(fw)+0xFFF)//0x1000}): {changed_sectors}")

    # Disassemble the hook and stub to verify
    disasm_tc32(bytes(fw), 0x16FF0, 0x17020, "Patched USB Command Dispatcher (0x16ff0..0x17020)")
    disasm_tc32(bytes(fw), 0x11130, 0x11154, "Patched Calc Shortcut Button Handler (0x11130..0x11154)")
    disasm_tc32(bytes(fw), 0x21200, 0x21288, "Injected 0xD0 & Calc Button Stubs (0x21200..0x21288)")


if __name__ == "__main__":
    main()
