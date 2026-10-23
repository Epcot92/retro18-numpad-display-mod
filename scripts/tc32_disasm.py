"""Telink TC32 Disassembler for 8BitDo Retro 18 Mechanical Numpad Firmware (retro18_fw_v107.bin)."""
import pathlib
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FW_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\retro18_fw_v107.bin")
LOAD_BASE = 0x5000

REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"]


def format_reglist(mask: int, extra: str = "") -> str:
    names = [REGS[i] for i in range(8) if (mask & (1 << i))]
    if extra:
        names.append(extra)
    return "{" + ", ".join(names) + "}"


def disasm_tc32(fw: bytes, flash_start: int, flash_end: int, title: str) -> None:
    print(f"\n=== {title} (Flash 0x{flash_start:05x}..0x{flash_end:05x}) ===")
    # First collect all literal pool addresses targeted by tloadr [pc, #imm] so we render them as .word!
    lit_addrs = set()
    pc = flash_start
    while pc < flash_end:
        foff = pc - LOAD_BASE
        hw = struct.unpack_from("<H", fw, foff)[0]
        hi = hw >> 8
        lo = hw & 0xFF
        if 0x90 <= hi <= 0x97 and pc + 2 < flash_end:
            hw2 = struct.unpack_from("<H", fw, foff + 2)[0]
            if 0x98 <= (hw2 >> 8) <= 0x9F:
                pc += 4
                continue
        if 0x08 <= hi <= 0x0F:
            lit_va = ((pc + 4) & ~3) + lo * 4
            lit_addrs.add(lit_va)
        pc += 2

    pc = flash_start
    while pc < flash_end:
        foff = pc - LOAD_BASE
        if pc in lit_addrs and (pc % 4 == 0):
            val = struct.unpack_from("<I", fw, foff)[0]
            print(f"  0x{pc:05x}: {fw[foff:foff+4].hex():<10} .word    0x{val:08x}")
            pc += 4
            continue

        hw = struct.unpack_from("<H", fw, foff)[0]
        hi = hw >> 8
        lo = hw & 0xFF

        # 1. 32-bit tjl (branch and link): 0x90..0x97 followed by 0x98..0x9f
        if 0x90 <= hi <= 0x97 and pc + 2 < len(fw) + LOAD_BASE:
            hw2 = struct.unpack_from("<H", fw, foff + 2)[0]
            hi2 = hw2 >> 8
            if 0x98 <= hi2 <= 0x9F:
                s = (hw >> 10) & 1
                imm10 = hw & 0x3FF
                imm11 = hw2 & 0x7FF
                off22 = (s << 21) | (imm10 << 11) | imm11
                if s:
                    off22 -= 1 << 22
                target = (pc + 4 + (off22 << 1)) & 0xFFFFFFFF
                raw_hex = fw[foff : foff + 4].hex()
                print(f"  0x{pc:05x}: {raw_hex:<10} tjl      0x{target:05x}")
                pc += 4
                continue

        raw_hex = fw[foff : foff + 2].hex()
        # 2. tloadr rD, [pc, #imm8*4]: 0x08..0x0f
        if 0x08 <= hi <= 0x0F:
            rd = hi - 0x08
            lit_va = ((pc + 4) & ~3) + lo * 4
            lit_foff = lit_va - LOAD_BASE
            val = struct.unpack_from("<I", fw, lit_foff)[0] if 0 <= lit_foff <= len(fw) - 4 else 0
            print(f"  0x{pc:05x}: {raw_hex:<10} tloadr   r{rd}, [pc, #0x{lo*4:x}] ; [0x{lit_va:05x}] = 0x{val:08x}")
        # 3. tpush: 0x64..0x65
        elif hi in (0x64, 0x65):
            lr = "lr" if (hi & 1) else ""
            print(f"  0x{pc:05x}: {raw_hex:<10} tpush    {format_reglist(lo, lr)}")
        # 4. tpop: 0x6c..0x6d or 0x87
        elif hi in (0x6C, 0x6D):
            pc_reg = "pc" if (hi & 1) else ""
            print(f"  0x{pc:05x}: {raw_hex:<10} tpop     {format_reglist(lo, pc_reg)}")
        elif 0x80 <= hi <= 0x87:
            simm11 = hw & 0x7FF
            if simm11 & 0x400:
                simm11 -= 0x800
            target = pc + 4 + (simm11 << 1)
            print(f"  0x{pc:05x}: {raw_hex:<10} tjmp     0x{target:05x} (raw 0x{hw:04x})")
        # 5. tmovs rD, #imm8: 0xa0..0xa7
        elif 0xA0 <= hi <= 0xA7:
            rd = hi - 0xA0
            print(f"  0x{pc:05x}: {raw_hex:<10} tmovs    r{rd}, #0x{lo:02x} ({lo})")
        elif 0xA8 <= hi <= 0xAF:
            rn = hi - 0xA8
            print(f"  0x{pc:05x}: {raw_hex:<10} tcmp     r{rn}, #0x{lo:02x} ({lo})")
        elif 0x40 <= hi <= 0x47:
            rd = hw & 7
            rn = (hw >> 3) & 7
            imm5 = (hw >> 6) & 0x1F
            print(f"  0x{pc:05x}: {raw_hex:<10} tstrb    r{rd}, [r{rn}, #0x{imm5:x}]")
        elif 0x48 <= hi <= 0x4F:
            rd = hw & 7
            rn = (hw >> 3) & 7
            imm5 = (hw >> 6) & 0x1F
            print(f"  0x{pc:05x}: {raw_hex:<10} tldrb    r{rd}, [r{rn}, #0x{imm5:x}]")
        elif 0x20 <= hi <= 0x27:
            rn = hi - 0x20
            print(f"  0x{pc:05x}: {raw_hex:<10} tcmp     r{rn}, #0x{lo:02x} ({lo})")
        elif 0x30 <= hi <= 0x37:
            rd = hi - 0x30
            print(f"  0x{pc:05x}: {raw_hex:<10} tadds    r{rd}, #0x{lo:02x}")
        elif 0x38 <= hi <= 0x3F:
            rd = hi - 0x38
            print(f"  0x{pc:05x}: {raw_hex:<10} tsubs    r{rd}, #0x{lo:02x}")
        elif 0x58 <= hi <= 0x59:
            rd = hw & 7
            rn = (hw >> 3) & 7
            rm = (hw >> 6) & 7
            print(f"  0x{pc:05x}: {raw_hex:<10} tldrb/w  r{rd}, [r{rn}, r{rm}] (0x{hw:04x})")
        elif 0x50 <= hi <= 0x51:
            rd = hw & 7
            rn = (hw >> 3) & 7
            rm = (hw >> 6) & 7
            print(f"  0x{pc:05x}: {raw_hex:<10} tstrb/w  r{rd}, [r{rn}, r{rm}] (0x{hw:04x})")
        elif 0xC0 <= hi <= 0xCF:
            cond = hi & 0xF
            simm8 = lo if lo < 128 else lo - 256
            target = pc + 4 + (simm8 << 1)
            print(f"  0x{pc:05x}: {raw_hex:<10} tbcc_{cond:x}   0x{target:05x} (raw 0x{hw:04x})")
        elif 0xE0 <= hi <= 0xE7:
            simm11 = hw & 0x7FF
            if simm11 & 0x400:
                simm11 -= 0x800
            target = pc + 2 + (simm11 << 1)
            print(f"  0x{pc:05x}: {raw_hex:<10} tjmp     0x{target:05x}")
        else:
            print(f"  0x{pc:05x}: {raw_hex:<10} inst     0x{hw:04x}")
        pc += 2


if __name__ == "__main__":
    fw = FW_PATH.read_bytes()
    disasm_tc32(fw, 0x149F0, 0x14E20, "7-Segment Display Formatter & Digit Lookup")
