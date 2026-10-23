"""Disassemble 8BitDoAdvance.dll functions referencing PID 0x5203 and decode CIL methods in UltimateV2."""
import pathlib
import struct
import sys
import capstone

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DLL_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\UltimateV2_code_only.dll")
ADVANCE_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDoAdvance.dll"
)


def parse_pe_sections(data: bytes):
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    opt_off = pe_off + 24
    magic = int.from_bytes(data[opt_off : opt_off + 2], "little")
    image_base = int.from_bytes(data[opt_off + 28 : opt_off + 32], "little")
    num_sec = int.from_bytes(data[pe_off + 6 : pe_off + 8], "little")
    opt_size = int.from_bytes(data[pe_off + 20 : pe_off + 22], "little")
    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sec):
        s = data[sec_off + i * 40 : sec_off + (i + 1) * 40]
        name = s[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", s, 8)
        sections.append((name, va, vsize, roff, rsize))
    return image_base, sections


def off_to_rva(off: int, sections) -> int:
    for _, va, vsize, roff, rsize in sections:
        if roff <= off < roff + rsize:
            return va + (off - roff)
    return -1


def rva_to_off(rva: int, sections) -> int:
    for _, va, vsize, roff, rsize in sections:
        if va <= rva < va + max(vsize, rsize):
            return roff + (rva - va)
    return -1


def disasm_advance_hits() -> None:
    adv = ADVANCE_PATH.read_bytes()
    image_base, sections = parse_pe_sections(adv)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    hits = [0x48907, 0x666CD, 0x91F17, 0x924B2]
    for h in hits:
        rva = off_to_rva(h, sections)
        print(f"\n=== 8BitDoAdvance.dll hit at file offset 0x{h:x} (RVA 0x{rva:x}, VA 0x{image_base + rva:x}) ===")
        start = max(0, h - 96)
        end = min(len(adv), h + 160)
        start_va = image_base + off_to_rva(start, sections)
        for insn in md.disasm(adv[start:end], start_va):
            marker = " <-- 0x5203" if abs((insn.address - start_va) - (h - start)) <= 6 else ""
            print(f"  0x{insn.address:08x}: {insn.bytes.hex():<20} {insn.mnemonic:<8} {insn.op_str}{marker}")


def inspect_cil_hits() -> None:
    data = DLL_PATH.read_bytes()
    meta_off = 0x00222F1C
    sig, maj, min_v, reserved, ver_len = struct.unpack_from("<IHHII", data, meta_off)
    cur = meta_off + 16 + ver_len
    flags, num_streams = struct.unpack_from("<HH", data, cur)
    cur += 4
    us_off = 0
    for _ in range(num_streams):
        off, size = struct.unpack_from("<II", data, cur)
        cur += 8
        name = bytearray()
        while data[cur] != 0:
            name.append(data[cur])
            cur += 1
        cur += 1
        while (cur - meta_off) % 4 != 0:
            cur += 1
        if name == b"#US":
            us_off = meta_off + off

    def get_us_string(token: int) -> str:
        pos = us_off + (token & 0x00FFFFFF)
        b0 = data[pos]
        if (b0 & 0x80) == 0:
            length = b0
            pos += 1
        elif (b0 & 0xC0) == 0x80:
            length = ((b0 & 0x3F) << 8) | data[pos + 1]
            pos += 2
        else:
            length = ((b0 & 0x1F) << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
            pos += 4
        return data[pos : pos + length - 1].decode("utf-16le", errors="replace")

    cil_hits = [0xB7F2, 0x12508, 0x138F0, 0x168648, 0x168E0D, 0x16AA85, 0x16E38A, 0x183D54, 0x184630]
    for h in cil_hits:
        print(f"\n=== UltimateV2 CIL window around 0x{h:x} ===")
        win = data[max(0, h - 128) : min(meta_off, h + 256)]
        base = max(0, h - 128)
        # Scan window for ldstr (0x72 xx xx xx 70) and ldc.i4 (0x20 xx xx xx xx)
        i = 0
        while i < len(win) - 5:
            op = win[i]
            if op == 0x72 and win[i + 4] == 0x70:
                tok = struct.unpack_from("<I", win, i + 1)[0]
                try:
                    s = get_us_string(tok)
                    print(f"  [0x{base+i:06x}] ldstr 0x{tok:08x} -> {s!r}")
                except Exception:
                    pass
                i += 5
            elif op == 0x20:
                val = struct.unpack_from("<i", win, i + 1)[0]
                if 0x1000 <= val <= 0xFFFF:
                    print(f"  [0x{base+i:06x}] ldc.i4 {val} (0x{val:04x})")
                i += 5
            elif op == 0x28 and win[i + 4] in (0x06, 0x0A):
                tok = struct.unpack_from("<I", win, i + 1)[0]
                print(f"  [0x{base+i:06x}] call 0x{tok:08x}")
                i += 5
            else:
                i += 1


if __name__ == "__main__":
    disasm_advance_hits()
    inspect_cil_hits()
