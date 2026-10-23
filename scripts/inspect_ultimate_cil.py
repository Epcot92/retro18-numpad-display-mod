"""Inspect PE sections, CLI header, and PDB symbols of 8BitDo Ultimate Software V2.dll."""
import pathlib
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DLL_PATH = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\8BitDo Ultimate Software V2.dll")
PDB_PATH = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo Ultimate Software V2.pdb"
)


def inspect_pe_and_cli() -> None:
    data = DLL_PATH.read_bytes()
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    opt_off = pe_off + 24
    magic = int.from_bytes(data[opt_off : opt_off + 2], "little")
    dd_off = opt_off + (96 if magic == 0x10B else 112)
    cli_rva = int.from_bytes(data[dd_off + 14 * 8 : dd_off + 14 * 8 + 4], "little")
    cli_size = int.from_bytes(data[dd_off + 14 * 8 + 4 : dd_off + 14 * 8 + 8], "little")
    num_sec = int.from_bytes(data[pe_off + 6 : pe_off + 8], "little")
    opt_size = int.from_bytes(data[pe_off + 20 : pe_off + 22], "little")
    sec_off = opt_off + opt_size

    print(f"=== {DLL_PATH.name} ({len(data)} bytes) ===")
    print(f"  CLI Header RVA: 0x{cli_rva:08x}, Size: {cli_size}")
    sections = []
    for i in range(num_sec):
        s = data[sec_off + i * 40 : sec_off + (i + 1) * 40]
        name = s[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", s, 8)
        sections.append((name, va, vsize, roff, rsize))
        print(f"  Section {name:<8}: VA=0x{va:08x} VSize=0x{vsize:08x} ROff=0x{roff:08x} RSize=0x{rsize:08x}")

    def rva_to_off(rva: int) -> int:
        for _, va, vsize, roff, rsize in sections:
            if va <= rva < va + max(vsize, rsize):
                return roff + (rva - va)
        return -1

    cli_off = rva_to_off(cli_rva)
    cb, major, minor, meta_rva, meta_size, flags = struct.unpack_from("<IHHIII", data, cli_off)
    res_rva, res_size = struct.unpack_from("<II", data, cli_off + 24)
    meta_off = rva_to_off(meta_rva)
    print(f"  Metadata RVA:  0x{meta_rva:08x} (file offset 0x00222f1c), Size: {meta_size} bytes ({meta_size/1024:.1f} KB)")
    print(f"  Resources RVA: 0x{res_rva:08x}, Size: {res_size} bytes ({res_size/1024/1024:.1f} MB)")
    print(f"  Metadata Magic: {data[meta_off:meta_off+4]!r}")

    # Create a trimmed PE with only the first 0x002bc000 bytes of .text (code + metadata, without the 95MB resources)
    trim_vsize = 0x002BC000
    trim_rsize = 0x002BC000
    trimmed = bytearray(data[: 0x200 + trim_rsize])
    # Update NumSections = 1 (just .text)
    trimmed[pe_off + 6 : pe_off + 8] = (1).to_bytes(2, "little")
    # Clear Resource Directory and Reloc Directory in Optional Header DataDirectories
    trimmed[dd_off + 2 * 8 : dd_off + 2 * 8 + 8] = b"\x00" * 8
    trimmed[dd_off + 5 * 8 : dd_off + 5 * 8 + 8] = b"\x00" * 8
    # Update .text VSize and RSize
    trimmed[sec_off + 8 : sec_off + 12] = trim_vsize.to_bytes(4, "little")
    trimmed[sec_off + 16 : sec_off + 20] = trim_rsize.to_bytes(4, "little")
    # Clear CLI Resources RVA/Size
    trimmed[cli_off + 24 : cli_off + 32] = b"\x00" * 8
    out_trim = DLL_PATH.parent / "UltimateV2_code_only.dll"
    out_trim.write_bytes(trimmed)
    print(f"  -> Wrote trimmed assembly: {out_trim} ({len(trimmed)} bytes)")


def inspect_pdb_strings() -> None:
    pdb = PDB_PATH.read_bytes()
    print(f"\n=== {PDB_PATH.name} ({len(pdb)} bytes, magic={pdb[:4]!r}) ===")
    # Find BSJB streams in Portable PDB
    sig, maj, min_v, reserved, ver_len = struct.unpack_from("<IHHII", pdb, 0)
    ver_str = pdb[16 : 16 + ver_len].rstrip(b"\x00").decode("utf-8", errors="replace")
    cur = 16 + ver_len
    flags, streams = struct.unpack_from("<HH", pdb, cur)
    cur += 4
    print(f"  PDB Version: {ver_str}, Streams: {streams}")
    for _ in range(streams):
        off, size = struct.unpack_from("<II", pdb, cur)
        cur += 8
        name_bytes = bytearray()
        while pdb[cur] != 0:
            name_bytes.append(pdb[cur])
            cur += 1
        cur += 1
        while cur % 4 != 0:
            cur += 1
        print(f"  Stream {name_bytes.decode():<12}: offset=0x{off:08x}, size={size}")


if __name__ == "__main__":
    inspect_pe_and_cli()
    inspect_pdb_strings()
