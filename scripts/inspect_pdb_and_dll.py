"""Analyze 8BitDo Firmware Updater REA output, 8BitDoAdvance.dll exports, and Portable PDB source info."""
import json
import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ULTIMATE_DIR = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37"
)
EXTRACT_DIR = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies")


def load_json_auto(path: pathlib.Path) -> dict:
    raw_bytes = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            text = raw_bytes.decode(enc)
            idx = text.find('{"evidence_id"')
            if idx != -1:
                return json.loads(text[idx:])
        except Exception:
            continue
    raise ValueError(f"Could not parse JSON from {path}")


def inspect_native_dll_exports(dll_path: pathlib.Path) -> None:
    print(f"\n=== Native DLL Exports: {dll_path.name} ===")
    data = dll_path.read_bytes()
    # Quick PE export directory parser
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    opt_off = pe_off + 24
    magic = int.from_bytes(data[opt_off : opt_off + 2], "little")
    dd_off = opt_off + (96 if magic == 0x10B else 112)
    exp_rva = int.from_bytes(data[dd_off : dd_off + 4], "little")
    exp_size = int.from_bytes(data[dd_off + 4 : dd_off + 8], "little")
    num_sec = int.from_bytes(data[pe_off + 6 : pe_off + 8], "little")
    opt_size = int.from_bytes(data[pe_off + 20 : pe_off + 22], "little")
    sec_off = opt_off + opt_size

    sections = []
    for i in range(num_sec):
        s = data[sec_off + i * 40 : sec_off + (i + 1) * 40]
        name = s[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = int.from_bytes(s[8:12], "little")
        va = int.from_bytes(s[12:16], "little")
        rsize = int.from_bytes(s[16:20], "little")
        roff = int.from_bytes(s[20:24], "little")
        sections.append((name, va, vsize, roff, rsize))

    def rva_to_off(rva: int) -> int:
        for _, va, vsize, roff, rsize in sections:
            span = max(vsize, rsize)
            if va <= rva < va + span:
                return roff + (rva - va)
        return -1

    if exp_rva == 0:
        print("  No exports.")
        return

    eoff = rva_to_off(exp_rva)
    num_funcs = int.from_bytes(data[eoff + 20 : eoff + 24], "little")
    num_names = int.from_bytes(data[eoff + 24 : eoff + 28], "little")
    funcs_rva = int.from_bytes(data[eoff + 28 : eoff + 32], "little")
    names_rva = int.from_bytes(data[eoff + 32 : eoff + 36], "little")
    ords_rva = int.from_bytes(data[eoff + 36 : eoff + 40], "little")

    names_off = rva_to_off(names_rva)
    ords_off = rva_to_off(ords_rva)
    funcs_off = rva_to_off(funcs_rva)
    print(f"  Exported functions: {num_funcs}, Named exports: {num_names}")
    for i in range(num_names):
        name_rva = int.from_bytes(data[names_off + i * 4 : names_off + i * 4 + 4], "little")
        ord_idx = int.from_bytes(data[ords_off + i * 2 : ords_off + i * 2 + 2], "little")
        fn_rva = int.from_bytes(data[funcs_off + ord_idx * 4 : funcs_off + ord_idx * 4 + 4], "little")
        noff = rva_to_off(name_rva)
        end = data.find(b"\x00", noff)
        fn_name = data[noff:end].decode("ascii", errors="replace")
        print(f"    [{ord_idx:3d}] 0x{fn_rva:08x} {fn_name}")


def inspect_fw_updater_rea() -> None:
    for fname in ("fw_updater_members.json", "fw_updater_tools_members.json"):
        p = EXTRACT_DIR / fname
        doc = load_json_auto(p)
        res = doc["normalized_result"]
        types = res.get("types") or []
        methods = res.get("methods") or []
        print(f"\n=== {fname} (Evidence: {doc['evidence_id']}) ===")
        print(f"  Types: {len(types)}, Methods: {len(methods)}")
        type_by_token = {t["token"]: t["full_name"] for t in types}
        for t in types:
            print(f"  Type {t['token']}: {t['full_name']} (methods={t['method_list']['count']})")


if __name__ == "__main__":
    inspect_native_dll_exports(ULTIMATE_DIR / "8BitDoAdvance.dll")
    inspect_native_dll_exports(ULTIMATE_DIR / "RTKHIDKit.dll")
    inspect_native_dll_exports(ULTIMATE_DIR / "data" / "AutoUpdate.dll")
    inspect_fw_updater_rea()
