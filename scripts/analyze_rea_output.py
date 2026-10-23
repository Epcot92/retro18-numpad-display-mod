"""Analyze REA managed member output for 8BitDo Ultimate Software V2.dll & DriverLibrary.dll."""
import json
import pathlib
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ULTIMATE_JSON = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies\ultimate_v2_code_members.json")
DRIVER_JSON = pathlib.Path(
    r"C:\Users\User\.gemini\antigravity-cli\brain\7bc45d22-3bf0-4082-b0fa-ae417fad0769\.system_generated\steps\105\output.txt"
)


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


def analyze_ultimate_v2() -> None:
    doc = load_json_auto(ULTIMATE_JSON)
    res = doc["normalized_result"]

    types = res.get("types") or []
    methods = res.get("methods") or []
    fields = res.get("fields") or []
    us = res.get("user_strings")
    strings = us.get("items", []) if isinstance(us, dict) else (us or [])

    print(f"=== 8BitDo Ultimate Software V2.dll (REA Evidence ID: {doc['evidence_id']}) ===")
    print(f"  Types: {len(types)}, Methods: {len(methods)}, Fields: {len(fields)}, Strings: {len(strings)}")

    type_by_token = {t["token"]: t["full_name"] for t in types}

    print("\n--- Notable Types ---")
    for t in types:
        fn = t["full_name"]
        if any(k in fn.lower() for k in ("hid", "numpad", "retro", "calc", "key", "update", "device", "vid", "pid")):
            print(f"  {t['token']}: {fn} (methods={t['method_list']['count']}, fields={t['field_list']['count']})")

    print("\n--- P/Invoke / ImplMap / HID Methods ---")
    for m in methods:
        name = m["name"]
        owner = type_by_token.get(m.get("declaring_type_token"), "?")
        if any(k in name.lower() or k in owner.lower() for k in ("hid", "5203", "20995", "numpad", "calc", "retro", "led", "display", "screen", "time")):
            print(f"  {owner}.{name} (rva={m.get('rva')}, flags={m.get('flags')})")

    print("\n--- Relevant User Strings ---")
    for s in strings:
        val = s.get("value", "")
        if any(k in val.lower() for k in ("5203", "20995", "numpad", "calc", "retro", "dfu", "rtk", "update", "led", "screen", "display")):
            print(f"  {s['token']}: {val!r}")


def analyze_driver_lib() -> None:
    raw = DRIVER_JSON.read_text(encoding="utf-8", errors="replace")
    idx = raw.find("{")
    doc = json.loads(raw[idx:])
    res = doc["normalized_result"]
    types = res.get("types", [])
    methods = res.get("methods", [])
    type_by_token = {t["token"]: t["full_name"] for t in types}
    print(f"\n=== DriverLibrary.dll (REA Evidence ID: {doc['evidence_id']}) ===")
    for t in types:
        if not t["full_name"].startswith("S1L"):
            print(f"  Type {t['token']}: {t['full_name']}")
    print("\n--- DriverLibrary Methods (XVIHIDLib / HID) ---")
    for m in methods:
        owner = type_by_token.get(m.get("declaring_type_token"), "?")
        if "HID" in owner or "Device" in owner:
            print(f"  {owner}.{m['name']}")


if __name__ == "__main__":
    analyze_ultimate_v2()
    analyze_driver_lib()
