"""Extract embedded .NET assemblies from 8BitDo Ultimate Software V2.exe."""
import pathlib
import struct
import zlib

ULTIMATE_DIR = pathlib.Path(
    r"D:\Chrome DL\8BitDo_Ultimate_Software_V2_Windows_V1.37\8BitDo_Ultimate_Software_V2_Windows_V1.37"
)
EXTRACT_DIR = pathlib.Path(r"D:\GEMINI_ANTI\extracted_assemblies")


def find_and_extract_bundle() -> None:
    exe_path = ULTIMATE_DIR / "8BitDo Ultimate Software V2.exe"
    data = exe_path.read_bytes()

    for marker in (b"DriverLibrary.dll", b"GenericHid.dll", b"8BitDo Ultimate Software V2.dll"):
        idx = data.rfind(marker)
        print(f"rfind({marker.decode()}) = 0x{idx:x}")
        if idx != -1:
            start = max(0, idx - 64)
            chunk = data[start : idx + len(marker) + 32]
            print(" ", chunk.hex())

    # Search for DriverLibrary.dll at the end (bundle manifest is at the very end of the file)
    idx = data.rfind(b"8BitDo Ultimate Software V2.dll")
    # Walk backwards up to 64KB to find the bundle header (major=6 or 2, minor=0)
    for back in range(16, 65536):
        pos = idx - back
        if pos < 0:
            break
        major, minor, count = struct.unpack_from("<IIi", data, pos)
        if major in (1, 2, 6) and minor == 0 and 20 < count < 500:
            id_len = data[pos + 12]
            if 8 <= id_len <= 64:
                bundle_id = data[pos + 13 : pos + 13 + id_len]
                if all(32 <= b < 127 for b in bundle_id):
                    print(
                        f"Found bundle manifest at 0x{pos:x}: v{major}.{minor}, count={count}, id={bundle_id.decode()}"
                    )
                    cur = pos + 13 + id_len
                    if major >= 2:
                        cur += 40
                    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
                    for i in range(count):
                        offset, size = struct.unpack_from("<qq", data, cur)
                        cur += 16
                        comp_size = 0
                        if major >= 6:
                            comp_size = struct.unpack_from("<q", data, cur)[0]
                            cur += 8
                        ftype = data[cur]
                        cur += 1
                        path_len = 0
                        shift = 0
                        while True:
                            b = data[cur]
                            cur += 1
                            path_len |= (b & 0x7F) << shift
                            if (b & 0x80) == 0:
                                break
                            shift += 7
                        rel_path = data[cur : cur + path_len].decode("utf-8", errors="replace")
                        cur += path_len
                        if any(
                            k in rel_path.lower()
                            for k in ("8bitdo", "driverlibrary", "generichid", "hid", "advance")
                        ):
                            print(
                                f"  [{i}] {rel_path}: offset=0x{offset:x}, size={size}, comp_size={comp_size}, type={ftype}"
                            )
                            raw_slice = (
                                data[offset : offset + comp_size]
                                if comp_size > 0
                                else data[offset : offset + size]
                            )
                            if comp_size > 0:
                                raw_slice = zlib.decompress(raw_slice, -15)
                            out_path = EXTRACT_DIR / pathlib.Path(rel_path).name
                            out_path.write_bytes(raw_slice)
                            print(f"      -> Saved {out_path} ({len(raw_slice)} bytes)")
                    break


if __name__ == "__main__":
    find_and_extract_bundle()
