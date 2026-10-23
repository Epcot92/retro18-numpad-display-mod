"""Unit and firmware integrity tests for the 8BitDo Retro 18 Mechanical Numpad display mod."""
import pathlib
import struct
import sys
import unittest
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools" / "8cryptdo" / "8cryptdo-main"))

from retro18_display import (
    encode_7seg_text,
    format_cpu_ram_text,
    format_ticker_item,
    generate_scroll_frames,
    SystemStatsMonitor,
)
from retro18_lyrics import parse_lrc, render_punch_frame_for_line, split_into_punch_phrases
from retro18_tui import Retro18TuiApp, render_digit_lines
from cryptdo8 import Yichip, select_section, decrypt_section


class TestRetro18Display(unittest.TestCase):
    def test_lyrics_parser_and_punch_in_frames(self) -> None:
        phrases = split_into_punch_phrases("On the two year anniversary I complied to Benihana")
        self.assertTrue(len(phrases) >= 4)
        sample_lrc = (
            "[00:19.15] On the two year anniversary\n"
            "[00:24.00] And the promise we could stay polite\n"
        )
        lines = parse_lrc(sample_lrc)
        self.assertEqual(len(lines), 2)
        self.assertAlmostEqual(lines[0].time_sec, 19.15, places=2)
        f_start = render_punch_frame_for_line(lines[0], lines[1].time_sec, 19.25)
        f_end = render_punch_frame_for_line(lines[0], lines[1].time_sec, 23.00)
        self.assertEqual(len(f_start), 9)
        self.assertEqual(len(f_end), 9)
        self.assertNotEqual(f_start, f_end)

    def test_tui_preview_and_triggers(self) -> None:
        app = Retro18TuiApp()
        app.input_text = "HELLO NIKO"
        preview = app.compute_preview_9()
        self.assertEqual(len(preview), 9)
        top, mid, bot = render_digit_lines(0x7F)  # '8'
        self.assertIn("━━", top)
        self.assertIn("┃━━┃", mid)
        self.assertIn("┃━━┃", bot)

    def test_scroll_frames_and_ticker_formatting(self) -> None:
        item = format_ticker_item("NVDA", 142.5)
        self.assertEqual(item, "NVDA 142.50")
        btc = format_ticker_item("BTC-USD", 95123.4)
        self.assertEqual(btc, "BTC 95123")
        frames = generate_scroll_frames("HELLO NIKO", pad_lead=9, pad_trail=9)
        self.assertGreater(len(frames), 18)
        self.assertTrue(all(len(f) == 9 for f in frames))
        # First and last frames should be all blank (0x00 * 9)
        self.assertEqual(frames[0], bytes(9))
        self.assertEqual(frames[-1], bytes(9))

    def test_cpu_ram_formatter_and_monitor(self) -> None:
        s = format_cpu_ram_text(18, 45)
        self.assertEqual(s, "C 18 r 45")
        self.assertEqual(len(encode_7seg_text(s)), 9)
        mon = SystemStatsMonitor()
        cpu, ram = mon.sample()
        self.assertTrue(0 <= cpu <= 100)
        self.assertTrue(0 <= ram <= 100)
    def test_digits_match_firmware_sram_init(self) -> None:
        # Firmware SRAM 0x00844644 is initialized to "123456789" -> 06 5b 4f 66 6d 7d 07 7f 6f
        self.assertEqual(
            encode_7seg_text("123456789"),
            bytes.fromhex("06 5b 4f 66 6d 7d 07 7f 6f"),
        )

    def test_error_matches_firmware_0x14b14(self) -> None:
        # Firmware function 0x14b14 writes "    Error" -> 00 00 00 00 79 50 50 5c 50
        self.assertEqual(
            encode_7seg_text("Error", align="right"),
            bytes.fromhex("00 00 00 00 79 50 50 5c 50"),
        )

    def test_all_segments_with_dots_matches_0x14a80(self) -> None:
        # Firmware function 0x14a80 fills 9 bytes with 0xFF ("8.8.8.8.8.8.8.8.8.")
        self.assertEqual(
            encode_7seg_text("8.8.8.8.8.8.8.8.8."),
            bytes([0xFF] * 9),
        )

    def test_clock_formats(self) -> None:
        # " 19-45-30" -> [blank, '1', '9', '-', '4', '5', '-', '3', '0']
        self.assertEqual(
            encode_7seg_text(" 19-45-30", align="right"),
            bytes([0x00, 0x06, 0x6F, 0x40, 0x66, 0x6D, 0x40, 0x4F, 0x3F]),
        )
        # "19.45.30" with dot merging -> 6 digits total, right-aligned
        self.assertEqual(
            encode_7seg_text("19.45.30", align="right"),
            bytes([0x00, 0x00, 0x00, 0x06, 0x6F | 0x80, 0x66, 0x6D | 0x80, 0x4F, 0x3F]),
        )

    def test_patched_firmware_and_dat_integrity(self) -> None:
        fw_path = ROOT / "extracted_assemblies" / "retro18_fw_v107_clock_mod.bin"
        dat_path = ROOT / "extracted_assemblies" / "retro18_fw_v107_clock_mod.dat"
        self.assertTrue(fw_path.exists())
        self.assertTrue(dat_path.exists())

        fw = fw_path.read_bytes()
        dat = dat_path.read_bytes()

        # Verify Telink header & CRC32
        self.assertEqual(fw[8:12], b"KNLT")
        tl_size = struct.unpack_from("<I", fw, 0x18)[0]
        self.assertEqual(zlib.crc32(fw[:tl_size]) & 0xFFFFFFFF, 0xFFFFFFFF)

        # Verify .dat decryption matches fw byte-for-byte
        _, sec = select_section(dat, 0)
        self.assertEqual(sec["id"], 107)
        self.assertEqual(sec["addr"], 0x5000)
        self.assertEqual(sec["pid"], 0x5203)
        decrypted = decrypt_section(dat, sec, Yichip())
        self.assertEqual(decrypted, fw)


if __name__ == "__main__":
    unittest.main()
