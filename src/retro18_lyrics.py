"""Live YouTube Music / Windows Media Session Synchronized Lyrics Engine for the 8BitDo Retro 18 Numpad.

Tracks active media playback on Windows (YouTube Music in Chrome/Edge/PWA, Spotify, etc.) via
`Windows.Media.Control`, fetches millisecond-timestamped LRC lyrics via `syncedlyrics`, and computes
9-digit 7-segment display frames using Dynamic Word/Phrase Punch-In:
  - Splits each lyric line into <=9-character word chunks and flashes each phrase static on the 9 digits
    in exact proportion to the vocal line's timing.
  - Automatically falls back to smooth scrolling for single words >9 characters.
  - Displays an animated equalizer / beat pulse during instrumental intros and gaps.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import datetime
import pathlib
import re
import threading
import time

from retro18_display import encode_7seg_sequence, encode_7seg_text

LRC_CACHE_DIR = pathlib.Path(__file__).resolve().parent.parent / ".lyrics_cache"
_LRC_LINE_RE = re.compile(r"\[(\d+):(\d+(?:\.\d+)?)\](.*)")
_CLEAN_CHARS_RE = re.compile(r"[^A-Z0-9 \-\._=:/!\?]")


@dataclass
class LyricLine:
    time_sec: float
    text: str
    phrases: list[str]


def clean_lyric_for_7seg(raw: str) -> str:
    """Normalize a lyric string into clean uppercase characters supported by the 7-segment font."""
    s = raw.upper().replace("'", "").replace("\u2019", "").replace(",", " ").replace('"', "")
    s = _CLEAN_CHARS_RE.sub(" ", s)
    return " ".join(s.split())


def split_into_punch_phrases(text: str, max_width: int = 9) -> list[str]:
    """Pack words into punchy <=9-char phrases for the 9-digit LED screen."""
    cleaned = clean_lyric_for_7seg(text)
    if not cleaned:
        return []
    words = cleaned.split(" ")
    phrases: list[str] = []
    current = ""
    for w in words:
        if not current:
            current = w
        elif len(current) + 1 + len(w) <= max_width:
            current = f"{current} {w}"
        else:
            phrases.append(current)
            current = w
    if current:
        phrases.append(current)
    return phrases


def parse_lrc(lrc_text: str) -> list[LyricLine]:
    """Parse LRC timestamped lyrics into sorted `LyricLine` entries with pre-packed punch phrases."""
    lines: list[LyricLine] = []
    for raw_line in lrc_text.splitlines():
        m = _LRC_LINE_RE.match(raw_line.strip())
        if not m:
            continue
        minutes = int(m.group(1))
        seconds = float(m.group(2))
        t_sec = minutes * 60.0 + seconds
        body = m.group(3).strip()
        phrases = split_into_punch_phrases(body)
        lines.append(LyricLine(time_sec=t_sec, text=body, phrases=phrases))
    lines.sort(key=lambda x: x.time_sec)
    return lines


def render_punch_frame_for_line(
    line: LyricLine, next_time_sec: float, current_pos_sec: float
) -> bytes:
    """Compute the exact 9-byte 7-segment frame for `line` at `current_pos_sec`."""
    if not line.phrases:
        # Instrumental / beat pulse animation between vocal lines
        beat = int(current_pos_sec * 4.0) % 4
        patterns = [
            " _ - _ - ",
            " - _ - _ ",
            " = - = - ",
            " - = - = ",
        ]
        return encode_7seg_text(patterns[beat], align="center")

    line_dur = max(0.6, min(10.0, next_time_sec - line.time_sec - 0.12))
    elapsed = max(0.0, current_pos_sec - line.time_sec)

    # Weight each phrase's duration by its character length so longer phrases stay up longer
    weights = [max(2, len(p)) for p in line.phrases]
    total_w = sum(weights)

    acc = 0.0
    chosen_phrase = line.phrases[-1]
    phrase_elapsed = 0.0
    phrase_dur = line_dur
    for p, w in zip(line.phrases, weights):
        p_dur = line_dur * (w / total_w)
        if elapsed <= acc + p_dur:
            chosen_phrase = p
            phrase_elapsed = elapsed - acc
            phrase_dur = max(0.2, p_dur)
            break
        acc += p_dur

    # If the phrase fits in 9 digits, punch it in centered!
    seq = encode_7seg_sequence(chosen_phrase)
    if len(seq) <= 9:
        return encode_7seg_text(chosen_phrase, align="center")

    # Single word >9 characters: smoothly pan across the word over phrase_dur
    steps = len(seq) - 9 + 1
    progress = min(1.0, max(0.0, phrase_elapsed / phrase_dur))
    idx = min(steps - 1, int(progress * steps))
    return bytes(seq[idx : idx + 9])


class LiveLyricsSynchronizer:
    """Background synchronizer that reads Windows Media Session (YouTube Music) and serves 9-digit frames."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._track_key = ""
        self._title = ""
        self._artist = ""
        self._is_playing = False
        self._base_pos_sec = 0.0
        self._base_mono = time.monotonic()
        self._lyrics: list[LyricLine] = []
        self._fetching_key = ""
        self._status_banner = "NO MEDIA"
        self.offset_sec: float = 0.20  # Slight lead (+200ms) so words punch in right on camera beat
        self._started = False
        self._thread = threading.Thread(target=self._run_loop, daemon=True)

    def start(self) -> None:
        if not self._started:
            self._started = True
            LRC_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            self._thread.start()

    def adjust_offset(self, delta_sec: float) -> float:
        with self._lock:
            self.offset_sec = round(self.offset_sec + delta_sec, 2)
            return self.offset_sec

    def get_current_position(self) -> float:
        with self._lock:
            if not self._is_playing:
                return self._base_pos_sec + self.offset_sec
            return self._base_pos_sec + (time.monotonic() - self._base_mono) + self.offset_sec

    def get_current_frame(self) -> bytes:
        pos = self.get_current_position()
        with self._lock:
            if not self._title:
                return encode_7seg_text("PLAY SONG", align="center")
            if not self._lyrics:
                # While fetching or if song is instrumental, scroll the song title
                banner = clean_lyric_for_7seg(f"{self._title} - {self._artist}")
                seq = [0x00] * 9 + encode_7seg_sequence(banner) + [0x00] * 4
                idx = int(time.monotonic() * 6.0) % max(1, len(seq) - 8)
                return bytes((seq[idx : idx + 9] + [0x00] * 9)[:9])

            # Find active LyricLine at `pos`
            active_idx = -1
            for i, line in enumerate(self._lyrics):
                if pos >= line.time_sec:
                    active_idx = i
                else:
                    break

            if active_idx == -1:
                # Intro before first vocal line: show animated beat bars
                beat = int(time.monotonic() * 4.0) % 2
                return encode_7seg_text(" - = - = " if beat else " = - = - ", align="center")

            line = self._lyrics[active_idx]
            next_time = (
                self._lyrics[active_idx + 1].time_sec
                if active_idx + 1 < len(self._lyrics)
                else line.time_sec + 5.0
            )
            return render_punch_frame_for_line(line, next_time, pos)

    def get_status_summary(self) -> str:
        pos = self.get_current_position()
        with self._lock:
            if not self._title:
                return "Waiting for YouTube Music / Media playback..."
            state_str = "PLAYING" if self._is_playing else "PAUSED"
            return f"{state_str}: {self._artist} - {self._title} ({pos:.1f}s, {len(self._lyrics)} lines)"

    def _fetch_lyrics_for(self, artist: str, title: str, track_key: str) -> None:
        safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", track_key)[:90] + ".lrc"
        cache_file = LRC_CACHE_DIR / safe_name
        lrc_text: str | None = None
        if cache_file.exists():
            try:
                lrc_text = cache_file.read_text(encoding="utf-8")
            except Exception:
                pass

        if not lrc_text:
            try:
                import syncedlyrics

                # Strip common YouTube suffixes like "(Official Video)" or "[Official Audio]"
                clean_title = re.sub(r"\(.*?\)|\[.*?\]", "", title).strip() or title
                clean_artist = artist.replace(" - Topic", "").strip()
                query = f"{clean_artist} {clean_title}".strip()
                lrc_text = syncedlyrics.search(query)
                if lrc_text:
                    cache_file.write_text(lrc_text, encoding="utf-8")
            except Exception:
                lrc_text = None

        parsed = parse_lrc(lrc_text) if lrc_text else []
        with self._lock:
            if self._track_key == track_key:
                self._lyrics = parsed

    async def _poll_media_once(self) -> None:
        from winrt.windows.media.control import (
            GlobalSystemMediaTransportControlsSessionManager as MediaManager,
        )

        mgr = await MediaManager.request_async()
        session = mgr.get_current_session()
        if session is None:
            sessions = mgr.get_sessions()
            if sessions:
                session = sessions[0]
        if session is None:
            return

        info = await session.try_get_media_properties_async()
        tl = session.get_timeline_properties()
        pb = session.get_playback_info()

        title = (info.title or "").strip()
        artist = (info.artist or "").strip()
        status = int(pb.playback_status)  # 4 == Playing, 5 == Paused
        is_playing = status == 4

        raw_pos = tl.position.total_seconds()
        updated = tl.last_updated_time
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        # Windows SMTC updates `tl.position` on play/pause/seek/track-change and sets `last_updated_time`
        if is_playing and updated and updated.year > 2000:
            age = (now_utc - updated).total_seconds()
            if 0.0 <= age <= 600.0:
                raw_pos += age

        track_key = f"{artist} - {title}".strip(" -")
        need_fetch = False
        with self._lock:
            self._title = title
            self._artist = artist
            self._is_playing = is_playing
            self._base_pos_sec = max(0.0, raw_pos)
            self._base_mono = time.monotonic()
            if track_key and track_key != self._track_key:
                self._track_key = track_key
                self._lyrics = []
                need_fetch = True

        if need_fetch and title:
            threading.Thread(
                target=self._fetch_lyrics_for,
                args=(artist, title, track_key),
                daemon=True,
            ).start()

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        while True:
            try:
                loop.run_until_complete(self._poll_media_once())
            except Exception:
                pass
            time.sleep(0.4)
