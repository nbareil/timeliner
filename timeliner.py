#! /usr/bin/env -S uv run -q
# /// script
# dependencies = [
#     "colorama",
#     "click",
#     "tzdata"
# ]
# ///

from __future__ import annotations

import glob
import heapq
import json
import os
import re
import sys
import tempfile

from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from itertools import chain
from operator import itemgetter
from pathlib import Path
from typing import Iterator, List, Optional, Pattern, Set
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import click
from colorama import Fore, Style, init

# Type aliases
Timestamp = int
PathStr = str

# Constants
DATETIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")
TIMESTAMP_TYPES = {"atime", "mtime", "ctime", "btime"}
MD5_LENGTH = 50
SEPARATOR = "-" * 50
# Inputs at or below this many lines are processed in-process (no worker pool
# or temp files); larger inputs use the chunked/parallel path. Set near the
# measured crossover: below ~30k lines the pool-spawn overhead outweighs the
# parallelism, above it the chunked path wins (it renders rows on worker cores).
SMALL_INPUT_THRESHOLD = 30000
DEFAULT_HIGHLIGHT_COLOR = Fore.RED
HIGHLIGHT_STYLE = Style.BRIGHT

# Display/filter timezone, process-wide. Forensic epochs are UTC; we render and
# filter in UTC by default and let --tz override. Set once at startup via
# set_display_tz(); the formatting lru_caches read this global, so it must be
# cleared whenever the tz changes (only happens at startup).
_DISPLAY_TZ = ZoneInfo("UTC")


def set_display_tz(name: Optional[str]) -> None:
    """Set the process-wide display/filter timezone (None => UTC)."""
    global _DISPLAY_TZ
    try:
        _DISPLAY_TZ = ZoneInfo(name) if name else ZoneInfo("UTC")
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise click.BadParameter(f"Unknown timezone '{name}'") from e
    # format_datetime reads _DISPLAY_TZ directly (no cache); the others are
    # lru_cached on (timestamp[, period]) and must be invalidated on tz change.
    format_iso.cache_clear()
    get_period_key.cache_clear()


# Not frozen: entries are never hashed or used as dict keys (keys are
# (timestamp, name) tuples), and a frozen dataclass forces a slow
# object.__setattr__ per field in __init__ -- costly at 1.2M+ constructions.
@dataclass(slots=True)
class TimelineEntry:
    """Represents a single timeline entry with all its timestamps."""

    name: PathStr
    md5: str
    size: int
    atime: Timestamp
    mtime: Timestamp
    ctime: Timestamp
    btime: Timestamp

    def get_timestamp(self, time_type: str) -> Timestamp:
        """Get the timestamp value for a specific time type."""
        return getattr(self, time_type)

    def to_json_dict(self, timestamp: Timestamp, macb: str) -> dict:
        """Convert entry to a dictionary suitable for JSON output.

        Carries both the numeric epoch and an ISO-8601 (offset-aware) string,
        the full path, and all four source timestamps so a consuming agent does
        not have to re-parse the human-readable output.
        """
        return {
            "epoch": timestamp,
            "timestamp": format_iso(timestamp),
            "macb": macb,
            "name": self.name,
            "size": self.size,
            "md5": self.md5,
            "atime": self.atime,
            "mtime": self.mtime,
            "ctime": self.ctime,
            "btime": self.btime,
        }


class KeywordHighlighter:
    """Handles keyword-based highlighting of output lines."""

    def __init__(self, keywords: List[str], case_sensitive: bool = False):
        flags = 0 if case_sensitive else re.IGNORECASE
        self.patterns = [
            re.compile(f"({re.escape(kw)})", flags)
            for kw in keywords
            if kw.strip()  # Skip empty lines
        ]

    @classmethod
    def from_file(
        cls, filepath: Path, case_sensitive: bool = False
    ) -> KeywordHighlighter:
        """Create a highlighter from a keywords file."""
        try:
            with filepath.open("r") as f:
                keywords = [line.strip() for line in f]
            return cls(keywords, case_sensitive)
        except Exception as e:
            print(f"Warning: Could not read keywords file: {e}", file=sys.stderr)
            return cls([], case_sensitive)

    def highlight(self, text: str) -> str:
        """Apply highlighting to text based on keywords."""
        if not self.patterns:
            return text

        for pattern in self.patterns:
            text = pattern.sub(
                f"{DEFAULT_HIGHLIGHT_COLOR}{HIGHLIGHT_STYLE}\\1{Style.RESET_ALL}", text
            )
        return text


class BodyfileParser:
    """Handles parsing of bodyfile format files."""

    @staticmethod
    def parse_line(line: str) -> Optional[TimelineEntry]:
        """Parse a single line of bodyfile format."""
        # Fast path: the common (Linux) bodyfile has no escapes or quotes, so a
        # plain split is both correct and much faster than the char-by-char scan.
        if "\\" not in line and '"' not in line:
            return BodyfileParser._build_entry(line.split("|"))
        return BodyfileParser._parse_line_escaped(line)

    @staticmethod
    def _build_entry(fields: List[str]) -> Optional[TimelineEntry]:
        """Build a TimelineEntry from 11 already-split fields, else None."""
        if len(fields) != 11:
            return None
        try:
            return TimelineEntry(
                md5=fields[0],
                name=fields[1],
                size=int(fields[6]),
                atime=int(fields[7]),
                mtime=int(fields[8]),
                ctime=int(fields[9]),
                btime=int(fields[10]),
            )
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _parse_line_escaped(line: str) -> Optional[TimelineEntry]:
        """Parse a line that contains escaped pipes or quoted fields."""
        # Split by unescaped pipes
        fields = []
        current_field = []
        escape = False
        in_quotes = False

        for char in line:
            if escape:
                if not in_quotes and char in ('\\', '|'):  # Only treat \\ and \| as escape sequences
                    current_field.append(char)
                else:
                    # For other characters after \, keep both the \ and the character
                    current_field.append('\\')
                    current_field.append(char)
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                in_quotes = not in_quotes
                current_field.append(char)
            elif char == '|' and not escape and not in_quotes:
                fields.append(''.join(current_field))
                current_field = []
            else:
                if not escape:  # Only append if not in escape sequence
                    current_field.append(char)

        # Always append the final field, even when empty (line ending in '|'),
        # so trailing empty fields are not silently dropped.
        fields.append(''.join(current_field))

        return BodyfileParser._build_entry(fields)

def _boundary_epoch(dt: Optional[datetime]) -> Optional[int]:
    """Convert a naive wall-clock filter boundary to a UTC epoch.

    Filter datetimes parsed from --since/--to/--around are wall-clock in the
    display timezone, so attach _DISPLAY_TZ before converting (the old code used
    naive .timestamp(), which silently assumed the machine's local timezone).
    """
    if dt is None:
        return None
    return int(dt.replace(tzinfo=_DISPLAY_TZ).timestamp())


def _name_matches(
    name: str, grep_re: Optional[Pattern], exclude_re: Optional[Pattern]
) -> bool:
    """Apply --grep/--exclude path filters: include must match, exclude must not."""
    if grep_re is not None and not grep_re.search(name):
        return False
    if exclude_re is not None and exclude_re.search(name):
        return False
    return True


def _timestamp_valid(
    timestamp: Timestamp,
    since_ts: Optional[int],
    until_ts: Optional[int],
    include_bogus: bool = False,
) -> bool:
    """Check if a timestamp is valid and within the specified range.

    Non-positive epochs (<= 0) are "bogus" -- the -1 missing-field sentinel, 0,
    and negatives all render in the 1970s and are forensic noise. They are
    dropped by default; pass include_bogus=True (the --bogus flag) to keep them.
    """
    if timestamp <= 0 and not include_bogus:
        return False
    if since_ts is not None and timestamp < since_ts:
        return False
    if until_ts is not None and timestamp > until_ts:
        return False
    return True


@dataclass(frozen=True, slots=True)
class _WindowBounds:
    """Precomputed string forms of the since/until epoch boundaries.

    Used by the cheap pre-reject in the parse loops: comparing the raw bodyfile
    time-field strings against these avoids the int() conversions for the lines
    that a time filter (--around/--since/--to) is going to drop anyway.
    """

    have_since: bool
    since_len: int  # len(str(since_ts))
    since_str: str  # str(since_ts)
    have_until: bool
    until_len: int
    until_str: str


def _make_window_bounds(
    since_ts: Optional[int], until_ts: Optional[int]
) -> Optional[_WindowBounds]:
    """Build pre-filter bounds, or None when the cheap path does not apply.

    Returns None when there is no time window at all, so the parse loops behave
    exactly as before. A negative boundary disables the cheap path on that side
    (the length/lexical == numeric equivalence only holds for non-negative
    integers); the exact int filter still applies it.
    """
    have_since = since_ts is not None and since_ts >= 0
    have_until = until_ts is not None and until_ts >= 0
    if not have_since and not have_until:
        return None
    s = str(since_ts) if have_since else ""
    u = str(until_ts) if have_until else ""
    return _WindowBounds(have_since, len(s), s, have_until, len(u), u)


def _field_clean_digits(s: str) -> bool:
    """True if s is a non-negative ASCII integer with no leading zero.

    For such strings, numeric ordering equals (length, then lexical) ordering,
    which is what makes the string pre-reject sound. isascii() rules out exotic
    Unicode digits (e.g. "²".isdigit() is True but does not order numerically).
    """
    return s.isascii() and s.isdigit() and (len(s) == 1 or s[0] != "0")


def _provably_outside_window(fields: List[str], bounds: _WindowBounds) -> bool:
    """True only if every time field is provably outside [since, until].

    Conservative: returns True (safe to skip the line) only when all four time
    fields are clean digit strings that the (length, lexical) test places
    outside the window. Anything ambiguous -- non-digit, negative, zero-padded,
    or possibly in range -- returns False so the line falls through to the exact
    int filter. Keeping extra lines is always safe; only skipping must be proven.
    """
    if len(fields) != 11:
        return False  # malformed: let _build_entry reject it
    for i in (7, 8, 9, 10):  # atime, mtime, ctime, btime
        s = fields[i]
        if not _field_clean_digits(s):
            return False
        below = bounds.have_since and (
            len(s) < bounds.since_len
            or (len(s) == bounds.since_len and s < bounds.since_str)
        )
        above = bounds.have_until and (
            len(s) > bounds.until_len
            or (len(s) == bounds.until_len and s > bounds.until_str)
        )
        if not (below or above):
            return False  # this field is/may be in range -> keep the line
    return True


def _parse_with_prefilter(
    line: str, bounds: Optional[_WindowBounds]
) -> Optional[TimelineEntry]:
    """Parse a line, cheaply skipping lines provably outside the time window.

    Mirrors BodyfileParser.parse_line's fast/escaped dispatch, but on the fast
    path it reuses the split fields to pre-reject out-of-window lines before the
    expensive int() conversions in _build_entry. The escaped path and the exact
    int filter downstream are unchanged.
    """
    if "\\" not in line and '"' not in line:
        fields = line.split("|")
        if bounds is not None and _provably_outside_window(fields, bounds):
            return None
        return BodyfileParser._build_entry(fields)
    return BodyfileParser._parse_line_escaped(line)


def _macb_for(entry: TimelineEntry, timestamp: Timestamp) -> str:
    """Generate the MACB string for a timeline entry at a given timestamp.

    Hot path: built by direct field comparison (no getattr/genexpr) since this
    runs once per emitted row in both the in-process and chunked-merge paths.
    """
    return (
        ("m" if entry.mtime == timestamp else ".")
        + ("a" if entry.atime == timestamp else ".")
        + ("c" if entry.ctime == timestamp else ".")
        + ("b" if entry.btime == timestamp else ".")
    )


@dataclass(frozen=True)
class RenderOptions:
    """How a row is rendered to its final string.

    Bundled into one object so it threads cleanly from the processor through
    the (module-level, can't-see-self) worker to render_row; a new render flag
    is added here and used in render_row, without touching every call site.
    """

    show_md5: bool = False
    jsonl: bool = False
    highlighter: Optional[KeywordHighlighter] = None


def render_row(timestamp: Timestamp, entry: TimelineEntry, opts: RenderOptions) -> str:
    """Render one timeline row to its final output string.

    Shared by the in-process path and the parallel workers so both produce
    byte-identical output. Pure with respect to the global display timezone
    (read by format_datetime/format_iso); does not touch stats.
    """
    macb = _macb_for(entry, timestamp)

    if opts.jsonl:
        return json.dumps(entry.to_json_dict(timestamp, macb))

    date_str = format_datetime(timestamp)
    md5_str = f"{entry.md5:<{MD5_LENGTH}}" if opts.show_md5 else ""
    base_line = f"{date_str}: {md5_str}{macb} {entry.name}"

    if opts.highlighter is not None:
        base_line = opts.highlighter.highlight(base_line)

    if entry.size == 0:
        return f"{Fore.LIGHTBLACK_EX}{base_line}{Style.RESET_ALL}"
    return base_line


# NUL separates the merge sort key from the already-rendered payload. NUL can
# never appear in a Unix path or in our formatted output, so it is a safe
# delimiter (unlike tab, which is a legal filename character).
_RECORD_SEP = "\x00"


def encode_record(timestamp: Timestamp, name: PathStr, payload: str) -> str:
    """Encode one already-rendered row as an intermediate record.

    The record carries only the sort key (timestamp, name) and the final
    rendered payload -- the worker has already done all formatting, so the
    parent merge does no per-row TimelineEntry reconstruction or formatting.
    The payload may contain ANSI codes; it is never part of the sort key.
    """
    return f"{timestamp}{_RECORD_SEP}{name}{_RECORD_SEP}{payload}"


def decode_record(line: str) -> tuple[Timestamp, PathStr, str]:
    """Decode an intermediate record into (timestamp, name, rendered payload)."""
    ts_str, name, payload = line.split(_RECORD_SEP, 2)
    return int(ts_str), name, payload.rstrip("\n")


class TimelineProcessor:
    """Processes timeline entries and handles filtering and formatting."""

    def __init__(
        self,
        *,
        separate: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        time_filters: Optional[Set[str]] = None,
        show_md5: bool = False,
        jsonl: bool = False,
        highlighter: Optional[KeywordHighlighter] = None,
        grep_re: Optional[Pattern] = None,
        exclude_re: Optional[Pattern] = None,
        include_bogus: bool = False,
        stats: Optional[dict] = None,
    ):
        self.separate = separate
        self.since_ts = _boundary_epoch(since)
        self.until_ts = _boundary_epoch(until)
        self.include_bogus = include_bogus
        # Precomputed string bounds for the cheap pre-reject in the parse loop;
        # None when there is no usable time window (then the loop is unchanged).
        self._bounds = _make_window_bounds(self.since_ts, self.until_ts)
        self.time_filters = time_filters or TIMESTAMP_TYPES
        self.render = RenderOptions(
            show_md5=show_md5, jsonl=jsonl, highlighter=highlighter
        )
        self.grep_re = grep_re
        self.exclude_re = exclude_re
        # Caller-owned accumulator updated at each emitted row (both paths render
        # through _format_line in the parent, so the count is exact).
        self.stats = stats

    def process_stream(self, stream: Iterator[str]) -> Iterator[str]:
        """Process a stream of bodyfile lines and yield formatted output lines."""
        entries = self._collect_entries(stream)
        if not entries:
            return

        yield from self._format_entries(entries)

    def _collect_entries(
        self, stream: Iterator[str]
    ) -> dict[tuple[Timestamp, PathStr], TimelineEntry]:
        """Collect and filter timeline entries."""
        entries = {}
        bounds = self._bounds
        valid_entries = (
            entry
            for entry in (_parse_with_prefilter(line, bounds) for line in stream)
            if entry is not None
        )

        for entry in valid_entries:
            if not _name_matches(entry.name, self.grep_re, self.exclude_re):
                continue
            for time_type in self.time_filters:
                timestamp = entry.get_timestamp(time_type)
                if self._is_timestamp_valid(timestamp):
                    entries[timestamp, entry.name] = entry

        return entries

    def _is_timestamp_valid(self, timestamp: Timestamp) -> bool:
        """Check if a timestamp is valid and within the specified range."""
        return _timestamp_valid(
            timestamp, self.since_ts, self.until_ts, self.include_bogus
        )

    def _format_entries(
        self, entries: dict[tuple[Timestamp, PathStr], TimelineEntry]
    ) -> Iterator[str]:
        """Format and yield output lines."""
        last_period = None

        # The dict key is already the (timestamp, name) sort tuple, so sort on
        # it directly (itemgetter(0)) instead of rebuilding it in a lambda.
        for (timestamp, _), entry in sorted(entries.items(), key=itemgetter(0)):
            if self.separate and not self.render.jsonl:
                current_period = get_period_key(timestamp, self.separate)
                if last_period is not None and current_period != last_period:
                    yield SEPARATOR
                last_period = current_period

            yield self._format_line(timestamp, entry)

    def _format_line(self, timestamp: Timestamp, entry: TimelineEntry) -> str:
        """Format a single timeline entry (and accumulate stats)."""
        if self.stats is not None:
            self._record_stats(timestamp)
        return render_row(timestamp, entry, self.render)

    def _record_stats(self, timestamp: Timestamp) -> None:
        """Accumulate count and time span for the emitted rows."""
        s = self.stats
        s["count"] += 1
        if s["min_ts"] is None or timestamp < s["min_ts"]:
            s["min_ts"] = timestamp
        if s["max_ts"] is None or timestamp > s["max_ts"]:
            s["max_ts"] = timestamp


def format_datetime(timestamp: Timestamp) -> str:
    """Format a timestamp as a datetime string in the display timezone.

    Hot path: runs once per emitted row. strftime is comparatively slow and the
    timestamps rarely repeat (so an lru_cache barely hits), so build the fixed
    "YYYY-MM-DD HH:MM:SS" layout directly from the datetime components.
    """
    # isoformat(sep=" ") yields "YYYY-MM-DD HH:MM:SS[+HH:MM]" in one C call;
    # slicing to 19 chars drops the offset, matching the fixed display layout.
    return datetime.fromtimestamp(timestamp, tz=_DISPLAY_TZ).isoformat(sep=" ")[:19]


@lru_cache(maxsize=1024)
def format_iso(timestamp: Timestamp) -> str:
    """Format a timestamp as an offset-aware ISO-8601 string."""
    return datetime.fromtimestamp(timestamp, tz=_DISPLAY_TZ).isoformat()


# Maps every accepted --separate value to a canonical period. Both the noun
# forms (day, week, ...) and the adverb aliases (daily, weekly, ...) are
# supported; "hourly"/"hour" add an hour-level period.
SEPARATE_PERIODS = {
    "hour": "hour",
    "hourly": "hour",
    "day": "day",
    "daily": "day",
    "week": "week",
    "weekly": "week",
    "month": "month",
    "monthly": "month",
    "year": "year",
    "yearly": "year",
}


@lru_cache(maxsize=128)
def get_period_key(timestamp: Timestamp, period: str) -> str:
    """Generate a period key for timeline separation.

    `period` is a canonical period name (see SEPARATE_PERIODS values).
    """
    dt = datetime.fromtimestamp(timestamp, tz=_DISPLAY_TZ)
    if period == "hour":
        return dt.strftime("%Y-%m-%d %H")
    if period == "day":
        return dt.strftime("%Y-%m-%d")
    elif period == "week":
        return (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")
    elif period == "month":
        return dt.strftime("%Y-%m")
    return dt.strftime("%Y")



def parse_datetime(dt_str: str) -> datetime:
    """Parse a datetime string in various formats."""
    for fmt in DATETIME_FORMATS:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    raise click.BadParameter(
        f"Time data '{dt_str}' does not match any of the supported formats: {', '.join(DATETIME_FORMATS)}"
    )

def _worker_init(tz_name: str) -> None:
    """Pool initializer: set each worker's display timezone.

    Workers render rows themselves, so they must agree with the parent on the
    display timezone. Fork inherits it, but setting it explicitly makes the
    chunked path correct under any multiprocessing start method.
    """
    set_display_tz(tz_name if tz_name != "UTC" else None)


def _process_chunk_worker(
    chunk: List[str],
    time_filters: Optional[Set[str]],
    since_ts: Optional[int],
    until_ts: Optional[int],
    grep_re: Optional[Pattern],
    exclude_re: Optional[Pattern],
    render: RenderOptions,
    include_bogus: bool,
) -> Optional[str]:
    """Parse, filter, and fully render a chunk into a sorted temp file.

    Runs in a worker process. The expensive per-row work -- MACB, datetime
    formatting, JSON/highlight rendering -- happens here, on the worker cores,
    so the parent's serial k-way merge only parses the sort key and emits the
    precomputed payload. Returns the temp file path, or None on empty/error.
    """
    filters = time_filters or TIMESTAMP_TYPES
    # Built once per chunk; cheaply skips lines provably outside the time window
    # before the per-line int() conversions (None when there is no window).
    bounds = _make_window_bounds(since_ts, until_ts)
    try:
        # Dedup within the chunk by (timestamp, name); cross-chunk dedup happens
        # at the merge step. Keep first occurrence for determinism.
        records: dict[tuple[Timestamp, PathStr], TimelineEntry] = {}
        for line in chunk:
            entry = _parse_with_prefilter(line, bounds)
            if entry is None:
                continue
            if not _name_matches(entry.name, grep_re, exclude_re):
                continue
            for time_type in filters:
                timestamp = entry.get_timestamp(time_type)
                if not _timestamp_valid(timestamp, since_ts, until_ts, include_bogus):
                    continue
                key = (timestamp, entry.name)
                if key not in records:
                    records[key] = entry

        if not records:
            return None

        temp_file = tempfile.NamedTemporaryFile(
            mode="w", delete=False, encoding="utf-8", newline=""
        )
        try:
            for timestamp, name in sorted(records):
                payload = render_row(timestamp, records[timestamp, name], render)
                temp_file.write(encode_record(timestamp, name, payload) + "\n")
            temp_file.close()
            return temp_file.name
        except Exception:
            temp_file.close()
            Path(temp_file.name).unlink(missing_ok=True)
            raise
    except Exception as e:  # noqa: BLE001 - report and drop the chunk
        print(f"Error processing chunk: {e}", file=sys.stderr)
        return None


class ChunkedTimelineProcessor(TimelineProcessor):
    """Processes timeline entries in chunks using parallel processing.

    Used only for large inputs. Workers parse/filter chunks into sorted,
    ANSI-free intermediate temp files; the parent k-way merges them, dedups
    across chunk boundaries, and renders each row with the shared formatter.
    """

    # Smaller chunks keep more worker cores busy (a 100k chunk on a 300k input
    # used only 3 of N cores); 25k was near-optimal in benchmarks while keeping
    # the open-temp-file count bounded for very large inputs.
    CHUNK_SIZE = 25000  # Number of lines per chunk
    MAX_WORKERS = max(1, (os.cpu_count() or 2) - 1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.temp_files: List[str] = []

    def process_stream(self, stream: Iterator[str]) -> Iterator[str]:
        """Process a stream of bodyfile lines in chunks, always sorted."""
        try:
            self.temp_files = self._process_chunks_parallel(stream)
            yield from self._sort_and_merge(self.temp_files)
        finally:
            self._cleanup_temp_files()

    def _process_chunks_parallel(self, stream: Iterator[str]) -> List[str]:
        """Process chunks in parallel, returning temp files in submission order."""
        results: dict[int, str] = {}
        pending: dict[Future, int] = {}
        next_index = 0
        max_outstanding = self.MAX_WORKERS * 2

        def submit(executor, chunk: List[str]) -> None:
            nonlocal next_index
            future = executor.submit(
                _process_chunk_worker,
                chunk,
                self.time_filters,
                self.since_ts,
                self.until_ts,
                self.grep_re,
                self.exclude_re,
                self.render,
                self.include_bogus,
            )
            pending[future] = next_index
            next_index += 1

        def drain_one() -> None:
            done = next(as_completed(pending))
            index = pending.pop(done)
            temp_file = done.result()
            if temp_file:
                results[index] = temp_file

        current_chunk: List[str] = []
        with ProcessPoolExecutor(
            max_workers=self.MAX_WORKERS,
            initializer=_worker_init,
            initargs=(_DISPLAY_TZ.key,),
        ) as executor:
            for line in stream:
                current_chunk.append(line)
                if len(current_chunk) >= self.CHUNK_SIZE:
                    submit(executor, current_chunk)
                    current_chunk = []
                    # Bound memory: don't let unbounded chunks queue up.
                    while len(pending) >= max_outstanding:
                        drain_one()

            if current_chunk:
                submit(executor, current_chunk)

            while pending:
                drain_one()

        # Order temp files by submission index for deterministic merge input.
        return [results[i] for i in sorted(results)]

    def _sort_and_merge(self, temp_files: List[str]) -> Iterator[str]:
        """K-way merge sorted temp files by (timestamp, name); dedup adjacents.

        Workers already rendered each row, so this serial step only parses the
        sort key and emits the precomputed payload -- no per-row formatting.
        """
        if not temp_files:
            return

        record_stats = self._record_stats if self.stats is not None else None
        emit_separator = bool(self.separate) and not self.render.jsonl

        heap: list = []
        file_handles = []
        try:
            for file_index, temp_file in enumerate(temp_files):
                fh = open(temp_file, "r", encoding="utf-8")
                file_handles.append(fh)
                line = fh.readline()
                if line:
                    timestamp, name, payload = decode_record(line)
                    # file_index is unique per handle, so it breaks ties
                    # deterministically before the payload is ever compared.
                    heapq.heappush(heap, (timestamp, name, file_index, payload, fh))

            last_period = None
            last_key = None
            while heap:
                timestamp, name, file_index, payload, fh = heapq.heappop(heap)

                key = (timestamp, name)
                if key != last_key:
                    if emit_separator:
                        current_period = get_period_key(timestamp, self.separate)
                        if last_period is not None and current_period != last_period:
                            yield SEPARATOR
                        last_period = current_period
                    if record_stats is not None:
                        record_stats(timestamp)
                    yield payload
                    last_key = key

                line = fh.readline()
                if line:
                    timestamp, name, payload = decode_record(line)
                    heapq.heappush(heap, (timestamp, name, file_index, payload, fh))
        finally:
            for fh in file_handles:
                try:
                    fh.close()
                except Exception:
                    pass

    def _cleanup_temp_files(self):
        """Remove all temporary files."""
        for temp_file in self.temp_files:
            try:
                Path(temp_file).unlink(missing_ok=True)
            except Exception:
                pass


def resolve_input_paths(filenames: tuple) -> List[str]:
    """Expand globs and validate literal paths, returning files to read.

    An empty result means read from stdin. A glob that matches nothing is
    silently dropped; a literal path that does not exist is an error.
    """
    resolved: List[str] = []
    for name in filenames:
        if any(ch in name for ch in "*?[]"):
            matches = sorted(glob.glob(name))
            resolved.extend(matches)
        else:
            if not Path(name).exists():
                raise click.BadParameter(f"File '{name}' does not exist")
            resolved.append(name)
    return resolved


def process_input_files(filenames: tuple) -> Iterator[str]:
    """Yield stripped lines from all input files (or stdin if none given)."""
    paths = resolve_input_paths(filenames)
    sources = paths or ["-"]  # no files => read stdin
    for source in sources:
        with click.open_file(source, "r", encoding="utf-8", errors="replace") as f:
            yield from (line.strip() for line in f)


def _has_time_component(dt_str: str) -> bool:
    """Return True if the date string includes a time-of-day (HH:MM[:SS])."""
    return ":" in dt_str


def parse_time_range(
    around, since, to, window, **kwargs
) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse and return the time range from arguments.

    When only a date is given (YYYY-MM-DD), the boundary is expanded to the full
    day; when a time is also given (YYYY-MM-DD HH:MM[:SS]), the exact time is
    used:

    For --since: start of day if date-only, else the exact time.
    For --to:    end of day if date-only, else the exact time.
    For --around: window days around the center; full days if date-only, else
                  exactly ``window`` days before/after the given time.

    Returns:
        tuple[Optional[datetime], Optional[datetime]]: The start and end datetimes
    """

    def start_of_day(dt: datetime) -> datetime:
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    def end_of_day(dt: datetime) -> datetime:
        return dt.replace(hour=23, minute=59, second=59, microsecond=999999)

    if around:
        center_dt = parse_datetime(around)
        if _has_time_component(around):
            return center_dt - timedelta(days=window), center_dt + timedelta(days=window)
        # Date-only: full days, window days before/after.
        since_dt = start_of_day(center_dt - timedelta(days=window))
        until_dt = end_of_day(center_dt + timedelta(days=window))
        return since_dt, until_dt

    since_dt = None
    until_dt = None

    if since:
        parsed = parse_datetime(since)
        since_dt = parsed if _has_time_component(since) else start_of_day(parsed)

    if to:
        parsed = parse_datetime(to)
        until_dt = parsed if _has_time_component(to) else end_of_day(parsed)
    return since_dt, until_dt


def get_time_filters(**kwargs) -> Optional[Set[str]]:
    """Resolve which timestamp types to include from the CLI flags.

    Start from the explicit allow-list (--atime/--mtime/--ctime/--btime) if any
    were given, else all four; then drop any excluded by --no-atime/--no-mtime/
    --no-ctime/--no-btime. Returns None when the result is all four (the default,
    so callers fall back to TIMESTAMP_TYPES). Raises if every type is excluded.
    """
    included = {t for t in TIMESTAMP_TYPES if kwargs.get(t)}
    if not included:
        included = set(TIMESTAMP_TYPES)
    excluded = {t for t in TIMESTAMP_TYPES if kwargs.get(f"no_{t}")}
    result = included - excluded
    if not result:
        raise click.BadParameter("all timestamp types were excluded; nothing to show")
    return result if result != TIMESTAMP_TYPES else None


def _compile_regex(pattern: Optional[str], option: str) -> Optional[Pattern]:
    """Compile a user-supplied regex, raising a clean error on bad syntax."""
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error as e:
        raise click.BadParameter(f"Invalid {option} regex: {e}")


def run_timeline(stream: Iterator[str], **processor_kwargs) -> Iterator[str]:
    """Dispatch to the in-process or chunked processor based on input size.

    Buffers up to SMALL_INPUT_THRESHOLD lines: if the input fits, process it
    in-process (no worker pool or temp files); otherwise hand the buffered head
    plus the rest of the stream to the chunked/parallel processor.
    """
    head: List[str] = []
    for line in stream:
        head.append(line)
        if len(head) > SMALL_INPUT_THRESHOLD:
            processor = ChunkedTimelineProcessor(**processor_kwargs)
            yield from processor.process_stream(chain(head, stream))
            return

    processor = TimelineProcessor(**processor_kwargs)
    yield from processor.process_stream(iter(head))


@click.command()
@click.version_option(version="2.0", prog_name="timeliner.py")
@click.argument("filenames", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "-o",
    "--output",
    type=click.File("w"),
    default="-",
    help="Write output to a file instead of stdout",
)
@click.option(
    "--stats",
    is_flag=True,
    help="Print summary statistics (count, time span) to stderr",
)
@click.option(
    "--separate",
    type=click.Choice(list(SEPARATE_PERIODS)),
    help="Add separator when crossing specified time period (e.g. day/daily, "
    "week/weekly; also hour/hourly)",
)
@click.option(
    "--after",
    "--since",
    "since",
    help="Filter entries at/after this date/time (YYYY-MM-DD [HH:MM:SS]); "
    "alias: --since",
)
@click.option(
    "--before",
    "--to",
    "to",
    help="Filter entries at/before this date/time (YYYY-MM-DD [HH:MM:SS]); "
    "alias: --to",
)
@click.option(
    "--around", help="Filter entries around this date/time (YYYY-MM-DD [HH:MM:SS])"
)
@click.option(
    "--window",
    type=int,
    default=2,
    help="Number of days before and after for --around (default: 2)",
)
@click.option(
    "--tz",
    "--timezone",
    "tz",
    metavar="IANA",
    help="Display/filter timezone (IANA name, e.g. America/New_York). Default: UTC",
)
@click.option("--show-md5", is_flag=True, help="Show MD5 hash in output")
@click.option("--jsonl", is_flag=True, help="Output in JSON Lines format")
@click.option(
    "--highlight-file",
    type=click.Path(exists=True, path_type=Path),
    help="File containing keywords to highlight (one per line)",
)
@click.option(
    "--case-sensitive", is_flag=True, help="Make keyword highlighting case-sensitive"
)
@click.option(
    "--grep",
    "grep",
    metavar="REGEX",
    help="Only include entries whose path matches REGEX",
)
@click.option(
    "--exclude",
    "exclude",
    metavar="REGEX",
    help="Exclude entries whose path matches REGEX",
)
@click.option(
    "--bogus",
    is_flag=True,
    help="Include bogus timestamps (epoch <= 0, i.e. resolving to 1970); "
    "hidden by default",
)
@click.option("--atime", is_flag=True, help="Include atime")
@click.option("--mtime", is_flag=True, help="Include mtime")
@click.option("--ctime", is_flag=True, help="Include ctime")
@click.option("--btime", is_flag=True, help="Include btime")
@click.option("--no-atime", is_flag=True, help="Exclude atime")
@click.option("--no-mtime", is_flag=True, help="Exclude mtime")
@click.option("--no-ctime", is_flag=True, help="Exclude ctime")
@click.option("--no-btime", is_flag=True, help="Exclude btime")
def main(filenames: tuple, output, stats: bool, **kwargs):
    """Process bodyfile(s) and generate timeline.

    FILENAMES are bodyfiles to read (globs allowed); reads stdin if none given.
    """
    try:
        if not kwargs["jsonl"] and output.isatty():
            init()

        # Set timezone before parsing time ranges so filter boundaries are
        # interpreted in the display timezone.
        set_display_tz(kwargs["tz"])

        since_dt, until_dt = parse_time_range(**kwargs)
        time_filters = get_time_filters(**kwargs)

        # Setup highlighter
        highlighter = None
        if kwargs["highlight_file"] and not kwargs["jsonl"]:
            highlighter = KeywordHighlighter.from_file(
                kwargs["highlight_file"], case_sensitive=kwargs["case_sensitive"]
            )

        grep_re = _compile_regex(kwargs["grep"], "--grep")
        exclude_re = _compile_regex(kwargs["exclude"], "--exclude")

        stats_acc = {"count": 0, "min_ts": None, "max_ts": None} if stats else None

        # Normalize the --separate alias (e.g. "daily" -> "day") to the
        # canonical period the processor and get_period_key expect.
        separate = SEPARATE_PERIODS.get(kwargs["separate"]) if kwargs["separate"] else None

        # Process and output (in-process for small inputs, chunked for large)
        lines = run_timeline(
            process_input_files(filenames),
            separate=separate,
            since=since_dt,
            until=until_dt,
            time_filters=time_filters,
            show_md5=kwargs["show_md5"],
            jsonl=kwargs["jsonl"],
            highlighter=highlighter,
            grep_re=grep_re,
            exclude_re=exclude_re,
            include_bogus=kwargs["bogus"],
            stats=stats_acc,
        )
        for line in lines:
            click.echo(line, file=output)

        if stats_acc is not None:
            _print_stats(stats_acc)

    except click.ClickException:
        raise
    except OSError as e:
        raise click.ClickException(str(e))


def _print_stats(stats_acc: dict) -> None:
    """Print summary statistics to stderr."""
    count = stats_acc["count"]
    if count and stats_acc["min_ts"] is not None:
        span = f"{format_iso(stats_acc['min_ts'])} .. {format_iso(stats_acc['max_ts'])}"
    else:
        span = "(none)"
    click.echo(f"entries: {count}  span: {span}", file=sys.stderr)


if __name__ == "__main__":
    main()
