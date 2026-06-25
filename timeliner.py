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
# or temp files); larger inputs use the chunked/parallel path. Matches one chunk.
SMALL_INPUT_THRESHOLD = 100000
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
    format_datetime.cache_clear()
    format_iso.cache_clear()
    get_period_key.cache_clear()


@dataclass(slots=True, frozen=True)
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
    timestamp: Timestamp, since_ts: Optional[int], until_ts: Optional[int]
) -> bool:
    """Check if a timestamp is valid and within the specified range."""
    if timestamp == -1:  # Skip invalid timestamps
        return False
    if since_ts is not None and timestamp < since_ts:
        return False
    if until_ts is not None and timestamp > until_ts:
        return False
    return True


def _macb_for(entry: TimelineEntry, timestamp: Timestamp) -> str:
    """Generate the MACB string for a timeline entry at a given timestamp."""
    return "".join(
        "macb"[i] if entry.get_timestamp(t) == timestamp else "."
        for i, t in enumerate(("mtime", "atime", "ctime", "btime"))
    )


def encode_record(timestamp: Timestamp, entry: TimelineEntry) -> str:
    """Encode one timeline row as a tab-separated intermediate record.

    The record carries the full entry (all four timestamps) so the parent
    process can render text or rich JSON identically to the single-process
    path. Never contains ANSI codes -- coloring/highlighting is applied only
    at final emit time, so it cannot pollute the sort key.
    """
    return (
        f"{timestamp}\t{entry.atime}\t{entry.mtime}\t{entry.ctime}\t"
        f"{entry.btime}\t{entry.size}\t{entry.md5}\t{entry.name}"
    )


def decode_record(line: str) -> tuple[Timestamp, TimelineEntry]:
    """Decode an intermediate record back into (timestamp, entry)."""
    parts = line.rstrip("\n").split("\t", 7)
    timestamp = int(parts[0])
    entry = TimelineEntry(
        md5=parts[6],
        name=parts[7],
        size=int(parts[5]),
        atime=int(parts[1]),
        mtime=int(parts[2]),
        ctime=int(parts[3]),
        btime=int(parts[4]),
    )
    return timestamp, entry


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
        stats: Optional[dict] = None,
    ):
        self.separate = separate
        self.since_ts = _boundary_epoch(since)
        self.until_ts = _boundary_epoch(until)
        self.time_filters = time_filters or TIMESTAMP_TYPES
        self.show_md5 = show_md5
        self.jsonl = jsonl
        self.highlighter = highlighter
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
        valid_entries = (
            entry
            for entry in map(BodyfileParser.parse_line, stream)
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
        return _timestamp_valid(timestamp, self.since_ts, self.until_ts)

    def _format_entries(
        self, entries: dict[tuple[Timestamp, PathStr], TimelineEntry]
    ) -> Iterator[str]:
        """Format and yield output lines."""
        last_period = None

        for (timestamp, _), entry in sorted(
            entries.items(), key=lambda x: (x[0][0], x[0][1])
        ):
            if self.separate and not self.jsonl:
                current_period = get_period_key(timestamp, self.separate)
                if last_period is not None and current_period != last_period:
                    yield SEPARATOR
                last_period = current_period

            yield self._format_line(timestamp, entry)

    def _format_line(self, timestamp: Timestamp, entry: TimelineEntry) -> str:
        """Format a single timeline entry."""
        if self.stats is not None:
            self._record_stats(timestamp)

        macb = self._generate_macb(entry, timestamp)

        if self.jsonl:
            return json.dumps(entry.to_json_dict(timestamp, macb))

        date_str = format_datetime(timestamp)
        md5_str = f"{entry.md5:<{MD5_LENGTH}}" if self.show_md5 else ""
        base_line = f"{date_str}: {md5_str}{macb} {entry.name}"

        if self.highlighter and not self.jsonl:
            base_line = self.highlighter.highlight(base_line)

        if entry.size == 0:
            return f"{Fore.LIGHTBLACK_EX}{base_line}{Style.RESET_ALL}"
        return base_line

    def _record_stats(self, timestamp: Timestamp) -> None:
        """Accumulate count and time span for the emitted rows."""
        s = self.stats
        s["count"] += 1
        if s["min_ts"] is None or timestamp < s["min_ts"]:
            s["min_ts"] = timestamp
        if s["max_ts"] is None or timestamp > s["max_ts"]:
            s["max_ts"] = timestamp

    def _generate_macb(self, entry: TimelineEntry, timestamp: Timestamp) -> str:
        """Generate the MACB string for a timeline entry."""
        return _macb_for(entry, timestamp)


@lru_cache(maxsize=1024)
def format_datetime(timestamp: Timestamp) -> str:
    """Format a timestamp as a datetime string in the display timezone."""
    return datetime.fromtimestamp(timestamp, tz=_DISPLAY_TZ).strftime(DATETIME_FORMATS[0])


@lru_cache(maxsize=1024)
def format_iso(timestamp: Timestamp) -> str:
    """Format a timestamp as an offset-aware ISO-8601 string."""
    return datetime.fromtimestamp(timestamp, tz=_DISPLAY_TZ).isoformat()


@lru_cache(maxsize=128)
def get_period_key(timestamp: Timestamp, period: str) -> str:
    """Generate a period key for timeline separation."""
    dt = datetime.fromtimestamp(timestamp, tz=_DISPLAY_TZ)
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

def _process_chunk_worker(
    chunk: List[str],
    time_filters: Optional[Set[str]],
    since_ts: Optional[int],
    until_ts: Optional[int],
    grep_re: Optional[Pattern] = None,
    exclude_re: Optional[Pattern] = None,
) -> Optional[str]:
    """Parse and filter a chunk, writing sorted intermediate records to a temp file.

    Runs in a worker process. Emits only ANSI-free intermediate records (no
    formatting, no MACB text, no color) so the parent owns all presentation and
    the sort key stays clean. Returns the temp file path, or None on empty/error.
    """
    filters = time_filters or TIMESTAMP_TYPES
    try:
        # Dedup within the chunk by (timestamp, name); cross-chunk dedup happens
        # at the merge step. Keep first occurrence for determinism.
        records: dict[tuple[Timestamp, PathStr], TimelineEntry] = {}
        for line in chunk:
            entry = BodyfileParser.parse_line(line)
            if entry is None:
                continue
            if not _name_matches(entry.name, grep_re, exclude_re):
                continue
            for time_type in filters:
                timestamp = entry.get_timestamp(time_type)
                if not _timestamp_valid(timestamp, since_ts, until_ts):
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
                temp_file.write(encode_record(timestamp, records[timestamp, name]) + "\n")
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

    CHUNK_SIZE = 100000  # Number of lines per chunk
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
        with ProcessPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
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
        """K-way merge sorted temp files by (timestamp, name); dedup adjacents."""
        if not temp_files:
            return

        heap: list = []
        file_handles = []
        try:
            for file_index, temp_file in enumerate(temp_files):
                fh = open(temp_file, "r", encoding="utf-8")
                file_handles.append(fh)
                line = fh.readline()
                if line:
                    timestamp, entry = decode_record(line)
                    # file_index is unique per handle, so it breaks ties before
                    # the (non-comparable) entry is ever reached.
                    heapq.heappush(heap, (timestamp, entry.name, file_index, entry, fh))

            last_period = None
            last_key = None
            while heap:
                timestamp, name, file_index, entry, fh = heapq.heappop(heap)

                key = (timestamp, name)
                if key != last_key:
                    if self.separate and not self.jsonl:
                        current_period = get_period_key(timestamp, self.separate)
                        if last_period is not None and current_period != last_period:
                            yield SEPARATOR
                        last_period = current_period
                    yield self._format_line(timestamp, entry)
                    last_key = key

                line = fh.readline()
                if line:
                    timestamp, entry = decode_record(line)
                    heapq.heappush(heap, (timestamp, entry.name, file_index, entry, fh))
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
    """Get the set of time filters from arguments."""
    filters = {time_type for time_type in TIMESTAMP_TYPES if kwargs.get(time_type)}
    return filters or None


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
    type=click.Choice(["day", "week", "month", "year"]),
    help="Add separator when crossing specified time period",
)
@click.option(
    "--since", help="Filter entries since this date/time (YYYY-MM-DD [HH:MM:SS])"
)
@click.option(
    "--to", help="Filter entries up to this date/time (YYYY-MM-DD [HH:MM:SS])"
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
@click.option("--atime", is_flag=True, help="Include atime")
@click.option("--mtime", is_flag=True, help="Include mtime")
@click.option("--ctime", is_flag=True, help="Include ctime")
@click.option("--btime", is_flag=True, help="Include btime")
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

        # Process and output (in-process for small inputs, chunked for large)
        lines = run_timeline(
            process_input_files(filenames),
            separate=kwargs["separate"],
            since=since_dt,
            until=until_dt,
            time_filters=time_filters,
            show_md5=kwargs["show_md5"],
            jsonl=kwargs["jsonl"],
            highlighter=highlighter,
            grep_re=grep_re,
            exclude_re=exclude_re,
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
