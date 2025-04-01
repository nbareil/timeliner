#! /usr/bin/env -S uv run
# /// script
# dependencies = [
#     "colorama",
#     "click"
# ]
# ///

from __future__ import annotations

import heapq
import json
import re
import sys
import tempfile

from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO, Iterator, List, Optional, Pattern, Set, TextIO

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
DEFAULT_HIGHLIGHT_COLOR = Fore.RED
HIGHLIGHT_STYLE = Style.BRIGHT


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
        """Convert entry to a dictionary suitable for JSON output."""
        return {
            "timestamp": format_datetime(timestamp),
            "md5": self.md5,
            "macb": macb,
            "name": self.name,
            "size": self.size,
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
        try:
            fields = line.strip().split("|")
            if len(fields) != 11:
                return None

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
    ):
        self.separate = separate
        self.since_ts = int(since.timestamp()) if since else None
        self.until_ts = int(until.timestamp()) if until else None
        self.time_filters = time_filters or TIMESTAMP_TYPES
        self.show_md5 = show_md5
        self.jsonl = jsonl
        self.highlighter = highlighter

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
            for time_type in self.time_filters:
                timestamp = entry.get_timestamp(time_type)
                if self._is_timestamp_valid(timestamp):
                    entries[timestamp, entry.name] = entry

        return entries

    def _is_timestamp_valid(self, timestamp: Timestamp) -> bool:
        """Check if a timestamp is valid and within the specified range."""
        if timestamp == 0:
            return False
        if self.since_ts is not None and timestamp < self.since_ts:
            return False
        if self.until_ts is not None and timestamp > self.until_ts:
            return False
        return True

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

    def _generate_macb(self, entry: TimelineEntry, timestamp: Timestamp) -> str:
        """Generate the MACB string for a timeline entry."""
        return "".join(
            "macb"[i] if entry.get_timestamp(t) == timestamp else "."
            for i, t in enumerate(["mtime", "atime", "ctime", "btime"])
        )


@lru_cache(maxsize=1024)
def format_datetime(timestamp: Timestamp) -> str:
    """Format a timestamp as a datetime string."""
    return datetime.fromtimestamp(timestamp).strftime(DATETIME_FORMATS[0])


@lru_cache(maxsize=128)
def get_period_key(timestamp: Timestamp, period: str) -> str:
    """Generate a period key for timeline separation."""
    dt = datetime.fromtimestamp(timestamp)
    if period == "day":
        return dt.strftime("%Y-%m-%d")
    elif period == "week":
        return (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")
    elif period == "month":
        return dt.strftime("%Y-%m")
    return dt.strftime("%Y")


class ChunkedTimelineProcessor(TimelineProcessor):
    """Processes timeline entries in chunks to handle large files."""

    CHUNK_SIZE = 100000  # Number of lines per chunk

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.temp_files = []

    def process_stream(self, stream: Iterator[str]) -> Iterator[str]:
        """Process a stream of bodyfile lines in chunks."""
        try:
            # Split input into sorted chunks
            chunk_files = self._create_sorted_chunks(stream)

            # Merge chunks and yield results
            yield from self._merge_chunks(chunk_files)
        finally:
            # Cleanup temporary files
            self._cleanup_temp_files()

    def _create_sorted_chunks(self, stream: Iterator[str]) -> List[Path]:
        """Split input stream into sorted chunks stored in temporary files."""
        chunk = []
        chunk_files = []

        for line in stream:
            entry = BodyfileParser.parse_line(line)
            if not entry:
                continue
            ts_seen = set()
            # Process entry for all requested timestamp types
            for time_type in self.time_filters:
                timestamp = entry.get_timestamp(time_type)
                if timestamp not in ts_seen and self._is_timestamp_valid(timestamp):
                    chunk.append((timestamp, entry.name, line))
                    ts_seen.add(timestamp)

            if len(chunk) >= self.CHUNK_SIZE:
                chunk_files.append(self._write_sorted_chunk(chunk))
                chunk = []

        # Write final chunk if not empty
        if chunk:
            chunk_files.append(self._write_sorted_chunk(chunk))

        return chunk_files

    def _write_sorted_chunk(self, chunk: List[tuple]) -> Path:
        """Sort and write a chunk to a temporary file."""
        # Sort chunk by timestamp and name
        chunk.sort(key=lambda x: (x[0], x[1]))

        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        self.temp_files.append(Path(temp_file.name))

        # Write sorted entries
        for _, _, line in chunk:
            temp_file.write(f"{line}\n")

        temp_file.close()
        return Path(temp_file.name)

    def _merge_chunks(self, chunk_files: List[Path]) -> Iterator[str]:
        """Merge sorted chunks using a heap."""
        file_handles = []
        entry_heap = []

        try:
            self._initialize_heap(chunk_files, file_handles, entry_heap)
            yield from self._process_heap(entry_heap, file_handles)
        finally:
            self._close_file_handles(file_handles)

    def _initialize_heap(
        self, chunk_files: List[Path], file_handles: List[IO], entry_heap: List[tuple]
    ):
        """Initialize the heap with the first entry from each chunk file."""
        for chunk_file in chunk_files:
            fh = open(chunk_file, "r")
            file_handles.append(fh)
            line = fh.readline().strip()
            if line:
                entry = BodyfileParser.parse_line(line)
                if entry:
                    self._add_entry_to_heap(entry, line, fh, entry_heap)

    def _add_entry_to_heap(self, entry, line: str, fh: IO, entry_heap: List[tuple]):
        """Add an entry to the heap if it has a valid timestamp."""
        ts_seen = set()
        for time_type in self.time_filters:
            timestamp = entry.get_timestamp(time_type)
            if timestamp not in ts_seen and self._is_timestamp_valid(timestamp):
                heapq.heappush(entry_heap, (timestamp, entry.name, line, fh))
                ts_seen.add(timestamp)

    def _process_heap(
        self, entry_heap: List[tuple], file_handles: List[IO]
    ) -> Iterator[str]:
        """Process the heap and yield formatted entries."""
        last_period = None
        while entry_heap:
            timestamp, name, line, fh = heapq.heappop(entry_heap)
            entry = BodyfileParser.parse_line(line)
            if entry:
                yield from self._yield_formatted_entry(timestamp, entry, last_period)
                last_period = self._get_current_period(timestamp)
            self._process_next_line(fh, entry_heap)

    def _yield_formatted_entry(
        self, timestamp: datetime, entry, last_period
    ) -> Iterator[str]:
        """Yield a formatted entry, including a separator if necessary."""
        if self.separate and not self.jsonl:
            current_period = get_period_key(timestamp, self.separate)
            if last_period is not None and current_period != last_period:
                yield SEPARATOR
        yield self._format_line(timestamp, entry)

    def _get_current_period(self, timestamp: datetime) -> str:
        """Get the current period key if separation is enabled."""
        return (
            get_period_key(timestamp, self.separate)
            if self.separate and not self.jsonl
            else None
        )

    def _process_next_line(self, fh: IO, entry_heap: List[tuple]):
        """Process the next line from the file and add it to the heap if valid."""
        next_line = fh.readline().strip()
        if next_line:
            next_entry = BodyfileParser.parse_line(next_line)
            if next_entry:
                self._add_entry_to_heap(next_entry, next_line, fh, entry_heap)

    def _close_file_handles(self, file_handles: List[IO]):
        """Close all file handles."""
        for fh in file_handles:
            fh.close()

    def _cleanup_temp_files(self):
        """Remove all temporary files."""
        for temp_file in self.temp_files:
            try:
                temp_file.unlink()
            except Exception:
                pass


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


def process_input_file(path: Optional[Path]) -> Iterator[str]:
    # If no path is provided, use stdin
    file_obj = "-" if path is None else str(path)
    with click.open_file(file_obj, "r", encoding="utf-8", errors="replace") as f:
        yield from (line.strip() for line in f)


def parse_time_range(
    around, since, to, window, **kwargs
) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse and return the time range from arguments, using full days.

    For --around:
        - since_dt starts at 00:00:00 of the start day
        - until_dt ends at 23:59:59 of the end day

    For --since/--to:
        - since_dt starts at 00:00:00 of the specified day
        - until_dt ends at 23:59:59 of the specified day

    Args:
        args: Command line arguments containing since, to, around, and window parameters

    Returns:
        tuple[Optional[datetime], Optional[datetime]]: The start and end datetimes
    """

    def start_of_day(dt: datetime) -> datetime:
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    def end_of_day(dt: datetime) -> datetime:
        return dt.replace(hour=23, minute=59, second=59, microsecond=999999)

    if around:
        center_dt = parse_datetime(around)
        # Start at beginning of the day, window days before
        since_dt = start_of_day(center_dt - timedelta(days=window))
        # End at end of the day, window days after
        until_dt = end_of_day(center_dt + timedelta(days=window))
        return since_dt, until_dt

    since_dt = None
    until_dt = None

    if since:
        since_dt = start_of_day(parse_datetime(since))

    if to:
        until_dt = end_of_day(parse_datetime(to))
    return since_dt, until_dt


def get_time_filters(**kwargs) -> Optional[Set[str]]:
    """Get the set of time filters from arguments."""
    filters = {time_type for time_type in TIMESTAMP_TYPES if kwargs.get(time_type)}
    return filters or None


@click.command()
@click.argument(
    "filename", type=click.Path(exists=True, path_type=Path), required=False
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
@click.option("--atime", is_flag=True, help="Include atime")
@click.option("--mtime", is_flag=True, help="Include mtime")
@click.option("--ctime", is_flag=True, help="Include ctime")
@click.option("--btime", is_flag=True, help="Include btime")
def main(filename: Optional[Path], **kwargs):
    """Process bodyfile and generate timeline."""
    try:
        if not kwargs["jsonl"] and sys.stdout.isatty():
            init()

        since_dt, until_dt = parse_time_range(**kwargs)
        time_filters = get_time_filters(**kwargs)

        # Setup highlighter
        highlighter = None
        if kwargs["highlight_file"] and not kwargs["jsonl"]:
            highlighter = KeywordHighlighter.from_file(
                kwargs["highlight_file"], case_sensitive=kwargs["case_sensitive"]
            )

        # Create chunked processor
        processor = ChunkedTimelineProcessor(
            separate=kwargs["separate"],
            since=since_dt,
            until=until_dt,
            time_filters=time_filters,
            show_md5=kwargs["show_md5"],
            jsonl=kwargs["jsonl"],
            highlighter=highlighter,
        )

        # Process and output
        for line in processor.process_stream(process_input_file(filename)):
            click.echo(line)

    except Exception as e:
        raise click.ClickException(str(e))


if __name__ == "__main__":
    main()
