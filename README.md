# timeliner.py

A memory-efficient Python script for processing and analyzing bodyfile timeline data. This tool processes bodyfile format and generates a sorted, filtered, and optionally highlighted timeline output.

*Credit: This script was 90% written by LLM.*

## Features

- Process (large) bodyfile format timelines with minimal memory usage
  (small inputs run in-process; large ones are chunked across CPU cores)
- Merge multiple bodyfiles (and globs) into one globally-sorted timeline
- Filter entries by timestamp types: include with `--atime`/`--mtime`/`--ctime`/
  `--btime`, or exclude with `--no-atime`/`--no-mtime`/`--no-ctime`/`--no-btime`
- Bogus timestamps (epoch <= 0, i.e. resolving to 1970) are hidden by default;
  pass `--bogus` to include them
- Date range filtering with `--after`, `--before`, and `--around` (full-day
  when a date is given, exact when a time is given)
- Path filtering with `--grep` / `--exclude` regexes
- Timeline separation by hour, day, week, month, or year (adverb aliases:
  `--separate hourly|daily|weekly|monthly|yearly`)
- Keyword highlighting from a keyword file
- JSON Lines output with numeric epoch, ISO-8601 timestamp, and all four times
- Timestamps rendered and filtered in **UTC by default**, overridable with `--tz`

## Installation

The script is self-contained and runs via [uv](https://docs.astral.sh/uv/);
the inline script header declares its dependencies, so `./timeliner.py` will
fetch them on first run.

With [Nix](https://nixos.org/) (flakes enabled) you can run it without cloning:
`nix run github:nbareil/timeliner -- --help`.

### Dependencies

- colorama
- click
- tzdata (for `--tz` on minimal systems; UTC needs nothing)

## Usage

```
$ timeliner.py --help
Usage: timeliner.py [OPTIONS] [FILENAMES]...

  Process bodyfile(s) and generate timeline.

  FILENAMES are bodyfiles to read (globs allowed); reads stdin if none given.

Options:
  --version                       Show the version and exit.
  -o, --output FILENAME           Write output to a file instead of stdout
  --stats                         Print summary statistics (count, time span)
                                  to stderr
  --separate [hour|hourly|day|daily|week|weekly|month|monthly|year|yearly]
                                  Add separator when crossing specified time
                                  period (e.g. day/daily, week/weekly; also
                                  hour/hourly)
  --after TEXT                    Filter entries at/after this date/time
                                  (YYYY-MM-DD [HH:MM:SS])
  --before TEXT                   Filter entries at/before this date/time
                                  (YYYY-MM-DD [HH:MM:SS])
  --around TEXT                   Filter entries around this date/time (YYYY-
                                  MM-DD [HH:MM:SS])
  --window INTEGER                Number of days before and after for --around
                                  (default: 2)
  --tz, --timezone IANA           Display/filter timezone (IANA name, e.g.
                                  America/New_York). Default: UTC
  --show-md5                      Show MD5 hash in output
  --jsonl                         Output in JSON Lines format
  --highlight-file PATH           File containing keywords to highlight (one
                                  per line)
  --case-sensitive                Make keyword highlighting case-sensitive
  --grep REGEX                    Only include entries whose path matches
                                  REGEX
  --exclude REGEX                 Exclude entries whose path matches REGEX
  --bogus                         Include bogus timestamps (epoch <= 0, i.e.
                                  resolving to 1970); hidden by default
  --atime                         Include atime
  --mtime                         Include mtime
  --ctime                         Include ctime
  --btime                         Include btime
  --no-atime                      Exclude atime
  --no-mtime                      Exclude mtime
  --no-ctime                      Exclude ctime
  --no-btime                      Exclude btime
  --help                          Show this message and exit.
```

> **Note:** timestamps are shown and filtered in **UTC** by default. Pass
> `--tz America/New_York` (or any IANA name) to render in another timezone.

## Usage examples
### Basic Processing

Basic usage reading from a file:

```
$ timeliner.py timeline.body
2023-06-12 15:39:49: macb /etc/passwd
2023-06-12 15:40:00: .a.. /home/user/document.txt
2023-06-12 15:45:23: m... /var/log/syslog
```

Show entries at/after a specific date:

```
$ timeliner.py --after "2023-06-12 15:40:00" bodyfile.txt
2023-06-12 15:40:00: .a.. /home/user/document.txt
2023-06-12 15:45:23: m... /var/log/syslog
```

Show entries within a date range:

```
$ timeliner.py --after "2023-06-12" --before "2023-06-13" bodyfile.txt
2023-06-12 15:39:49: macb /etc/passwd
2023-06-12 15:40:00: .a.. /home/user/document.txt
2023-06-13 09:15:22: m... /var/log/syslog
```

Show entries around a specific date:

```
$ timeliner.py --around "2023-06-12" bodyfile.txt
2023-06-10 10:00:00: macb /etc/crontab
2023-06-12 15:39:49: macb /etc/passwd
2023-06-14 08:30:00: m... /var/log/auth.log
```

### Display options

Add day separators (`--separate daily` is an alias; `hourly`, `weekly`,
`monthly`, and `yearly` work too):

```
$ timeliner.py --separate day bodyfile.txt
2023-06-12 15:39:49: macb /etc/passwd
2023-06-12 15:40:00: .a.. /home/user/document.txt
--------------------------------------------------
2023-06-13 09:15:22: m... /var/log/syslog
2023-06-13 10:30:45: ..c. /etc/hosts
```

Show the first field (aka: Show MD5 hashes), this is helpful when you are working on
multiple files at the same time, I put the original hostname in the MD5 field (and btw, it
doesn't need to be real MD5:

```
$ timeliner.py --show-md5 bodyfile.txt
2023-06-12 15:39:49: d41d8cd98f00b204e9800998ecf8427e macb /etc/passwd
2023-06-12 15:40:00: e1a7c76b42462133518f3927992d7d77 .a.. /home/user/document.txt
```

Highlight specific keywords:

```
$ timeliner.py --highlight-file keywords.txt timeline.body
```

Show only modification and access times:

```
$ timeliner.py --mtime --atime timeline.body
```

Or exclude specific timestamp types (here, everything but ctime):

```
$ timeliner.py --no-atime --no-mtime --no-btime timeline.body
```

Bogus timestamps (epoch <= 0, which render in 1970) are hidden by default;
use `--bogus` to include them:

```
$ timeliner.py --bogus timeline.body
```

Filter by path with regexes (`--grep` keeps matches, `--exclude` drops them;
they may be combined):

```
$ timeliner.py --grep '/var/log/' --exclude '\.gz$' timeline.body
```

Render in a specific timezone (default is UTC):

```
$ timeliner.py --tz America/New_York timeline.body
```

### JSON Lines output

`--jsonl` emits one JSON object per line, carrying both the numeric epoch and
an offset-aware ISO-8601 timestamp plus all four source timestamps — convenient
for piping into `jq` or feeding a downstream tool/agent:

```
$ timeliner.py --jsonl timeline.body | head -1
{"epoch": 1623456789, "timestamp": "2021-06-12T00:13:09+00:00", "macb": "m...", "name": "/etc/passwd", "size": 1024, "md5": "md5", "atime": 1623456789, "mtime": 1623456789, "ctime": 1623456789, "btime": 1623456789}
```

### Advanced usage

When you are working on tens of bodyfile at the same file, you can use the MD5 field which is usually empty to put the hostname. For example:

```
$ cd uac-hunt-package/
$ tree -L 2
serverA
├── bodyfile
│   └── bodyfile.txt
├── live_response
│   ├── hardware
│   ├── network
│   ├── packages
│   ├── process
│   ├── storage
│   └── system
└── uac.log
serverB
├── bodyfile
│   └── bodyfile.txt
├── live_response
│   ├── hardware
│   ├── network
│   ├── packages
│   ├── process
│   ├── storage
│   └── system
└── uac.log
...
$ ls
serverA serverB serverC
```

After tagging the MD5 field of each host's bodyfile with its hostname, you can
pass all the bodyfiles (or a glob) directly — they are merged into a single
globally-sorted timeline:

```
$ timeliner.py --show-md5 */bodyfile/bodyfile.txt
2023-11-28 14:23:15: serverA macb /etc/hosts
2023-11-28 14:25:33: serverA .a.. /var/log/auth.log
2023-11-28 15:02:44: serverB m... /home/user/.bash_history
2023-11-28 15:10:19: serverA ..c. /etc/shadow
2023-11-28 16:45:02: serverB macb /usr/bin/python3
2023-11-29 08:12:55: serverB .a.. /home/user/Documents/report.pdf
2023-11-29 09:30:17: serverC m... /var/spool/cron/crontabs/root
2023-11-29 10:15:44: serverB ..cb /etc/passwd
2023-11-29 11:42:03: serverA m.c. /var/log/syslog
2023-11-29 13:05:21: serverB .a.b /home/user/.ssh/known_hosts
```
