# timeliner.py

A memory-efficient Python script for processing and analyzing bodyfile timeline data. This tool processes bodyfile format and generates a sorted, filtered, and optionally highlighted timeline output.

*Credit: This script was 90% written by LLM.*

## Features

- Process (large) bodyfile format timelines with minimal memory usage
- Filter entries by timestamp types (atime, mtime, ctime, btime)
- Date range filtering with `--since`, `--to`, and `--around` options
- Timeline separation by day, week, month, or year
- Keyword highlighting with custom color support
- JSON Lines output format support

## Installation
### Dependencies

- colorama
- click

## Features

```
$ timeliner.py --help
Usage: timeliner.py [OPTIONS] [FILENAME]

  Process bodyfile and generate timeline.

Options:
  --separate [day|week|month|year]
                                  Add separator when crossing specified time
                                  period
  --since TEXT                    Filter entries since this date/time (YYYY-
                                  MM-DD [HH:MM:SS])
  --to TEXT                       Filter entries up to this date/time (YYYY-
                                  MM-DD [HH:MM:SS])
  --around TEXT                   Filter entries around this date/time (YYYY-
                                  MM-DD [HH:MM:SS])
  --window INTEGER                Number of days before and after for --around
                                  (default: 2)
  --show-md5                      Show MD5 hash in output
  --jsonl                         Output in JSON Lines format
  --highlight-file PATH           File containing keywords to highlight (one
                                  per line)
  --case-sensitive                Make keyword highlighting case-sensitive
  --atime                         Include atime
  --mtime                         Include mtime
  --ctime                         Include ctime
  --btime                         Include btime
  --help                          Show this message and exit.
```

## Usage examples
### Basic Processing

Basic usage reading from a file:

```
$ timeliner.py timeline.body
2023-06-12 15:39:49: macb /etc/passwd
2023-06-12 15:40:00: .a.. /home/user/document.txt
2023-06-12 15:45:23: m... /var/log/syslog
```

Show entries since a specific date:

```
$ timeliner.py --since "2023-06-12 15:40:00" bodyfile.txt
2023-06-12 15:40:00: .a.. /home/user/document.txt
2023-06-12 15:45:23: m... /var/log/syslog
```

Show entries within a date range:

```
$ timeliner.py --since "2023-06-12" --to "2023-06-13" bodyfile.txt
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

Add day separators:

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
$ grep '^' */bodyfile/bodyfile.txt |perl -pe 's!/bodyfile/bodyfile.txt:0!!' > master-bodyfile-with-fname.txt
$ timeliner.py --show-md5 master-bodyfile-with-fname.txt
$ ./timeline-processor.py --show-md5 bodyfile.txt
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
