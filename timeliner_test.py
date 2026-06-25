import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

import timeliner
from timeliner import (
    BodyfileParser,
    ChunkedTimelineProcessor,
    KeywordHighlighter,
    TimelineEntry,
    TimelineProcessor,
    format_datetime,
    main,
    parse_datetime,
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_bodyfile(tmp_path):
    content = "\n".join(
        [
            "md5|/path/to/file1|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792",
            "md5|/path/to/file2|0|0|0|0|1024|1623370389|1623370390|1623370391|1623370392",
            "md5|/path/to/file5|0|0|0|0|1024|1623629589|1623629590|1623629591|1623629592",
        ]
    )
    input_file = tmp_path / "sample.txt"
    input_file.write_text(content)
    return input_file


def test_basic_timeline(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile)])
    assert result.exit_code == 0
    assert "/path/to/file1" in result.output
    assert "/path/to/file2" in result.output


def test_timezone_default_utc(runner, tmp_path):
    # 1623456789 == 2021-06-12 00:13:09 UTC. Output must be UTC regardless of
    # the machine's local timezone.
    input_file = tmp_path / "tz.txt"
    input_file.write_text(
        "md5|/path/to/file|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789\n"
    )
    result = runner.invoke(main, [str(input_file)])
    assert result.exit_code == 0
    assert "2021-06-12 00:13:09" in result.output


def test_timezone_override(runner, tmp_path):
    # Same epoch rendered in America/New_York (UTC-4 in June) -> 20:13:09 prior day.
    input_file = tmp_path / "tz.txt"
    input_file.write_text(
        "md5|/path/to/file|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789\n"
    )
    result = runner.invoke(main, [str(input_file), "--tz", "America/New_York"])
    assert result.exit_code == 0
    assert "2021-06-11 20:13:09" in result.output


def test_timezone_invalid(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--tz", "Not/AZone"])
    assert result.exit_code != 0
    assert "Error" in result.output


def test_timezone_affects_filter_boundary(runner, tmp_path):
    # 1623456789 == 2021-06-12 02:53:09 UTC, but 2021-06-11 22:53:09 in New York.
    # A --since of 2021-06-12 (start of day) should INCLUDE it under UTC but
    # EXCLUDE it under New York (where the event is on the 11th).
    input_file = tmp_path / "tz.txt"
    input_file.write_text(
        "md5|/path/to/file|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789\n"
    )
    utc = runner.invoke(main, [str(input_file), "--since", "2021-06-12"])
    assert "/path/to/file" in utc.output

    ny = runner.invoke(
        main, [str(input_file), "--since", "2021-06-12", "--tz", "America/New_York"]
    )
    assert "/path/to/file" not in ny.output


def test_since_filter(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--since", "2021-06-12"])
    assert result.exit_code == 0
    assert "/path/to/file1" in result.output
    assert "/path/to/file2" not in result.output


def test_to_filter(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--to", "2021-06-12"])
    assert result.exit_code == 0
    assert "/path/to/file2" in result.output
    assert "/path/to/file5" not in result.output


def test_around_filter(runner, tmp_path):
    content = "\n".join(
        [
            "md5|/path/to/file1|0|0|0|0|1024|1623283989|1623283990|1623283991|1623283992",  # 2021-06-10
            "md5|/path/to/file2|0|0|0|0|1024|1623370389|1623370390|1623370391|1623370392",  # 2021-06-11
            "md5|/path/to/file3|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792",  # 2021-06-12
            "md5|/path/to/file4|0|0|0|0|1024|1623543189|1623543190|1623543191|1623543192",  # 2021-06-13
            "md5|/path/to/file5|0|0|0|0|1024|1623629589|1623629590|1623629591|1623629592",  # 2021-06-14
        ]
    )
    input_file = tmp_path / "around_test.txt"
    input_file.write_text(content)

    result = runner.invoke(
        main, [str(input_file), "--around", "2021-06-12", "--window", "1"]
    )
    assert result.exit_code == 0
    assert "/path/to/file1" not in result.output
    assert "/path/to/file2" in result.output
    assert "/path/to/file3" in result.output
    assert "/path/to/file4" in result.output
    assert "/path/to/file5" not in result.output


def test_time_range_around_full_days(runner, tmp_path):
    # Create test files with timestamps across multiple days
    content = "\n".join(
        [
            # 2024-02-01 12:00:00
            "md5|/path/to/file1|0|0|0|0|1024|1706789200|1706789200|1706789200|1706789200",
            # 2024-02-02 00:00:01
            "md5|/path/to/file2|0|0|0|0|1024|1706832001|1706832001|1706832001|1706832001",
            # 2024-02-02 23:59:59
            "md5|/path/to/file3|0|0|0|0|1024|1706918399|1706918399|1706918399|1706918399",
            # 2024-02-03 12:00:00
            "md5|/path/to/file4|0|0|0|0|1024|1706961600|1706961600|1706961600|1706961600",
            # 2024-02-04 00:00:01
            "md5|/path/to/file5|0|0|0|0|1024|1707004801|1707004801|1707004801|1707004801",
            # 2024-02-04 23:59:59
            "md5|/path/to/file6|0|0|0|0|1024|1707091199|1707091199|1707091199|1707091199",
            # 2024-02-05 12:00:00
            "md5|/path/to/file7|0|0|0|0|1024|1707134400|1707134400|1707134400|1707134400",
        ]
    )
    input_file = tmp_path / "full_days_test.txt"
    input_file.write_text(content)

    result = runner.invoke(
        main, [str(input_file), "--around", "2024-02-03", "--window", "1"]
    )

    assert result.exit_code == 0
    # Should NOT include 2024-02-01
    assert "/path/to/file1" not in result.output

    # Should include ALL of 2024-02-02
    assert "/path/to/file2" in result.output
    assert "/path/to/file3" in result.output

    # Should include 2024-02-03
    assert "/path/to/file4" in result.output

    # Should include ALL of 2024-02-04
    assert "/path/to/file5" in result.output
    assert "/path/to/file6" in result.output

    # Should NOT include 2024-02-05
    assert "/path/to/file7" not in result.output


def test_time_range_since_until_full_days(runner, tmp_path):
    content = "\n".join(
        [
            # 2024-02-03 00:00:01
            "md5|/path/to/file1|0|0|0|0|1024|1706918401|1706918401|1706918401|1706918401",
            # 2024-02-03 23:59:59
            "md5|/path/to/file2|0|0|0|0|1024|1707004799|1707004799|1707004799|1707004799",
            # 2024-02-04 12:00:00
            "md5|/path/to/file3|0|0|0|0|1024|1707048000|1707048000|1707048000|1707048000",
        ]
    )
    input_file = tmp_path / "since_until_test.txt"
    input_file.write_text(content)

    result = runner.invoke(
        main, [str(input_file), "--since", "2024-02-03", "--to", "2024-02-03"]
    )

    assert result.exit_code == 0

    # Should include ALL of 2024-02-03
    assert "/path/to/file1" in result.output
    assert "/path/to/file2" in result.output

    # Should NOT include 2024-02-04
    assert "/path/to/file3" not in result.output


def test_since_with_time_component(runner, tmp_path):
    # --since with HH:MM:SS must use the exact time, not the start of day.
    content = "\n".join(
        [
            # 2024-02-03 11:59:59 UTC
            "md5|/path/before|0|0|0|0|1024|1706961599|1706961599|1706961599|1706961599",
            # 2024-02-03 12:00:01 UTC
            "md5|/path/after|0|0|0|0|1024|1706961601|1706961601|1706961601|1706961601",
        ]
    )
    input_file = tmp_path / "since_time.txt"
    input_file.write_text(content)

    result = runner.invoke(main, [str(input_file), "--since", "2024-02-03 12:00:00"])
    assert result.exit_code == 0
    assert "/path/before" not in result.output
    assert "/path/after" in result.output


def test_to_with_time_component(runner, tmp_path):
    # --to with HH:MM:SS must use the exact time, not the end of day.
    content = "\n".join(
        [
            # 2024-02-03 11:59:59 UTC
            "md5|/path/before|0|0|0|0|1024|1706961599|1706961599|1706961599|1706961599",
            # 2024-02-03 13:00:00 UTC
            "md5|/path/after|0|0|0|0|1024|1706965200|1706965200|1706965200|1706965200",
        ]
    )
    input_file = tmp_path / "to_time.txt"
    input_file.write_text(content)

    result = runner.invoke(main, [str(input_file), "--to", "2024-02-03 12:00:00"])
    assert result.exit_code == 0
    assert "/path/before" in result.output
    assert "/path/after" not in result.output


def test_timestamp_ordering(runner, tmp_path):
    content = "\n".join(
        [
            "md5|/path/to/file2|0|0|0|0|1024|1623456790|1623456790|1623456790|1623456790",
            "md5|/path/to/file1|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789",
            "md5|/path/to/file3|0|0|0|0|1024|1623456791|1623456791|1623456791|1623456791",
        ]
    )
    input_file = tmp_path / "ordering_test.txt"
    input_file.write_text(content)

    result = runner.invoke(main, [str(input_file)])
    print(result.output)
    lines = result.output.splitlines()
    assert "file1" in lines[0]
    assert "file2" in lines[1]
    assert "file3" in lines[2]


def test_atime_filter(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--atime"])
    assert result.exit_code == 0
    assert "a.." in result.output
    assert "m..." not in result.output


def test_jsonl_output(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--jsonl"])
    assert result.exit_code == 0
    print(result.output)
    lines = result.output.splitlines()
    for line in lines:
        parsed = json.loads(line)
        assert "timestamp" in parsed
        assert "md5" in parsed
        assert "macb" in parsed
        assert "name" in parsed
        assert "size" in parsed


def test_jsonl_rich_fields(runner, tmp_path):
    input_file = tmp_path / "rich.txt"
    input_file.write_text(
        "md5|/path/to/file|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n"
    )
    result = runner.invoke(main, [str(input_file), "--jsonl"])
    assert result.exit_code == 0
    obj = json.loads(result.output.splitlines()[0])

    # Numeric epoch is present and an int.
    assert isinstance(obj["epoch"], int)
    # All four source timestamps are carried through.
    for field in ("atime", "mtime", "ctime", "btime"):
        assert field in obj
    assert obj["atime"] == 1623456789
    assert obj["btime"] == 1623456792
    # The human timestamp is offset-aware ISO-8601 (parseable, has a tzinfo).
    parsed = datetime.fromisoformat(obj["timestamp"])
    assert parsed.tzinfo is not None
    assert obj["name"] == "/path/to/file"


def test_show_md5(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--show-md5"])
    assert result.exit_code == 0
    assert "md5" in result.output


@pytest.fixture
def grep_bodyfile(tmp_path):
    content = "\n".join(
        [
            "md5|/var/log/auth.log|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789",
            "md5|/etc/passwd|0|0|0|0|1024|1623456790|1623456790|1623456790|1623456790",
            "md5|/home/user/notes.txt|0|0|0|0|1024|1623456791|1623456791|1623456791|1623456791",
        ]
    )
    input_file = tmp_path / "grep.txt"
    input_file.write_text(content)
    return input_file


def test_grep_include(runner, grep_bodyfile):
    result = runner.invoke(main, [str(grep_bodyfile), "--grep", r"\.log$"])
    assert result.exit_code == 0
    assert "/var/log/auth.log" in result.output
    assert "/etc/passwd" not in result.output
    assert "/home/user/notes.txt" not in result.output


def test_exclude(runner, grep_bodyfile):
    result = runner.invoke(main, [str(grep_bodyfile), "--exclude", "/etc/"])
    assert result.exit_code == 0
    assert "/etc/passwd" not in result.output
    assert "/var/log/auth.log" in result.output
    assert "/home/user/notes.txt" in result.output


def test_grep_and_exclude_combined(runner, grep_bodyfile):
    # Include anything under /var or /home, but exclude .txt files.
    result = runner.invoke(
        main, [str(grep_bodyfile), "--grep", "/(var|home)/", "--exclude", r"\.txt$"]
    )
    assert result.exit_code == 0
    assert "/var/log/auth.log" in result.output
    assert "/home/user/notes.txt" not in result.output
    assert "/etc/passwd" not in result.output


def test_grep_invalid_regex(runner, grep_bodyfile):
    result = runner.invoke(main, [str(grep_bodyfile), "--grep", "["])
    assert result.exit_code != 0
    assert "Error" in result.output


# Regression test for the highlighter being dead in the chunked code path:
# highlighting is now applied at the parent emit step, so it works regardless
# of tty (the ANSI codes are literal strings independent of colorama.init()).
def test_highlight_keywords(runner, tmp_path):
    # Create input file
    input_file = tmp_path / "highlight_test.txt"
    input_file.write_text(
        "md5|/path/to/test_file1|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n"
    )

    # Create highlight file
    highlight_file = tmp_path / "keywords.txt"
    highlight_file.write_text("test_file")

    # color=True so click.echo does not strip ANSI (it strips on non-tty output).
    result = runner.invoke(
        main, [str(input_file), "--highlight-file", str(highlight_file)], color=True
    )
    assert result.exit_code == 0
    assert "\033[31m" in result.output


def test_case_sensitive_highlight(runner, tmp_path):
    input_file = tmp_path / "case_test.txt"
    input_file.write_text(
        "md5|/path/to/TEST_file1|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n"
    )

    highlight_file = tmp_path / "keywords.txt"
    highlight_file.write_text("test_file")

    # Test case-insensitive (default)
    result1 = runner.invoke(
        main, [str(input_file), "--highlight-file", str(highlight_file)], color=True
    )
    assert "\033[31m" in result1.output

    # Test case-sensitive
    result2 = runner.invoke(
        main,
        [str(input_file), "--highlight-file", str(highlight_file), "--case-sensitive"],
        color=True,
    )
    assert "\033[31m" not in result2.output


def test_separate_by_day(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--separate", "day"])
    assert result.exit_code == 0
    assert "-" * 50 in result.output


def test_invalid_date_format(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--since", "invalid-date"])
    assert result.exit_code != 0
    assert "Error" in result.output


def test_nonexistent_file(runner):
    result = runner.invoke(main, ["nonexistent.txt"])
    assert result.exit_code != 0
    assert "Error" in result.output


def test_help(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "Options:" in result.output


def test_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "2.0" in result.output


def test_output_file(runner, sample_bodyfile, tmp_path):
    out = tmp_path / "out.txt"
    result = runner.invoke(main, [str(sample_bodyfile), "-o", str(out)])
    assert result.exit_code == 0
    assert result.output.strip() == ""  # nothing on stdout
    written = out.read_text()
    assert "/path/to/file1" in written
    assert "/path/to/file2" in written


def test_stats_to_stderr(runner, sample_bodyfile):
    result = runner.invoke(
        main, [str(sample_bodyfile), "--stats"], catch_exceptions=False
    )
    assert result.exit_code == 0
    # Each of the 3 files has 4 distinct timestamps => 12 emitted rows.
    assert "entries: 12" in result.output
    assert "span:" in result.output


def test_multiple_inputs(runner, tmp_path):
    file_a = tmp_path / "a.body"
    file_a.write_text(
        "md5|/host_a/file|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789\n"
    )
    file_b = tmp_path / "b.body"
    file_b.write_text(
        "md5|/host_b/file|0|0|0|0|1024|1623456000|1623456000|1623456000|1623456000\n"
    )
    result = runner.invoke(main, [str(file_a), str(file_b)])
    assert result.exit_code == 0
    lines = result.output.strip().split("\n")
    # Globally sorted across both inputs: host_b (earlier ts) comes first.
    assert "/host_b/file" in lines[0]
    assert "/host_a/file" in lines[1]


def test_glob_input(runner, tmp_path):
    (tmp_path / "s1.body").write_text(
        "md5|/host1/file|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789\n"
    )
    (tmp_path / "s2.body").write_text(
        "md5|/host2/file|0|0|0|0|1024|1623456790|1623456790|1623456790|1623456790\n"
    )
    result = runner.invoke(main, [str(tmp_path / "*.body")])
    assert result.exit_code == 0
    assert "/host1/file" in result.output
    assert "/host2/file" in result.output


def test_multiple_time_filters(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--atime", "--mtime"])
    assert result.exit_code == 0
    assert "a" in result.output
    assert "m" in result.output


def test_no_duplicate(runner):
    result = runner.invoke(
        main,
        input="XXX|/path/to/file1|66069|-rwxr-xr-x|0|0|56824|1708319813|1708319813|1709111492|0",
    )
    print(result.output)
    assert result.exit_code == 0
    assert "/path/to/file1" in result.output
    assert len(result.output.strip().split("\n")) == 3


def test_negative_ts(runner):
    result = runner.invoke(
        main,
        input=r"0|\\Users\John\Desktop\My Document.docx|291779||0|0|143711|-1|-1|-1|1427897741",
    )
    print(result.output)
    assert result.exit_code == 0
    assert "My Document.docx" in result.output
    assert len(result.output.strip().split("\n")) == 1


def test_stdin_input(runner):
    result = runner.invoke(
        main,
        input="md5|/path/to/file1|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n",
    )
    assert result.exit_code == 0
    assert "/path/to/file1" in result.output


def test_empty_input(runner):
    result = runner.invoke(main, input="")
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_invalid_bodyfile_format(runner):
    result = runner.invoke(main, input="invalid|format|line\n")
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_utf8_encoded_bodyfile(runner, tmp_path):
    input_file = tmp_path / "utf8_input.txt"
    input_file.write_text(
        "md5|/path/to/file_üñîçødé|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n",
        encoding="utf-8",
    )

    result = runner.invoke(main, [str(input_file)])
    assert result.exit_code == 0
    assert "file_üñîçødé" in result.output


def test_latin1_encoded_bodyfile(runner, tmp_path):
    input_file = tmp_path / "latin1_input.txt"
    input_file.write_text(
        "md5|/path/to/file_áéíóú|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n",
        encoding="latin-1",
    )

    result = runner.invoke(main, [str(input_file)])
    assert result.exit_code == 0
    assert "file_" in result.output


def test_ascii_encoded_bodyfile(runner, tmp_path):
    input_file = tmp_path / "ascii_input.txt"
    input_file.write_text(
        "md5|/path/to/file_ascii|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n",
        encoding="ascii",
    )

    result = runner.invoke(main, [str(input_file)])
    assert result.exit_code == 0
    assert "file_ascii" in result.output


def test_invalid_bytes_in_bodyfile(runner, tmp_path):
    input_file = tmp_path / "invalid_input.txt"
    with input_file.open("wb") as f:
        f.write(
            b"md5|/path/to/file_\xff\xfe|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n"
        )

    result = runner.invoke(main, [str(input_file)])
    assert result.exit_code == 0
    assert "file_" in result.output  # The invalid bytes should be replaced or ignored


def test_mixed_encoding_bodyfile(runner, tmp_path):
    input_file = tmp_path / "mixed_input.txt"
    with input_file.open("wb") as f:
        f.write(
            b"md5|/path/to/file_utf8_\xc3\xbc|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n"
        )
        f.write(
            b"md5|/path/to/file_latin1_\xe9|0|0|0|0|1024|1623456793|1623456794|1623456795|1623456796\n"
        )

    result = runner.invoke(main, [str(input_file)])
    print(result.output.encode("utf-8"))
    assert result.exit_code == 0
    assert "file_utf8_" in result.output
    assert "file_latin1_" in result.output

def test_bodyfile_with_leading_escaped_pipes():
    input_line = r"0|file\|with\|pipes\\|0|0|0|0|9529053861562548261|1331893980|1331893980|1331894001|1264526371"
    entry = BodyfileParser.parse_line(input_line)
    print(entry)
    assert entry is not None
    assert entry.name == 'file|with|pipes\\'

def test_bodyfile_with_pipes():
    input_line = r"0|file\|with\|pipes|0|0|0|0|9529053861562548261|1331893980|1331893980|1331894001|1264526371"
    entry = BodyfileParser.parse_line(input_line)
    print(entry)
    assert entry is not None
    assert entry.name == r"file|with|pipes"

def test_bodyfile_unquoted_field():
    input_line = r'0|Cissesrv        ImagePath="C:\Program Files\HP\Cissesrv\cissesrv.exe"|0||0|0|0|0|1535229693|0|0'
    entry = BodyfileParser.parse_line(input_line)
    print(entry)
    print(input_line)
    assert entry is not None
    assert entry.name == r'Cissesrv        ImagePath="C:\Program Files\HP\Cissesrv\cissesrv.exe"'

def test_buggy_size():
    input_line = r'0|\\\WINDOWS\Debug\UserMode\ChkAcc.bak (indx)|0|0|0|0|9529053861562548261|1331893980|1331893980|1331894001|1264526371'
    entry = BodyfileParser.parse_line(input_line)
    assert entry is not None
    assert r'\WINDOWS\Debug\UserMode\ChkAcc.bak (indx)' in entry.name

def test_windows_paths():
    test_cases = [
        # Simple Windows path
         ('0|C:\\Windows\\System32\\cmd.exe|0|0|0|0|0|1535229693|0|0|0',
          'C:\\Windows\\System32\\cmd.exe'),

         # Path with spaces
         ('0|C:\\Program Files\\Common Files\\file.txt|0|0|0|0|0|1535229693|0|0|0',
          'C:\\Program Files\\Common Files\\file.txt'),

         # Path with quoted spaces and escaped pipes
         ('0|"C:\\Program Files\\My App\\file with\\|pipe.txt"|0|0|0|0|0|1535229693|0|0|0',
          '"C:\\Program Files\\My App\\file with\\|pipe.txt"'),

         # Path with multiple escaped pipes
         ('0|file\\|with\\|multiple\\|pipes|0|0|0|0|0|1535229693|0|0|0',
          'file|with|multiple|pipes'),

         # Quoted path with escaped quotes
         ('0|"C:\\Path with \\"quotes\\"\\file.txt"|0|0|0|0|0|1535229693|0|0|0',
          '"C:\\Path with \\"quotes\\"\\file.txt"'),
    ]

    for input_line, expected_name in test_cases:
        entry = BodyfileParser.parse_line(input_line)
        assert entry is not None
        assert entry.name == expected_name


def test_fast_path_no_escapes():
    # A plain line (no backslash/quote) goes through the fast split path.
    input_line = "md5|/path/to/file|0|0|0|0|1024|1|2|3|4"
    entry = BodyfileParser.parse_line(input_line)
    assert entry is not None
    assert entry.name == "/path/to/file"
    assert entry.size == 1024
    assert (entry.atime, entry.mtime, entry.ctime, entry.btime) == (1, 2, 3, 4)


def test_fast_and_escaped_paths_agree():
    # A line with neither escapes nor quotes must parse identically whether it
    # goes through the fast path or is forced through the escaped path.
    input_line = "md5|/path/to/file|0|0|0|0|1024|1|2|3|4"
    fast = BodyfileParser.parse_line(input_line)
    slow = BodyfileParser._parse_line_escaped(input_line)
    assert fast == slow


def test_trailing_empty_field_preserved():
    # A line ending in '|' (empty btime) must still yield 11 fields. The fast
    # path keeps trailing empties; the escaped path must too. btime is empty,
    # so it fails int() and the whole line is rejected (rather than silently
    # losing the field and mis-parsing a 10-field line).
    assert BodyfileParser.parse_line("md5|/path/to/file|0|0|0|0|1024|1|2|3|") is None
    # An escaped variant ending in an empty field behaves the same way.
    assert BodyfileParser._parse_line_escaped(r"md5|/p\|ath|0|0|0|0|1024|1|2|3|") is None


def test_wrong_field_count_rejected():
    assert BodyfileParser.parse_line("too|few|fields") is None
    assert BodyfileParser.parse_line("md5|/p|0|0|0|0|1024|1|2|3|4|extra") is None


def test_cross_chunk_dedup(runner, tmp_path, monkeypatch):
    # Force the chunked path with a tiny chunk size so the same (timestamp,
    # name) lands in two different chunks. The merge must collapse the
    # duplicate to one line.
    monkeypatch.setattr(timeliner, "SMALL_INPUT_THRESHOLD", 0)
    monkeypatch.setattr(ChunkedTimelineProcessor, "CHUNK_SIZE", 2)
    dup = "md5|/path/to/dup|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789"
    content = "\n".join(
        [
            dup,  # chunk 1
            "md5|/path/to/x|0|0|0|0|1024|1623456000|1623456000|1623456000|1623456000",
            dup,  # chunk 2 - same entry again
            "md5|/path/to/y|0|0|0|0|1024|1623456111|1623456111|1623456111|1623456111",
            dup,  # chunk 3 - and again
        ]
    )
    input_file = tmp_path / "dup.txt"
    input_file.write_text(content)

    result = runner.invoke(main, [str(input_file)])
    assert result.exit_code == 0
    lines = result.output.strip().split("\n")
    assert sum("/path/to/dup" in line for line in lines) == 1


def test_chunked_path_sorted_deterministic(runner, tmp_path, monkeypatch):
    # With a tiny chunk size, output must still be globally sorted regardless of
    # which worker finishes first.
    monkeypatch.setattr(timeliner, "SMALL_INPUT_THRESHOLD", 0)
    monkeypatch.setattr(ChunkedTimelineProcessor, "CHUNK_SIZE", 1)
    content = "\n".join(
        [
            "md5|/path/c|0|0|0|0|1024|1623456791|1623456791|1623456791|1623456791",
            "md5|/path/a|0|0|0|0|1024|1623456789|1623456789|1623456789|1623456789",
            "md5|/path/b|0|0|0|0|1024|1623456790|1623456790|1623456790|1623456790",
        ]
    )
    input_file = tmp_path / "order.txt"
    input_file.write_text(content)

    result = runner.invoke(main, [str(input_file)])
    assert result.exit_code == 0
    lines = result.output.strip().split("\n")
    assert "/path/a" in lines[0]
    assert "/path/b" in lines[1]
    assert "/path/c" in lines[2]


# --- Time-window pre-filter (--around/--since/--to fast path) ---------------

from timeliner import (  # noqa: E402
    _make_window_bounds,
    _provably_outside_window,
)


def _fields(atime, mtime, ctime, btime, name="/x"):
    """Build the 11 split fields of a bodyfile line with given time strings."""
    return ["0", name, "0", "0", "0", "0", "100", atime, mtime, ctime, btime]


def test_make_window_bounds_none_cases():
    # No window, and negative boundaries, must disable the cheap path.
    assert _make_window_bounds(None, None) is None
    assert _make_window_bounds(-5, -1) is None
    # A single negative boundary disables only that side.
    b = _make_window_bounds(-5, 1704240000)
    assert b is not None and not b.have_since and b.have_until
    b = _make_window_bounds(1703894400, None)
    assert b is not None and b.have_since and not b.have_until


def test_prefilter_all_fields_outside_is_skippable():
    b = _make_window_bounds(1703894400, 1704240000)  # ~2024-01-01 window
    # Every field well below `since` -> provably outside -> safe to skip.
    assert _provably_outside_window(_fields("100", "100", "100", "100"), b) is True
    # Every field well above `until` -> also skippable.
    hi = "9999999999"
    assert _provably_outside_window(_fields(hi, hi, hi, hi), b) is True


def test_prefilter_one_field_in_window_is_kept():
    b = _make_window_bounds(1703894400, 1704240000)
    # mtime inside the window -> must NOT be skipped.
    assert _provably_outside_window(_fields("100", "1703900000", "100", "100"), b) is False


def test_prefilter_ambiguous_fields_are_kept():
    b = _make_window_bounds(1703894400, 1704240000)
    # Zero-padded, non-digit, negative sentinel, and Unicode-digit fields are
    # not "clean" -> never skipped (the exact int filter decides downstream).
    assert _provably_outside_window(_fields("01703900000", "100", "100", "100"), b) is False
    assert _provably_outside_window(_fields("abc", "100", "100", "100"), b) is False
    assert _provably_outside_window(_fields("-1", "100", "100", "100"), b) is False
    assert _provably_outside_window(_fields("²", "100", "100", "100"), b) is False
    # Wrong field count -> not skippable (let _build_entry reject it).
    assert _provably_outside_window(["0", "/x", "0"], b) is False


def test_prefilter_zero_padded_in_range_is_emitted(runner, tmp_path):
    # A zero-padded epoch field that is actually IN range must still appear:
    # the pre-filter must not skip it just because it cannot prove it out.
    # 1704067200 = 2024-01-01 00:00:00 UTC; padded to 11 chars with a leading 0.
    content = "md5|/padded/file|0|0|0|0|1024|01704067200|01704067200|01704067200|01704067200"
    input_file = tmp_path / "padded.txt"
    input_file.write_text(content)
    result = runner.invoke(main, [str(input_file), "--around", "2024-01-01"])
    assert result.exit_code == 0
    assert "/padded/file" in result.output


def test_prefilter_negative_sentinel_with_window(runner, tmp_path):
    # A line mixing -1 sentinels with one in-window timestamp: the valid time
    # is emitted, the -1 fields are dropped -- same as without the pre-filter.
    content = "md5|/mixed/file|0|0|0|0|1024|-1|1704067200|-1|-1"
    input_file = tmp_path / "mixed.txt"
    input_file.write_text(content)
    result = runner.invoke(main, [str(input_file), "--around", "2024-01-01"])
    assert result.exit_code == 0
    assert "/mixed/file" in result.output
    assert len(result.output.strip().split("\n")) == 1


def test_prefilter_open_ended_since_and_to(runner, tmp_path):
    content = "\n".join(
        [
            "md5|/past/file|0|0|0|0|1024|1577836800|1577836800|1577836800|1577836800",  # 2020-01-01
            "md5|/future/file|0|0|0|0|1024|1735689600|1735689600|1735689600|1735689600",  # 2025-01-01
        ]
    )
    input_file = tmp_path / "openended.txt"
    input_file.write_text(content)

    # --since only: keeps the future row, drops the past row.
    r = runner.invoke(main, [str(input_file), "--since", "2024-01-01"])
    assert r.exit_code == 0
    assert "/future/file" in r.output and "/past/file" not in r.output

    # --to only: keeps the past row, drops the future row.
    r = runner.invoke(main, [str(input_file), "--to", "2024-01-01"])
    assert r.exit_code == 0
    assert "/past/file" in r.output and "/future/file" not in r.output
