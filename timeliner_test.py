import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from timeliner import (
    BodyfileParser,
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


def test_show_md5(runner, sample_bodyfile):
    result = runner.invoke(main, [str(sample_bodyfile), "--show-md5"])
    assert result.exit_code == 0
    assert "md5" in result.output


# Disabled test because we are checking if we are on a tty, or we disable the coloring
def disabled_test_highlight_keywords(runner, tmp_path):
    # Create input file
    input_file = tmp_path / "highlight_test.txt"
    input_file.write_text(
        "md5|/path/to/test_file1|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n"
    )

    # Create highlight file
    highlight_file = tmp_path / "keywords.txt"
    highlight_file.write_text("test_file")

    result = runner.invoke(
        main, [str(input_file), "--highlight-file", str(highlight_file)]
    )
    assert result.exit_code == 0
    assert "\033[31m" in result.output


# Disabled test because we are checking if we are on a tty, or we disable the coloring
def disabled_test_case_sensitive_highlight(runner, tmp_path):
    input_file = tmp_path / "case_test.txt"
    input_file.write_text(
        "md5|/path/to/TEST_file1|0|0|0|0|1024|1623456789|1623456790|1623456791|1623456792\n"
    )

    highlight_file = tmp_path / "keywords.txt"
    highlight_file.write_text("test_file")

    # Test case-insensitive (default)
    result1 = runner.invoke(
        main, [str(input_file), "--highlight-file", str(highlight_file)]
    )
    assert "\033[31m" in result1.output

    # Test case-sensitive
    result2 = runner.invoke(
        main,
        [str(input_file), "--highlight-file", str(highlight_file), "--case-sensitive"],
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
    assert len(result.output.strip().split("\n")) == 2


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
