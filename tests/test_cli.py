"""Tests for the command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iocextract.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"


def test_extract_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["extract", str(FIXTURE)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 12
    assert payload["counts"]["ipv4"] == 4
    assert len(payload["iocs"]) == 12
    assert {"type", "value", "defanged"} <= set(payload["iocs"][0])


def test_extract_type_filter(capsys: pytest.CaptureFixture[str]) -> None:
    main(["extract", str(FIXTURE), "-t", "sha256"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 1
    assert payload["iocs"][0]["type"] == "sha256"


def test_extract_table_defang(capsys: pytest.CaptureFixture[str]) -> None:
    main(["extract", str(FIXTURE), "-f", "table", "-t", "ipv4", "--defang"])
    out = capsys.readouterr().out
    assert "192[.]168[.]1[.]15" in out
    assert "192.168.1.15" not in out


def test_extract_reads_stdin(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("ping 4.4.4.4 now"))
    main(["extract"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["iocs"][0]["value"] == "4.4.4.4"


def test_defang_command(capsys: pytest.CaptureFixture[str]) -> None:
    main(["defang", "go to http://evil.com now"])
    assert capsys.readouterr().out.strip() == "go to hxxp://evil[.]com now"


def test_refang_command(capsys: pytest.CaptureFixture[str]) -> None:
    main(["refang", "hxxp://evil[.]com"])
    assert capsys.readouterr().out.strip() == "http://evil.com"


def test_missing_subcommand_errors() -> None:
    with pytest.raises(SystemExit):
        main([])
