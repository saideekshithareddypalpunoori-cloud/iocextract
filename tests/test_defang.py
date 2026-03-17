"""Tests for the defang / refang pair."""

from __future__ import annotations

import pytest

from iocextract.defang import defang, refang


@pytest.mark.parametrize(
    ("plain", "fanged"),
    [
        ("http://evil.com/x", "hxxp://evil[.]com/x"),
        ("https://evil.com", "hxxps://evil[.]com"),
        ("1.2.3.4", "1[.]2[.]3[.]4"),
        ("user@evil.com", "user[@]evil[.]com"),
    ],
)
def test_defang_examples(plain: str, fanged: str) -> None:
    assert defang(plain) == fanged


def test_defanged_output_has_no_live_scheme_or_dots() -> None:
    out = defang("visit http://malware.example.org/payload now")
    assert "http://" not in out
    assert "malware.example" not in out  # bare dotted host is broken up
    assert "malware[.]example[.]org" in out
    assert "hxxp://" in out


def test_refang_round_trip_is_identity_for_urls_and_ips() -> None:
    for original in ("http://evil.com/a", "https://c2.bad.net", "10.11.12.13"):
        assert refang(defang(original)) == original


@pytest.mark.parametrize(
    ("fanged", "plain"),
    [
        ("hxxp://bad[.]com", "http://bad.com"),
        ("hXXps://bad[.]com", "https://bad.com"),
        ("evil(.)com", "evil.com"),
        ("evil[dot]com", "evil.com"),
        ("user[at]evil[.]com", "user@evil.com"),
        ("host{.}tld", "host.tld"),
    ],
)
def test_refang_accepts_many_styles(fanged: str, plain: str) -> None:
    assert refang(fanged) == plain


def test_refang_leaves_clean_text_untouched() -> None:
    clean = "the cat sat at home on 2026-07-12"
    assert refang(clean) == clean
