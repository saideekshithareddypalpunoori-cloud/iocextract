"""Tests for the extraction engine, including false-positive guards."""

from __future__ import annotations

from pathlib import Path

import pytest

from iocextract import extract
from iocextract.models import IOCType

FIXTURE = Path(__file__).parent / "fixtures" / "sample.log"


@pytest.fixture(scope="module")
def sample_result():  # type: ignore[no-untyped-def]
    return extract(FIXTURE.read_text(encoding="utf-8"))


def test_sample_log_total_and_counts(sample_result) -> None:  # type: ignore[no-untyped-def]
    assert sample_result.total == 12
    assert sample_result.counts == {
        "domain": 1,
        "email": 1,
        "ipv4": 4,
        "ipv6": 1,
        "md5": 1,
        "sha1": 1,
        "sha256": 1,
        "url": 2,
    }


def test_sample_log_ipv4_values(sample_result) -> None:  # type: ignore[no-untyped-def]
    assert sample_result.values(IOCType.IPV4) == [
        "10.0.0.7",
        "192.168.1.15",
        "203.0.113.45",
        "93.184.216.34",
    ]


def test_sample_log_hashes(sample_result) -> None:  # type: ignore[no-untyped-def]
    assert sample_result.values(IOCType.MD5) == [
        "d41d8cd98f00b204e9800998ecf8427e"
    ]
    assert sample_result.values(IOCType.SHA1) == [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ]
    assert sample_result.values(IOCType.SHA256) == [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]


def test_sample_log_url_email_domain_ipv6(sample_result) -> None:  # type: ignore[no-untyped-def]
    assert sample_result.values(IOCType.URL) == [
        "http://malware-c2.evil-domain.com/beacon?id=7",
        "https://evil.example.org/upload?token=42",
    ]
    assert sample_result.values(IOCType.EMAIL) == ["attacker@bad-actor.net"]
    assert sample_result.values(IOCType.DOMAIN) == ["cdn.legit-service.com"]
    assert sample_result.values(IOCType.IPV6) == ["2001:db8::1"]


# --- False-positive guards ------------------------------------------------


def test_three_part_version_is_not_an_ip() -> None:
    result = extract("running agent version 1.2.3 in prod")
    assert result.total == 0


def test_five_octet_sequence_is_not_an_ip() -> None:
    result = extract("build tag 10.20.30.40.50 was rejected")
    assert result.values(IOCType.IPV4) == []


def test_version_adjacent_to_letters_is_not_an_ip() -> None:
    assert extract("release v1.2.3.4rc1 shipped").total == 0


def test_octet_over_255_is_rejected() -> None:
    assert extract("nonsense 999.1.1.1 here").values(IOCType.IPV4) == []


def test_filename_with_known_extension_is_not_a_domain() -> None:
    result = extract("the dropper was invoice.exe on disk")
    assert result.values(IOCType.DOMAIN) == []


def test_timestamp_is_not_ipv6() -> None:
    assert extract("event at 08:14:22 today").values(IOCType.IPV6) == []


# --- Structural behaviour -------------------------------------------------


def test_domain_inside_url_is_not_double_reported() -> None:
    result = extract("beacon to http://evil.com/c2")
    assert result.values(IOCType.URL) == ["http://evil.com/c2"]
    assert result.values(IOCType.DOMAIN) == []


def test_domain_inside_email_is_not_double_reported() -> None:
    result = extract("from mallory@evil.com yesterday")
    assert result.values(IOCType.EMAIL) == ["mallory@evil.com"]
    assert result.values(IOCType.DOMAIN) == []


def test_dedupe_across_repeated_indicators() -> None:
    result = extract("8.8.8.8 and again 8.8.8.8 and 8.8.8.8")
    assert result.values(IOCType.IPV4) == ["8.8.8.8"]


def test_url_trailing_punctuation_is_stripped() -> None:
    result = extract("see (http://evil.com/x), thanks.")
    assert result.values(IOCType.URL) == ["http://evil.com/x"]


def test_defanged_indicators_are_refanged_before_extraction() -> None:
    result = extract("c2 at hxxp://bad-guy[.]net/panel talks to 1[.]2[.]3[.]4")
    assert result.values(IOCType.URL) == ["http://bad-guy.net/panel"]
    assert result.values(IOCType.IPV4) == ["1.2.3.4"]


def test_hash_length_classification() -> None:
    md5 = "a" * 32
    sha1 = "b" * 40
    sha256 = "c" * 64
    result = extract(f"{md5} {sha1} {sha256}")
    assert result.values(IOCType.MD5) == [md5]
    assert result.values(IOCType.SHA1) == [sha1]
    assert result.values(IOCType.SHA256) == [sha256]


def test_every_ioc_carries_a_defanged_form() -> None:
    result = extract("http://evil.com from 9.9.9.9")
    for ioc in result.iocs:
        assert "[.]" in ioc.defanged
        assert "http://" not in ioc.defanged


def test_empty_input_yields_no_iocs() -> None:
    result = extract("nothing to see here, just prose about the weather")
    assert result.total == 0
    assert result.to_json() is not None
