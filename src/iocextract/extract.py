"""Core extraction engine.

The extractor refangs the input first (so both live and defanged indicators
are caught), gathers every candidate match with its character span, then
resolves overlaps by type priority. This is what lets a domain inside a URL
(``evil.com`` in ``http://evil.com/x``) collapse into the single URL indicator
instead of being double-reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import patterns
from .defang import defang, refang
from .models import IOC, ExtractionResult, IOCType

# Lower number == higher priority when two candidate spans overlap.
_PRIORITY: dict[IOCType, int] = {
    IOCType.URL: 0,
    IOCType.EMAIL: 1,
    IOCType.SHA256: 2,
    IOCType.SHA1: 3,
    IOCType.MD5: 4,
    IOCType.IPV6: 5,
    IOCType.IPV4: 6,
    IOCType.DOMAIN: 7,
}

_COMPILED: list[tuple[IOCType, re.Pattern[str]]] = [
    (IOCType.URL, patterns.URL),
    (IOCType.EMAIL, patterns.EMAIL),
    (IOCType.SHA256, patterns.SHA256),
    (IOCType.SHA1, patterns.SHA1),
    (IOCType.MD5, patterns.MD5),
    (IOCType.IPV6, patterns.IPV6),
    (IOCType.IPV4, patterns.IPV4),
    (IOCType.DOMAIN, patterns.DOMAIN),
]

# Punctuation that should never terminate a URL match.
_URL_TRAILING = ".,;:!?\"'>)]}"


@dataclass(frozen=True)
class _Candidate:
    ioc_type: IOCType
    value: str
    start: int
    end: int


def _normalise(ioc_type: IOCType, raw: str) -> tuple[str, int]:
    """Clean a raw match; return ``(value, end_trim)`` where ``end_trim`` is
    the number of characters stripped from the right (so spans stay accurate).
    """
    value = raw
    trim = 0
    if ioc_type is IOCType.URL:
        stripped = value.rstrip(_URL_TRAILING)
        trim = len(value) - len(stripped)
        value = stripped
    if ioc_type in {IOCType.DOMAIN, IOCType.EMAIL, IOCType.URL}:
        value = value.lower()
    if ioc_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
        value = value.lower()
    return value, trim


def _is_filename(candidate: str) -> bool:
    """A single-label ``name.ext`` where ``ext`` is a known file extension."""
    if candidate.count(".") != 1:
        return False
    _, ext = candidate.rsplit(".", 1)
    return ext.lower() in patterns.FILE_EXTENSIONS


def _gather(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for ioc_type, pattern in _COMPILED:
        for match in pattern.finditer(text):
            raw = match.group(0)
            value, trim = _normalise(ioc_type, raw)
            if not value:
                continue
            if ioc_type is IOCType.DOMAIN and _is_filename(value):
                continue
            candidates.append(
                _Candidate(ioc_type, value, match.start(), match.end() - trim)
            )
    return candidates


def extract(text: str) -> ExtractionResult:
    """Extract, dedupe and classify every IOC found in ``text``."""
    normalised = refang(text)
    candidates = _gather(normalised)

    # Resolve overlaps: sort by priority, then by span; accept greedily.
    candidates.sort(key=lambda c: (_PRIORITY[c.ioc_type], c.start, -(c.end)))
    accepted: list[_Candidate] = []
    occupied: list[tuple[int, int]] = []
    for cand in candidates:
        if any(cand.start < end and start < cand.end for start, end in occupied):
            continue
        accepted.append(cand)
        occupied.append((cand.start, cand.end))

    # Dedupe on (type, value); keep first occurrence order for stable output.
    seen: set[tuple[IOCType, str]] = set()
    unique: list[_Candidate] = []
    for cand in sorted(accepted, key=lambda c: c.start):
        key = (cand.ioc_type, cand.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(cand)

    # Final ordering: group by priority, then alphabetically by value.
    unique.sort(key=lambda c: (_PRIORITY[c.ioc_type], c.value))
    iocs = [
        IOC(type=c.ioc_type, value=c.value, defanged=defang(c.value))
        for c in unique
    ]
    return ExtractionResult(iocs=iocs)
