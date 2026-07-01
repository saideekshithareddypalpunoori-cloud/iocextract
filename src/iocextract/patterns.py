"""Compiled regular expressions for IOC extraction.

Every pattern is anchored with look-around guards so that indicators embedded
in larger tokens (version strings, file names, longer hex blobs, timestamps)
are *not* misclassified. See ``extract.py`` for how overlapping candidate
matches are resolved by priority.
"""

from __future__ import annotations

import re

# --- IPv4 -----------------------------------------------------------------
# A single 0-255 octet.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# Four dotted octets. The ``[\w.]`` look-arounds reject:
#   * version strings adjacent to letters:  v1.2.3.4  / 1.2.3.4rc1
#   * dotted sequences with too many parts: 10.20.30.40.50  (5 groups)
# A bare three-part version like ``1.2.3`` never matches because IPv4
# structurally requires four octets.
IPV4 = re.compile(rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\w.])")

# --- IPv6 -----------------------------------------------------------------
# Full and compressed forms (no zone id / IPv4-mapped tail, kept intentionally
# tight to avoid matching ``HH:MM:SS`` timestamps, which never contain "::"
# and never reach eight colon-separated groups).
_H16 = r"[0-9a-fA-F]{1,4}"
IPV6 = re.compile(
    r"(?<![\w:])(?:"
    rf"(?:{_H16}:){{7}}{_H16}|"
    rf"(?:{_H16}:){{1,7}}:|"
    rf"(?:{_H16}:){{1,6}}:{_H16}|"
    rf"(?:{_H16}:){{1,5}}(?::{_H16}){{1,2}}|"
    rf"(?:{_H16}:){{1,4}}(?::{_H16}){{1,3}}|"
    rf"(?:{_H16}:){{1,3}}(?::{_H16}){{1,4}}|"
    rf"(?:{_H16}:){{1,2}}(?::{_H16}){{1,5}}|"
    rf"{_H16}:(?::{_H16}){{1,6}}|"
    rf":(?:(?::{_H16}){{1,7}}|:)"
    r")(?![\w:])"
)

# --- URL ------------------------------------------------------------------
# Scheme-anchored; trailing punctuation is stripped in extract.py.
URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\]\)]+", re.IGNORECASE)

# --- Email ----------------------------------------------------------------
EMAIL = re.compile(
    r"(?<![\w.+-])[a-zA-Z0-9._%+-]+@"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}(?![\w.])"
)

# --- Domain ---------------------------------------------------------------
# One or more labels plus an alphabetic TLD. IPv4 addresses never match
# (numeric TLD). Common file extensions are filtered in extract.py so that
# ``invoice.exe`` is treated as a filename, not a domain.
DOMAIN = re.compile(
    r"(?<![\w.@/-])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}(?![\w.])"
)

# --- Hashes ---------------------------------------------------------------
MD5 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
SHA1 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")

# Extensions that look like a TLD but are almost always filenames.
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe", "dll", "sys", "bin", "dat", "tmp", "bak", "log", "txt", "md",
        "csv", "json", "xml", "yaml", "yml", "html", "htm", "css", "js", "ts",
        "py", "rb", "go", "rs", "java", "class", "jar", "png", "jpg", "jpeg",
        "gif", "bmp", "svg", "ico", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
        "pptx", "zip", "gz", "tar", "rar", "7z", "iso", "img", "ps1", "sh",
        "bat", "cmd", "vbs", "dmp", "pcap",
    }
)
