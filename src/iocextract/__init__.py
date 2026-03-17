"""iocextract -- extract and defang Indicators of Compromise from text.

A small, dependency-light (stdlib + pydantic) blue-team utility for turning
raw logs, emails and reports into a clean, deduplicated, classified set of
indicators -- and for safely defanging / refanging them for sharing.
"""

from __future__ import annotations

from .cli import main
from .defang import defang, refang
from .extract import extract
from .models import IOC, ExtractionResult, IOCType

__all__ = [
    "IOC",
    "ExtractionResult",
    "IOCType",
    "defang",
    "extract",
    "main",
    "refang",
]

__version__ = "0.1.0"
