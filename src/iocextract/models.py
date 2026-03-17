"""Pydantic data models for IOC extraction results."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    """The kinds of indicator this library recognises."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    DOMAIN = "domain"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IOC(BaseModel):
    """A single, normalised indicator of compromise."""

    type: IOCType
    value: str = Field(description="Refanged, normalised indicator value.")
    defanged: str = Field(description="Safe-to-share defanged representation.")


class ExtractionResult(BaseModel):
    """The full result of running the extractor over a body of text."""

    iocs: list[IOC] = Field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        """Number of indicators per type, sorted by type name."""
        counter: Counter[str] = Counter(ioc.type.value for ioc in self.iocs)
        return dict(sorted(counter.items()))

    @property
    def total(self) -> int:
        return len(self.iocs)

    def of_type(self, ioc_type: IOCType) -> list[IOC]:
        """Return only the indicators of a given type."""
        return [ioc for ioc in self.iocs if ioc.type is ioc_type]

    def values(self, ioc_type: IOCType) -> list[str]:
        """Convenience: the ``value`` strings for one type."""
        return [ioc.value for ioc in self.of_type(ioc_type)]

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialise to a JSON document with a summary header."""
        payload = {
            "total": self.total,
            "counts": self.counts,
            "iocs": [ioc.model_dump(mode="json") for ioc in self.iocs],
        }
        import json

        return json.dumps(payload, indent=indent)
