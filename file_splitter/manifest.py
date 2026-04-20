"""Manifest models and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import json


@dataclass(slots=True)
class PartMeta:
    part: int
    file: str
    start: int
    end: int
    size: int
    sha256: str | None = None
    sha1: str | None = None
    url: str | None = None

    def to_dict(self) -> dict:
        payload = {
            "part": self.part,
            "file": self.file,
            "start": self.start,
            "end": self.end,
            "size": self.size,
        }
        if self.sha256:
            payload["sha256"] = self.sha256
        if self.sha1:
            payload["sha1"] = self.sha1
        if self.url:
            payload["url"] = self.url
        return payload

    @classmethod
    def from_dict(cls, payload: dict) -> "PartMeta":
        return cls(
            part=int(payload["part"]),
            file=str(payload["file"]),
            start=int(payload["start"]),
            end=int(payload["end"]),
            size=int(payload["size"]),
            sha256=payload.get("sha256"),
            sha1=payload.get("sha1"),
            url=payload.get("url"),
        )


@dataclass(slots=True)
class Manifest:
    file_name: str
    file_size: int
    chunk_size: int
    parts: list[PartMeta] = field(default_factory=list)
    schema_version: int = 1
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    sha256: str | None = None

    def validate(self) -> None:
        if self.file_size < 0:
            raise ValueError("file_size must be >= 0")
        if self.chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        if not self.parts and self.file_size > 0:
            raise ValueError("parts cannot be empty for non-empty files")

        expected_start = 0
        total = 0

        for idx, part in enumerate(self.parts):
            if part.part != idx:
                raise ValueError(f"invalid part index at position {idx}: {part.part}")
            if part.start != expected_start:
                raise ValueError(
                    f"range gap/overlap at part {idx}: expected start {expected_start}, got {part.start}"
                )
            if part.end < part.start:
                raise ValueError(f"invalid range at part {idx}: end < start")

            computed_size = part.end - part.start + 1
            if computed_size != part.size:
                raise ValueError(
                    f"invalid size at part {idx}: expected {computed_size}, got {part.size}"
                )

            if idx < len(self.parts) - 1 and part.size != self.chunk_size:
                raise ValueError(
                    f"part {idx} must match chunk_size ({self.chunk_size}), got {part.size}"
                )

            expected_start = part.end + 1
            total += part.size

        if total != self.file_size:
            raise ValueError(
                f"sum(parts.size) must equal file_size ({self.file_size}), got {total}"
            )

    def to_dict(self) -> dict:
        payload = {
            "schema_version": self.schema_version,
            "created_at_utc": self.created_at_utc,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "chunk_size": self.chunk_size,
            "parts": [part.to_dict() for part in self.parts],
        }
        if self.sha256:
            payload["sha256"] = self.sha256
        return payload

    def save(self, path: str | Path) -> None:
        self.validate()
        output = Path(path)
        output.write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8",
            newline="\n",
        )

    @classmethod
    def from_dict(cls, payload: dict) -> "Manifest":
        manifest = cls(
            schema_version=int(payload.get("schema_version", 1)),
            created_at_utc=str(payload.get("created_at_utc", "")),
            file_name=str(payload["file_name"]),
            file_size=int(payload["file_size"]),
            chunk_size=int(payload["chunk_size"]),
            parts=[PartMeta.from_dict(p) for p in payload["parts"]],
            sha256=payload.get("sha256"),
        )
        manifest.validate()
        return manifest

    @classmethod
    def load(cls, path: str | Path) -> "Manifest":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)
