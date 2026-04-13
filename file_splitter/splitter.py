"""Split files into fixed-size raw chunks and generate manifest."""

from __future__ import annotations

import hashlib
from pathlib import Path

try:
    from .constants import DEFAULT_BUFFER_SIZE, DEFAULT_PART_SIZE
    from .io_utils import copy_exact_bytes
    from .manifest import Manifest, PartMeta
except ImportError:  # pragma: no cover - standalone script compatibility
    from constants import DEFAULT_BUFFER_SIZE, DEFAULT_PART_SIZE
    from io_utils import copy_exact_bytes
    from manifest import Manifest, PartMeta


def split_file(
    input_path: str,
    output_dir: str | None = None,
    part_size: int = DEFAULT_PART_SIZE,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
    include_hashes: bool = False,
) -> Path:
    """Split a file and create a JSON manifest.

    Returns the manifest path.
    """
    if part_size <= 0:
        raise ValueError("part_size must be > 0")
    if buffer_size <= 0:
        raise ValueError("buffer_size must be > 0")

    source = Path(input_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"input file not found: {source}")

    out_dir = Path(output_dir).resolve() if output_dir else source.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    file_size = source.stat().st_size
    base_name = source.name

    parts: list[PartMeta] = []
    offset = 0
    part_index = 0
    global_hash = hashlib.sha256() if include_hashes else None

    with source.open("rb") as src:
        while offset < file_size:
            target = min(part_size, file_size - offset)
            part_name = f"{base_name}.part{part_index}"
            part_path = out_dir / part_name

            part_hash = hashlib.sha256() if include_hashes else None
            hashers = tuple(h for h in (part_hash, global_hash) if h is not None)

            with part_path.open("wb") as dst:
                copied = copy_exact_bytes(
                    src=src,
                    dst=dst,
                    target_bytes=target,
                    buffer_size=buffer_size,
                    hashers=hashers,
                )

            if copied != target:
                raise IOError(
                    f"unexpected EOF while writing {part_name}: expected {target}, got {copied}"
                )

            start = offset
            end = offset + copied - 1
            offset += copied

            parts.append(
                PartMeta(
                    part=part_index,
                    file=part_name,
                    start=start,
                    end=end,
                    size=copied,
                    sha256=part_hash.hexdigest() if part_hash is not None else None,
                )
            )
            part_index += 1

    manifest = Manifest(
        file_name=base_name,
        file_size=file_size,
        chunk_size=part_size,
        parts=parts,
        sha256=global_hash.hexdigest() if global_hash is not None else None,
    )
    manifest_path = out_dir / f"{base_name}.manifest.json"
    manifest.save(manifest_path)
    return manifest_path


if __name__ == "__main__":
    try:
        from .cli import main
    except ImportError:  # pragma: no cover - standalone script compatibility
        from cli import main

    raise SystemExit(main())
