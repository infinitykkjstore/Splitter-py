"""Merge part files back into the original file via raw byte concatenation."""

from __future__ import annotations

import hashlib
from pathlib import Path

try:
    from .constants import DEFAULT_BUFFER_SIZE
    from .io_utils import copy_exact_bytes
    from .manifest import Manifest
except ImportError:  # pragma: no cover - standalone script compatibility
    from constants import DEFAULT_BUFFER_SIZE
    from io_utils import copy_exact_bytes
    from manifest import Manifest


def merge_file(
    manifest_path: str,
    output_path: str,
    base_dir: str | None = None,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
    verify_hashes: bool = False,
) -> Path:
    """Merge parts listed in manifest into output_path.

    Returns the output path.
    """
    if buffer_size <= 0:
        raise ValueError("buffer_size must be > 0")

    manifest_file = Path(manifest_path).resolve()
    manifest = Manifest.load(manifest_file)

    parts_dir = Path(base_dir).resolve() if base_dir else manifest_file.parent
    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    global_hash = hashlib.sha256() if verify_hashes and manifest.sha256 else None

    with output.open("wb") as merged:
        for part in manifest.parts:
            part_path = parts_dir / part.file
            if not part_path.is_file():
                raise FileNotFoundError(f"part not found: {part_path}")

            part_hash = hashlib.sha256() if verify_hashes and part.sha256 else None
            hashers = tuple(h for h in (part_hash, global_hash) if h is not None)

            with part_path.open("rb") as part_fh:
                copied = copy_exact_bytes(
                    src=part_fh,
                    dst=merged,
                    target_bytes=part.size,
                    buffer_size=buffer_size,
                    hashers=hashers,
                )

                if copied != part.size:
                    raise IOError(
                        f"invalid part size in {part_path.name}: expected {part.size}, got {copied}"
                    )

            actual_size = part_path.stat().st_size
            if actual_size != part.size:
                raise IOError(
                    f"part file size mismatch for {part_path.name}: expected {part.size}, got {actual_size}"
                )

            if part_hash is not None:
                digest = part_hash.hexdigest()
                if digest != part.sha256:
                    raise IOError(
                        f"part hash mismatch for {part_path.name}: expected {part.sha256}, got {digest}"
                    )

    merged_size = output.stat().st_size
    if merged_size != manifest.file_size:
        raise IOError(
            f"merged file size mismatch: expected {manifest.file_size}, got {merged_size}"
        )

    if global_hash is not None:
        digest = global_hash.hexdigest()
        if digest != manifest.sha256:
            raise IOError(
                f"merged file hash mismatch: expected {manifest.sha256}, got {digest}"
            )

    return output
