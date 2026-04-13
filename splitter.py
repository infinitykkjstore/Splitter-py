"""Backward-compatible CLI entrypoint.

Allows running:
python splitter.py split <arquivo>
"""

from file_splitter.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
