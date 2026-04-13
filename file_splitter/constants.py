"""Project-wide constants."""

BYTES_IN_GIB = 1024**3

# 1.9 GiB in bytes (2040109465)
DEFAULT_PART_SIZE = int(1.9 * BYTES_IN_GIB)

# Large enough to reduce syscall overhead without high memory use.
DEFAULT_BUFFER_SIZE = 8 * 1024 * 1024
