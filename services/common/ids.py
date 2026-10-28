"""Sortable, prefixed identifiers.

ULID-style layout: 48-bit millisecond timestamp + 80 random bits, Crockford base32,
so IDs sort by creation time and can be generated without coordination.
"""

import secrets
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _b32(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        value, rem = divmod(value, 32)
        chars.append(_ALPHABET[rem])
    return "".join(reversed(chars))


def new_id(prefix: str, *, now_ms: int | None = None) -> str:
    ts = now_ms if now_ms is not None else time.time_ns() // 1_000_000
    return f"{prefix}_{_b32(ts, 10)}{_b32(secrets.randbits(80), 16)}"
