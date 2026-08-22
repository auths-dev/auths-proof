from __future__ import annotations

from typing import Any, Dict, List, Tuple, Union


MapKey = Union[int, str]


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CBOR length")
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFF_FFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    if value <= 0xFFFF_FFFF_FFFF_FFFF:
        return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")
    raise ValueError("integer outside CBOR bounds")


def encode(value: Any) -> bytes:
    """Encode the closed Auths wire subset using deterministic CBOR."""
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        items: List[Tuple[bytes, bytes]] = []
        for key, item in value.items():
            if not isinstance(key, (int, str)) or isinstance(key, bool):
                raise TypeError("Auths CBOR map keys must be integers or strings")
            encoded_key = encode(key)
            items.append((encoded_key, encode(item)))
        items.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(items)) + b"".join(key + item for key, item in items)
    raise TypeError("unsupported Auths CBOR value")


def decode(data: bytes) -> Any:
    """Decode and require canonical deterministic CBOR for the closed wire subset."""
    offset = 0

    def read_length(additional: int) -> int:
        nonlocal offset
        if additional < 24:
            return additional
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if size is None or offset + size > len(data):
            raise ValueError("unsupported or truncated CBOR length")
        value = int.from_bytes(data[offset : offset + size], "big")
        offset += size
        minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[size]
        if value < minimum:
            raise ValueError("non-canonical CBOR integer")
        return value

    def read() -> Any:
        nonlocal offset
        if offset >= len(data):
            raise ValueError("truncated CBOR")
        initial = data[offset]
        offset += 1
        major, additional = initial >> 5, initial & 31
        if major == 7 and additional in (20, 21, 22):
            return {20: False, 21: True, 22: None}[additional]
        length = read_length(additional)
        if major == 0:
            return length
        if major == 1:
            return -1 - length
        if major in (2, 3):
            if offset + length > len(data):
                raise ValueError("truncated CBOR bytes")
            raw = data[offset : offset + length]
            offset += length
            return raw if major == 2 else raw.decode("utf-8", "strict")
        if major == 4:
            return [read() for _ in range(length)]
        if major == 5:
            result: Dict[MapKey, Any] = {}
            previous: Tuple[int, bytes] | None = None
            for _ in range(length):
                key_start = offset
                key = read()
                key_bytes = data[key_start:offset]
                order = (len(key_bytes), key_bytes)
                if (
                    not isinstance(key, (int, str))
                    or isinstance(key, bool)
                    or key in result
                    or (previous is not None and order <= previous)
                ):
                    raise ValueError("invalid deterministic CBOR map")
                previous = order
                result[key] = read()
            return result
        raise ValueError("unsupported CBOR value")

    result = read()
    if offset != len(data) or encode(result) != data:
        raise ValueError("non-canonical CBOR")
    return result
