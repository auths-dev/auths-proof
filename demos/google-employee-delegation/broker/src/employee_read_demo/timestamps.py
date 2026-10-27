"""One offset-aware timestamp parser for producer and credential metadata.

Parsing a timestamp establishes neither freshness nor clock trust. Each caller
still applies its own observation window or credential-expiry policy.
"""

from datetime import datetime
import re


_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)


def parse_aware_timestamp(value: object) -> datetime:
    """Read bounded RFC3339 producer metadata, including ``Z`` on Python 3.10.

    Reject missing offsets rather than interpreting a producer's timestamp in
    the consumer host's local timezone. Errors contain no supplied metadata.
    """
    if (not isinstance(value, str) or not 1 <= len(value) <= 128
            or _TIMESTAMP.fullmatch(value) is None):
        raise ValueError("invalid timestamp shape")
    # Python 3.10 does not accept the Z spelling accepted by later versions.
    # Normalize only the terminal UTC designator, never arbitrary input text.
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise ValueError("invalid timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp requires an explicit timezone")
    return parsed
