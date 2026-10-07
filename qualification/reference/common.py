"""Bounded byte/encoding primitives for reviewed, release-only references."""

import hashlib
import json
import re


class Refusal(ValueError):
    """A stable, secret-free reference refusal."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def closed(value, fields):
    require(type(value) is dict and set(value) == set(fields),
            'qualification.reference.closed-fields')


def text(value, minimum=1, maximum=256):
    require(type(value) is str and minimum <= len(value.encode('utf-8')) <= maximum
            and all(ord(character) >= 32 for character in value),
            'qualification.reference.text-bound')
    return value


def identifier(value, pattern):
    require(type(value) is str and re.fullmatch(pattern, value) is not None,
            'qualification.reference.resource-binding')
    return value


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum,
            'qualification.reference.integer-bound')
    return value


def digest(value):
    return identifier(value, r'[0-9a-f]{64}')


def canonical(value):
    # Reference carriers contain no floating-point values. Native code owns
    # CBOR and protocol commitments; this is only the ASCII request oracle.
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def echo(namespace, operation, action_commitment):
    digest(action_commitment)
    return 'auths-e1-' + sha256(b'auths.gateway-echo/1\0' + namespace.encode()
                              + b'\0' + operation.encode() + b'\0'
                              + bytes.fromhex(action_commitment))


def idempotency(namespace, operation):
    return 'auths-i1-' + sha256(b'auths.gateway-idempotency-key/1\0'
                              + namespace.encode() + b'\0' + operation.encode())
