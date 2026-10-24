"""Write independent, synthetic snapshot constructor/decoder vectors.

This is fixture generation, not validation. No signing key is used and signature
bytes are shape-only values; these vectors never assert cryptographic authority.
The final assurance pass runs every consumer against the emitted shared corpus.
"""
import hashlib
import json
from pathlib import Path


def head(major, value):
    for limit, tag, width in [(24, None, 0), (256, 24, 1), (65536, 25, 2), (2**32, 26, 4), (2**64, 27, 8)]:
        if value < limit:
            return bytes([major * 32 + (value if tag is None else tag)]) + (value.to_bytes(width, 'big') if width else b'')
    raise ValueError('unrepresentable fixture word')


def encode(value):
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode('utf-8')
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(map(encode, value))
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(encode(key) + encode(item) for key, item in sorted(value.items()))
    raise TypeError(type(value))


def signed(kind, state, sequence, signature_byte):
    statement = {
        0: 1, 1: 'status-test-v1',
        2: 'did:example:subject' if kind == 'principal' else bytes([9]) * 32,
        3: state, 4: sequence, 5: 0, 6: 100, 7: 'did:example:issuer', 8: [],
    }
    signature = {0: {0: 'did-key', 1: 'did:example:issuer#key-1', 2: 'eddsa-ed25519'}, 1: bytes([signature_byte]) * 64}
    return {0: statement, 1: signature}


def identifier(kind, item):
    content = encode(item[0])
    tag = 5 if kind == 'principal' else 6
    return hashlib.sha256(b'AUTHS-ID' + (1).to_bytes(2, 'big') + tag.to_bytes(2, 'big') + len(content).to_bytes(8, 'big') + content).digest()


def main():
    cases = []
    for kind in ['principal', 'grant']:
        active = signed(kind, 0, 7, 1)
        revoked = signed(kind, 1, 7, 2)
        resigned = signed(kind, 0, 7, 3)
        newer = signed(kind, 0, 8, 1)
        vectors = [
            ('empty', [], True, 20, 80, True),
            ('one', [active], True, 20, 80, True),
            ('distinct-same-sort-key', [active, revoked], True, 20, 80, True),
            ('distinct-sequence', [active, newer], True, 20, 80, True),
            ('adjacent-duplicate', [active, active], False, 20, 80, False),
            ('signature-does-not-change-identity', [active, resigned], False, 20, 80, False),
            ('separated-identical-statement', [active, revoked, active], False, 20, 80, False),
            ('separated-resigned-statement', [active, revoked, resigned], False, 20, 80, False),
            ('inverted-snapshot-window', [active], False, 80, 20, True),
            ('statement-window-too-short', [active], False, 20, 101, True),
        ]
        for name, values, accepts, observed, valid, canonical_order in vectors:
            if canonical_order:
                values = sorted(values, key=lambda item: identifier(kind, item))
            snapshot = {0: bytes([253]) * 32, 1: observed, 2: valid, 3: values, 4: [], 5: []}
            cases.append({'name': kind + '-' + name, 'kind': kind, 'accepts': accepts,
                          'snapshot_cbor_hex': encode(snapshot).hex()})
    output = {'schema': 'auths-proof-status-snapshot-uniqueness/v1',
              'scope': 'Synthetic codec/carrier acceptance only; signature bytes confer no authority.',
              'cases': cases}
    Path(__file__).with_name('snapshot-uniqueness-v1.json').write_text(json.dumps(output, indent=2) + '\n')


if __name__ == '__main__':
    main()
