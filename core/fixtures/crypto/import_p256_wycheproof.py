#!/usr/bin/env python3
"""Reproduce the strict Auths P-256 corpus from the pinned public upstream file."""
import argparse
import hashlib
import json
from pathlib import Path

COMMIT = "878e5366008753df2064d40c49f8e2f50f9c6af7"
SOURCE = f"https://raw.githubusercontent.com/C2SP/wycheproof/{COMMIT}/testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json"
SOURCE_SHA256 = "c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986"
ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
FIELD = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
CURVE_B = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)


def render(source: bytes) -> str:
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("upstream vector bytes differ from the reviewed revision")
    data = json.loads(source)
    if data["algorithm"] != "ECDSA" or data["numberOfTests"] != 262:
        raise ValueError("unexpected upstream corpus")
    rows = []

    def add(name, key, message, signature, error, key_valid=True):
        rows.append((name, key.hex(), message.hex(), signature.hex(), error,
                     "true" if key_valid else "false"))

    def refusal(signature):
        if len(signature) != 64:
            return "invalid-signature-encoding"
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        if not (0 < r < ORDER and 0 < s < ORDER):
            return "invalid-signature-encoding"
        return "verification-failed"

    first = None
    source_cases = 0
    for group in data["testGroups"]:
        if group["sha"] != "SHA-256" or group["publicKey"]["curve"] != "secp256r1":
            raise ValueError("unexpected upstream algorithm")
        uncompressed = bytes.fromhex(group["publicKey"]["uncompressed"])
        if len(uncompressed) != 65 or uncompressed[0] != 4:
            raise ValueError("unexpected upstream public-key representation")
        key = bytes([2 | (uncompressed[-1] & 1)]) + uncompressed[1:33]
        for case in group["tests"]:
            source_cases += 1
            name = f"wycheproof-{case['tcId']}"
            message, signature = bytes.fromhex(case["msg"]), bytes.fromhex(case["sig"])
            if case["result"] == "invalid":
                add(name, key, message, signature, refusal(signature))
                continue
            if case["result"] != "valid" or len(signature) != 64:
                raise ValueError("unexpected upstream result")
            s = int.from_bytes(signature[32:], "big")
            if not 0 < s < ORDER:
                raise ValueError("invalid scalar in a valid upstream signature")
            add(name, key, message, signature,
                "ok" if s <= ORDER // 2 else "verification-failed")
            low = signature[:32] + min(s, ORDER - s).to_bytes(32, "big")
            high = signature[:32] + max(s, ORDER - s).to_bytes(32, "big")
            if s > ORDER // 2:
                add(name + "-low-s", key, message, low, "ok")
            else:
                add(name + "-high-s", key, message, high, "verification-failed")
            add(name + "-changed-message", key, message + b"\x00", low, "verification-failed")
            if first is None:
                first = key, message, low, uncompressed
    if source_cases != 262 or first is None:
        raise ValueError("incomplete source corpus")
    key, message, low, uncompressed = first
    for size in (0, 1, 31, 32, 63, 65, 66, 128):
        signature = (low + bytes(128))[:size]
        add(f"auths-signature-width-{size}", key, message, signature,
            "invalid-signature-encoding")
    for component, offset in (("r", 0), ("s", 32)):
        for label, value in (("zero", 0), ("order", ORDER), ("maximum", (1 << 256) - 1)):
            signature = bytearray(low)
            signature[offset:offset+32] = value.to_bytes(32, "big")
            add(f"auths-{component}-{label}", key, message, bytes(signature),
                "invalid-signature-encoding")
    for label, scalar in (("half-order", ORDER // 2), ("half-order-plus-one", ORDER // 2 + 1)):
        add(f"auths-s-{label}", key, message, low[:32] + scalar.to_bytes(32, "big"), "verification-failed")
    invalid_x = next(x for x in range(100) if pow((x**3 - 3*x + CURVE_B) % FIELD,
                                                (FIELD - 1) // 2, FIELD) == FIELD - 1)
    invalid_keys = {
        "empty": b"", "infinity": b"\x00", "x-only": key[1:],
        "uncompressed": uncompressed, "compact": b"\x05" + key[1:],
        "hybrid-even": b"\x06" + uncompressed[1:],
        "hybrid-odd": b"\x07" + uncompressed[1:],
        "truncated": key[:-1], "trailing": key + b"\x00",
        "wrong-tag": b"\x01" + key[1:],
        "out-of-field": b"\x02" + FIELD.to_bytes(32, "big"),
        "non-point-even": b"\x02" + invalid_x.to_bytes(32, "big"),
        "non-point-odd": b"\x03" + invalid_x.to_bytes(32, "big"),
    }
    for label, malformed_key in invalid_keys.items():
        add(f"auths-key-{label}", malformed_key, message, low, "invalid-key", False)
        add(f"auths-key-{label}-before-signature", malformed_key, message, b"", "invalid-key", False)
    for label, changed in (("domain", b"AUTHS-WRONG-DOMAIN" + message),
                           ("profile", b"wrong-profile\x00" + message),
                           ("descriptor", message + b"wrong-descriptor")):
        add(f"auths-changed-{label}", key, changed, low, "verification-failed")
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("duplicate vector name")
    header = ["# auths.p256-sha256-v1-corpus/1", f"# source: {SOURCE}",
              f"# source-sha256: {SOURCE_SHA256}",
              "# All 262 upstream cases retained; compressed keys preserve the published point.",
              "# Valid high-S signatures remain refusals; n-s supplies the low-S equivalent.",
              "# Derived message, scalar, encoding, and error-priority cases are explicit Auths checks.",
              "id\tkey_hex\tmessage_hex\tsignature_hex\tresult\tkey_valid"]
    return "\n".join(header + ["\t".join(row) for row in rows]) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    rendered = render(args.upstream.resolve().read_bytes())
    output = args.output.resolve()
    if args.write:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
    elif output.read_text() != rendered:
        raise SystemExit("P-256 corpus is stale")
    print(f"P-256 corpus: {len(rendered.splitlines()) - 7} cases")


if __name__ == "__main__":
    main()
