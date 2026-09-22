#!/usr/bin/env python3
"""Generate the Git object and envelope vectors for auths-git-signing.

This generator deliberately shares no code with the Rust parser. It builds
commit and tag objects, the armored envelope, and the payload digest from
their byte-level definitions with the Python standard library, so the Rust
test checks one implementation against another.

Run from the repository root:

    python3 product/integrations/auths-git-signing/fixtures/generate_objects.py

The output is deterministic; a second run must not change objects.json.
"""

import base64
import hashlib
import json
import pathlib
import struct

OUT = pathlib.Path(__file__).with_name("objects.json")

SHA1_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
SHA1_PARENT_A = "1111111111111111111111111111111111111111"
SHA1_PARENT_B = "2222222222222222222222222222222222222222"
SHA256_TREE = "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"
SHA256_PARENT = "3333333333333333333333333333333333333333333333333333333333333333"
AUTHOR = "author Agent <agent@example.invalid> 1790000000 +0000"
COMMITTER = "committer Agent <agent@example.invalid> 1790000000 +0000"
TAGGER = "tagger Agent <agent@example.invalid> 1790000000 +0000"

PGP = (
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "iHUEABYKAB0WIQRnb3RoaW5nLXRvLXNlZS1oZXJlAAoJEA==\n"
    "-----END PGP SIGNATURE-----\n"
)
SSH = (
    "-----BEGIN SSH SIGNATURE-----\n"
    "U1NIU0lHAAAAAQ==\n"
    "-----END SSH SIGNATURE-----\n"
)


def envelope(proof: bytes, action: bytes) -> str:
    frame = (
        b"AUTHS-GIT-SIGNATURE/1\n"
        + struct.pack(">I", len(proof))
        + proof
        + struct.pack(">I", len(action))
        + action
    )
    encoded = base64.b64encode(frame).decode("ascii")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    return (
        "-----BEGIN SIGNED MESSAGE-----\n"
        + "".join(line + "\n" for line in lines)
        + "-----END SIGNED MESSAGE-----\n"
    )


def header_block(name: str, signature: str) -> str:
    lines = signature.rstrip("\n").split("\n")
    return name + " " + "\n ".join(lines)


def commit(headers, message: str, signature=None, sig_name="gpgsig", sig_at=None):
    """Returns (raw object, unsigned payload) as bytes."""
    payload = "\n".join(headers) + "\n\n" + message
    if signature is None:
        return payload.encode(), payload.encode()
    signed = list(headers)
    block = header_block(sig_name, signature)
    signed.insert(len(signed) if sig_at is None else sig_at, block)
    raw = "\n".join(signed) + "\n\n" + message
    return raw.encode(), payload.encode()


def tag(headers, message: str, signature=None):
    payload = "\n".join(headers) + "\n\n" + message
    raw = payload + (signature or "")
    return raw.encode(), payload.encode()


def digest(kind: str, payload: bytes) -> str:
    return hashlib.sha256(
        b"auths.git-signature/1\0" + kind.encode() + b"\0" + payload
    ).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


CASES = []


def ok(case_id, form, raw, payload, kind, fmt, tag_name=None, proof=None, action=None):
    expect = {
        "kind": kind,
        "object_format": fmt,
        "tag_name": tag_name,
        "payload": b64(payload),
        "payload_digest": digest(kind, payload),
    }
    if proof is not None:
        expect["proof"] = b64(proof)
        expect["action"] = b64(action)
    CASES.append({"id": case_id, "form": form, "input": b64(raw), "expect": {"ok": expect}})


def err(case_id, form, raw, code):
    CASES.append({"id": case_id, "form": form, "input": b64(raw), "expect": {"error": code}})


def valid_signed(case_id, raw, payload, kind, fmt, tag_name, proof, action):
    ok(case_id, "signed-object", raw, payload, kind, fmt, tag_name, proof, action)
    ok(case_id + "/payload", "unsigned-payload", payload, payload, kind, fmt, tag_name)


P1, A1 = b"proof-one" * 20, b"action-one"
P2, A2 = b"proof-two" * 50, b"action-two" * 3
SIG1, SIG2 = envelope(P1, A1), envelope(P2, A2)

# Valid commits.
base = [f"tree {SHA1_TREE}", AUTHOR, COMMITTER]
valid_signed("commit-sha1-root", *commit(base, "root\n", SIG1), "commit", "sha1", None, P1, A1)
two_parents = [f"tree {SHA1_TREE}", f"parent {SHA1_PARENT_A}", f"parent {SHA1_PARENT_B}", AUTHOR, COMMITTER]
valid_signed("commit-sha1-merge", *commit(two_parents, "merge\n\nbody\n", SIG2), "commit", "sha1", None, P2, A2)
sha256_headers = [f"tree {SHA256_TREE}", f"parent {SHA256_PARENT}", AUTHOR, COMMITTER]
valid_signed("commit-sha256", *commit(sha256_headers, "sha256\n", SIG1, "gpgsig-sha256"), "commit", "sha256", None, P1, A1)
mergetag = header_block(
    "mergetag",
    f"object {SHA1_PARENT_B}\ntype commit\ntag v0.9\n{TAGGER}\n\nold release\n{PGP}",
)
extra = [f"tree {SHA1_TREE}", f"parent {SHA1_PARENT_A}", f"parent {SHA1_PARENT_B}", AUTHOR, COMMITTER, "encoding ISO-8859-1", mergetag]
valid_signed("commit-mergetag-and-encoding", *commit(extra, "merge tag\n", SIG1), "commit", "sha1", None, P1, A1)
valid_signed("commit-crlf-message", *commit(base, "line one\r\nline two\r\n", SIG1), "commit", "sha1", None, P1, A1)
valid_signed("commit-signature-not-last", *commit(base + ["encoding UTF-8"], "x\n", SIG1, sig_at=3), "commit", "sha1", None, P1, A1)
valid_signed("commit-empty-message", *commit(base, "", SIG2), "commit", "sha1", None, P2, A2)

# Valid tags.
tag_sha1 = [f"object {SHA1_PARENT_A}", "type commit", "tag v1.2.3", TAGGER]
valid_signed("tag-sha1", *tag(tag_sha1, "release 1.2.3\n", SIG1), "tag", "sha1", "v1.2.3", P1, A1)
tag_sha256 = [f"object {SHA256_PARENT}", "type commit", "tag release/2026-09", TAGGER]
valid_signed("tag-sha256-namespaced", *tag(tag_sha256, "september\n", SIG2), "tag", "sha256", "release/2026-09", P2, A2)
valid_signed("tag-empty-message", *tag(tag_sha1, "", SIG1), "tag", "sha1", "v1.2.3", P1, A1)

# Commit hostile cases.
err("commit-unsigned", "signed-object", commit(base, "x\n")[0], "git.unsigned")
dup = commit(base, "x\n", SIG1)[0].decode().replace("\n\nx\n", "\n" + header_block("gpgsig", SIG2) + "\n\nx\n")
err("commit-duplicate-signature", "signed-object", dup.encode(), "git.signature-ambiguous")
both = commit(base, "x\n", SIG1)[0].decode().replace("\n\nx\n", "\n" + header_block("gpgsig-sha256", SIG2) + "\n\nx\n")
err("commit-sha1-with-sha256-signature-too", "signed-object", both.encode(), "git.signature-ambiguous")
err("commit-sha256-with-sha1-header-name", "signed-object", commit(sha256_headers, "x\n", SIG1, "gpgsig")[0], "git.signature-ambiguous")
err("commit-sha1-with-sha256-header-name", "signed-object", commit(base, "x\n", SIG1, "gpgsig-sha256")[0], "git.signature-ambiguous")
err("commit-cr-in-header", "signed-object", commit([f"tree {SHA1_TREE}\r", AUTHOR, COMMITTER], "x\n", SIG1)[0], "git.object-malformed")
err("commit-nul-in-message", "signed-object", commit(base, "x\0y\n", SIG1)[0], "git.object-malformed")
err("commit-missing-author", "signed-object", commit([f"tree {SHA1_TREE}", COMMITTER], "x\n", SIG1)[0], "git.object-malformed")
err("commit-parent-after-author", "signed-object", commit([f"tree {SHA1_TREE}", AUTHOR, f"parent {SHA1_PARENT_A}", COMMITTER], "x\n", SIG1)[0], "git.object-malformed")
err("commit-duplicate-committer", "signed-object", commit(base + [COMMITTER], "x\n", SIG1)[0], "git.object-malformed")
err("commit-uppercase-tree", "signed-object", commit([f"tree {SHA1_TREE.upper()}", AUTHOR, COMMITTER], "x\n", SIG1)[0], "git.object-malformed")
err("commit-short-tree", "signed-object", commit([f"tree {SHA1_TREE[:-1]}", AUTHOR, COMMITTER], "x\n", SIG1)[0], "git.object-malformed")
err("commit-mixed-format-parent", "signed-object", commit([f"tree {SHA1_TREE}", f"parent {SHA256_PARENT}", AUTHOR, COMMITTER], "x\n", SIG1)[0], "git.object-malformed")
no_blank = ("\n".join(base) + "\n" + header_block("gpgsig", SIG1) + "\n").encode()
err("commit-no-message-separator", "signed-object", no_blank, "git.object-malformed")
err("commit-ssh-signature", "signed-object", commit(base, "x\n", SSH)[0], "git.not-auths-envelope")
err("commit-pgp-signature", "signed-object", commit(base, "x\n", PGP)[0], "git.not-auths-envelope")
lines = SIG1.split("\n")
lines[1] = lines[1][:10] + "!" + lines[1][11:]
err("commit-envelope-invalid-base64", "signed-object", commit(base, "x\n", "\n".join(lines))[0], "git.envelope-malformed")
trailing = SIG1 + "trailing\n"
err("commit-envelope-trailing-text", "signed-object", commit(base, "x\n", trailing)[0], "git.envelope-malformed")
err("unknown-object-type", "signed-object", b"blob 12\n\nx\n", "git.object-malformed")
err("empty-object", "signed-object", b"", "git.object-malformed")

# Tag hostile cases.
err("tag-unsigned", "signed-object", tag(tag_sha1, "x\n")[0], "git.unsigned")
err("tag-of-tree", "signed-object", tag([f"object {SHA1_TREE}", "type tree", "tag v1", TAGGER], "x\n", SIG1)[0], "git.object-malformed")
err("tag-missing-tagger", "signed-object", tag([f"object {SHA1_PARENT_A}", "type commit", "tag v1"], "x\n", SIG1)[0], "git.object-malformed")
err("tag-extra-header", "signed-object", tag(tag_sha1 + ["gpgsig abc"], "x\n", SIG1)[0], "git.object-malformed")
err("tag-two-signature-blocks", "signed-object", tag(tag_sha1, "x\n" + PGP, SIG1)[0], "git.signature-ambiguous")
err("tag-name-double-dot", "signed-object", tag([f"object {SHA1_PARENT_A}", "type commit", "tag a..b", TAGGER], "x\n", SIG1)[0], "git.tag-name-invalid")
err("tag-name-leading-dash", "signed-object", tag([f"object {SHA1_PARENT_A}", "type commit", "tag -rc", TAGGER], "x\n", SIG1)[0], "git.tag-name-invalid")
err("tag-pgp-signature", "signed-object", tag(tag_sha1, "x\n", PGP)[0], "git.not-auths-envelope")

# Unsigned payloads that already carry a signature.
err("payload-commit-with-signature-header", "unsigned-payload", commit(base, "x\n", SIG1)[0], "git.signature-ambiguous")
err("payload-tag-with-armor-line", "unsigned-payload", tag(tag_sha1, "x\n" + SSH)[1], "git.signature-ambiguous")
err("payload-cr-in-tag-header", "unsigned-payload", tag([f"object {SHA1_PARENT_A}\r", "type commit", "tag v1", TAGGER], "x\n")[1], "git.object-malformed")

corpus = {"schema": "auths.git-signing-object-vectors/1", "cases": CASES}
OUT.write_text(json.dumps(corpus, indent=1, sort_keys=True) + "\n")
print(f"wrote {len(CASES)} cases to {OUT}")
