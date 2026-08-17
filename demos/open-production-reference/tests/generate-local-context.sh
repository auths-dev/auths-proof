#!/bin/sh
# Writes the local-fixture TrustedContext the compose stack mounts at
# /run/config/trusted-context.cbor.
#
# `[verification] trusted_context_path` is mandatory: a node that cannot state
# its trust anchors cannot decide anything. Nothing produced a context for the
# compose demo, so all three replicas crash-looped on startup with
# "the trusted context is unavailable".
#
# Generated per run rather than committed. A checked-in context carries an
# evaluation time and snapshot freshness window, so it would go stale exactly
# the way a checked-in certificate does.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../compose" && pwd)
mkdir -p "$root/context"
: "${AUTHS_LOCAL_SEED:?provide the same 32-byte unpadded base64url seed the stack uses}"
cargo run --locked -q -p auths-node --bin auths-local-context -- \
  "$root/context/trusted-context.cbor" "${AUTHS_CONTEXT_LIFETIME_SECONDS:-21600}"
