# Generated trust material

`trusted-context.cbor` is written here by `tests/generate-local-context.sh`
before the compose stack starts, and is deliberately not committed.

`[verification] trusted_context_path` is mandatory: a node that cannot state its
trust anchors cannot decide anything. The context carries an evaluation time and
status-snapshot freshness window, so a checked-in copy would expire the same way
a checked-in certificate does.

The anchor key is derived from `AUTHS_LOCAL_SEED`, domain-separated from the
node's own custody key. **This is a local fixture**: anyone holding the seed can
derive the anchor and author grants against it. A production deployment mounts
operator-held context bytes as a secret -- see `config/production.example.toml`.
