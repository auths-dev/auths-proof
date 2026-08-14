# TLS PostgreSQL lifecycle evidence

This fixture proves that the shipping PostgreSQL lifecycle store connects only
through certificate-verified TLS and preserves its atomic lifecycle contract
across three independent store instances.

Run from the repository root:

```text
docker compose -f product/stores/auths-stores/tests/postgres_tls/compose.yaml up -d --wait
AUTHS_POSTGRES_URL='host=localhost port=55438 dbname=auths_lifecycle user=auths password=local-fixture-password sslmode=require' \
AUTHS_POSTGRES_CA_PEM="$PWD/product/stores/auths-stores/tests/postgres_tls/generated/ca.crt" \
AUTHS_POSTGRES_SERVER_NAME=localhost \
cargo test -p auths-stores --test postgres_lifecycle -- --ignored
docker compose -f product/stores/auths-stores/tests/postgres_tls/compose.yaml down -v
```

The certificates and database are disposable. The harness records no customer
data, credentials, actions, or receipt payloads.
