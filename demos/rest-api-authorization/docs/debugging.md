# Records API demo debugging

## Local native process

Run from the repository root:

```text
PORT=4180 \
AUTHS_RECORDS_PUBLIC_URL=http://localhost:4180 \
AUTHS_RECORDS_STATE_PATH=.state/records/ledger-v2.json \
cargo run -p auths-records-demo -- serve
```

Open `http://localhost:4180`. Do not open `web/index.html` with `file://`; the
page intentionally depends on the native issuer, verifier, ledger, protected
routes, Iroh endpoint, and receipt store.

If the Iroh endpoint cannot bind, check that local UDP sockets are permitted.
The ignored Rust test exercises the real adapter:

```text
cargo test -p auths-records-demo \
  iroh_executes_and_https_replay_cannot_duplicate_the_effect \
  -- --ignored --nocapture
```

## Docker

From `demos/rest-api-authorization`:

```text
docker compose up --build
```

Open `http://localhost:4180`. State is held in the `records-data` volume. Use
`docker compose down` to stop the service. Add `--volumes` only when you
intentionally want to discard replay, budget, record, and receipt state.

## Header and proxy limits

The copyable `curl` uses bounded `Auths-Proof` and `Auths-Presentation`
headers. Reverse proxies must allow the configuration's
`maximum_http_header_bytes`; they must not truncate or rewrite either value.
An HTTP 400 before an Auths receipt usually means the carrier was rejected by
the route adapter. A denied receipt means the semantic verifier ran and
reported a stable code.

## Fly.io

The Fly service terminates public HTTPS and persists the current typed-customer
ledger at `/data/auths-records/ledger-v2.json`. The previous demo ledger, if
present, is left untouched instead of being destructively rewritten across the
schema change. The process also creates a real Iroh
endpoint using the N0 preset, so its advertised endpoint can contain relay and
direct addressing information. Do not replace it with a WebSocket or HTTP
endpoint labelled “Iroh.”

Useful checks:

```text
fly status --app auths-records-demo
fly logs --app auths-records-demo
curl https://auths-records-demo.fly.dev/healthz
```

If the machine is healthy over HTTPS but Iroh is unavailable, inspect outbound
UDP and relay connectivity. HTTPS health alone is not evidence that the Iroh
path works; run the generated native command against the advertised endpoint.

## Receipt lookup

The API form is `/api/v1/receipts/{decision-receipt-id}`. The human-designed
page is `/receipts/{decision-receipt-id}`. A missing or malformed ID returns a
closed 404 response rather than an empty or fabricated receipt.
