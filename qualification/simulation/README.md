# Independent operator rehearsal

The owner requested simulated bootstrap and provider qualification. Run it:

```sh
python3 qualification/simulation/run.py --out /tmp/auths-qualification-rehearsal
```

Use a fresh output directory. No provider credential, signing key file or
production environment is needed. The same run is a required job in recipe
qualification CI, and uploads its public reports and signing artifacts.

The platform-account Stripe refund and Airtable record update harnesses compile the maintained
recipes and drive the native submission driver over durable file claims and
mutable counting providers. Independent vertical wire oracles check the actual
method, URL, headers, body and idempotency commitment before each write. Reports
measure credential leases, write entries and fresh read-back confirmations.
Each measured report has a detached Ed25519 simulation attestation from a fresh
in-memory key. A separate native stage re-reads the published files and verifies
their signatures and report digests. Changed bytes or simulation scope refuse.
These self-signed reports have no production or protected-run signing authority;
the disposable root ceremony below exercises that separate trust machinery.
They exercise exact writes, original/fresh proof replay, reopening the store,
lost responses, and crashes before the response record is durable.

The first ceremony generates an ephemeral root and release signer in memory,
certifies the signer, signs two explicitly placeholder records, constructs the
index and revocation list, and imports them into the native required gate.
Actual engine credential-store counters show zero leases before signing and
one after verified import. Unsigned, expired and missing-root inputs refuse.
The placeholder records explicitly exclude every provider-run claim; they test
the trust transition, while provider measurements are separate artifacts.

CI also packages the compiled native harness with its SHA-256 and commit.
It runs that kit in Docker with networking disabled and no source checkout
mounted. Download the `qualification-simulation-kit-*` artifact, make the
`qualification-harness` executable, and run with Python 3.9 or later:

```sh
chmod +x /path/to/kit/qualification-harness
python3 /path/to/kit/run.py --candidate-kit /path/to/kit --out /tmp/rehearsal
```

The kit must match the host OS and architecture. Its request and policy fixtures
are compiled in. No Rust toolchain or repository import is needed for that run.

These are simulation artifacts. They cannot enable the shipping gateway:
its pinned root is unchanged, the tuples use development stores, and the
bootstrap records name placeholder provenance. No file is installed under
`qualification/trust` or `qualification/families`, and readiness remains false.
Native proof/socket and installed-package journeys remain separate SDK workflow
checks. This rehearsal does not claim the full protected production corpus.

The owner approved platform-only Stripe test refunds to avoid paid Connect
onboarding. Both maintained live harnesses passed using the downloaded gateway
and installed Python 0.0.1rc1 wheel in Docker. Their signed reports are retained
in `evidence/stripe-platform-live-2026-10-07/` and
`evidence/airtable-live-2026-10-07/`; see [live instructions](live/README.md).
Those actual provider runs use development custody and exclude protected
production qualification and full mandatory-corpus coverage.
