# Independent operator rehearsal

The owner requested simulated bootstrap and provider qualification. Run it:

```sh
python3 qualification/simulation/run.py --out /tmp/auths-qualification-rehearsal
```

Use a fresh output directory. No provider credential, signing key file or
production environment is needed. The same run is a required job in recipe
qualification CI, and uploads its public reports and signing artifacts.

The Stripe refund and Airtable record update harnesses compile the maintained
recipes and drive the native submission driver over durable file claims and
mutable counting providers. Independent vertical wire oracles check the actual
method, URL, headers, body and idempotency commitment before each write. Reports
measure credential leases, write entries and fresh read-back confirmations.
They exercise exact writes, original/fresh proof replay, reopening the store,
lost responses, and crashes before the response record is durable.

The first ceremony generates an ephemeral root and release signer in memory,
certifies the signer, signs two explicitly placeholder records, constructs the
index and revocation list, and imports them into the native required gate.
Actual engine credential-store counters show zero leases before signing and
one after verified import. Unsigned, expired and missing-root inputs refuse.
The placeholder records explicitly exclude every provider-run claim; they test
the trust transition, while provider measurements are separate artifacts.

These are simulation artifacts. They cannot enable the shipping gateway:
its pinned root is unchanged, the tuples use development stores, and the
bootstrap records name placeholder provenance. No file is installed under
`qualification/trust` or `qualification/families`, and readiness remains false.
Native proof/socket and installed-package journeys remain separate SDK workflow
checks. This rehearsal does not claim the full protected production corpus.
