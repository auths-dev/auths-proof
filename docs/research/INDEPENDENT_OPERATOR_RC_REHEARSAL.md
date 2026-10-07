# Independent operator RC rehearsal

Status: in progress, 7 October 2026. This records the agent acting as a fresh
operator; it does not claim an unfamiliar human trial or security review.

## Installed Python recipes

The current recipe manifest contains two effect-free verification recipes.
A fresh Linux amd64 Docker container installed the downloaded `0.0.1rc1` wheel
(SHA-256 `6d079aa4960256a754315d911b55d80bc02848b1ad14225420ea8eae4905656f`).
Networking was disabled. Only the wheel and copied public documentation code
were mounted; no checkout or provider credential reached the application.

| Observation | Resolution | Verification |
| --- | --- | --- |
| The identity recipe authenticated and rejected a changed message. | No change required. | Actual installed-wheel result: `authenticated`, `changedRejected: true`. |
| Copying the authority recipe produced `KeyError: AUTHS_RECIPE_FIXTURE`; its input files were undocumented. | The generated page now lists the exact three input files, supplies a runnable installed-SDK setup example and shows the environment setting. The program reports a useful missing-input message. | A new clean container ran setup and the recipe: `authorized`, `changedRejected: true`. |
| Both generated pages claimed receipt/recovery and duplicate-provider-entry exercises despite being effect-free. | The generator now describes each actual verification boundary and the Python mutation check precisely. | Pages regenerated from their maintained programs. |

The authority setup uses the existing native SDK authoring helper, a fresh
in-memory key and explicit disposable trust. It writes only public proof,
action and context bytes. It grants no production trust or execution capability.
The current CI job's historical “ten recipes” display name is stale; coverage is
determined by `bindings/recipes/manifest.json`, not that label.

## Provider operator journeys

The real Airtable update and platform-account Stripe test refund passed using
installed artifacts, separate application/operator identities, private staged
credentials and durable state. The exact signed development reports, support
bundles and exclusions are under `qualification/simulation/evidence/`.
Docker Desktop host file sharing did not enforce the intended credential-owner
check; the maintained harnesses now stage credential stdin inside the container.
Gateway proof authoring uses its reviewed verifier configuration. Stripe cleanup
reads the test PaymentIntent and charge; refund objects have no `livemode` field.

## Remaining release verification

The tested wheel came from CI, not a published GitHub release. Once promotion
completes, download the actual release asset, verify its manifest/checksum and
repeat these clean-install runs. Protected production qualification and the
full production evidence wall remain unfinished; development rehearsals cannot
supply those claims.
