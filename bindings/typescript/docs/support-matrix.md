# Runtime support matrix

The exact package contract is `sdk-runtime-contract.json`. CI rejects package,
WASM, entry-point, profile, or ABI drift before publication.

| Surface | Supported repository-local target |
| --- | --- |
| Local application runtime | Node.js 20.6.0+ ESM on macOS or Linux |
| Gateway transport | Operator-provisioned Unix-domain socket; no remote URL or TCP fallback |
| Application authentication | A proof for one exact action; no Auths app token |
| Provider writes | Only through the operator-run gateway |
| Production effect routes | None; every provider recipe remains qualification-gated |
| Identity ABI | 1 |
| Authoring ABI | 1 |
| Effect-free hosts | The separately documented browser/worker verification surfaces |

Provider credentials, connection onboarding, and durable attempt stores belong
to the gateway deployment. They are not SDK constructor arguments and do not
enter the application process.

Auths is prelaunch, with no external compatibility state to preserve. Breaking
source changes use one clean cutover. Stable V1, publication, production, and
independently reviewed claims remain blocked until exact release artifacts and
each provider recipe pass their security, live-provider, crash/recovery, and
gateway evidence gates.

The effect-free verification package can still be installed on Windows; the
gateway client requires a Unix-domain socket and is not available there.
