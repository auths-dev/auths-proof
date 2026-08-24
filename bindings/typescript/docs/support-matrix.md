# Runtime support matrix

The exact package contract is `sdk-runtime-contract.json`. CI rejects package,
WASM, entry-point, profile, or ABI drift before publication.

| Surface | Supported repository-local target |
| --- | --- |
| Local application runtime | Node.js 20.6.0+ ESM on macOS or Linux |
| Agent transport | Unix-domain socket; no remote URL or TCP fallback |
| Application authentication | Ambient local workload identity; no Auths app token |
| Provider selection | Non-secret connection alias on a generated domain client |
| Generated profile clients | Stripe refund v1, PostgreSQL bounded update v1, OpenTofu saved-plan apply v1 |
| Production effect routes | None; all current provider profiles remain qualification-gated |
| Generated-package ABI | `@auths-dev/sdk/profile-runtime`, `auths.profile-client-runtime/1` |
| Identity ABI | 1 |
| Authoring ABI | 1 |
| Effect-free hosts | The separately documented browser/worker verification surfaces |

Provider credentials, connection onboarding, workload authority, and durable
stores belong to the local agent deployment. They are not SDK constructor
arguments and do not enter the application process.

Auths is prelaunch, with no external compatibility state to preserve. Breaking
source changes use one clean cutover. Stable V1, publication, production, and
independently reviewed claims remain blocked until exact release artifacts and
each provider profile pass their security, live-provider, crash/recovery, and
local-agent evidence gates.

The effect-free verification package can still be installed on Windows, but
the stateful `connect()` path fails closed there until the named-pipe server,
peer SID/PID authentication, DACL validation, and secure authority storage are
implemented and qualified.
