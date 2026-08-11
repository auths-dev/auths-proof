# Migration from `advanced`

The experimental `@auths-dev/sdk/advanced` catch-all is removed before stable
V1. Replace each import by intent:

| Previous use | New subpath |
| --- | --- |
| Package-owned local verification | `@auths-dev/sdk/verify` and `loadVerifier` |
| Safe decision/commitment projection | `@auths-dev/sdk/inspection` |
| Caller-supplied or differential engine | `@auths-dev/sdk/diagnostics` |
| Runtime/ABI compatibility report | `@auths-dev/sdk/diagnostics` and `diagnoseSdk` |
| Redacted events/support bundle | `@auths-dev/sdk/observability` |

There is no compatibility re-export: retaining it would preserve the mixed
trust boundary. A diagnostic authorized result is inert and cannot be
converted to `VerifiedAction` or any profile command.
