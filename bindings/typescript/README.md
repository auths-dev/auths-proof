# `@auths-dev/sdk`

Auths proves what software may do, executes the exact protected action through
a closed profile, and leaves a verifiable receipt.

## Install

```bash
npm install @auths-dev/sdk
```

The package includes its WASM implementation. Consumers do not need Rust.

## Protect one MCP action

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const provider = mcp.developmentProvider({
  tools: {
    async publish_report(arguments_) {
      return { published: true, arguments: arguments_ };
    },
  },
});

const auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
try {
  const result = await auths.execute({
    action: mcp.callTool({
      name: "publish_report",
      arguments: { period: "weekly" },
    }),
    provider,
  });
  console.log(result);
} finally {
  await auths.close();
}
```

On runtimes that support explicit resource management, `await using` may be
used instead of the `try`/`finally` form.

## Public entry points

One npm package provides a progressively disclosed API:

| Import | Purpose |
| --- | --- |
| `@auths-dev/sdk` | create, delegate, execute, resume, product results and errors |
| `@auths-dev/sdk/identity` | standalone identity decoding and authentication |
| `@auths-dev/sdk/verify` | effect-free proof, decision and receipt verification |
| `@auths-dev/sdk/profiles` | qualified effect domains; initially MCP |
| `@auths-dev/sdk/integrations` | maintained compositions and mechanism adapters |
| `@auths-dev/sdk/framework` | proven signer and atomic-reservation contracts |
| `@auths-dev/sdk/testkit` | deterministic fixtures and conformance suites |

The root does not re-export the other entry points. Internal security machinery
remains private.

## Identity without capabilities

`@auths-dev/sdk/identity` is independent of grants, approvals and execution.
It supports method- and suite-labelled public identities without forcing an
application into the protected workflow.

## Verification without effects

`@auths-dev/sdk/verify` is deterministic and effect-free. Verification never
becomes authorization and returns no executable handle. Differential tools
belong to `@auths-dev/sdk/testkit`.

## Production boundary

The development composition uses ephemeral keys and in-memory state. It is not
production durable. Production applications provide qualified profile
integrations plus the narrowly proven framework mechanisms they need. Provider
credentials remain behind the profile gateway and are acquired only after
Auths has authorized and durably reserved the exact action.

## Support

Supported Node, browser, package, ABI and semantic-subject claims are recorded
in `sdk-runtime-contract.json`. Public declarations are frozen in
`api/public-api.txt`, and packed-artifact tests prove that removed prelaunch
subpaths do not resolve.

## Capability status

The closed product workflow and its installed-artifact evidence are complete
in this repository. This README does not promote those repository-local claims
to an independently reviewed or published release.

- Implementation tier: `full-workflow-sdk`
- Evidence status: `repository-local-complete`
- Promoted tier: `verifier-binding`
- Publication status: `blocked`
- Promotion status: `blocked`

Publication, promotion, and independent-review status remain governed by
`sdk-capability.json`.
