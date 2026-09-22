# Developer gateway type map (AP-SPEC-053)

This is the implementation type review required by AP-SPEC-053 §4. The first
journey is one customer-run gateway, three independently authored operations,
one credential header per connection, and no provider-effect qualification.

## UX

The developer generates an `ExactMcpTool` from `profile.toml`, compiles a
closed recipe against `profile.lock.json`, and submits proof plus canonical
action bytes. The operator reviews the compiled origin, request shape, schema
digest, and recipe digest before binding a credential. The app never sends a
URL, method, header, body, or token to the gateway. The result distinguishes
proof authorization, provider entry, response recording, ambiguity, and
read-only observation.

## Architecture

```text
developer profile + recipe -> typed compiler -> immutable digest
                                               |
operator trust + connection + credential ------+--> separate gateway
app proof + action -----------------------------+        |
                                                      closed HTTPS request
```

`auths-profile-mcp::McpToolCall` and `McpProfile` own the canonical action
and verified-command projection. `auths-verifier::verify_v1_sealed` owns
authorization. `auths-connections::ConnectionBinding`, `ConnectionId`,
`ConnectionState`, `ConnectionCredentialStore`, `SecretBytes`, and generation
own credential identity and custody. The gateway must not recreate these.
SDK `AttemptStore::confirmed` is adapter acceptance, not gateway effect
evidence; `auths-lifecycle::Committed` is not a projection of an HTTP response.

| New type / owner | Invariant | Why an existing type is insufficient |
| --- | --- | --- |
| `auths-gateway::OperatorNamespace` | 1–64 canonical ASCII token bytes, operator-approved literal | `SemanticId` permits `:` and `/` and is not an operator/account replay namespace. |
| `auths-gateway::LogicalOperationId` | 1–128 canonical ASCII token bytes; replay key independent of proof challenge | `OperationId` names a local-agent operation, not a durable cross-proof logical request. |
| `auths-gateway::CompiledRecipe` | bounded, validated, digest-stable request grammar tied to a profile lock | `ExactMcpTool` owns action shape, not outbound HTTP mapping. |
| `auths-gateway::ClosedProviderRequest` | request built only from a native-verified command and approved literals | Provider-specific commands cannot express a self-service closed transport mapping. |
| `auths-gateway::GatewayAttemptStage` | `not-entered`, `attempting`, `response-recorded`, `unknown`, `observed` | SDK `confirmed` and lifecycle `Committed` make stronger or different claims. |
| `auths-gateway::GatewayConnectionDescriptor` | canonical data-only descriptor binds one namespace, recipe digest, and gateway-injected credential header | `ConnectionBinding` carries an opaque provider descriptor but does not parse the gateway-specific recipe grammar. It remains the owner of connection ID, account commitment, and generation. |
| `auths-gateway::GatewaySubmitResult` | disjoint proof refusal, no-entry, ambiguous entry, response, and observation outcomes | A generic verifier result has no transport stage; SDK `confirmed` overstates what an HTTP response establishes. |
| `auths-gateway::GatewayEngine` | independently provisioned trust and approved digest are fixed before an app can submit proof/action bytes | Self-hosted SDK verification runs inside the credential-owning app and cannot enforce the deployment boundary. This coordinator still needs a separate service and adversarial deployment test before a non-bypassable claim. |

The lock-file parser and recipe source AST are private input-boundary types.
They reject unknown fields before producing `CompiledRecipe`. Public types have
private fields and validating constructors. No callback receives a credential.

## APIs

- `CompiledRecipe::compile(recipe_bytes, profile_lock_bytes)` validates the
  source and emits an immutable digest and review summary; it grants no
  execution authority.
- A sealed `McpCommand` plus a compiled recipe produces a
  `ClosedProviderRequest`; there is no public constructor from caller HTTP.
- The application socket accepts only proof and canonical action bytes. The
  operator channel separately installs the recipe and credential binding.
  That service/channel is not yet implemented by the compiler and coordinator
  alone; no isolated-deployment claim follows from this type map.

The three fixture profiles deliberately contain only root scalar fields.
Nested profile fields, dynamic query parameters, optional body omission, and
provider-specific response interpretation remain rejected in the first
compiler version. The Airtable gateway operation omits the app-owned demo's
`expected` precondition because a post-write observation cannot enforce it;
the two modes must not pretend to have identical provider semantics.
