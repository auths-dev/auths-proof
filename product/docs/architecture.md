# Architecture

```text
official rmcp CallToolRequestParams
                |
                v
     canonical MCP call profile
                |
        proof-exchange port
                |
                v
      MCP authorization service
        |       |         |
     replay   Auths     channel
     ledger   verifier   policy
        \       |         /
         +------+--------+
                |
                v
           tool executor
```

`auths-profile-mcp` maps MCP semantics to exact signed bytes and an
Auths permission. It does not verify proofs or depend on networking.

`auths-runtime` owns application challenge consumption, Auths trust
composition, transport policy, permission cross-checking, and the
authorization-before-execution gate. It depends only on the semantic exchange
port, never Iroh.

`auths-evidence-assemblers` owns effectful conversion of live WebAuthn,
SPIFFE/X.509, and HSM observations into exact content-addressed evidence.
`auths-custody` owns external signing intents and transaction-binding checks;
it contains no private keys or provider SDKs.

`auths-config` compiles declarative policy into an explicit context binding.
`auths-stores` supplies single-process durable reference implementations for
challenge, budget, and receipt state. `auths-operations` binds readiness and
privacy-preserving events to the compiled configuration. None of these
components can construct an Auths verdict or sealed verified action.

`auths-apps-testkit` is the lab composition boundary. It selects in-memory or
Iroh transport and carries deterministic test signers. Test signing keys and
Iroh types do not enter production service crates.
