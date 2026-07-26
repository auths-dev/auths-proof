# Auths Software Supply-Chain Action Profile V1

**Profile:** `auths.supply-chain/1`  
**Media type:** `application/vnd.auths.supply-chain-action.v1+json`

The closed RFC 8785 JSON schema binds one operation (`approve`, `attest`,
`publish`, or `release`), a lowercase SHA-256 subject digest, an explicit
predicate-type token, and an explicit builder token.

```text
capability = supply-chain/<operation>
resource   = supply-chain://subjects/<subject digest>
```

Auths proves permission to perform or approve the operation. It does not claim
that a builder ran or an artifact has provenance; in-toto, Sigstore, or other
evidence must establish those facts separately. The verified decoder
re-derives the permission from canonical bytes, and the approval display binds
the subject, predicate, builder, operation, and action digest.

