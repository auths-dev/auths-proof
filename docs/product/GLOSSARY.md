# Auths product glossary

Auths lets software prove exactly what it may do, execute through a closed
action family, and leave a signed receipt.

## The five security nouns

| Term | Plain meaning | Boundary |
| --- | --- | --- |
| Identity | Who or what is presenting a credential | Identity does not grant permission. |
| Authority | The bounded things an identity may do | Delegation can only make authority narrower. |
| Action | The exact proposed operation | An action is inert data. |
| Approval | Optional confirmation of the exact transaction | Approval is not authority. |
| Receipt | Signed evidence of a decision or observed effect | A receipt cannot be replayed as permission. |

`Result` is an ordinary language return value, not a sixth security concept.

## The five product verbs

| Verb | Outcome |
| --- | --- |
| `create` | Bind an Auths instance to identity, authority, trust, and resources. |
| `delegate` | Give another identity narrower authority. |
| `execute` | Authorize and run an exact action through its qualified action family. |
| `resume` | Continue a commitment-bound incomplete execution. |
| `verify` | Evaluate proof or receipt evidence without executing an effect. |

`authenticate` proves control of identity material over exact bytes. `approve`
confirms one exact transaction. Neither creates authority.

## Progressive precision

Beginner documentation says “trust configuration,” “action family,” “ordered
plan,” “opaque authorized command,” “execution reservation,” and “execution
state.” Framework and protocol documentation uses the exact underlying terms
when those distinctions become relevant.

The machine-readable vocabulary contract is
[`sdk-glossary.json`](sdk-glossary.json). `cargo xtask sdk-vocabulary` checks
beginner language and projects every current TypeScript and Python export onto
its owner layer without creating another API snapshot.
