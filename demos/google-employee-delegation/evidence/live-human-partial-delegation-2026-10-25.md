# Operator-assisted Jules delegation: partial live evidence

On 25 October 2026, a human used the loopback partial delegation lab to
review and sign one exact Project A task with a new non-exportable browser
Ed25519 key. The lab verified the signature on the native employee-to-agent
grant, then used a distinct agent key to sign the exact MCP read action.

The redacted, owner-only result was saved outside the repository. Its SHA-256
is `ff98eb87ff8404644d0832afb56be7feb9a7d66222a21ec516f5ae65fdd3f789`.
The producer's independently reviewed partial report has SHA-256
`4d9132c5457e1a7a7ea75624cf28febea0312c50925edab95f1f1700ed2318da`.

| Check | Observed |
| --- | --- |
| Browser key signature | Verified on native child grant |
| Distinct agent principal and action signature | Yes |
| Native authorization | `authorized` |
| Project A | 1,249 bytes released; two Google requests; content hash matched producer |
| Project B | Excluded task challenge denied before provider request |
| Signed receipt | Verified |
| After revocation | New challenge denied |

**Scope of evidence:** Google verified Jules's previously issued grant, but
did not authenticate the human at this browser as Jules. The distinct agent
key ran in the diagnostic broker process, not an isolated agent process.
The demo_co versioned Google export was unavailable, so this run did not
activate the production importer or broker-owned OAuth vault. It is not full
AP-SPEC-070 acceptance. The signed run used the lab source in the worktree
before it was committed; the result digest pins that run, but this record
does not claim a clean committed-revision rerun.
