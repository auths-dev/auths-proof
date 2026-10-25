# Google Drive text release reference for AP-SPEC-071

The generated [profile lock](profile.lock.json) and [recipe](recipe.json) are
operator-review inputs for the managed read-release capability in
[AP-SPEC-071](../../../docs/specs/0071-human-agent-read-write-delegation-demo.md).
They compile a credential-free GET of one verified Google file ID at
`/drive/v3/files/{resource_id}/export?mimeType=text/plain`. The response must
be a complete `200` `text/plain` body of at most 64 KiB; at most 16 KiB may be
projected for one release. The compiler test checks the exact path, encoded
query, recipient binding and text projection against this checked-in source.

The profile has bounded operation, task, agent and resource fields. Its
`resource_id` limit is 64 bytes; demo_co has observed 44-byte IDs for existing
canonical Docs, but must check the selected source ID in each export. Auths
task admission must prove that this ID is among the human's exact approved
sources before the credential-owning process calls Google. This recipe alone
does not prove that permission, identify Jules's OAuth subject, send content,
charge budgets or acknowledge delivery. It is **not installed release
evidence** and does not replace AP-SPEC-070's present application-owned read
broker.

The production release engine must bind a subject and credential generation,
count the provider call, enforce a complete response and task budget, durably
claim the release before agent-channel entry, and emit only the keyed redacted
receipt. An independent demo_co probe must compare private source bytes with
the bytes the agent was allowed to receive without publishing either body.
