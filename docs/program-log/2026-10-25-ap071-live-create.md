# AP-071 live Project A create, awaiting population

On 25 October 2026, Jules signed a 30-minute task delegating one bounded
Project A read and at most two writes to a separately registered agent. The
agent signed and acknowledged the source read, signed an exact create
proposal, and signed a short draft derived from the released source. Jules
then signed one exact two-effect plan for a Project A handoff Doc and its
complete initial text. The gateway submitted one Google Drive `files.create`
using Jules's held grant and journaled an observed outcome and a bound child.

The child is `17AyVwNPIaKOlfFbOx7rjt76Fgf7k_M8EnWb_4-Cnhj4`, under the
signed Project A folder `1ZtmuBMypwxDZ_onYgV3tspl-_Mzv_8SA`, titled
`Auths AP-071 Project A handoff`, with recovery marker
`ap071_6c707f5bfed71ae8ea8fdcd045d14a20`. The create operation ID is
`CyzLIqfY0DdJMg08dv8EVNTX`. There was exactly one create submission; do
not retry it. The original demo_co pre-create observation is generation 3,
SHA-256 `49693171eab7f3fdd386ad17f85f1181594943ba94bd0eeaae2ef483f9990a2a`,
at 16:45:58 UTC. Google's `createdTime` is 16:46:27.888 UTC, within that
observation's five-minute window.

demo_co independently read the exact child and found the signed title,
parent, shared drive, marker and Google Docs MIME type, one unique marker
match, an exact three-child folder inventory, and no change to the working or
canonical Project A/B Docs. The new child is still blank. Its Docs body has
one section break followed by one paragraph containing only the terminal
newline; Drive's three-byte plain-text export is solely a UTF-8 BOM.

Population did not enter Google. The live task installation omitted the
mandatory `populate_preflight` signer pin, and the original effect plan
expired at 16:48:33 UTC before the omission was discovered. The gateway
returned `gateway.task.preflight-not-installed`. Its journal does not allow
replacing an effect plan after the create, so this plan cannot be silently
extended or reused. The correct continuation is a new, human-approved,
populate-only task scoped to this exact existing child and exact draft, with
a fresh Jules credential-bearing check of metadata, `canEdit`, tab and
revision. It must issue no second create. After one revision-guarded insert,
demo_co should run `google create-inspect` against the original generation 3
baseline and inspect the working Doc and excluded files again.

The broker now refuses to prepare a paired create/populate card without the
preflight pin, accepts the observed blank Docs structure, and gives a newly
signed effect plan a 15-minute execution window bounded by the task expiry.
The signing challenge itself still expires after five minutes. These changes
were exercised by 18 focused broker tests. They do not retroactively change
the signed plan or the live installed gateway state.
