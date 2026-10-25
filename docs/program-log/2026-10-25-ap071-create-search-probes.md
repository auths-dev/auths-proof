# AP-071 read-only create-recovery search probes, 25 October 2026

At 22:14 UTC, Auths used the existing Jules Google grant and the reviewed
`search_jules_created_child` runner against the live Atlas Project A folder.
The runner leased a subject-checked Jules credential, exhausted the Drive
marker search and, for a sole candidate, rechecked metadata by exact ID.
It made no create, populate, update or delete request.

The operator used the same private write evidence SHA-256
`f3dff8ba878766fd77304af6c5f4cac4c7baef113b011a4a4335cc1b5fbb9717`
and credential pins SHA-256
`cd29c3c2a3d4cf27252a21668200d914415fda7d926fa0fabcd0a21b35656570`
as the earlier paired run. The existing marker
`ap071_6c707f5bfed71ae8ea8fdcd045d14a20` returned exactly the preserved
child `17AyVwNPIaKOlfFbOx7rjt76Fgf7k_M8EnWb_4-Cnhj4`. A never-used
marker `ap071_00000000000000000000000000000000` returned no candidate.
The live operator output disclosed no credential or document content.

demo_co independently checked the preserved child's unique marker, title,
sole Project A parent, shared-drive ID and populated raw export commitment
from its admin view. It found five current direct Project A children and zero
hits for the never-used marker. Its historical reference is producer
generation 0007, SHA-256
`6ddec2c52642fba0c0a09fec83fbd0d0be0aaa43fec699adec63c749fea0b7cb`.
The admin view did not change the fixture or create new evidence files.

The focused parser and runner suites passed 6 and 3 tests respectively on
this branch, including injected duplicate, incomplete, paginated and capped
search responses. Those cases did not occur in the live provider probes.
The one-match result is **only a candidate**: this run had no lost create
response, active signed recovery task, independent new-child verdict or
human-signed recovered-child binding. Zero matches do not prove non-creation
and cannot authorize a create retry. The full installed lost-response matrix
and guided recovery remain open under [AP-SPEC-071](../specs/0071-human-agent-read-write-delegation-demo.md).
