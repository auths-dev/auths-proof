# AP-071 v3 blank-candidate producer handoff, 25 October 2026

demo_co supplied a read-only observation contract for the interval after a
response-less Google `files.create` and before any population. Its unsigned
source commit is `8e27499`, and the frozen producer schema SHA-256 is
`f8208d99951d959ff1bdad9600b1947823a542b40c2ebf0561e348cf917b5d2e`.
Auths copied that schema as a pinned test-only input; it did not implement or
run the producer probe.

The observation requires a fresh v3 five-child baseline, then a candidate
with the exact signed ID, title and public marker, sole Project A parent,
shared Drive, and creation time within five minutes of the baseline. The
producer checks a complete six-child inventory, preservation of all five
neighbor raw exports and canonical Project A/B state, and the still-blank
Docs layout with a three-byte BOM-only export. Auths's consumer checks these
fields against owner-private baseline and candidate pins. Its synthetic suite
passes the exact case and refuses changed marker, child ID, baseline digest,
neighbor verdict, blank digest/length and late creation time.

The producer command is `demo_co google create-inspect-v3-candidate`, with a
baseline generation/SHA and exact candidate ID/title/marker. No new baseline,
create, interim observation or final observation has run for this contract.
The producer artifact states provider facts only. Auths still needs the
fresh human-signed recovery binding and a gateway admission path before a
found child can be populated.

Auths also added a test-only join from its owner-private Jules recovery
search report to this producer artifact. It requires a pinned report digest,
one exact candidate, matching original task/create operation and baseline,
the same candidate ID/marker/parent/drive, and the same Jules subject and
connection generation. It refuses zero/multiple status, changed IDs, changed
account facts and any report claiming child authority. The joined verdict
remains evidence for a later human review, never a child permission itself.
