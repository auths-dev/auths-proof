# Independent reviews

Place public review reports below this directory. Each completed review record
must name an external reviewer and affiliation, carry the report digest and
retention date, classify every finding, and leave no critical or high finding
open. A remediation that changes executable bytes belongs to a new candidate.

No independent review has been claimed for this candidate.

Record completion with one `auths.assurance-review/1` object containing the
exact candidate digest and a `complete` review value. Each report is a bounded
local path below the candidate directory plus its SHA-256 and retention date.
The Rust verifier rejects missing or modified reports and every unresolved
critical or high finding.
