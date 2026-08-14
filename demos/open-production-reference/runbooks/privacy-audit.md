# Privacy audit

Capture logs, metrics, traces, crash output, dashboard queries, and assurance
records while exercising maximum-sized hostile inputs. Search the capture for:

- raw authority, proof, action, plan, and receipt bytes;
- recovery references and disclosure authorizations;
- provider credentials, KMS ARNs, PKCS#11 PINs, database URLs, and tokens;
- repository candidates, SQL values, OpenTofu variables, and full identities;
- unbounded caller labels or provider error strings.

Expected operational dimensions are closed enums, bounded numeric buckets,
semantic/build identifiers, and qualified profile identifiers. A prohibited
value blocks the candidate. Redaction after export is not an acceptable fix;
remove the value at the Rust projection boundary.
