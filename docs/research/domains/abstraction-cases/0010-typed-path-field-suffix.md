# Case 0010: fixed suffix after a verified path field

## Candidate

Some HTTPS APIs place a fixed operation name or representation extension in
the **same path segment** as a resource identifier. A recipe containing only
whole fixed and whole field segments cannot represent that route without
moving the suffix into the agent's field value or pinning one resource ID in
each recipe. Both would make the human-to-agent action less clear.

| Independent API reference | Documented path | Domain semantics kept outside the gateway |
| --- | --- | --- |
| [Google Docs `documents.batchUpdate`](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/batchUpdate) | `POST /v1/documents/{documentId}:batchUpdate` | Docs permission, revision meaning, tab and replacement semantics |
| [Twilio Message resource](https://www.twilio.com/docs/messaging/api/message-resource) | `GET /2010-04-01/Accounts/{AccountSid}/Messages/{Sid}.json` | Message SID/account meaning, response format and any redaction/send effect |

These independent references establish a path-construction need, not an
installed Twilio connection or a live Google edit. AP-SPEC-071's
[Google edit reference](../../../../demos/google-employee-delegation/write_reference/README.md)
supplies the first compiled recipe. A second installed provider recipe and
hostile tests are still needed before promoting this as qualified production
coverage.

## Shared mechanism and boundary

`field-suffix` names one existing typed profile field and one fixed suffix.
The compiler accepts 2–32 ASCII bytes: `:` or `.` followed only by letters,
digits, `_` or `-`. It refuses `/`, `?`, `#`, `%`, control bytes, dot traversal
and an empty suffix. The constructor percent-encodes the verified field as a
single path segment and then appends the approved suffix. The agent supplies
neither suffix nor URL. The operator review shows `<field>:operation` or
`<field>.json`, and the compiled recipe digest commits to the suffix.

The gateway never interprets `batchUpdate` or `.json`. It constructs bytes
and preserves the existing pinned-origin, credential, response and replay
rules. A provider's method, effect, account scope, retry safety and response
meaning remain in its vertical. Credential-only guard reads continue to
require fully fixed paths.

## Evidence and promotion gate

The local gateway compiler tests cover Google's colon path, encoded
slash/query characters in the field, rejected unsafe suffixes and review
output. Twilio's extension shape is documented independent demand, not an
installed conformance test. The existing kernel constructor remains unchanged.
That is construction evidence only.
Qualification still requires a second installed HTTPS recipe using the same
`field-suffix` constructor; provider counting and differential comparison of
the exact request URL; mutation of field, suffix and recipe digest; and a
gateway lifecycle/replay check. An operator must explicitly approve each
recipe digest. No unreviewed recipe or provider-specific production branch is
authorized by this case.
