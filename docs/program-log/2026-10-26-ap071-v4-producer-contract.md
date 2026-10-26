# AP-071 six-to-seven-child producer contract, 26 October 2026

demo_co committed a forward-only v4 Project A inspector at
`0724645b8c1a66b68c4b8a8a4e9d9cc4b31dfc92`. It does not create or edit a
Google file. The existing six-child Project A inventory remains the input.
This contract exists for a **new** same-build response-less create run; it
does not reinterpret the earlier v3 five-to-six-child evidence.

Auths pins frozen copies of three producer schemas:

| Artifact | Schema SHA-256 |
| --- | --- |
| `google-create-v4-baseline-v1.schema.json` | `0532aaa734fc0d0ff80fdc2f190bffbcfb6b157bd06311c2a862491cce677e4a` |
| `google-create-v4-candidate-blank-v1.schema.json` | `1faaf0a27b7585bc73e740fe3767d551a57a3c5ebfedee7ca32e9ca2b390d9ec` |
| `google-create-observation-v4.schema.json` | `e62d06be69358da61baef197dc5c2c360e7bff6674e94bbd38279a6f6a6e656b` |

The pre-create baseline must pin the v3 generation-0018 baseline and
generation-0020 final hashes, all six direct Project A children with their
exact raw export hashes and lengths, three prior recovery markers, unchanged
canonical Project A/B documents and Jules's Project B write denial. Auths
requires the generation path and file digest to match owner-private pins and
the baseline to be no more than five minutes old before the one-shot create.

After an unknown create, Jules's subject-bound, complete marker search and
demo_co's independent blank seventh-child observation must name the same
unique candidate. The blank observation requires the exact folder, title,
marker, seven-child inventory, preserved neighbors, blank Docs layout and
three-byte BOM export. The operator join grants no authority by itself: the
gateway still requires its original unknown attempt, a new Jules recovery
signature, a fresh credential-bearing metadata GET and one durable child
binding. The final v4 observation binds that blank candidate and compares
the exact raw populated export hash and byte count supplied by the approved
plan, plus unchanged neighbors and canonical Docs.

The Auths v4 consumer is test-only evidence interpretation. The gateway's
provider-neutral native task, budgets, credential custody and data-only
recipes continue to own read release and both writes. A successful v4
producer observation alone cannot claim an authorized Auths effect.
