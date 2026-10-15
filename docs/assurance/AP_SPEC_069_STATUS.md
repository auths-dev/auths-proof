# AP-SPEC-069 implementation status

This is the implementation ledger for
[AP-SPEC-069](../specs/0069-authorization-to-execution-formal-assurance.md).
It is not an assurance claim. Completion requires the specification's exact
shipping-source refinement and hosted evidence gates.

| Milestone | State | Evidence / remaining work |
| --- | --- | --- |
| M0: claims and extraction slices | In progress | The spec fixes 24 obligations. The new shipping CBOR head reader/encoder translate under the pinned strict Charon/Aeneas route. The independent head model proves fixed-width integer and canonical head round trips. The production refinement, audited inventory, and reproducible qualification still need to be joined. |
| M1: complete codec | In progress | The object codecs now use the in-repository CBOR reader/encoder; the previous dependency is a test oracle. Differential hostile-input properties and existing corpus/fixture checks need hosted validation. Object/carrier, work/allocation bounds, and complete codec refinements remain required. |
| M2: crypto integration | Pending | E5.1–E5.4. |
| M3: complete verifier | Pending | E2.1–E2.5. |
| M4: mapping and driver | Pending | E3.1–E3.5. |
| M5: history and storage | Pending | E4.1–E4.6, including collection fencing and authority-derived entry expiry. |
| M6: composed assurance | Pending | Final history theorem, adequacy review, and exact-release evidence. |

No E1–E5 workstream is complete yet. Existing component claims retain their
current scope; new source or a successful model proof alone does not expand
the public assurance claim.
