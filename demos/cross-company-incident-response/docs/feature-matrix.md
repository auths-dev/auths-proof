# Auths feature evidence

| Feature | Screen | Automated evidence |
|---|---|---|
| P-256 and Ed25519 identities | Actors | `test_cross_sdk_fixture_python_projection`, browser verification test |
| authority attenuation | Authority graph, attack lab | browser scope-expansion control with zero signer calls |
| exact domain profile actions | Plan review | browser `buildIncidentPlan`, control-room unit tests |
| ordered plan commitment | Plan review | TypeScript SDK `profile.plan` and browser smoke test |
| threshold approval | Approvals | TypeScript SDK `thresholdApproval`, integration test |
| review / approval separation | Plan review, timeline | state-machine tests |
| one-use execution / replay | Receipts, attack lab | `test_replay_and_runtime_transitions` |
| lifecycle and rotation | Actors, attack lab | `test_rotation_recipe` |
| HTTPS transport | delivery cards | local integration test |
| Iroh transport neutrality | delivery cards, attack lab | `real_iroh_delivery_is_semantics_free` and integration test |
| unknown outcomes | attack lab, receipts | `test_failure_matrix` |
| cross-SDK agreement | Receipt inspector | Python fixture test and browser fixture test |
| non-forgeable command | execution timeline | TypeScript compile/runtime tests inherited from SDK plus browser gateway path |
