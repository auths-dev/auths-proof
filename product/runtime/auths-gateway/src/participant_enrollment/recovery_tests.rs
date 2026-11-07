//! Full native holder/control/resource proofs for the first commissioned
//! successor lifecycle. Public fixture keys only; no process-isolation claim.
use super::*;
use crate::participant_enrollment::EnrollmentLifecycle;

struct RecoveryFixture {
    original: Fixture,
    successors: [Signer; 3],
    controls: [SignedGrant; 3],
    resources: [SignedGrant; 3],
    tree: EnrollmentTree,
    predecessor: [u8; 32],
    descendant: [u8; 32],
    descendant_action: Submission,
}
impl RecoveryFixture {
    fn new() -> Self {
        Self::with_generations(1, [2, 2, 3])
    }
    #[expect(
        clippy::too_many_lines,
        reason = "retain the complete explicit signed fixture or hostile-case matrix as one reviewable construction"
    )]
    fn with_generations(old_generation: u64, generations: [u64; 3]) -> Self {
        let mut original = Fixture::with_depth(0x44, 2);
        original.enrollment.child_instance_generation = old_generation;
        original
            .pins
            .permitted_channels
            .get_mut("agent-b-channel")
            .unwrap()
            .instance_generation = old_generation;
        original.enrollment.ceilings.provider_reads = 1;
        original.enrollment.not_before = NOW - 1;
        original.enrollment.expires_at = NOW + 100;
        let mut extra = original.pins.scopes[0].clone();
        extra.scope_id = "project-b-read".into();
        extra.resource = EnrollmentResourceBinding::Exact {
            handle: "record-b".into(),
        };
        original.pins.scopes.push(extra);
        let successors = [Signer::new(0x66), Signer::new(0x77), Signer::new(0x88)];
        for (index, signer) in successors.iter().enumerate() {
            original.pins.permitted_channels.insert(
                format!("standby-{index}"),
                EnrollmentChannelPins {
                    channel_binding: [u8::try_from(0x66 + index).unwrap(); 32],
                    principal: signer.principal.clone(),
                    instance_generation: generations[index],
                },
            );
        }
        let old_descendant = Signer::new(0x55);
        original.pins.permitted_channels.insert(
            "old-descendant".into(),
            EnrollmentChannelPins {
                channel_binding: [0x55; 32],
                principal: old_descendant.principal.clone(),
                instance_generation: 1,
            },
        );
        original.commit_root();
        let controls = std::array::from_fn(|index| {
            grant(
                &original.parent,
                &successors[index],
                PARTICIPANT_SERVICE,
                CONTROL_TOOLS,
                Some(grant_id(original.parent_control.statement()).unwrap()),
                1,
            )
        });
        let resources = std::array::from_fn(|index| {
            grant_for_audiences(
                &original.parent,
                &successors[index],
                RESOURCE_SERVICE,
                &[RESOURCE_TOOL],
                Some(grant_id(original.parent_resource.statement()).unwrap()),
                1,
                original
                    .parent_resource
                    .statement()
                    .audiences()
                    .as_slice()
                    .to_vec(),
            )
        });
        let activation = original.root_activation(&original.pins);
        let witnesses: Vec<_> = original
            .pins
            .scopes
            .iter()
            .map(|scope| {
                let EnrollmentResourceBinding::Exact { handle } = &scope.resource else {
                    panic!("exact fixture scope")
                };
                original.root_resource(handle, &original.parent_resource)
            })
            .collect();
        let witnesses: Vec<_> = original
            .pins
            .scopes
            .iter()
            .zip(&witnesses)
            .map(|(scope, proof)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(proof),
            })
            .collect();
        let mut tree = EnrollmentTree::bootstrap(
            &original.context,
            &original.pins,
            NOW,
            &RootEnrollmentProofs {
                activation: invocation(&activation),
                resources: &witnesses,
            },
        )
        .unwrap();
        let predecessor = original.enroll_tree(&mut tree).unwrap();
        let descendant_control = grant(
            &original.child,
            &old_descendant,
            PARTICIPANT_SERVICE,
            CONTROL_TOOLS,
            Some(grant_id(original.child_control.statement()).unwrap()),
            0,
        );
        let descendant_resource = grant_for_audiences(
            &original.child,
            &old_descendant,
            RESOURCE_SERVICE,
            &[RESOURCE_TOOL],
            Some(grant_id(original.child_resource.statement()).unwrap()),
            0,
            original
                .parent_resource
                .statement()
                .audiences()
                .as_slice()
                .to_vec(),
        );
        let parent_pins = tree.parent_pins(predecessor, NOW).unwrap();
        let mut descriptor = child_descriptor(
            &old_descendant,
            &descendant_control,
            &descendant_resource,
            &parent_pins,
        );
        descriptor.enrollment_id = "old-descendant".into();
        descriptor.delivery_channel = "old-descendant".into();
        descriptor.remaining_depth = 0;
        descriptor.not_before = parent_pins.not_before;
        descriptor.expires_at = parent_pins.expires_at;
        let parent = chained(
            &[&original.root, &original.parent, &original.child],
            &[&original.parent_control, &original.child_control],
            PARTICIPANT_SERVICE,
            ENROLL_PARTICIPANT_TOOL,
            json!({"enrollment":descriptor}).as_object().unwrap(),
        );
        let child = chained(
            &[
                &original.root,
                &original.parent,
                &original.child,
                &old_descendant,
            ],
            &[
                &original.parent_control,
                &original.child_control,
                &descendant_control,
            ],
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            json!({"enrollment_commitment":descriptor.commitment().unwrap()})
                .as_object()
                .unwrap(),
        );
        let descendant_action = chained(
            &[
                &original.root,
                &original.parent,
                &original.child,
                &old_descendant,
            ],
            &[
                &original.parent_resource,
                &original.child_resource,
                &descendant_resource,
            ],
            RESOURCE_SERVICE,
            RESOURCE_TOOL,
            json!({"record_id":"record-a"}).as_object().unwrap(),
        );
        let witnesses = [EnrollmentResourceWitness {
            scope_id: "project-a-read",
            invocation: invocation(&descendant_action),
        }];
        let descendant = tree
            .enroll(
                &original.context,
                predecessor,
                NOW,
                &ParticipantEnrollmentProofs {
                    parent: invocation(&parent),
                    child: invocation(&child),
                    resources: &witnesses,
                },
            )
            .unwrap();
        assert!(
            tree.verify_operation_scope(
                &original.context,
                "project-a-read",
                NOW,
                &invocation(&descendant_action)
            )
            .is_ok()
        );
        Self {
            original,
            successors,
            controls,
            resources,
            tree,
            predecessor,
            descendant,
            descendant_action,
        }
    }
    fn proposal(&self, index: usize, predecessor: [u8; 32]) -> ParticipantEnrollment {
        let mut descriptor = self.original.enrollment.clone();
        descriptor.lifecycle = EnrollmentLifecycle::Recover { predecessor };
        descriptor.child_principal = self.successors[index].principal.as_str().into();
        descriptor.child_instance_generation =
            self.original.pins.permitted_channels[&format!("standby-{index}")].instance_generation;
        descriptor.enrollment_id = format!("recovered-{index}");
        descriptor.delivery_channel = format!("standby-{index}");
        descriptor.control_grant = *grant_id(self.controls[index].statement())
            .unwrap()
            .as_bytes();
        for scope in &mut descriptor.scopes {
            scope.grant_id = *grant_id(self.resources[index].statement())
                .unwrap()
                .as_bytes();
        }
        descriptor
    }
    fn enroll(
        &self,
        tree: &mut EnrollmentTree,
        index: usize,
        descriptor: &ParticipantEnrollment,
    ) -> Result<[u8; 32], EnrollmentTreeError> {
        let parent = self.original.parent_proof(descriptor);
        let child = chained(
            &[
                &self.original.root,
                &self.original.parent,
                &self.successors[index],
            ],
            &[&self.original.parent_control, &self.controls[index]],
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            json!({"enrollment_commitment":descriptor.commitment().unwrap()})
                .as_object()
                .unwrap(),
        );
        let signed: Vec<_> = descriptor
            .scopes
            .iter()
            .map(|scope| {
                let pins = self
                    .original
                    .pins
                    .scopes
                    .iter()
                    .find(|pin| pin.scope_id == scope.scope_id);
                let handle = pins
                    .and_then(|pins| match &pins.resource {
                        EnrollmentResourceBinding::Exact { handle } => Some(handle.as_str()),
                        EnrollmentResourceBinding::CreatedChild { .. } => None,
                    })
                    .unwrap_or("record-a");
                chained(
                    &[
                        &self.original.root,
                        &self.original.parent,
                        &self.successors[index],
                    ],
                    &[&self.original.parent_resource, &self.resources[index]],
                    RESOURCE_SERVICE,
                    RESOURCE_TOOL,
                    json!({"record_id":handle}).as_object().unwrap(),
                )
            })
            .collect();
        let resources: Vec<_> = descriptor
            .scopes
            .iter()
            .zip(&signed)
            .map(|(scope, signed)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(signed),
            })
            .collect();
        tree.enroll(
            &self.original.context,
            self.original.pins.enrollment_commitment,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &resources,
            },
        )
    }
    fn withdraw(&mut self, participant: [u8; 32]) {
        let proof = self.original.withdraw_as_parent(participant);
        self.tree
            .revoke_authorized(&self.original.context, NOW, &invocation(&proof))
            .unwrap();
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "retain the complete explicit signed fixture or hostile-case matrix as one reviewable construction"
)]
fn recovery_relation_matrix() -> Value {
    let mut maximum =
        RecoveryFixture::with_generations(MAX_JSON_INTEGER - 1, [MAX_JSON_INTEGER; 3]);
    maximum.withdraw(maximum.predecessor);
    let max_proposal = maximum.proposal(0, maximum.predecessor);
    let mut max_tree = maximum.tree.clone();
    let max_id = maximum.enroll(&mut max_tree, 0, &max_proposal).unwrap();
    assert_eq!(
        max_tree.capacity_origin(max_id).unwrap(),
        maximum.predecessor
    );
    let mut overflow = RecoveryFixture::with_generations(MAX_JSON_INTEGER, [1, 1, 1]);
    overflow.withdraw(overflow.predecessor);
    let wrapped = overflow.proposal(0, overflow.predecessor);
    let mut wrapped_tree = overflow.tree.clone();
    assert!(
        overflow.enroll(&mut wrapped_tree, 0, &wrapped).is_err(),
        "maximum instance generation wrapped or regained a fresh allowance"
    );
    for malformed in [
        json!({"kind":"fresh","predecessor":vec![0u8;32]}),
        json!({"kind":"recover"}),
        json!({"kind":"renew"}),
        json!({"kind":"recover","predecessor":[1,2,3]}),
        json!({"kind":"recover","predecessor":vec![0u8;32],"extra":true}),
        json!("fresh"),
    ] {
        assert!(
            serde_json::from_value::<EnrollmentLifecycle>(malformed.clone()).is_err(),
            "malformed lifecycle accepted: {malformed}"
        );
    }
    let mut fixture = RecoveryFixture::new();
    let base = fixture.proposal(0, fixture.predecessor);
    let unchanged = fixture.tree.encode().unwrap();
    let mut current = fixture.tree.clone();
    assert!(
        fixture.enroll(&mut current, 0, &base).is_err(),
        "active predecessor recovered"
    );
    assert_eq!(current.encode().unwrap(), unchanged);
    fixture.withdraw(fixture.predecessor);
    let frozen = fixture.tree.encode().unwrap();
    let mut cases = Vec::new();
    for name in [
        "obsolete-schema",
        "unknown-predecessor",
        "root-predecessor",
        "wrong-parent",
        "skipped-generation",
        "uncommissioned-holder",
        "widened-reads",
        "changed-ceiling",
        "earlier-validity",
        "later-expiry",
        "widened-scope",
        "old-control-grant",
        "old-resource-grant",
        "old-principal",
        "zero-instance",
    ] {
        let mut changed = base.clone();
        let mut signer = 0;
        match name {
            "obsolete-schema" => changed.schema = "auths.participant-enrollment/1".into(),
            "unknown-predecessor" => {
                changed.lifecycle = EnrollmentLifecycle::Recover {
                    predecessor: [0xA0; 32],
                }
            }
            "root-predecessor" => {
                changed.lifecycle = EnrollmentLifecycle::Recover {
                    predecessor: fixture.original.pins.enrollment_commitment,
                }
            }
            "wrong-parent" => changed.parent_enrollment = [0xA1; 32],
            "skipped-generation" => {
                changed = fixture.proposal(2, fixture.predecessor);
                signer = 2;
            }
            "uncommissioned-holder" => changed.delivery_channel = "unregistered".into(),
            "widened-reads" => changed.ceilings.provider_reads += 1,
            "changed-ceiling" => changed.ceilings.disclosure_bytes -= 1,
            "earlier-validity" => changed.not_before -= 1,
            "later-expiry" => changed.expires_at += 1,
            "widened-scope" => changed.scopes.push(ParticipantScopeGrant {
                scope_id: "project-b-read".into(),
                grant_id: *grant_id(fixture.resources[0].statement())
                    .unwrap()
                    .as_bytes(),
            }),
            "old-control-grant" => {
                changed.control_grant = fixture.original.enrollment.control_grant;
            }
            "old-resource-grant" => {
                changed.scopes[0].grant_id = fixture.original.enrollment.scopes[0].grant_id;
            }
            "old-principal" => {
                changed.child_principal = fixture.original.child.principal.as_str().into();
            }
            "zero-instance" => changed.child_instance_generation = 0,
            _ => panic!("case"),
        }
        let mut tree = fixture.tree.clone();
        assert!(
            fixture.enroll(&mut tree, signer, &changed).is_err(),
            "invalid recovery accepted: {name}"
        );
        assert_eq!(
            tree.encode().unwrap(),
            frozen,
            "refusal mutated tree: {name}"
        );
        cases.push(name);
    }
    let mut tree = fixture.tree.clone();
    let next = fixture.enroll(&mut tree, 0, &base).unwrap();
    assert_eq!(tree.capacity_origin(next).unwrap(), fixture.predecessor);
    assert_eq!(
        tree.parent_pins(next, NOW).unwrap().principal,
        fixture.successors[0].principal
    );
    assert_eq!(
        tree.parent_pins(fixture.predecessor, NOW),
        Err(EnrollmentTreeError::Inactive)
    );
    assert_eq!(
        tree.parent_pins(fixture.descendant, NOW),
        Err(EnrollmentTreeError::Inactive)
    );
    assert!(
        tree.verify_operation_scope(
            &fixture.original.context,
            "project-a-read",
            NOW,
            &invocation(&fixture.descendant_action)
        )
        .is_err()
    );
    let old_action = fixture.original.resource_proof("record-a");
    assert!(
        tree.verify_operation_scope(
            &fixture.original.context,
            "project-a-read",
            NOW,
            &invocation(&old_action)
        )
        .is_err()
    );
    let new_action = chained(
        &[
            &fixture.original.root,
            &fixture.original.parent,
            &fixture.successors[0],
        ],
        &[&fixture.original.parent_resource, &fixture.resources[0]],
        RESOURCE_SERVICE,
        RESOURCE_TOOL,
        json!({"record_id":"record-a"}).as_object().unwrap(),
    );
    assert!(
        tree.verify_operation_scope(
            &fixture.original.context,
            "project-a-read",
            NOW,
            &invocation(&new_action)
        )
        .is_ok()
    );
    let alternate = fixture.proposal(1, fixture.predecessor);
    let before = tree.encode().unwrap();
    assert!(
        fixture.enroll(&mut tree, 1, &alternate).is_err(),
        "forked successor accepted"
    );
    assert_eq!(tree.encode().unwrap(), before);
    fixture.tree = tree;
    fixture.withdraw(next);
    let third = fixture.proposal(2, next);
    let mut tree = fixture.tree.clone();
    let third = fixture.enroll(&mut tree, 2, &third).unwrap();
    assert_eq!(tree.capacity_origin(third).unwrap(), fixture.predecessor);
    assert_eq!(
        tree.parent_pins(next, NOW),
        Err(EnrollmentTreeError::Inactive)
    );
    let restored = EnrollmentTree::decode(&tree.encode().unwrap(), &fixture.original.pins).unwrap();
    assert_eq!(
        restored.capacity_origin(third).unwrap(),
        fixture.predecessor
    );
    assert_eq!(restored.participant_count(), 5);
    // Decoding cannot silently discard the predecessor's withdrawal or accept
    // a successor cycle. The writer format is one canonical current schema.
    let mut corrupt: Value = serde_json::from_slice(&tree.encode().unwrap()).unwrap();
    corrupt["children"][fixture.original.enrollment.enrollment_id.as_str()]["revoked"] =
        json!(false);
    assert!(
        EnrollmentTree::decode(
            &serde_json_canonicalizer::to_vec(&corrupt).unwrap(),
            &fixture.original.pins
        )
        .is_err()
    );
    let old = fixture.predecessor;
    json!({"schema":"auths.instance-recovery-vectors/1","native_invalid_cases":cases,
        "active_predecessor_refused":true,"old_instance_remains_inactive":true,"old_descendant_native_proof_refused":true,"new_native_scope_proof_accepted":true,"one_successor_per_predecessor":true,
        "successor_chain":2,"original_capacity_origin":hex::encode(old),"retained_participants":5,
        "closed_lifecycle_decode_checked":true,"obsolete_descriptor_refused":true,"maximum_exact_generation_accepted":true,"generation_wrap_to_one_refused":true,"canonical_roundtrip":true,"unwithdrawn_predecessor_decode_refused":true,
        "scope":"native control, new holder acceptance, independent resource grants and pure retained tree; no store or transport assertion",
        "not_established":["capacity-store-conservation","file-postgres-fences","installed-key-isolation","provider-effects","source-linked-formal","full-F12"]})
}

#[test]
fn native_instance_recovery_fixture_is_current() {
    let mut report = recovery_relation_matrix();
    report["retained_chain_boundary"] = retained_successor_chain_boundary();
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/instance-recovery.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

/// Reach the actual retained-node bound with full native proofs, then refuse
/// the next commissioned key. This exercises the shipping origin traversal on
/// every prefix, rather than comparing a separately implemented graph model.
#[expect(
    clippy::too_many_lines,
    reason = "retain the complete explicit signed fixture or hostile-case matrix as one reviewable construction"
)]
fn retained_successor_chain_boundary() -> Value {
    let mut fixture = Fixture::with_depth(0x44, 1);
    let signers: Vec<_> = (0..15).map(|index| Signer::new(0x80 + index)).collect();
    for (index, signer) in signers.iter().enumerate() {
        fixture.pins.permitted_channels.insert(
            format!("chain-{index:02}"),
            EnrollmentChannelPins {
                channel_binding: [0x80 + u8::try_from(index).unwrap(); 32],
                principal: signer.principal.clone(),
                instance_generation: u64::try_from(index).unwrap() + 2,
            },
        );
    }
    fixture.commit_root();
    let activation = fixture.root_activation(&fixture.pins);
    let root_witness = fixture.root_resource("record-a", &fixture.parent_resource);
    let mut tree = fixture
        .bootstrap_with(&fixture.pins, &activation, &root_witness, NOW)
        .unwrap();
    let original = fixture.enroll_tree(&mut tree).unwrap();
    let mut current = original;
    let mut old_proof = fixture.resource_proof("record-a");
    let mut accepted = 0;
    for (index, signer) in signers.iter().enumerate() {
        let withdrawal = fixture.withdraw_as_parent(current);
        tree.revoke_authorized(&fixture.context, NOW, &invocation(&withdrawal))
            .unwrap();
        let control = grant(
            &fixture.parent,
            signer,
            PARTICIPANT_SERVICE,
            CONTROL_TOOLS,
            Some(grant_id(fixture.parent_control.statement()).unwrap()),
            0,
        );
        let resource = grant_for_audiences(
            &fixture.parent,
            signer,
            RESOURCE_SERVICE,
            &[RESOURCE_TOOL],
            Some(grant_id(fixture.parent_resource.statement()).unwrap()),
            0,
            fixture
                .parent_resource
                .statement()
                .audiences()
                .as_slice()
                .to_vec(),
        );
        let mut descriptor = fixture.enrollment.clone();
        descriptor.lifecycle = EnrollmentLifecycle::Recover {
            predecessor: current,
        };
        descriptor.child_principal = signer.principal.as_str().into();
        descriptor.child_instance_generation = u64::try_from(index).unwrap() + 2;
        descriptor.enrollment_id = format!("recovery-chain-{index:02}");
        descriptor.delivery_channel = format!("chain-{index:02}");
        descriptor.control_grant = *grant_id(control.statement()).unwrap().as_bytes();
        descriptor.scopes[0].grant_id = *grant_id(resource.statement()).unwrap().as_bytes();
        let parent = fixture.parent_proof(&descriptor);
        let child = chained(
            &[&fixture.root, &fixture.parent, signer],
            &[&fixture.parent_control, &control],
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            json!({"enrollment_commitment":descriptor.commitment().unwrap()})
                .as_object()
                .unwrap(),
        );
        let read = chained(
            &[&fixture.root, &fixture.parent, signer],
            &[&fixture.parent_resource, &resource],
            RESOURCE_SERVICE,
            RESOURCE_TOOL,
            json!({"record_id":"record-a"}).as_object().unwrap(),
        );
        let resources = [EnrollmentResourceWitness {
            scope_id: "project-a-read",
            invocation: invocation(&read),
        }];
        let proofs = ParticipantEnrollmentProofs {
            parent: invocation(&parent),
            child: invocation(&child),
            resources: &resources,
        };
        let before = tree.encode().unwrap();
        let result = tree.enroll(
            &fixture.context,
            fixture.pins.enrollment_commitment,
            NOW,
            &proofs,
        );
        if index == 14 {
            assert_eq!(result, Err(EnrollmentTreeError::Full));
            assert_eq!(tree.encode().unwrap(), before);
            break;
        }
        current = result.unwrap();
        accepted += 1;
        assert_eq!(tree.capacity_origin(current).unwrap(), original);
        assert!(
            tree.verify_operation_scope(
                &fixture.context,
                "project-a-read",
                NOW,
                &invocation(&old_proof)
            )
            .is_err()
        );
        assert!(
            tree.verify_operation_scope(
                &fixture.context,
                "project-a-read",
                NOW,
                &invocation(&read)
            )
            .is_ok()
        );
        old_proof = read;
    }
    assert_eq!(accepted, 14);
    assert_eq!(tree.participant_count(), MAX_PARTICIPANTS);
    let restored = EnrollmentTree::decode(&tree.encode().unwrap(), &fixture.pins).unwrap();
    assert_eq!(restored.capacity_origin(current).unwrap(), original);
    json!({"accepted_successors":accepted,"retained_participants":tree.participant_count(),
        "original_capacity_origin_every_prefix":true,"old_native_proof_refused_every_prefix":true,
        "next_commissioned_successor_refused_full":true,"original_history_roundtrip":true})
}
