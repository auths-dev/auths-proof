//! Executable refinement checks for the generated Auths-Proof Lean model.

#![forbid(unsafe_code)]

#[cfg(test)]
mod refinement {
    use auths_algebra_kernel::{AttenuationChecks, Truth, attenuation_accepts, threshold_counts};
    use auths_authority::{AuthorScopeDecision, AuthorityDimension, evaluate_author_scope_view};
    use auths_composition::{BranchOutcome, evaluate};
    use auths_model::{
        ActionConstraint, AssurancePolicyId, Audience, AudienceSet, AuthorizationPlan,
        BodyDigestSet, BudgetAlgebraId, BudgetCeiling, CapabilityId, CriticalExtension,
        CriticalExtensions, DenialReason, Digest, ExtensionId, FreshnessLimit, GrantId, Permission,
        PermissionSet, PrincipalId, ProfileId, ProfileRef, ProofRef, Requirement, ResourceId,
        ScopeAuthorityView, StatusMethodId, StatusPolicy, Timestamp, ValidityWindow,
        VerifierLimits, action_constraint_allows, action_constraint_attenuates,
        assurance_policy_id_equal, audience_set_contains, audience_set_is_subset,
        body_digest_set_contains, body_digest_set_is_subset, budget_ceiling_attenuates,
        critical_extensions_equal, inclusive_window_contains, optional_budget_attenuates,
        optional_budget_covers, optional_grant_id_equal, permission_set_contains,
        permission_set_is_subset, principal_id_equal, profile_ref_equal, status_policy_attenuates,
    };
    use serde::Deserialize;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "kebab-case")]
    enum VectorTruth {
        Denied,
        Indeterminate,
        Authorized,
    }

    impl From<VectorTruth> for Truth {
        fn from(value: VectorTruth) -> Self {
            match value {
                VectorTruth::Denied => Self::Denied,
                VectorTruth::Indeterminate => Self::Indeterminate,
                VectorTruth::Authorized => Self::Authorized,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct ThresholdVector {
        required: u16,
        authorized: usize,
        indeterminate: usize,
        expected: VectorTruth,
    }

    #[derive(Debug, Deserialize)]
    struct ThresholdVectorFile {
        schema: String,
        exhaustive_bound: u16,
        cases: Vec<ThresholdVector>,
    }

    #[derive(Debug, Deserialize)]
    struct AttenuationVector {
        checks: [bool; 11],
        accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    struct AttenuationVectorFile {
        schema: String,
        dimensions: usize,
        cases: Vec<AttenuationVector>,
    }

    #[derive(Debug, Deserialize)]
    struct MutationVector {
        id: String,
        operator: String,
        witness: String,
    }

    #[derive(Debug, Deserialize)]
    struct MutationVectorFile {
        schema: String,
        cases: Vec<MutationVector>,
    }

    #[derive(Debug, Deserialize)]
    struct RichAuthorityVector {
        id: String,
        kind: String,
        args: Vec<u64>,
        child: Vec<u64>,
        parent: Vec<u64>,
        expected: bool,
    }

    #[derive(Debug, Deserialize)]
    struct RichAuthorityVectorFile {
        schema: String,
        cases: Vec<RichAuthorityVector>,
    }

    fn checks(values: [bool; 11]) -> AttenuationChecks {
        AttenuationChecks {
            root_preserved: values[0],
            depth_decreases: values[1],
            profile_attenuates: values[2],
            permissions_attenuate: values[3],
            validity_attenuates: values[4],
            audiences_attenuate: values[5],
            action_constraint_attenuates: values[6],
            budget_attenuates: values[7],
            status_attenuates: values[8],
            assurance_attenuates: values[9],
            extensions_attenuate: values[10],
        }
    }

    fn shipping_plan_truth(vector: &ThresholdVector) -> (Truth, usize) {
        let total = usize::from(auths_algebra_kernel::EXHAUSTIVE_THRESHOLD_BOUND);
        let leaves: Vec<_> = (0..total)
            .map(|index| {
                let marker = u8::try_from(index + 1).unwrap_or(u8::MAX);
                AuthorizationPlan::proof(ProofRef::new([marker; 32]))
            })
            .collect();
        let plan = AuthorizationPlan::k_of_n(vector.required, leaves)
            .expect("Lean emits thresholds within the target V1 plan bound");
        let outcomes: BTreeMap<_, _> = (0..total)
            .map(|index| {
                let marker = u8::try_from(index + 1).unwrap_or(u8::MAX);
                let outcome = if index < vector.authorized {
                    BranchOutcome::Authorized
                } else if index < vector.authorized + vector.indeterminate {
                    BranchOutcome::Indeterminate(Requirement::ExternalFactUnavailable)
                } else {
                    BranchOutcome::Denied(DenialReason::PermissionNotGranted)
                };
                (ProofRef::new([marker; 32]), outcome)
            })
            .collect();
        let mut visited = 0;
        let outcome = evaluate(&plan, &VerifierLimits::default(), &mut |reference| {
            visited += 1;
            outcomes[&reference]
        })
        .expect("Lean emits a target V1 bounded plan");
        let truth = match outcome {
            BranchOutcome::Authorized => Truth::Authorized,
            BranchOutcome::Indeterminate(_) => Truth::Indeterminate,
            BranchOutcome::Denied(_) | BranchOutcome::StructurallyInvalid(_) => Truth::Denied,
        };
        (truth, visited)
    }

    fn digest(byte: u8) -> Digest {
        Digest::new([byte; 32])
    }

    fn permission(name: &str) -> Permission {
        Permission::new(
            CapabilityId::parse(name).expect("valid capability"),
            ResourceId::parse(&format!("resource://{name}")).expect("valid resource"),
        )
    }

    fn audience(name: &str) -> Audience {
        Audience::parse(&format!("audience://{name}")).expect("valid audience")
    }

    fn budget(algebra: &str, value: u64) -> BudgetCeiling {
        BudgetCeiling::new(
            BudgetAlgebraId::parse(algebra).expect("valid budget algebra"),
            value,
        )
    }

    fn status(method: &str, age: u64) -> StatusPolicy {
        StatusPolicy::SnapshotRequired {
            method: StatusMethodId::parse(method).expect("valid status method"),
            max_age: FreshnessLimit::new(age).expect("positive freshness limit"),
        }
    }

    fn profile(name: &str, version: u16) -> ProfileRef {
        ProfileRef::new(ProfileId::parse(name).expect("valid profile"), version)
            .expect("non-zero profile version")
    }

    fn indexed_permissions(values: &[u64]) -> PermissionSet {
        PermissionSet::new(
            values
                .iter()
                .map(|value| permission(&format!("permission-{value}")))
                .collect(),
        )
        .expect("Lean emits non-empty bounded permission sets")
    }

    fn indexed_audiences(values: &[u64]) -> AudienceSet {
        AudienceSet::new(
            values
                .iter()
                .map(|value| audience(&format!("audience-{value}")))
                .collect(),
        )
        .expect("Lean emits non-empty bounded audience sets")
    }

    fn indexed_digests(values: &[u64]) -> BodyDigestSet {
        BodyDigestSet::new(
            values
                .iter()
                .map(|value| digest(u8::try_from(*value).expect("Lean digest byte")))
                .collect(),
        )
        .expect("Lean emits non-empty bounded digest sets")
    }

    fn shipping_rich_authority_result(vector: &RichAuthorityVector) -> bool {
        match vector.kind.as_str() {
            "window" => inclusive_window_contains(
                vector.args[0],
                vector.args[1],
                vector.args[2],
                vector.args[3],
            ),
            "finite-set-subset" => {
                let child_permissions = indexed_permissions(&vector.child);
                let parent_permissions = indexed_permissions(&vector.parent);
                let child_audiences = indexed_audiences(&vector.child);
                let parent_audiences = indexed_audiences(&vector.parent);
                let child_digests = indexed_digests(&vector.child);
                let parent_digests = indexed_digests(&vector.parent);
                let permission_result =
                    permission_set_is_subset(&child_permissions, &parent_permissions);
                let audience_result = audience_set_is_subset(&child_audiences, &parent_audiences);
                let digest_result = body_digest_set_is_subset(&child_digests, &parent_digests);
                assert_eq!(permission_result, audience_result, "{}", vector.id);
                assert_eq!(permission_result, digest_result, "{}", vector.id);
                permission_result
            }
            "finite-set-member" => {
                let value = vector.args[0];
                let permissions = indexed_permissions(&vector.parent);
                let audiences = indexed_audiences(&vector.parent);
                let digests = indexed_digests(&vector.parent);
                let permission_result = permission_set_contains(
                    &permissions,
                    &permission(&format!("permission-{value}")),
                );
                let audience_result =
                    audience_set_contains(&audiences, &audience(&format!("audience-{value}")));
                let digest_result = body_digest_set_contains(
                    &digests,
                    &digest(u8::try_from(value).expect("Lean digest byte")),
                );
                assert_eq!(permission_result, audience_result, "{}", vector.id);
                assert_eq!(permission_result, digest_result, "{}", vector.id);
                permission_result
            }
            "budget" => {
                let child = budget(&format!("algebra-{}", vector.args[0]), vector.args[1]);
                let parent = budget(&format!("algebra-{}", vector.args[2]), vector.args[3]);
                budget_ceiling_attenuates(&child, &parent)
            }
            "optional-budget" => {
                let value = budget("algebra-1", 10);
                let child = (vector.args[0] == 1).then_some(&value);
                let parent = (vector.args[1] == 1).then_some(&value);
                optional_budget_attenuates(child, parent)
            }
            "budget-covers" => {
                let ceiling = budget(&format!("algebra-{}", vector.args[1]), vector.args[2]);
                let requested = budget(&format!("algebra-{}", vector.args[4]), vector.args[5]);
                optional_budget_covers(
                    (vector.args[0] == 1).then_some(&ceiling),
                    (vector.args[3] == 1).then_some(&requested),
                )
            }
            "status" => {
                let child = status(&format!("method-{}", vector.args[0]), vector.args[1]);
                let parent = status(&format!("method-{}", vector.args[2]), vector.args[3]);
                status_policy_attenuates(&child, &parent)
            }
            "action-allows-exact" => {
                let expected = digest(u8::try_from(vector.args[0]).expect("Lean digest byte"));
                let actual = digest(u8::try_from(vector.args[1]).expect("Lean digest byte"));
                action_constraint_allows(&ActionConstraint::ExactBodyDigest(expected), actual)
            }
            "action-set-attenuation" => {
                let child = ActionConstraint::AllowedBodyDigests(indexed_digests(&vector.child));
                let parent = ActionConstraint::AllowedBodyDigests(indexed_digests(&vector.parent));
                action_constraint_attenuates(&child, &parent)
            }
            "action-singleton-exact-attenuation" => {
                let child = ActionConstraint::AllowedBodyDigests(indexed_digests(&vector.child));
                let parent = ActionConstraint::ExactBodyDigest(digest(
                    u8::try_from(vector.args[0]).expect("Lean digest byte"),
                ));
                action_constraint_attenuates(&child, &parent)
            }
            kind => panic!("unknown Lean rich-authority vector kind {kind}"),
        }
    }

    fn containment_mutation_is_killed(id: &str) -> Option<bool> {
        match id {
            "validity-start-direction" => {
                let canonical = inclusive_window_contains(10, 20, 11, 20);
                let mutant = 11 <= 10;
                Some(canonical && !mutant)
            }
            "validity-end-direction" => {
                let canonical = inclusive_window_contains(10, 20, 10, 19);
                let mutant = 19 >= 20;
                Some(canonical && !mutant)
            }
            "permission-subset-direction" => {
                let child = PermissionSet::new(vec![permission("read")]).expect("child set");
                let parent = PermissionSet::new(vec![permission("read"), permission("write")])
                    .expect("parent set");
                Some(
                    permission_set_is_subset(&child, &parent)
                        && !permission_set_is_subset(&parent, &child),
                )
            }
            "audience-subset-direction" => {
                let child = AudienceSet::new(vec![audience("one")]).expect("child set");
                let parent =
                    AudienceSet::new(vec![audience("one"), audience("two")]).expect("parent set");
                Some(
                    audience_set_is_subset(&child, &parent)
                        && !audience_set_is_subset(&parent, &child),
                )
            }
            "permission-membership-decision" => {
                let present = permission("read");
                let set = PermissionSet::new(vec![present.clone()]).expect("permission set");
                let canonical = permission_set_contains(&set, &present);
                let mutant = !canonical;
                Some(canonical && !mutant)
            }
            "audience-membership-decision" => {
                let present = audience("one");
                let set = AudienceSet::new(vec![present.clone()]).expect("audience set");
                let canonical = audience_set_contains(&set, &present);
                let mutant = !canonical;
                Some(canonical && !mutant)
            }
            "body-digest-membership-decision" => {
                let present = digest(1);
                let set = BodyDigestSet::new(vec![present]).expect("digest set");
                let canonical = body_digest_set_contains(&set, &present);
                let mutant = !canonical;
                Some(canonical && !mutant)
            }
            "body-digest-subset-direction" => {
                let child = BodyDigestSet::new(vec![digest(1)]).expect("child set");
                let parent = BodyDigestSet::new(vec![digest(1), digest(2)]).expect("parent set");
                Some(
                    body_digest_set_is_subset(&child, &parent)
                        && !body_digest_set_is_subset(&parent, &child),
                )
            }
            _ => None,
        }
    }

    fn constraint_mutation_is_killed(id: &str) -> Option<bool> {
        match id {
            "action-exact-equality" => {
                let constraint = ActionConstraint::ExactBodyDigest(digest(1));
                let canonical = action_constraint_allows(&constraint, digest(2));
                let mutant = true;
                Some(!canonical && mutant)
            }
            "action-constructor-fallback" => {
                let child = ActionConstraint::allowed_body_digests(vec![digest(1), digest(2)])
                    .expect("allowed-body child");
                let parent = ActionConstraint::ExactBodyDigest(digest(1));
                let canonical = action_constraint_attenuates(&child, &parent);
                let mutant = true;
                Some(!canonical && mutant)
            }
            "action-singleton-exact-rejection" => {
                let child = ActionConstraint::allowed_body_digests(vec![digest(1)])
                    .expect("singleton allowed-body child");
                let parent = ActionConstraint::ExactBodyDigest(digest(1));
                let canonical = action_constraint_attenuates(&child, &parent);
                let mutant = false;
                Some(canonical && !mutant)
            }
            "budget-value-direction" => {
                let child = budget("numeric-v1", 5);
                let parent = budget("numeric-v1", 10);
                let canonical = budget_ceiling_attenuates(&child, &parent);
                let mutant = child.value() >= parent.value();
                Some(canonical && !mutant)
            }
            "budget-algebra-equality" => {
                let child = budget("numeric-v1", 5);
                let parent = budget("credits-v1", 10);
                let canonical = budget_ceiling_attenuates(&child, &parent);
                let mutant = child.value() <= parent.value();
                Some(!canonical && mutant)
            }
            "optional-budget-bounded-parent" => {
                let parent = budget("numeric-v1", 10);
                let canonical = optional_budget_attenuates(None, Some(&parent));
                let mutant = true;
                Some(!canonical && mutant)
            }
            "optional-budget-no-request" => {
                let ceiling = budget("numeric-v1", 10);
                let canonical = optional_budget_covers(Some(&ceiling), None);
                let mutant = optional_budget_attenuates(None, Some(&ceiling));
                Some(canonical && !mutant)
            }
            _ => None,
        }
    }

    fn policy_and_linkage_mutation_is_killed(id: &str) -> Option<bool> {
        match id {
            "status-age-direction" => {
                let child = status("snapshot-v1", 5);
                let parent = status("snapshot-v1", 10);
                let canonical = status_policy_attenuates(&child, &parent);
                let mutant = 5 >= 10;
                Some(canonical && !mutant)
            }
            "status-method-equality" => {
                let child = status("snapshot-a-v1", 5);
                let parent = status("snapshot-b-v1", 10);
                let canonical = status_policy_attenuates(&child, &parent);
                let mutant = 5 <= 10;
                Some(!canonical && mutant)
            }
            "profile-version-equality" => {
                let child = profile("profile-v1", 1);
                let parent = profile("profile-v1", 2);
                let canonical = profile_ref_equal(&child, &parent);
                let mutant = child.id() == parent.id();
                Some(!canonical && mutant)
            }
            "assurance-equality" => {
                let child = AssurancePolicyId::parse("assurance-a-v1").expect("child assurance");
                let parent = AssurancePolicyId::parse("assurance-b-v1").expect("parent assurance");
                let canonical = assurance_policy_id_equal(&child, &parent);
                let mutant = true;
                Some(!canonical && mutant)
            }
            "critical-extension-equality" => {
                let extension_id = ExtensionId::parse("exact-marker-v1").expect("extension id");
                let child = CriticalExtensions::new(vec![
                    CriticalExtension::new(extension_id.clone(), vec![1]).expect("child extension"),
                ])
                .expect("child extensions");
                let parent = CriticalExtensions::new(vec![
                    CriticalExtension::new(extension_id, vec![2]).expect("parent extension"),
                ])
                .expect("parent extensions");
                let canonical = critical_extensions_equal(&child, &parent);
                let mutant = true;
                Some(!canonical && mutant)
            }
            "delegation-depth-strictness" => {
                let profile = profile("profile-v1", 1);
                let permissions =
                    PermissionSet::new(vec![permission("read")]).expect("permissions");
                let validity =
                    ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).expect("validity");
                let audiences = AudienceSet::new(vec![audience("one")]).expect("audiences");
                let constraint = ActionConstraint::AnyBody;
                let status = StatusPolicy::ExpiryOnly;
                let assurance = AssurancePolicyId::parse("assurance-v1").expect("assurance");
                let extensions = CriticalExtensions::empty();
                let parent = ScopeAuthorityView {
                    profile: &profile,
                    permissions: &permissions,
                    validity,
                    audiences: &audiences,
                    action_constraint: &constraint,
                    budget_ceiling: None,
                    remaining_depth: 2,
                    status_policy: &status,
                    assurance_floor: &assurance,
                    extensions: &extensions,
                };
                let child = ScopeAuthorityView {
                    remaining_depth: 2,
                    ..parent
                };
                let canonical = evaluate_author_scope_view(parent, child);
                let mutant = AuthorScopeDecision::Accepted;
                Some(
                    canonical == AuthorScopeDecision::Denied(AuthorityDimension::DelegationDepth)
                        && canonical != mutant,
                )
            }
            "principal-linkage-equality" => {
                let child = PrincipalId::parse("did:key:child").expect("child principal");
                let parent = PrincipalId::parse("did:key:parent").expect("parent principal");
                let canonical = principal_id_equal(&child, &parent);
                let mutant = true;
                Some(!canonical && mutant)
            }
            "grant-linkage-equality" => {
                let child = GrantId::new([1; 32]);
                let parent = GrantId::new([2; 32]);
                let canonical = optional_grant_id_equal(Some(child), Some(parent));
                let mutant = true;
                Some(!canonical && mutant)
            }
            _ => None,
        }
    }

    fn required_mutation_is_killed(id: &str) -> bool {
        containment_mutation_is_killed(id)
            .or_else(|| constraint_mutation_is_killed(id))
            .or_else(|| policy_and_linkage_mutation_is_killed(id))
            .unwrap_or(false)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn lean_threshold_vectors_exhaust_target_v1_and_refine_shipping_rust() {
            let vectors: ThresholdVectorFile = serde_json::from_str(include_str!(
                "../../../formal-vectors/v1/threshold-counts.json"
            ))
            .expect("valid Lean-generated threshold vectors");
            assert_eq!(vectors.schema, "auths-proof-threshold-vectors/v1");
            assert_eq!(
                usize::from(vectors.exhaustive_bound),
                auths_model::DEFAULT_MAX_PLAN_LEAVES
            );
            assert_eq!(
                vectors.exhaustive_bound,
                auths_algebra_kernel::EXHAUSTIVE_THRESHOLD_BOUND
            );
            assert_eq!(vectors.cases.len(), 2_448);
            for vector in vectors.cases {
                let expected = Truth::from(vector.expected);
                assert_eq!(
                    threshold_counts(vector.required, vector.authorized, vector.indeterminate),
                    expected
                );
                let (shipping, visited) = shipping_plan_truth(&vector);
                assert_eq!(shipping, expected);
                assert_eq!(
                    visited,
                    usize::from(auths_algebra_kernel::EXHAUSTIVE_THRESHOLD_BOUND)
                );
            }
        }

        #[test]
        fn lean_attenuation_vectors_exhaust_the_generated_projection() {
            let vectors: AttenuationVectorFile = serde_json::from_str(include_str!(
                "../../../formal-vectors/v1/attenuation-checks.json"
            ))
            .expect("valid Lean-generated attenuation vectors");
            assert_eq!(vectors.schema, "auths-proof-attenuation-vectors/v1");
            assert_eq!(vectors.dimensions, 11);
            assert_eq!(vectors.cases.len(), 2_048);
            for vector in vectors.cases {
                assert_eq!(attenuation_accepts(&checks(vector.checks)), vector.accepted);
            }
        }

        #[test]
        fn versioned_required_semantic_mutation_matrix_is_killed() {
            let matrix: MutationVectorFile = serde_json::from_str(include_str!(
                "../../../../formal/refinement-mutations-v1.json"
            ))
            .expect("valid versioned semantic mutation matrix");
            assert_eq!(matrix.schema, "auths-proof-semantic-mutations/v1");
            assert_eq!(matrix.cases.len(), 23);

            let mut identifiers = BTreeSet::new();
            for mutation in matrix.cases {
                assert!(!mutation.operator.trim().is_empty());
                assert!(!mutation.witness.trim().is_empty());
                assert!(
                    identifiers.insert(mutation.id.clone()),
                    "duplicate required mutation {}",
                    mutation.id
                );
                assert!(
                    required_mutation_is_killed(&mutation.id),
                    "required semantic mutation survived: {}",
                    mutation.id
                );
            }
        }

        #[test]
        fn lean_rich_authority_vectors_refine_shipping_rust_predicates() {
            let vectors: RichAuthorityVectorFile = serde_json::from_str(include_str!(
                "../../../formal-vectors/v1/rich-authority.json"
            ))
            .expect("valid Lean-generated rich-authority vectors");
            assert_eq!(vectors.schema, "auths-proof-rich-authority-vectors/v1");
            assert_eq!(vectors.cases.len(), 26);
            for vector in vectors.cases {
                assert_eq!(
                    shipping_rich_authority_result(&vector),
                    vector.expected,
                    "Lean/Rust rich-authority mismatch for {}",
                    vector.id
                );
            }
        }
    }
}
