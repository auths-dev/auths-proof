//! Native proof admission for one closed content-release request. Task-policy
//! activation, credential custody and delivery remain separate boundaries.

use crate::bounds::authorized_chains;
use crate::engine::{
    GatewaySubmitResult, authorized_action, not_entered, verify_sealed_for_audience,
};
use crate::{ClosedReleaseRequest, CompiledReleaseRecipe};
use auths_model::{Audience, PrincipalId, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;

/// A release request whose action, sole agent actor and delegation ancestry
/// came from one native authorized branch. Its private fields prevent callers
/// from inventing these facts after verification.
pub(crate) struct VerifiedReleaseRequest {
    request: ClosedReleaseRequest,
    authority: crate::bounds::NativeAuthority,
}

impl VerifiedReleaseRequest {
    pub(crate) fn request(&self) -> &ClosedReleaseRequest {
        &self.request
    }

    pub(crate) fn actor(&self) -> &PrincipalId {
        self.authority.actor()
    }

    pub(crate) fn authority(&self) -> &crate::bounds::NativeAuthority {
        &self.authority
    }
}

/// Verify a single agent action and its delegation path before a release
/// task can reserve a provider call. Journal admission must establish the exact
/// enrolled resource grant ancestry and charge every participant ancestor.
/// Unsupported critical policy is refused rather than silently ignored.
#[cfg(test)]
pub(crate) fn verify_release_request(
    recipe: &CompiledReleaseRecipe,
    context: &TrustedContext,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<VerifiedReleaseRequest, GatewaySubmitResult> {
    let audience = Audience::parse(&format!("mcp://{}", recipe.service()))
        .map_err(|_| not_entered("gateway.release.profile"))?;
    verify_release_for_audience(recipe, context, audience, now, proof_cbor, action_cbor)
}

pub(crate) fn verify_task_release_request(
    task: &crate::task_activation::ApprovedAgentTask,
    recipe: &CompiledReleaseRecipe,
    context: &TrustedContext,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<VerifiedReleaseRequest, GatewaySubmitResult> {
    let audience = crate::task_enrollment::audience(task, &recipe.digest_hex())?;
    verify_release_for_audience(recipe, context, audience, now, proof_cbor, action_cbor)
}

fn verify_release_for_audience(
    recipe: &CompiledReleaseRecipe,
    context: &TrustedContext,
    audience: Audience,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<VerifiedReleaseRequest, GatewaySubmitResult> {
    let sealed = verify_sealed_for_audience(context, audience, now, proof_cbor, action_cbor)?;
    let action = authorized_action(&sealed)?;
    if action.action_ids().len() != 1 {
        return Err(not_entered("gateway.release.composition-unsupported"));
    }
    let command = McpProfile
        .decode_verified(action)
        .map_err(|_| not_entered("gateway.action.projection"))?;
    let canonical = auths_codec::encode_canonical_action(action.canonical_action())
        .map_err(|_| not_entered("gateway.action.commitment"))?;
    let commitment = auths_codec::domain_commitment("auths.canonical-action.v1", &canonical)
        .map_err(|_| not_entered("gateway.action.commitment"))?;
    let request = recipe
        .closed_request(&command, *commitment.as_bytes())
        .map_err(|error| not_entered(error.code()))?;
    let branches = authorized_chains(proof_cbor, action)
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    let bundle = auths_codec::decode_bundle(proof_cbor, &VerifierLimits::default())
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    if bundle.actions().len() != 1
        || !bundle.actions()[0]
            .envelope()
            .extensions()
            .as_slice()
            .is_empty()
    {
        return Err(not_entered("gateway.release.unsupported-action-policy"));
    }
    let [branch] = branches.as_slice() else {
        return Err(not_entered("gateway.release.single-actor-required"));
    };
    if branch.actor.as_str() != request.recipient() {
        return Err(not_entered("gateway.release.recipient-mismatch"));
    }
    let Some(terminal) = branch.chain.last() else {
        return Err(not_entered("gateway.release.human-grant-required"));
    };
    if terminal.statement().subject() != &branch.actor {
        return Err(not_entered("gateway.release.human-grant-recipient"));
    }
    if branch.chain.iter().any(|grant| {
        !grant.statement().extensions().as_slice().is_empty()
            || grant.statement().budget_ceiling().is_some()
    }) {
        return Err(not_entered("gateway.release.unsupported-grant-policy"));
    }
    Ok(VerifiedReleaseRequest {
        request,
        authority: branch.authority().map_err(not_entered)?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::GatewayObserver;
    use crate::harness::{self, Signer};
    use crate::observed_tests::submission;
    use crate::release_state::{ReleaseResourceScope, ReleaseTaskPolicy, ReleaseTaskState};
    use auths_codec::{body_digest, grant_id, grant_signing_preimage};
    use auths_model::{
        ActionConstraint, AssurancePolicyId, AudienceSet, CriticalExtensions, GrantId,
        GrantStatement, PermissionSet, SignatureEnvelope, SignedGrant, StatusPolicy,
    };
    use auths_profile_mcp::McpProfile;
    use serde_json::{Map, Value, json};
    use sha2::{Digest as _, Sha256};

    const NOW: u64 = 1_790_000_000;

    #[test]
    fn native_release_uses_recipe_audience_in_mixed_read_write_task() {
        let root = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context =
            harness::context_for_read_with_write_default(&root, observer.principal(), NOW)
                .expect("mixed task context");
        let recipe = recipe();
        let arguments = arguments(&recipe, agent.principal.as_str());
        let grant = exact_grant(&root, &agent, &arguments, NOW);
        let signed = submission(&root, &agent, &grant, &arguments, &[]);
        assert!(
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action,).is_ok()
        );
    }

    pub(crate) fn recipe() -> CompiledReleaseRecipe {
        let schema = json!({"kind": "object", "fields": {
            "agent_principal": {"kind": "string", "minimum": 1, "maximum": 128},
            "operation_id": {"kind": "string", "minimum": 1, "maximum": 64},
            "operator_namespace": {"type": "enum", "variants": [harness::NAMESPACE]},
            "recipe_digest": {"kind": "string", "minimum": 64, "maximum": 64},
            "record_id": {"kind": "string", "minimum": 1, "maximum": 64},
            "task_id": {"kind": "string", "minimum": 1, "maximum": 64},
            "task_commitment": {"kind": "string", "minimum": 64, "maximum": 64}
        }});
        let schema_digest = hex::encode(Sha256::digest(
            serde_json_canonicalizer::to_vec(&schema).expect("schema"),
        ));
        let lock = json!({
            "schema": "auths.self-hosted-profile-lock/1", "generator_format": 2,
            "profile": "release-native-test", "version": 1,
            "schema_digest": schema_digest, "command_schema": schema,
            "service": harness::SERVICE, "tool": harness::TOOL
        });
        let source = json!({
            "schema": "auths.gateway-release-recipe-source/1",
            "profile_schema_digest": schema_digest,
            "service": harness::SERVICE, "tool": harness::TOOL,
            "operator_namespace": harness::NAMESPACE,
            "credential": {"kind": "bearer"}, "origin": harness::ORIGIN,
            "path": [{"kind": "fixed", "value": "v0"},
                     {"kind": "field", "name": "record_id"}],
            "resource_field": "record_id", "recipient_field": "agent_principal",
            "response": {"status": 200, "media_type": "application/json",
                "maximum_provider_bytes": 16384, "maximum_release_bytes": 64,
                "projection": {"kind": "json-string", "pointer": "/fields/DemoStatus"}}
        });
        CompiledReleaseRecipe::compile(
            &serde_json::to_vec(&source).expect("source"),
            &serde_json::to_vec(&lock).expect("lock"),
        )
        .expect("release recipe")
    }

    pub(crate) fn arguments(recipe: &CompiledReleaseRecipe, recipient: &str) -> Map<String, Value> {
        json!({
            "agent_principal": recipient,
            "operation_id": "read-1",
            "operator_namespace": harness::NAMESPACE,
            "recipe_digest": recipe.digest_hex(),
            "record_id": harness::RECORD,
            "task_id": "task-1",
            "task_commitment": "11".repeat(32)
        })
        .as_object()
        .expect("arguments")
        .clone()
    }

    pub(crate) fn exact_grant(
        root: &Signer,
        agent: &Signer,
        arguments: &Map<String, Value>,
        now: u64,
    ) -> SignedGrant {
        exact_grant_link(root, agent, arguments, now, 0, None)
    }

    fn exact_grant_link(
        root: &Signer,
        agent: &Signer,
        arguments: &Map<String, Value>,
        now: u64,
        depth: u16,
        parent: Option<GrantId>,
    ) -> SignedGrant {
        let call = harness::call(arguments).expect("call");
        let canonical = McpProfile
            .canonicalize(&call.canonical_bytes().expect("body"))
            .expect("canonical");
        let statement = GrantStatement::new(
            root.principal.clone(),
            agent.principal.clone(),
            call.profile_ref().expect("profile"),
            PermissionSet::new(vec![call.permission().expect("permission")]).expect("permissions"),
            harness::window(now - 3_600, now + 3_600).expect("window"),
            AudienceSet::new(vec![harness::audience().expect("audience")]).expect("audiences"),
            ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
            None,
            depth,
            parent,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse(harness::ASSURANCE).expect("assurance"),
            CriticalExtensions::empty(),
        );
        let descriptor = root.descriptor();
        let signature =
            root.sign(&grant_signing_preimage(&statement, &descriptor).expect("preimage"));
        SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
    }

    fn task_policy(
        recipe: &CompiledReleaseRecipe,
        human: &Signer,
        agent: &Signer,
    ) -> ReleaseTaskPolicy {
        ReleaseTaskPolicy {
            task_id: "task-1".to_owned(),
            task_commitment: [0x11; 32],
            company_id: "atlas".to_owned(),
            initiator_principal: human.principal.as_str().to_owned(),
            agent_principal: agent.principal.as_str().to_owned(),
            not_before: NOW - 3_600,
            expires_at: NOW + 3_600,
            max_provider_calls: 1,
            max_releases: 1,
            max_release_bytes: 64,
            max_writes: 0,
            write_scopes: vec![],
            connection_id: "jules-connection".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
            resources: vec![ReleaseResourceScope {
                handle: harness::RECORD.to_owned(),
                recipe_digest: recipe.digest_hex(),
                connection_id: "jules-read".to_owned(),
                connection_generation: 3,
                connection_subject: "jules-subject".to_owned(),
            }],
        }
    }

    /// Sign a real bounded chain, preserving the terminal action's proof
    /// reference and native control bindings for every grant issuer.
    fn delegated_submission(
        signers: &[&Signer],
        arguments: &Map<String, Value>,
        root_depth: u16,
    ) -> crate::observed_tests::Submission {
        use auths_model::{BundleHeader, ControlBinding, ProofBundle, StatementRef};

        let mut grants = Vec::new();
        let mut parent = None;
        for (index, pair) in signers.windows(2).enumerate() {
            let grant = exact_grant_link(
                pair[0],
                pair[1],
                arguments,
                NOW,
                root_depth.saturating_sub(u16::try_from(index).expect("test chain length")),
                parent,
            );
            parent = Some(grant_id(grant.statement()).expect("grant ID"));
            grants.push(grant);
        }
        let mut signed = submission(
            signers[signers.len() - 2],
            signers[signers.len() - 1],
            grants.last().expect("terminal grant"),
            arguments,
            &[],
        );
        let terminal = auths_codec::decode_bundle(&signed.proof, &VerifierLimits::default())
            .expect("terminal bundle");
        let mut bindings: Vec<_> = grants
            .iter()
            .zip(signers)
            .map(|(grant, issuer)| {
                ControlBinding::new(
                    StatementRef::Grant(grant_id(grant.statement()).expect("grant ID")),
                    vec![issuer.evidence().id()],
                )
                .expect("grant binding")
            })
            .collect();
        bindings.extend(
            terminal
                .bindings()
                .iter()
                .filter(|binding| matches!(binding.statement(), StatementRef::Action(_)))
                .cloned(),
        );
        let bundle = ProofBundle::new(
            BundleHeader::v1(),
            grants,
            terminal.actions().to_vec(),
            terminal.plan().clone(),
            signers.iter().map(|signer| signer.evidence()).collect(),
            bindings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            terminal.canonical_body().map(<[u8]>::to_vec),
        )
        .expect("delegated bundle");
        signed.proof = auths_codec::encode_bundle(&bundle).expect("delegated proof");
        signed
    }

    #[test]
    fn delegated_read_retains_native_path_but_requires_enrolled_task_root() {
        let service = Signer::new(0x10);
        let human = Signer::new(0x11);
        let intermediary = Signer::new(0x21);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_with_depth(&service, observer.principal(), None, NOW, 3)
            .expect("delegation trust");
        let recipe = recipe();
        let arguments = arguments(&recipe, agent.principal.as_str());
        let signed =
            delegated_submission(&[&service, &human, &intermediary, &agent], &arguments, 2);
        let verified =
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action)
                .expect("native verified delegation");

        assert_eq!(verified.actor(), &agent.principal);
        assert_eq!(verified.authority().grants().len(), 3);
        let policy = task_policy(&recipe, &human, &agent);
        let mut state = ReleaseTaskState::from_test_policy(policy).expect("task policy");
        assert_eq!(
            state.reserve_verified_request(&verified, "jules-read", 3, "jules-subject", NOW),
            Err(crate::release_state::ReleaseStateError::Inactive),
            "a native proof alone cannot bypass mandatory root enrollment"
        );
        assert_eq!(state.counts(), (0, 0, 0));
    }

    #[test]
    fn delegated_read_cannot_redelegate_without_depth_or_change_the_approved_source() {
        let human = Signer::new(0x11);
        let intermediary = Signer::new(0x21);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context_with_depth(&human, observer.principal(), None, NOW, 2)
            .expect("delegation trust");
        let recipe = recipe();
        let arguments = arguments(&recipe, agent.principal.as_str());
        let exhausted = delegated_submission(&[&human, &intermediary, &agent], &arguments, 0);
        assert!(
            verify_release_request(&recipe, &context, NOW, &exhausted.proof, &exhausted.action)
                .is_err(),
            "native attenuation must reject an exhausted parent"
        );

        let signed = delegated_submission(&[&human, &intermediary, &agent], &arguments, 1);
        let mut changed = arguments.clone();
        changed.insert("record_id".to_owned(), json!(harness::OTHER_RECORD));
        let bundle = auths_codec::decode_bundle(&signed.proof, &VerifierLimits::default())
            .expect("delegated bundle");
        let changed_action = submission(
            &intermediary,
            &agent,
            bundle.grants().last().expect("terminal grant"),
            &changed,
            &[],
        );
        assert!(
            verify_release_request(
                &recipe,
                &context,
                NOW,
                &signed.proof,
                &changed_action.action
            )
            .is_err(),
            "delegation cannot substitute a different source body"
        );
    }

    #[test]
    fn native_proof_seals_actor_grant_and_resource_but_does_not_admit_task() {
        let root = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context(&root, observer.principal(), None, NOW).expect("context");
        let recipe = recipe();
        let arguments = arguments(&recipe, agent.principal.as_str());
        let grant = harness::grant(&root, &agent.principal, None, NOW).expect("tool grant");
        let signed = submission(&root, &agent, &grant, &arguments, &[]);
        let verified =
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action)
                .expect("native authorized proof");
        assert_eq!(verified.actor(), &agent.principal);
        assert_eq!(
            verified.authority().grants().first(),
            Some(&grant_id(grant.statement()).unwrap())
        );
        assert_eq!(verified.request().recipient(), agent.principal.as_str());
        assert_eq!(
            verified.request().url(),
            format!("{}/v0/{}", harness::ORIGIN, harness::RECORD)
        );

        let policy = task_policy(&recipe, &root, &agent);
        let mut pending = ReleaseTaskState::from_test_policy(policy).expect("policy");
        assert_eq!(
            pending.reserve_verified_request(&verified, "jules-read", 3, "jules-subject", NOW),
            Err(crate::release_state::ReleaseStateError::Inactive)
        );
        assert_eq!(pending.counts(), (0, 0, 0));
    }

    #[test]
    fn native_release_refuses_mismatched_recipient_and_accepts_task_scoped_grant() {
        let root = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context(&root, observer.principal(), None, NOW).expect("context");
        let recipe = recipe();
        let wrong_recipient = arguments(&recipe, Signer::new(0x44).principal.as_str());
        let grant = exact_grant(&root, &agent, &wrong_recipient, NOW);
        let signed = submission(&root, &agent, &grant, &wrong_recipient, &[]);
        assert!(matches!(
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action),
            Err(GatewaySubmitResult::NotEntered { code }) if code == "gateway.release.recipient-mismatch"
        ));

        let arguments = arguments(&recipe, agent.principal.as_str());
        let exact = exact_grant(&root, &agent, &arguments, NOW);
        let mut changed = arguments.clone();
        changed.insert("record_id".to_owned(), json!(harness::OTHER_RECORD));
        let signed = submission(&root, &agent, &exact, &changed, &[]);
        assert!(
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action).is_err(),
            "the human's body-digest grant cannot authorize another source"
        );
        let broad = harness::grant(&root, &agent.principal, None, NOW).expect("broad grant");
        let signed = submission(&root, &agent, &broad, &arguments, &[]);
        assert!(
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action).is_ok(),
            "the activated task independently bounds resource and budget"
        );
    }
}
