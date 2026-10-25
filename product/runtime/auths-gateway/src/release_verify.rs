//! Native proof admission for one closed content-release request. Task-policy
//! activation, credential custody and delivery remain separate boundaries.

use crate::bounds::authorized_chains;
use crate::engine::{GatewaySubmitResult, authorized_action, not_entered, verify_sealed};
use crate::{ClosedReleaseRequest, CompiledReleaseRecipe};
use auths_model::{ActionConstraint, PrincipalId, TrustedContext, VerifierLimits};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;

/// A release request whose action, sole agent actor and terminal human grant
/// came from one native authorized proof. Its private fields prevent callers
/// from inventing these facts after verification.
pub(crate) struct VerifiedReleaseRequest {
    request: ClosedReleaseRequest,
    actor: PrincipalId,
    human_issuer: PrincipalId,
}

impl VerifiedReleaseRequest {
    pub(crate) fn request(&self) -> &ClosedReleaseRequest {
        &self.request
    }

    pub(crate) fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub(crate) fn human_issuer(&self) -> &PrincipalId {
        &self.human_issuer
    }
}

/// Verify a single agent action and its exact human-issued grant before a
/// release task can reserve a provider call. Unsupported critical policy is
/// refused rather than silently ignored by this new capability.
pub(crate) fn verify_release_request(
    recipe: &CompiledReleaseRecipe,
    context: &TrustedContext,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<VerifiedReleaseRequest, GatewaySubmitResult> {
    let sealed = verify_sealed(context, now, proof_cbor, action_cbor)?;
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
    if terminal.statement().subject() != &branch.actor
        || matches!(
            terminal.statement().action_constraint(),
            ActionConstraint::AnyBody
        )
    {
        return Err(not_entered("gateway.release.exact-human-grant-required"));
    }
    if branch.chain.iter().any(|grant| {
        !grant.statement().extensions().as_slice().is_empty()
            || grant.statement().budget_ceiling().is_some()
    }) {
        return Err(not_entered("gateway.release.unsupported-grant-policy"));
    }
    Ok(VerifiedReleaseRequest {
        request,
        actor: branch.actor.clone(),
        human_issuer: terminal.statement().issuer().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GatewayObserver;
    use crate::harness::{self, Signer};
    use crate::observed_tests::submission;
    use crate::release_state::{ReleaseResourceScope, ReleaseTaskPolicy, ReleaseTaskState};
    use auths_codec::{body_digest, grant_signing_preimage};
    use auths_model::{
        AssurancePolicyId, AudienceSet, CriticalExtensions, GrantStatement, PermissionSet,
        SignatureEnvelope, SignedGrant, StatusPolicy,
    };
    use auths_profile_mcp::McpProfile;
    use serde_json::{Map, Value, json};
    use sha2::{Digest as _, Sha256};

    const NOW: u64 = 1_790_000_000;

    fn recipe() -> CompiledReleaseRecipe {
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

    fn arguments(recipe: &CompiledReleaseRecipe, recipient: &str) -> Map<String, Value> {
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

    fn exact_grant(root: &Signer, agent: &Signer, arguments: &Map<String, Value>) -> SignedGrant {
        let call = harness::call(arguments).expect("call");
        let canonical = McpProfile
            .canonicalize(&call.canonical_bytes().expect("body"))
            .expect("canonical");
        let statement = GrantStatement::new(
            root.principal.clone(),
            agent.principal.clone(),
            call.profile_ref().expect("profile"),
            PermissionSet::new(vec![call.permission().expect("permission")]).expect("permissions"),
            harness::window(NOW - 3_600, NOW + 3_600).expect("window"),
            AudienceSet::new(vec![harness::audience().expect("audience")]).expect("audiences"),
            ActionConstraint::ExactBodyDigest(body_digest(canonical.body())),
            None,
            0,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse(harness::ASSURANCE).expect("assurance"),
            CriticalExtensions::empty(),
        );
        let descriptor = root.descriptor();
        let signature =
            root.sign(&grant_signing_preimage(&statement, &descriptor).expect("preimage"));
        SignedGrant::new(statement, SignatureEnvelope::new(descriptor, signature))
    }

    #[test]
    fn native_proof_binds_agent_human_and_exact_read_before_task_charge() {
        let root = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context(&root, observer.principal(), None, NOW).expect("context");
        let recipe = recipe();
        let arguments = arguments(&recipe, agent.principal.as_str());
        let grant = exact_grant(&root, &agent, &arguments);
        let signed = submission(&root, &agent, &grant, &arguments, &[]);
        let verified =
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action)
                .expect("native authorized proof");
        assert_eq!(verified.actor(), &agent.principal);
        assert_eq!(verified.human_issuer(), &root.principal);
        assert_eq!(verified.request().recipient(), agent.principal.as_str());
        assert_eq!(
            verified.request().url(),
            format!("{}/v0/{}", harness::ORIGIN, harness::RECORD)
        );

        let policy = ReleaseTaskPolicy {
            task_id: "task-1".to_owned(),
            task_commitment: [0x11; 32],
            company_id: "atlas".to_owned(),
            human_principal: root.principal.as_str().to_owned(),
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
                connection_id: "jules-connection".to_owned(),
                connection_generation: 3,
            }],
        };
        let mut wrong_human = ReleaseTaskState::from_test_policy(ReleaseTaskPolicy {
            human_principal: Signer::new(0x44).principal.as_str().to_owned(),
            ..policy.clone()
        })
        .expect("policy");
        assert!(
            wrong_human
                .reserve_verified_request(&verified, "jules-connection", 3, NOW)
                .is_err()
        );
        assert_eq!(wrong_human.counts(), (0, 0, 0));
        let mut wrong_task = ReleaseTaskState::from_test_policy(ReleaseTaskPolicy {
            task_commitment: [0x12; 32],
            ..policy.clone()
        })
        .expect("policy");
        assert!(
            wrong_task
                .reserve_verified_request(&verified, "jules-connection", 3, NOW)
                .is_err()
        );
        assert_eq!(wrong_task.counts(), (0, 0, 0));
        let mut state = ReleaseTaskState::from_test_policy(policy).expect("policy");
        assert!(
            state
                .reserve_verified_request(&verified, "jules-connection", 4, NOW)
                .is_err()
        );
        assert_eq!(state.counts(), (0, 0, 0));
        state
            .reserve_verified_request(&verified, "jules-connection", 3, NOW)
            .expect("task admission");
        assert_eq!(state.counts(), (1, 0, 0));
        assert!(
            state
                .reserve_verified_request(&verified, "jules-connection", 3, NOW)
                .is_err()
        );
    }

    #[test]
    fn native_release_refuses_a_mismatched_recipient_and_broad_grant() {
        let root = Signer::new(0x11);
        let agent = Signer::new(0x22);
        let observer = GatewayObserver::from_test_seed(0x33);
        let context = harness::context(&root, observer.principal(), None, NOW).expect("context");
        let recipe = recipe();
        let wrong_recipient = arguments(&recipe, Signer::new(0x44).principal.as_str());
        let grant = exact_grant(&root, &agent, &wrong_recipient);
        let signed = submission(&root, &agent, &grant, &wrong_recipient, &[]);
        assert!(matches!(
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action),
            Err(GatewaySubmitResult::NotEntered { code }) if code == "gateway.release.recipient-mismatch"
        ));

        let arguments = arguments(&recipe, agent.principal.as_str());
        let exact = exact_grant(&root, &agent, &arguments);
        let mut changed = arguments.clone();
        changed.insert("record_id".to_owned(), json!(harness::OTHER_RECORD));
        let signed = submission(&root, &agent, &exact, &changed, &[]);
        assert!(
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action).is_err(),
            "the human's body-digest grant cannot authorize another source"
        );
        let broad = harness::grant(&root, &agent.principal, None, NOW).expect("broad grant");
        let signed = submission(&root, &agent, &broad, &arguments, &[]);
        assert!(matches!(
            verify_release_request(&recipe, &context, NOW, &signed.proof, &signed.action),
            Err(GatewaySubmitResult::NotEntered { code }) if code == "gateway.release.exact-human-grant-required"
        ));
    }
}
