//! Deterministic, side-effect-free Auths proof verification.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use auths_proof_adapter_api::{
    AdapterRegistry, ControlProofInput, PrincipalControlError, VerifiedPrincipal,
};
use auths_proof_codec::{
    action_id, action_signing_bytes, body_digest, decode_bundle, grant_id, grant_signing_bytes,
    CodecError, DecodeLimits,
};
use auths_proof_model::{
    AssuranceClaim, AssuranceClaims, Audience, Challenge, Decision, GrantId, Limitation,
    PermissionSet, PrincipalEvidenceEntry, PrincipalRef, ProofBundle, ProofPurpose,
    RevocationRequirement, SignedAction, SignedGrant, StatementId, Timestamp, TrustAnchor,
    TrustVerdict, ValidityWindow, VerdictReason, VerificationPolicy,
};

pub struct VerificationContext<'a> {
    pub now: Timestamp,
    pub expected_audience: &'a Audience,
    pub expected_challenge: &'a Challenge,
    pub action_body: &'a [u8],
    pub trust_anchors: &'a [TrustAnchor],
    pub policy: &'a VerificationPolicy,
    pub decode_limits: DecodeLimits,
}

#[derive(Clone)]
struct EffectiveAuthority {
    root: PrincipalRef,
    current_principal: PrincipalRef,
    permissions: PermissionSet,
    validity: ValidityWindow,
    remaining_delegation_depth: auths_proof_model::DelegationDepth,
    last_statement_time: Timestamp,
    last_grant_id: Option<GrantId>,
}

struct Progress {
    root: Option<PrincipalRef>,
    actor: Option<PrincipalRef>,
    grant_count: usize,
    assurance: Option<AssuranceClaims>,
    limitations: Vec<Limitation>,
}

impl Progress {
    fn new(bundle: &ProofBundle) -> Self {
        Self {
            root: None,
            actor: Some(bundle.action().payload().actor().clone()),
            grant_count: bundle.grants().len(),
            assurance: None,
            limitations: Vec::new(),
        }
    }

    fn observe_principal(&mut self, verified: &VerifiedPrincipal) {
        match &mut self.assurance {
            Some(existing) => existing.intersect_assign(verified.claims()),
            None => self.assurance = Some(verified.claims().clone()),
        }

        let revocable = verified.claims().as_slice().iter().any(|claim| {
            matches!(
                claim,
                AssuranceClaim::RotationAware | AssuranceClaim::RevocationCheckedAt(_)
            )
        });
        if !revocable
            && !self.limitations.iter().any(|limitation| {
                matches!(
                    limitation,
                    Limitation::IrrevocablePrincipal(principal)
                        if principal == verified.principal()
                )
            })
        {
            self.limitations.push(Limitation::IrrevocablePrincipal(
                verified.principal().clone(),
            ));
        }
    }

    fn verdict(self, decision: Decision, reason: VerdictReason) -> TrustVerdict {
        TrustVerdict::new(
            decision,
            vec![reason],
            self.root,
            self.actor,
            self.grant_count,
            self.assurance.unwrap_or_else(AssuranceClaims::empty),
            self.limitations,
        )
    }
}

#[derive(Clone, Copy)]
struct Failure {
    decision: Decision,
    reason: VerdictReason,
}

impl Failure {
    const fn denied(reason: VerdictReason) -> Self {
        Self {
            decision: Decision::Denied,
            reason,
        }
    }

    const fn indeterminate(reason: VerdictReason) -> Self {
        Self {
            decision: Decision::Indeterminate,
            reason,
        }
    }
}

pub fn verify(
    encoded_bundle: &[u8],
    context: &VerificationContext<'_>,
    adapters: &AdapterRegistry<'_>,
) -> TrustVerdict {
    let bundle = match decode_bundle(encoded_bundle, context.decode_limits) {
        Ok(bundle) => bundle,
        Err(error) => {
            let reason = codec_reason(&error);
            return TrustVerdict::new(
                Decision::Denied,
                vec![reason],
                None,
                None,
                0,
                AssuranceClaims::empty(),
                Vec::new(),
            );
        }
    };

    let mut progress = Progress::new(&bundle);
    match verify_bundle(&bundle, context, adapters, &mut progress) {
        Ok(()) => progress.verdict(Decision::Authorized, VerdictReason::AuthorizedByGrantChain),
        Err(failure) => progress.verdict(failure.decision, failure.reason),
    }
}

fn verify_bundle(
    bundle: &ProofBundle,
    context: &VerificationContext<'_>,
    adapters: &AdapterRegistry<'_>,
    progress: &mut Progress,
) -> Result<(), Failure> {
    validate_evidence_graph(bundle)?;
    verify_action_context(bundle.action(), context)?;

    let root_principal = bundle
        .grants()
        .first()
        .map(|grant| grant.payload().issuer())
        .unwrap_or_else(|| bundle.action().payload().actor());
    let anchor = if bundle.grants().is_empty() {
        context.trust_anchors.iter().find(|anchor| {
            anchor.principal() == root_principal
                && anchor
                    .authority()
                    .permissions()
                    .contains(bundle.action().payload().permission())
                && anchor
                    .validity()
                    .contains_window(&bundle.action().payload().validity())
        })
    } else {
        let required_permissions = bundle.grants()[0].payload().permissions();
        context.trust_anchors.iter().find(|anchor| {
            anchor.principal() == root_principal
                && required_permissions.is_subset_of(anchor.authority().permissions())
                && anchor
                    .validity()
                    .contains_window(&bundle.grants()[0].payload().validity())
                && anchor
                    .validity()
                    .contains(bundle.grants()[0].payload().issued_at())
        })
    }
    .ok_or_else(|| Failure::denied(VerdictReason::UntrustedRoot))?;

    progress.root = Some(anchor.principal().clone());

    let mut authority = EffectiveAuthority {
        root: anchor.principal().clone(),
        current_principal: anchor.principal().clone(),
        permissions: anchor.authority().permissions().clone(),
        validity: anchor.validity(),
        remaining_delegation_depth: anchor.max_delegation_depth(),
        last_statement_time: anchor.validity().from(),
        last_grant_id: None,
    };

    for (index, grant) in bundle.grants().iter().enumerate() {
        verify_grant_shape(grant, &authority, context.now, index)?;

        let verified = verify_grant_signature(grant, bundle, context, adapters)?;
        if index == 0 {
            enforce_assurance(
                verified.claims(),
                anchor.required_assurance().required_claims(),
                anchor.required_assurance().max_controller_status_age(),
                anchor.required_assurance().allow_irrevocable_principals(),
                anchor
                    .required_assurance()
                    .require_statement_time_for_historical_keys(),
                context.now,
            )?;
        }
        enforce_assurance(
            verified.claims(),
            context.policy.required_assurance(),
            context.policy.controller_status_max_age(),
            context.policy.allow_irrevocable_principals(),
            context.policy.require_statement_time_for_historical_keys(),
            context.now,
        )?;
        progress.observe_principal(&verified);

        let grant_identifier = grant_id(grant);
        match grant.payload().revocation() {
            RevocationRequirement::ExpiryOnly => {
                if !context.policy.allow_expiry_only_grants() {
                    return Err(Failure::indeterminate(
                        VerdictReason::ExpiryOnlyGrantDisallowed,
                    ));
                }
                progress
                    .limitations
                    .push(Limitation::ExpiryOnlyGrant(grant_identifier));
            }
            RevocationRequirement::StatusProofRequired { .. } => {
                return Err(Failure::indeterminate(
                    VerdictReason::MissingAuthorityStateEvidence,
                ));
            }
        }

        authority = EffectiveAuthority {
            root: authority.root,
            current_principal: grant.payload().subject().clone(),
            permissions: grant.payload().permissions().clone(),
            validity: grant.payload().validity(),
            remaining_delegation_depth: grant.payload().remaining_delegation_depth(),
            last_statement_time: grant.payload().issued_at(),
            last_grant_id: Some(grant_identifier),
        };
    }

    let action = bundle.action();
    if action.payload().actor() != &authority.current_principal {
        return Err(Failure::denied(VerdictReason::BrokenGrantChain));
    }
    if !authority
        .permissions
        .contains(action.payload().permission())
    {
        return Err(Failure::denied(VerdictReason::PermissionNotGranted));
    }
    if !authority
        .validity
        .contains_window(&action.payload().validity())
        || action.payload().issued_at() < authority.last_statement_time
    {
        return Err(Failure::denied(VerdictReason::DelegationExpanded));
    }

    let verified = verify_action_signature(action, bundle, context, adapters)?;
    enforce_assurance(
        verified.claims(),
        context.policy.required_assurance(),
        context.policy.controller_status_max_age(),
        context.policy.allow_irrevocable_principals(),
        context.policy.require_statement_time_for_historical_keys(),
        context.now,
    )?;
    if bundle.grants().is_empty() {
        enforce_assurance(
            verified.claims(),
            anchor.required_assurance().required_claims(),
            anchor.required_assurance().max_controller_status_age(),
            anchor.required_assurance().allow_irrevocable_principals(),
            anchor
                .required_assurance()
                .require_statement_time_for_historical_keys(),
            context.now,
        )?;
    }
    progress.observe_principal(&verified);
    Ok(())
}

fn validate_evidence_graph(bundle: &ProofBundle) -> Result<(), Failure> {
    let mut statement_ids = Vec::with_capacity(bundle.grants().len() + 1);
    for grant in bundle.grants() {
        statement_ids.push(StatementId::Grant(grant_id(grant)));
    }
    statement_ids.push(StatementId::Action(action_id(bundle.action())));
    statement_ids.sort();

    let bindings = bundle.principal_evidence_bindings();
    if bindings.len() != statement_ids.len() {
        return Err(Failure::indeterminate(
            VerdictReason::MissingPrincipalEvidence,
        ));
    }
    if bindings
        .windows(2)
        .any(|pair| pair[0].statement() == pair[1].statement())
    {
        return Err(Failure::denied(VerdictReason::DuplicateEvidenceBinding));
    }

    for statement in &statement_ids {
        if !bindings
            .iter()
            .any(|binding| binding.statement() == *statement)
        {
            return Err(Failure::indeterminate(
                VerdictReason::MissingPrincipalEvidence,
            ));
        }
    }
    for binding in bindings {
        if statement_ids.binary_search(&binding.statement()).is_err() {
            return Err(Failure::denied(VerdictReason::UnusedEvidence));
        }
        if !bundle
            .principal_evidence()
            .iter()
            .any(|evidence| evidence.id() == binding.evidence())
        {
            return Err(Failure::indeterminate(
                VerdictReason::MissingPrincipalEvidence,
            ));
        }
    }
    for evidence in bundle.principal_evidence() {
        if !bindings
            .iter()
            .any(|binding| binding.evidence() == evidence.id())
        {
            return Err(Failure::denied(VerdictReason::UnusedEvidence));
        }
    }
    Ok(())
}

fn verify_action_context(
    action: &SignedAction,
    context: &VerificationContext<'_>,
) -> Result<(), Failure> {
    if action.payload().audience() != context.expected_audience {
        return Err(Failure::denied(VerdictReason::AudienceMismatch));
    }
    if action.payload().challenge() != *context.expected_challenge {
        return Err(Failure::denied(VerdictReason::ChallengeMismatch));
    }
    if !action.payload().validity().contains(context.now) {
        return Err(Failure::denied(VerdictReason::ActionOutsideValidity));
    }
    if action.payload().body_digest() != body_digest(context.action_body) {
        return Err(Failure::denied(VerdictReason::ActionBodyMismatch));
    }
    Ok(())
}

fn verify_grant_shape(
    grant: &SignedGrant,
    authority: &EffectiveAuthority,
    now: Timestamp,
    index: usize,
) -> Result<(), Failure> {
    if grant.payload().issuer() != &authority.current_principal {
        return Err(Failure::denied(VerdictReason::BrokenGrantChain));
    }
    if !grant
        .payload()
        .permissions()
        .is_subset_of(&authority.permissions)
    {
        return Err(Failure::denied(VerdictReason::DelegationExpanded));
    }
    if !authority
        .validity
        .contains_window(&grant.payload().validity())
        || grant.payload().issued_at() < authority.last_statement_time
    {
        return Err(Failure::denied(VerdictReason::DelegationExpanded));
    }
    if !grant.payload().validity().contains(now) {
        return Err(Failure::denied(VerdictReason::GrantExpired));
    }
    if authority.remaining_delegation_depth.get() == 0
        || grant.payload().remaining_delegation_depth().get()
            >= authority.remaining_delegation_depth.get()
    {
        return Err(Failure::denied(VerdictReason::DelegationExpanded));
    }
    let expected_parent = authority.last_grant_id;
    if grant.payload().parent() != expected_parent || (index == 0 && expected_parent.is_some()) {
        return Err(Failure::denied(VerdictReason::BrokenGrantChain));
    }
    Ok(())
}

fn verify_grant_signature(
    grant: &SignedGrant,
    bundle: &ProofBundle,
    context: &VerificationContext<'_>,
    adapters: &AdapterRegistry<'_>,
) -> Result<VerifiedPrincipal, Failure> {
    let statement = StatementId::Grant(grant_id(grant));
    let bytes = grant_signing_bytes(grant.payload(), grant.signature().descriptor());
    verify_signature(
        grant.payload().issuer(),
        ProofPurpose::CapabilityDelegation,
        grant.payload().issued_at(),
        statement,
        &bytes,
        grant.signature(),
        bundle,
        context,
        adapters,
    )
}

fn verify_action_signature(
    action: &SignedAction,
    bundle: &ProofBundle,
    context: &VerificationContext<'_>,
    adapters: &AdapterRegistry<'_>,
) -> Result<VerifiedPrincipal, Failure> {
    let statement = StatementId::Action(action_id(action));
    let bytes = action_signing_bytes(action.payload(), action.signature().descriptor());
    verify_signature(
        action.payload().actor(),
        ProofPurpose::CapabilityInvocation,
        action.payload().issued_at(),
        statement,
        &bytes,
        action.signature(),
        bundle,
        context,
        adapters,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_signature(
    principal: &PrincipalRef,
    purpose: ProofPurpose,
    asserted_signing_time: Timestamp,
    statement: StatementId,
    signing_bytes: &[u8],
    signature: &auths_proof_model::SignatureEnvelope,
    bundle: &ProofBundle,
    context: &VerificationContext<'_>,
    adapters: &AdapterRegistry<'_>,
) -> Result<VerifiedPrincipal, Failure> {
    let evidence = evidence_for_statement(bundle, statement)?;
    let descriptor = signature.descriptor();
    if evidence.method() != descriptor.adapter() {
        return Err(Failure::denied(VerdictReason::PrincipalAdapterMismatch));
    }
    let adapter = adapters
        .principal_by_id(descriptor.adapter())
        .ok_or_else(|| Failure::indeterminate(VerdictReason::UnsupportedAdapter))?;
    if !adapter.supports(principal) {
        return Err(Failure::denied(VerdictReason::PrincipalAdapterMismatch));
    }
    adapter
        .verify_control(ControlProofInput {
            principal,
            purpose,
            verification_method: descriptor.verification_method(),
            algorithm: descriptor.algorithm(),
            signing_bytes,
            signature: signature.signature().as_slice(),
            evidence,
            asserted_signing_time,
            verification_time: context.now,
        })
        .map_err(control_failure)
}

fn evidence_for_statement(
    bundle: &ProofBundle,
    statement: StatementId,
) -> Result<&PrincipalEvidenceEntry, Failure> {
    let binding = bundle
        .principal_evidence_bindings()
        .iter()
        .find(|binding| binding.statement() == statement)
        .ok_or_else(|| Failure::indeterminate(VerdictReason::MissingPrincipalEvidence))?;
    bundle
        .principal_evidence()
        .iter()
        .find(|evidence| evidence.id() == binding.evidence())
        .ok_or_else(|| Failure::indeterminate(VerdictReason::MissingPrincipalEvidence))
}

fn enforce_assurance(
    actual: &AssuranceClaims,
    required: &AssuranceClaims,
    max_controller_status_age: Option<auths_proof_model::DurationSeconds>,
    allow_irrevocable: bool,
    require_statement_time_for_historical_keys: bool,
    verification_time: Timestamp,
) -> Result<(), Failure> {
    if !actual.contains_all(required) {
        return Err(Failure::indeterminate(
            VerdictReason::AssuranceRequirementNotMet,
        ));
    }
    let revocable = actual.as_slice().iter().any(|claim| {
        matches!(
            claim,
            AssuranceClaim::RotationAware | AssuranceClaim::RevocationCheckedAt(_)
        )
    });
    if !allow_irrevocable && !revocable {
        return Err(Failure::indeterminate(
            VerdictReason::IrrevocablePrincipalDisallowed,
        ));
    }
    if require_statement_time_for_historical_keys
        && actual
            .as_slice()
            .iter()
            .any(|claim| matches!(claim, AssuranceClaim::ControllerStateHistoricalAt(_)))
        && !actual
            .as_slice()
            .iter()
            .any(|claim| matches!(claim, AssuranceClaim::StatementExistenceProvenAt(_)))
    {
        return Err(Failure::indeterminate(
            VerdictReason::HistoricalStateUnavailable,
        ));
    }
    if let Some(max_age) = max_controller_status_age {
        let freshest = actual
            .as_slice()
            .iter()
            .filter_map(|claim| match claim {
                AssuranceClaim::ControllerStateCurrentAt(timestamp)
                | AssuranceClaim::RevocationCheckedAt(timestamp) => Some(*timestamp),
                _ => None,
            })
            .max();
        let fresh = freshest.is_some_and(|timestamp| {
            timestamp <= verification_time
                && verification_time
                    .as_secs()
                    .saturating_sub(timestamp.as_secs())
                    <= max_age.as_secs()
        });
        if !fresh {
            return Err(Failure::indeterminate(
                VerdictReason::StaleAuthorityStateEvidence,
            ));
        }
    }
    Ok(())
}

fn control_failure(error: PrincipalControlError) -> Failure {
    match error {
        PrincipalControlError::UnsupportedPrincipal => {
            Failure::denied(VerdictReason::PrincipalAdapterMismatch)
        }
        PrincipalControlError::AdapterMismatch => {
            Failure::denied(VerdictReason::PrincipalAdapterMismatch)
        }
        PrincipalControlError::VerificationMethodMismatch => {
            Failure::denied(VerdictReason::VerificationMethodMismatch)
        }
        PrincipalControlError::AlgorithmMismatch => {
            Failure::denied(VerdictReason::AlgorithmMismatch)
        }
        PrincipalControlError::InvalidEvidence => {
            Failure::denied(VerdictReason::InvalidEvidenceDigest)
        }
        PrincipalControlError::InvalidSignature => Failure::denied(VerdictReason::InvalidSignature),
        PrincipalControlError::ResourceLimitExceeded => {
            Failure::denied(VerdictReason::ResourceLimitExceeded)
        }
    }
}

fn codec_reason(error: &CodecError) -> VerdictReason {
    match error {
        CodecError::NonCanonical => VerdictReason::NonCanonicalProof,
        CodecError::LimitExceeded => VerdictReason::ResourceLimitExceeded,
        CodecError::DigestMismatch => VerdictReason::InvalidEvidenceDigest,
        _ => VerdictReason::MalformedProof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use auths_proof_author::{ActionBuilder, GrantBuilder, ProofBundleBuilder};
    use auths_proof_codec::{body_digest, encode_bundle};
    use auths_proof_model::{
        AssuranceRequirements, AuthorityScope, CapabilityId, DelegationDepth, Permission,
    };
    use auths_proof_raw_key::{
        test_signing::{ed25519_descriptor, sign_ed25519},
        RawKeyAdapter,
    };
    use proptest::prelude::*;

    const ROOT_SEED: [u8; 32] = [21; 32];
    const AGENT_SEED: [u8; 32] = [22; 32];

    struct Fixture {
        encoded: Vec<u8>,
        body: Vec<u8>,
        audience: Audience,
        challenge: Challenge,
        anchor: TrustAnchor,
    }

    fn fixture() -> Fixture {
        let root_descriptor = ed25519_descriptor(ROOT_SEED).expect("root descriptor");
        let agent_descriptor = ed25519_descriptor(AGENT_SEED).expect("agent descriptor");
        let root = root_descriptor.principal().expect("root principal");
        let agent = agent_descriptor.principal().expect("agent principal");
        let permission = Permission::new(
            CapabilityId::parse("mcp.tools.call").expect("capability"),
            auths_proof_model::ResourceId::parse("mcp://filesystem/read_file").expect("resource"),
        );
        let grant_draft = GrantBuilder::new(
            root.clone(),
            agent.clone(),
            root_descriptor
                .signature_descriptor()
                .expect("root signature descriptor"),
        )
        .permission(permission.clone())
        .issued_at(Timestamp::new(100))
        .valid_between(Timestamp::new(100), Timestamp::new(200))
        .expect("validity")
        .delegation_depth(DelegationDepth::new(0))
        .build()
        .expect("grant draft");
        let grant_signature = sign_ed25519(ROOT_SEED, grant_draft.signing_request().bytes());
        let grant = grant_draft.attach(grant_signature).expect("grant");

        let body = br#"{"path":"/safe.txt"}"#.to_vec();
        let audience = Audience::parse("mcp://filesystem").expect("audience");
        let challenge = Challenge::new([5; 32]);
        let action_draft = ActionBuilder::new(
            agent,
            agent_descriptor
                .signature_descriptor()
                .expect("agent signature descriptor"),
            permission.clone(),
            body_digest(&body),
            audience.clone(),
            Timestamp::new(120),
            Timestamp::new(130),
            challenge,
        )
        .build()
        .expect("action draft");
        let action_signature = sign_ed25519(AGENT_SEED, action_draft.signing_request().bytes());
        let action = action_draft.attach(action_signature).expect("action");

        let bundle = ProofBundleBuilder::new(
            action,
            agent_descriptor.evidence_entry().expect("agent evidence"),
        )
        .expect("bundle")
        .push_grant(
            grant,
            root_descriptor.evidence_entry().expect("root evidence"),
        )
        .expect("grant")
        .build()
        .expect("bundle");

        let anchor = TrustAnchor::new(
            root,
            AuthorityScope::new(PermissionSet::new(vec![permission]).expect("permissions")),
            ValidityWindow::new(Timestamp::new(90), Timestamp::new(210)).expect("anchor validity"),
            DelegationDepth::new(1),
            AssuranceRequirements::new(
                AssuranceClaims::new(vec![
                    AssuranceClaim::SelfCertifyingIdentifier,
                    AssuranceClaim::OfflineVerifiable,
                ]),
                None,
                true,
                true,
            ),
        );

        Fixture {
            encoded: encode_bundle(&bundle).expect("encode"),
            body,
            audience,
            challenge,
            anchor,
        }
    }

    fn verify_fixture(fixture: &Fixture, body: &[u8]) -> TrustVerdict {
        let adapter = RawKeyAdapter::new().expect("adapter");
        let principal_adapters: [&dyn auths_proof_adapter_api::PrincipalControlVerifier; 1] =
            [&adapter];
        let registry = AdapterRegistry::new(&principal_adapters, &[]);
        verify(
            &fixture.encoded,
            &VerificationContext {
                now: Timestamp::new(125),
                expected_audience: &fixture.audience,
                expected_challenge: &fixture.challenge,
                action_body: body,
                trust_anchors: core::slice::from_ref(&fixture.anchor),
                policy: &VerificationPolicy::live_action(),
                decode_limits: DecodeLimits::standard(),
            },
            &registry,
        )
    }

    #[test]
    fn raw_root_to_agent_action_is_authorized() {
        let fixture = fixture();
        let verdict = verify_fixture(&fixture, &fixture.body);
        assert_eq!(verdict.decision(), Decision::Authorized);
        assert_eq!(verdict.reasons(), &[VerdictReason::AuthorizedByGrantChain]);
    }

    #[test]
    fn modified_body_is_denied() {
        let fixture = fixture();
        let verdict = verify_fixture(&fixture, b"different");
        assert_eq!(verdict.decision(), Decision::Denied);
        assert_eq!(verdict.reasons(), &[VerdictReason::ActionBodyMismatch]);
    }

    #[test]
    fn historical_state_requires_statement_existence() {
        let result = enforce_assurance(
            &AssuranceClaims::new(vec![
                AssuranceClaim::OfflineVerifiable,
                AssuranceClaim::ControllerStateHistoricalAt(Timestamp::new(100)),
            ]),
            &AssuranceClaims::empty(),
            None,
            true,
            true,
            Timestamp::new(200),
        );
        assert!(matches!(
            result,
            Err(Failure {
                decision: Decision::Indeterminate,
                reason: VerdictReason::HistoricalStateUnavailable,
            })
        ));
    }

    #[test]
    fn controller_status_age_is_enforced() {
        let result = enforce_assurance(
            &AssuranceClaims::new(vec![
                AssuranceClaim::OfflineVerifiable,
                AssuranceClaim::ControllerStateCurrentAt(Timestamp::new(100)),
            ]),
            &AssuranceClaims::empty(),
            Some(auths_proof_model::DurationSeconds::new(10)),
            true,
            true,
            Timestamp::new(111),
        );
        assert!(matches!(
            result,
            Err(Failure {
                decision: Decision::Indeterminate,
                reason: VerdictReason::StaleAuthorityStateEvidence,
            })
        ));
    }

    proptest! {
        #[test]
        fn permission_attenuation_is_exact(child_indices in proptest::collection::vec(0_u8..12, 1..20)) {
            let root_descriptor = ed25519_descriptor(ROOT_SEED).expect("root descriptor");
            let agent_descriptor = ed25519_descriptor(AGENT_SEED).expect("agent descriptor");
            let root = root_descriptor.principal().expect("root principal");
            let agent = agent_descriptor.principal().expect("agent principal");
            let permission_for = |index: u8| {
                Permission::new(
                    CapabilityId::parse("mcp.tools.call").expect("capability"),
                    auths_proof_model::ResourceId::parse(&format!("mcp://filesystem/{index}"))
                        .expect("resource"),
                )
            };
            let parent_permissions = PermissionSet::new(
                (0_u8..8).map(permission_for).collect()
            ).expect("parent permissions");
            let mut builder = GrantBuilder::new(
                root.clone(),
                agent,
                root_descriptor.signature_descriptor().expect("root descriptor"),
            )
            .issued_at(Timestamp::new(100))
            .valid_between(Timestamp::new(100), Timestamp::new(200))
            .expect("validity")
            .delegation_depth(DelegationDepth::new(0));
            for index in &child_indices {
                builder = builder.permission(permission_for(*index));
            }
            let draft = builder.build().expect("grant draft");
            let signature = sign_ed25519(ROOT_SEED, draft.signing_request().bytes());
            let grant = draft.attach(signature).expect("grant");
            let authority = EffectiveAuthority {
                root,
                current_principal: grant.payload().issuer().clone(),
                permissions: parent_permissions,
                validity: ValidityWindow::new(Timestamp::new(90), Timestamp::new(210))
                    .expect("authority validity"),
                remaining_delegation_depth: DelegationDepth::new(1),
                last_statement_time: Timestamp::new(90),
                last_grant_id: None,
            };

            let result = verify_grant_shape(&grant, &authority, Timestamp::new(125), 0);
            if child_indices.iter().all(|index| *index < 8) {
                prop_assert!(result.is_ok());
            } else {
                let expansion_denied = matches!(
                    result,
                    Err(Failure {
                        decision: Decision::Denied,
                        reason: VerdictReason::DelegationExpanded,
                    })
                );
                prop_assert!(expansion_denied);
            }
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let adapter = RawKeyAdapter::new().expect("adapter");
            let principal_adapters: [&dyn auths_proof_adapter_api::PrincipalControlVerifier; 1] = [&adapter];
            let registry = AdapterRegistry::new(&principal_adapters, &[]);
            let audience = Audience::parse("mcp://filesystem").expect("audience");
            let challenge = Challenge::new([0; 32]);
            let policy = VerificationPolicy::live_action();
            let verdict = verify(
                &bytes,
                &VerificationContext {
                    now: Timestamp::new(0),
                    expected_audience: &audience,
                    expected_challenge: &challenge,
                    action_body: b"",
                    trust_anchors: &[],
                    policy: &policy,
                    decode_limits: DecodeLimits::standard(),
                },
                &registry,
            );
            prop_assert!(matches!(
                verdict.decision(),
                Decision::Denied | Decision::Indeterminate | Decision::Authorized
            ));
        }
    }
}
