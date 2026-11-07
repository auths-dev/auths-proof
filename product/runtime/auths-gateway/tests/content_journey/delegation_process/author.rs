//! Native public authoring APIs with external signature results. No private
//! key, alternate verifier, gateway permit or custom authorization evaluator.
use super::*;
use auths_author::{
    WorkflowProofBuilder, address_evidence, prepare_action, prepare_grant, prepare_profile_action,
};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::McpProfile;
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};

#[derive(Clone)]
pub(super) struct PublicIdentity {
    pub(super) principal: PrincipalId,
    pub(super) key: [u8; 32],
    descriptor: SignatureDescriptor,
    evidence: EvidenceObject,
}
impl PublicIdentity {
    pub(super) fn new(key: [u8; 32]) -> Self {
        let raw =
            RawKeyDescriptor::new(RawKeyType::Ed25519, key.to_vec()).expect("public descriptor");
        let principal = raw.principal().expect("native public principal");
        let descriptor = SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("method"),
            VerificationMethod::parse(principal.as_str()).expect("verification method"),
            SignatureSuiteId::parse("ed25519-v1").expect("suite"),
        );
        let evidence = address_evidence(
            EvidenceTypeId::parse(RAW_KEY_V1).expect("evidence type"),
            MediaType::parse(RAW_KEY_MEDIA_TYPE).expect("media"),
            raw.encode(),
        )
        .expect("addressed public evidence");
        Self {
            principal,
            key,
            descriptor,
            evidence,
        }
    }
}
pub(super) struct Grant {
    pub(super) signed: SignedGrant,
    issuer: PublicIdentity,
}
impl Grant {
    pub(super) fn id(&self) -> GrantId {
        auths_codec::grant_id(self.signed.statement()).expect("native grant ID")
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit native grant dimensions with external signature"
)]
pub(super) fn grant(
    issuer: &mut Actor,
    subject: &PublicIdentity,
    service: &str,
    tools: &[&str],
    parent: Option<GrantId>,
    depth: u16,
    audience: Audience,
    now: u64,
) -> Grant {
    let calls: Vec<_> = tools
        .iter()
        .map(|tool| McpToolCall::new(service, *tool, serde_json::Map::new()).expect("tool"))
        .collect();
    let statement = GrantStatement::new(
        issuer.public.principal.clone(),
        subject.principal.clone(),
        calls[0].profile_ref().expect("profile"),
        PermissionSet::new(
            calls
                .iter()
                .map(|call| call.permission().expect("permission"))
                .collect(),
        )
        .expect("permissions"),
        window(now - 60, now + 3600),
        AudienceSet::new(vec![audience]).expect("audience"),
        ActionConstraint::AnyBody,
        None,
        depth,
        parent,
        StatusPolicy::ExpiryOnly,
        AssurancePolicyId::parse("gateway-observer-test-v1").expect("assurance"),
        CriticalExtensions::empty(),
    );
    let request = prepare_grant(statement, issuer.public.descriptor.clone())
        .expect("native grant preparation");
    let signature = issuer.sign(request.signing_preimage());
    Grant {
        signed: request.complete(signature),
        issuer: issuer.public.clone(),
    }
}
pub(super) struct Invocation {
    pub(super) proof: Vec<u8>,
    pub(super) action: Vec<u8>,
}
impl Invocation {
    pub(super) fn borrowed(&self) -> EnrollmentInvocation<'_> {
        EnrollmentInvocation {
            proof: &self.proof,
            action: &self.action,
        }
    }
}
pub(super) fn author(
    signer: &mut Actor,
    grants: &[&Grant],
    call: &McpToolCall,
    audience: Audience,
    context: &TrustedContext,
    now: u64,
) -> Invocation {
    let canonical = McpProfile
        .canonicalize(&call.canonical_bytes().expect("native call"))
        .expect("native canonical action");
    let prepared = prepare_profile_action(
        canonical,
        audience,
        signer.public.principal.clone(),
        &grants.last().expect("grant chain").signed,
        [0; 32],
        now,
        Some(300),
    )
    .expect("native action preparation");
    let (canonical, envelope) = prepared.into_parts();
    let request =
        prepare_action(envelope, signer.public.descriptor.clone()).expect("native signing request");
    let signature = signer.sign(request.signing_preimage());
    let action = request.complete(signature);
    let mut proof = WorkflowProofBuilder::new();
    for grant in grants {
        let index = proof
            .push_grant(grant.signed.clone())
            .expect("native grant");
        proof
            .bind_grant_evidence(index, grant.issuer.evidence.clone())
            .expect("native evidence binding");
    }
    proof
        .bind_action_evidence(signer.public.evidence.clone())
        .expect("native actor binding");
    let assembled = proof
        .finish(&action, &canonical, context)
        .expect("native proof assembly");
    Invocation {
        proof: auths_codec::encode_bundle(assembled.proof()).expect("native bundle"),
        action: auths_codec::encode_canonical_action(&canonical).expect("native action"),
    }
}
pub(super) fn window(from: u64, until: u64) -> ValidityWindow {
    ValidityWindow::new(Timestamp::new(from), Timestamp::new(until)).expect("window")
}

pub(super) fn context(
    root: &PublicIdentity,
    calls: &[McpToolCall],
    resource: Audience,
    now: u64,
) -> TrustedContext {
    // Reuse only maintained registry/configuration inputs. Discard every fixed
    // test anchor, observer, key, and authority from the template.
    let template = auths_codec::decode_verifier_context(
        &tools_context(&[calls[0].clone()], now).expect("registry template"),
    )
    .expect("template");
    let anchor = TrustAnchor::new(
        TrustAnchorId::parse("resource-owner").expect("anchor"),
        root.principal.clone(),
        vec![PrincipalMethodId::parse("raw-key-v1").expect("method")],
        vec![calls[0].profile_ref().expect("profile")],
        PermissionSet::new(
            calls
                .iter()
                .map(|call| call.permission().expect("permission"))
                .collect(),
        )
        .expect("permissions"),
        vec![
            ResourceId::parse(&format!("mcp://{PARTICIPANT_SERVICE}/")).expect("namespace"),
            ResourceId::parse(&format!(
                "mcp://{}/",
                calls.last().expect("resource call").service()
            ))
            .expect("namespace"),
        ],
        AudienceSet::new(vec![control_audience(), resource]).expect("audiences"),
        window(now - 60, now + 3600),
        None,
        3,
        AssurancePolicyId::parse("gateway-observer-test-v1").expect("assurance"),
        StatusPolicy::ExpiryOnly,
    )
    .expect("trusted root");
    let context = TrustedContext::new(
        template.configuration(),
        CompositionRequirement::new(None, 1, 1, 1).expect("composition"),
        vec![anchor],
        template.accepted_registries().clone(),
        control_audience(),
        Challenge::new([0; 32]),
        Timestamp::new(now),
        template.assurance_policy().clone(),
        template.principal_status_snapshot().clone(),
        template.grant_status_snapshot().clone(),
        template.resource_matcher().clone(),
        template.profile_policy().clone(),
        template.channel_policy().clone(),
        VerifierLimits::default(),
    )
    .expect("fresh explicit context");
    assert_eq!(context.trust_anchors().len(), 1);
    assert!(context.observer_anchors().is_empty());
    context
}
pub(super) fn control_audience() -> Audience {
    Audience::parse(&format!("mcp://{PARTICIPANT_SERVICE}")).expect("control audience")
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "the installed-process fixture owns complete authoring or transport inputs through one bounded operation"
)]
pub(super) fn call(service: &str, tool: &str, args: Value) -> McpToolCall {
    McpToolCall::new(service, tool, args.as_object().expect("object").clone()).expect("native call")
}

impl auths_records_api::testkit::FixtureSigner for Actor {
    fn principal(&self) -> &PrincipalId {
        &self.public.principal
    }
    fn descriptor(&self) -> SignatureDescriptor {
        self.public.descriptor.clone()
    }
    fn evidence(&self) -> EvidenceObject {
        self.public.evidence.clone()
    }
    fn sign(&mut self, preimage: &[u8]) -> SignatureBytes {
        Actor::sign(self, preimage)
    }
}
