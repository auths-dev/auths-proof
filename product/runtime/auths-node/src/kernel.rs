//! The node's authorization path.
//!
//! Every authorization decision this node makes is the verified kernel's
//! decision. `auths-node` decodes bytes, supplies the trusted context and the
//! clock, claims stateful replay budget, applies the effect, and signs a
//! receipt. It never decides. The eleven attenuation dimensions declared in
//! `core/crates/auths-algebra-kernel/src/generated.rs` are checked exactly once,
//! inside `auths_verifier::verify`, and `tests/kernel_differential.rs` holds
//! that equality against the canonical corpus.
//!
//! The node issues no authority. `/v1/authority/create` and
//! `/v1/authority/delegate` refuse: see [`KernelRuntime::create`].

use crate::{
    api::NodeRuntime,
    profiles::{ReceiptSummary, RuntimeFailure, WorkflowProjection},
    sandbox_store::{
        MemorySandboxStore, PendingEffect, PostgresSandboxStore, SandboxStore, StoredReceipt,
    },
};
use auths_model::{CanonicalAction, Timestamp, TrustedContext};
use auths_operations::EffectState;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_production_client::{
    ClientOutcomeKind, NextCall, ProductVerb, ProductionRequest, ProductionResponse,
    QualifiedProfile, RecoveryReference,
};
use auths_registries::ImmutableRegistries;
use auths_verifier::{VerificationFailure, VerificationOutcome, VerifiedAction};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use minicbor::Encoder;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const RECEIPT_DOMAIN: &[u8] = b"AUTHS-NODE-RECEIPT\x00\x01";
const RECOVERY_DOMAIN: &[u8] = b"AUTHS-NODE-RECOVERY\x00\x01";
const DISCLOSURE_DOMAIN: &[u8] = b"AUTHS-NODE-DISCLOSURE\x00\x01";
const CLAIM_DOMAIN: &[u8] = b"AUTHS-NODE-EFFECT-CLAIM\x00\x01";

/// Marker prefix inside a canonical action body that makes one effect
/// deliberately recoverable, used by the open-production reference to exercise
/// the outcome-unknown path.
const RECOVERABLE_BODY_MARKER: &[u8] = b"AUTHS-NODE-RECOVER";

/// A stateful (proof, action) pair may produce at most this many effects.
///
/// The kernel proves the budget *ceiling* is not widened anywhere in the chain.
/// Stateful consumption is the node's obligation and is not something the pure
/// verifier can do. One effect per exact authorized pair is the fail-closed
/// choice: the caller who wants a second effect must present a second action.
const MAXIMUM_EFFECTS_PER_AUTHORIZED_PAIR: u32 = 1;

/// Source of the evaluation instant handed to the kernel.
///
/// This is a real dependency, not a test seam: an authorization decision is a
/// function of time, and a node that cannot be told what time it is cannot be
/// differentially compared against the kernel on fixed corpus inputs.
pub trait NodeClock: Send + Sync {
    fn now_unix_seconds(&self) -> u64;
}

/// Wall-clock time, used by every deployed node.
pub struct SystemNodeClock;

impl NodeClock for SystemNodeClock {
    fn now_unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

/// Immutable verification inputs the node holds on behalf of the kernel.
///
/// The node owns these rather than delegating to `auths-kernel-runtime` because
/// it needs the same registries for both the complete decision
/// ([`auths_verifier::verify`]) and the staged proof check behind
/// `/v1/authority/verify`, and `AuthsKernel` exposes no registry accessor.
pub struct NodeKernel {
    context_template: TrustedContext,
    principal_methods: Vec<Box<dyn PrincipalMethod + Send + Sync>>,
    signature_suites: Vec<Box<dyn SignatureSuite + Send + Sync>>,
}

impl NodeKernel {
    /// Builds the node's immutable verification inputs.
    ///
    /// # Errors
    ///
    /// Returns malformed when either executable registry is empty.
    pub fn new(
        context_template: TrustedContext,
        principal_methods: Vec<Box<dyn PrincipalMethod + Send + Sync>>,
        signature_suites: Vec<Box<dyn SignatureSuite + Send + Sync>>,
    ) -> Result<Self, RuntimeFailure> {
        if principal_methods.is_empty() || signature_suites.is_empty() {
            return Err(RuntimeFailure::Malformed);
        }
        Ok(Self {
            context_template,
            principal_methods,
            signature_suites,
        })
    }

    fn with_registries<T>(&self, call: impl FnOnce(&ImmutableRegistries<'_>) -> T) -> Option<T> {
        let methods: Vec<&dyn PrincipalMethod> = self
            .principal_methods
            .iter()
            .map(|method| method.as_ref() as &dyn PrincipalMethod)
            .collect();
        let suites: Vec<&dyn SignatureSuite> = self
            .signature_suites
            .iter()
            .map(|suite| suite.as_ref() as &dyn SignatureSuite)
            .collect();
        ImmutableRegistries::new(&methods, &suites)
            .ok()
            .map(|registries| call(&registries))
    }
}

/// A node whose authorization decisions are the kernel's decisions.
pub struct KernelRuntime {
    kernel: NodeKernel,
    signing: SigningKey,
    profiles: BTreeSet<QualifiedProfile>,
    store: Arc<dyn SandboxStore>,
    clock: Arc<dyn NodeClock>,
}

impl KernelRuntime {
    /// Builds a node on the supplied kernel with in-memory effect state.
    ///
    /// # Errors
    ///
    /// Returns malformed for a zero receipt seed or an empty profile set.
    pub fn new(
        kernel: NodeKernel,
        seed: [u8; 32],
        profiles: BTreeSet<QualifiedProfile>,
    ) -> Result<Self, RuntimeFailure> {
        Self::with_store(
            kernel,
            seed,
            profiles,
            Arc::new(MemorySandboxStore::default()),
            Arc::new(SystemNodeClock),
        )
    }

    /// Builds a node on the supplied kernel with `PostgreSQL` effect state.
    ///
    /// # Errors
    ///
    /// Returns malformed for a zero receipt seed or an empty profile set.
    pub fn with_postgres(
        kernel: NodeKernel,
        seed: [u8; 32],
        profiles: BTreeSet<QualifiedProfile>,
        store: PostgresSandboxStore,
    ) -> Result<Self, RuntimeFailure> {
        Self::with_store(
            kernel,
            seed,
            profiles,
            Arc::new(store),
            Arc::new(SystemNodeClock),
        )
    }

    /// Builds a node with an explicit clock.
    ///
    /// # Errors
    ///
    /// Returns malformed for a zero receipt seed or an empty profile set.
    pub fn with_clock(
        kernel: NodeKernel,
        seed: [u8; 32],
        profiles: BTreeSet<QualifiedProfile>,
        clock: Arc<dyn NodeClock>,
    ) -> Result<Self, RuntimeFailure> {
        Self::with_store(
            kernel,
            seed,
            profiles,
            Arc::new(MemorySandboxStore::default()),
            clock,
        )
    }

    pub(crate) fn with_store(
        kernel: NodeKernel,
        seed: [u8; 32],
        profiles: BTreeSet<QualifiedProfile>,
        store: Arc<dyn SandboxStore>,
        clock: Arc<dyn NodeClock>,
    ) -> Result<Self, RuntimeFailure> {
        if seed == [0; 32] || profiles.is_empty() {
            return Err(RuntimeFailure::Malformed);
        }
        Ok(Self {
            kernel,
            signing: SigningKey::from_bytes(&seed),
            profiles,
            store,
            clock,
        })
    }

    /// Refuses to issue authority.
    ///
    /// A `ProductionRequest` carries `identity` as unauthenticated caller-supplied
    /// bytes (`auths-production-client/src/lib.rs`: `identity: Vec<u8>`), the HTTP
    /// surface performs no client authentication (`api.rs::production_call` decodes
    /// the body and nothing else), and the reference ingress terminates TLS without
    /// client certificates. There is therefore no authenticated principal at this
    /// call site. Minting authority for a self-asserted identity would hand any
    /// caller a root, so the node refuses instead.
    ///
    /// Authority in target V1 originates from a trust anchor's signature and
    /// reaches the node inside the proof. Nothing about that requires a node.
    ///
    /// # Errors
    ///
    /// Always returns [`RuntimeFailure::UnauthenticatedPrincipal`].
    #[allow(clippy::unused_self, reason = "the refusal is a property of the node")]
    fn create(&self, _request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        Err(RuntimeFailure::UnauthenticatedPrincipal)
    }

    /// Refuses to delegate authority, for the reason given on [`Self::create`].
    ///
    /// Delegation narrows an authority the caller already holds; proving the
    /// caller holds it requires authenticating the caller, which this call site
    /// cannot do.
    #[allow(clippy::unused_self, reason = "the refusal is a property of the node")]
    fn delegate(&self, _request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        Err(RuntimeFailure::UnauthenticatedPrincipal)
    }

    /// Decides one request with the kernel and returns the sealed action.
    ///
    /// This is the node's whole decision path. It contains no attenuation,
    /// expiry, budget, audience, or permission logic of its own.
    ///
    /// # Errors
    ///
    /// Returns the kernel's denial or indeterminate class, or malformed when the
    /// supplied bytes are not a proof and a canonical action.
    pub fn authorize(
        &self,
        proof: &[u8],
        action_bytes: &[u8],
    ) -> Result<VerifiedAction, RuntimeFailure> {
        let action = self.decode_action(action_bytes)?;
        let context = self.request_context()?;
        let outcome = self
            .kernel
            .with_registries(|registries| {
                auths_verifier::verify(proof, &action, &context, registries)
            })
            .ok_or(RuntimeFailure::Unavailable)?;
        match outcome {
            VerificationOutcome::Authorized(verified) => Ok(*verified),
            VerificationOutcome::Denied(reason) => Err(RuntimeFailure::AuthorizationDenied(reason)),
            VerificationOutcome::Indeterminate(requirement) => {
                Err(RuntimeFailure::AuthorizationIndeterminate(requirement))
            }
        }
    }

    /// Derives the per-request trusted context.
    ///
    /// Trust anchors, registries, status snapshots, policies, and limits come
    /// from the deployment's immutable template. Only the evaluation instant is
    /// per-request, because the production request contract carries no audience
    /// or challenge field; see the note on `verify_proof`.
    fn request_context(&self) -> Result<TrustedContext, RuntimeFailure> {
        let template = &self.kernel.context_template;
        template
            .for_request(
                template.expected_audience().clone(),
                template.expected_challenge(),
                Timestamp::new(self.clock.now_unix_seconds()),
            )
            .map_err(|_| RuntimeFailure::Unavailable)
    }

    fn decode_action(&self, bytes: &[u8]) -> Result<CanonicalAction, RuntimeFailure> {
        auths_codec::decode_canonical_action(bytes, self.kernel.context_template.limits())
            .map_err(|_| RuntimeFailure::Malformed)
    }

    fn execute(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        self.require_profile(request.profile())?;
        let proof = request.authority().ok_or(RuntimeFailure::Malformed)?;
        let action_bytes = request.body().ok_or(RuntimeFailure::Malformed)?;
        let verified = self.authorize(proof, action_bytes)?;
        let claim = effect_claim(proof, action_bytes);
        let recoverable = verified
            .canonical_action()
            .body()
            .starts_with(RECOVERABLE_BODY_MARKER);
        self.store
            .claim_use(claim, MAXIMUM_EFFECTS_PER_AUTHORIZED_PAIR)?;
        if recoverable {
            let reference = Self::recovery_reference(claim)?;
            self.store.put_pending(
                reference.as_str(),
                &PendingEffect {
                    profile: request.profile(),
                    authority: claim,
                    action: action_bytes.to_vec(),
                    created_at: self.clock.now_unix_seconds(),
                },
            )?;
            return ProductionResponse::new(
                ClientOutcomeKind::Recoverable,
                Some(RuntimeFailure::ProviderOutcomeUnknown.code().to_owned()),
                NextCall::Resume,
                Some(reference),
                None,
                None,
            )
            .map_err(|_| RuntimeFailure::Malformed);
        }
        let (receipt, value) = self.complete_effect(
            request.profile(),
            claim,
            action_bytes,
            self.clock.now_unix_seconds(),
        )?;
        completed_response(receipt, value)
    }

    fn resume(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        let reference = request
            .recovery_reference()
            .ok_or(RuntimeFailure::Malformed)?;
        let Some(pending) = self.store.pending(reference.as_str())? else {
            let completed = self
                .store
                .recovered(reference.as_str())?
                .ok_or(RuntimeFailure::UnknownReference)?;
            if completed.profile != request.profile() {
                return Err(RuntimeFailure::UnknownReference);
            }
            return completed_response(completed.bytes, completed.value);
        };
        if pending.profile != request.profile() {
            return Err(RuntimeFailure::UnknownReference);
        }
        let (receipt_id, receipt) = self.build_effect(
            pending.profile,
            pending.authority,
            &pending.action,
            self.clock.now_unix_seconds(),
        )?;
        let completed =
            self.store
                .finish_pending(reference.as_str(), &pending, &receipt_id, &receipt)?;
        completed_response(completed.bytes, completed.value)
    }

    fn complete_effect(
        &self,
        profile: QualifiedProfile,
        claim: [u8; 32],
        action: &[u8],
        completed_at: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), RuntimeFailure> {
        let (receipt_id, receipt) = self.build_effect(profile, claim, action, completed_at)?;
        self.store.put_receipt(&receipt_id, &receipt)?;
        Ok((receipt.bytes, receipt.value))
    }

    fn build_effect(
        &self,
        profile: QualifiedProfile,
        claim: [u8; 32],
        action: &[u8],
        completed_at: u64,
    ) -> Result<(String, StoredReceipt), RuntimeFailure> {
        let value = effect_value(profile, action);
        let payload =
            encode_receipt_payload(profile, claim, digest(action), digest(&value), completed_at)?;
        let receipt = self.sign(RECEIPT_DOMAIN, &payload)?;
        let receipt_id = hex::encode(digest(&receipt));
        Ok((
            receipt_id,
            StoredReceipt {
                profile,
                completed_at,
                bytes: receipt,
                value,
            },
        ))
    }

    /// Answers `/v1/authority/verify` with the kernel's own staged result.
    ///
    /// The verify request shape carries no action (`ProductVerb::Verify` forbids
    /// the `authority` field, leaving one body), so this endpoint can only make
    /// the claim the kernel can make without one: the proof decodes canonically,
    /// its reference graph resolves, and every principal controls its keys. It
    /// deliberately does not claim any action is authorized.
    fn verify_proof(&self, proof: &[u8]) -> Result<(), RuntimeFailure> {
        let context = self.request_context()?;
        self.kernel
            .with_registries(|registries| {
                auths_verifier::decode_proof(proof, &context)
                    .and_then(|decoded| auths_verifier::resolve_proof(decoded, &context))
                    .and_then(|resolved| {
                        auths_verifier::verify_principal_control(resolved, &context, registries)
                    })
                    .map(|_| ())
            })
            .ok_or(RuntimeFailure::Unavailable)?
            .map_err(runtime_failure)
    }

    fn recovery_reference(claim: [u8; 32]) -> Result<RecoveryReference, RuntimeFailure> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| RuntimeFailure::Unavailable)?;
        let mut hasher = Sha256::new();
        hasher.update(RECOVERY_DOMAIN);
        hasher.update(claim);
        hasher.update(nonce);
        RecoveryReference::parse(&Base64UrlUnpadded::encode_string(&hasher.finalize()))
            .map_err(|_| RuntimeFailure::Malformed)
    }

    fn sign(&self, domain: &[u8], payload: &[u8]) -> Result<Vec<u8>, RuntimeFailure> {
        let preimage = preimage(domain, payload);
        let signature = self.signing.sign(&preimage).to_bytes();
        encode_envelope(payload, &signature)
    }

    fn require_profile(&self, profile: QualifiedProfile) -> Result<(), RuntimeFailure> {
        if self.profiles.contains(&profile) {
            Ok(())
        } else {
            Err(RuntimeFailure::ProfileDisabled)
        }
    }
}

fn runtime_failure(failure: VerificationFailure) -> RuntimeFailure {
    match failure {
        VerificationFailure::Denied(reason) => RuntimeFailure::AuthorizationDenied(reason),
        VerificationFailure::Indeterminate(requirement) => {
            RuntimeFailure::AuthorizationIndeterminate(requirement)
        }
    }
}

impl NodeRuntime for KernelRuntime {
    fn handle(&self, request: ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        match request.verb() {
            ProductVerb::Create => self.create(&request),
            ProductVerb::Delegate => self.delegate(&request),
            ProductVerb::Execute => self.execute(&request),
            ProductVerb::Resume => self.resume(&request),
            ProductVerb::Verify => {
                self.verify_proof(request.body().ok_or(RuntimeFailure::Malformed)?)?;
                ProductionResponse::new(
                    ClientOutcomeKind::Verified,
                    None,
                    NextCall::Never,
                    None,
                    None,
                    None,
                )
                .map_err(|_| RuntimeFailure::Malformed)
            }
        }
    }

    fn status(&self, reference: &RecoveryReference) -> Result<WorkflowProjection, RuntimeFailure> {
        if let Some(pending) = self.store.pending(reference.as_str())? {
            return Ok(WorkflowProjection {
                reference: reference.as_str().to_owned(),
                profile: pending.profile.as_str().into(),
                state: "outcome-unknown".into(),
                effect: EffectState::Possible,
                retry: NextCall::Resume,
                updated_at: pending.created_at,
                receipt_id: None,
            });
        }
        let completed = self
            .store
            .recovered(reference.as_str())?
            .ok_or(RuntimeFailure::UnknownReference)?;
        Ok(WorkflowProjection {
            reference: reference.as_str().to_owned(),
            profile: completed.profile.as_str().into(),
            state: "committed".into(),
            effect: EffectState::Applied,
            retry: NextCall::Never,
            updated_at: completed.completed_at,
            receipt_id: Some(hex::encode(digest(&completed.bytes))),
        })
    }

    fn receipt_summary(&self, receipt_id: &str) -> Result<ReceiptSummary, RuntimeFailure> {
        let receipt = self
            .store
            .receipt(receipt_id)?
            .ok_or(RuntimeFailure::UnknownReference)?;
        Ok(ReceiptSummary {
            receipt_id: receipt_id.into(),
            profile: receipt.profile.as_str().into(),
            effect: EffectState::Applied,
            completed_at: receipt.completed_at,
            disclosure: "summary",
        })
    }

    /// Discloses one receipt to a caller holding the node's disclosure
    /// authorization.
    ///
    /// An unknown receipt and an unauthorized disclosure return the same
    /// failure. Distinguishing them would turn this endpoint into an existence
    /// oracle for receipts the caller is not entitled to read.
    fn disclose_receipt(
        &self,
        receipt_id: &str,
        authorization: &[u8],
    ) -> Result<Vec<u8>, RuntimeFailure> {
        let expected = self.sign(DISCLOSURE_DOMAIN, receipt_id.as_bytes())?;
        if authorization != expected {
            return Err(RuntimeFailure::DisclosureDenied);
        }
        self.store
            .receipt(receipt_id)?
            .map(|receipt| receipt.bytes.clone())
            .ok_or(RuntimeFailure::DisclosureDenied)
    }

    fn ready(&self) -> bool {
        self.store.ready()
    }
}

/// Binds one stateful effect claim to the exact proof and the exact action.
fn effect_claim(proof: &[u8], action: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CLAIM_DOMAIN);
    hasher.update(digest(proof));
    hasher.update(digest(action));
    hasher.finalize().into()
}

fn completed_response(
    receipt: Vec<u8>,
    value: Vec<u8>,
) -> Result<ProductionResponse, RuntimeFailure> {
    ProductionResponse::new(
        ClientOutcomeKind::Completed,
        None,
        NextCall::Never,
        None,
        Some(value),
        Some(receipt),
    )
    .map_err(|_| RuntimeFailure::Malformed)
}

fn encode_receipt_payload(
    profile: QualifiedProfile,
    claim: [u8; 32],
    action: [u8; 32],
    result: [u8; 32],
    completed_at: u64,
) -> Result<Vec<u8>, RuntimeFailure> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.str(profile.as_str()))
        .and_then(|encoder| encoder.bytes(&claim))
        .and_then(|encoder| encoder.bytes(&action))
        .and_then(|encoder| encoder.bytes(&result))
        .and_then(|encoder| encoder.u64(completed_at))
        .map_err(|_| RuntimeFailure::Malformed)?;
    Ok(encoder.into_writer())
}

fn encode_envelope(payload: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>, RuntimeFailure> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(|_| RuntimeFailure::Malformed)?;
    Ok(encoder.into_writer())
}

fn preimage(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(domain.len() + 8 + payload.len());
    value.extend_from_slice(domain);
    value.extend_from_slice(
        &u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    value.extend_from_slice(payload);
    value
}

fn effect_value(profile: QualifiedProfile, action: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-NODE-EFFECT\x00\x01");
    hasher.update(profile.as_str().as_bytes());
    hasher.update(action);
    hasher.finalize().to_vec()
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_testkit::CorpusFixture;

    struct FrozenClock(u64);

    impl NodeClock for FrozenClock {
        fn now_unix_seconds(&self) -> u64 {
            self.0
        }
    }

    fn corpus_methods() -> Vec<Box<dyn PrincipalMethod + Send + Sync>> {
        let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
        vec![
            Box::new(auths_raw_key::RawKeyMethod::new().unwrap()),
            Box::new(auths_did_key::DidKeyMethod::new().unwrap()),
            Box::new(auths_did_keri::DidKeriMethod::new().unwrap()),
            Box::new(
                auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
                    .unwrap(),
            ),
            Box::new(
                auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
                    .unwrap(),
            ),
            Box::new(
                auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
                    .unwrap(),
            ),
            Box::new(
                auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status).unwrap(),
            ),
        ]
    }

    fn corpus_suites() -> Vec<Box<dyn SignatureSuite + Send + Sync>> {
        vec![
            Box::new(auths_signature::Ed25519Suite::new().unwrap()),
            Box::new(auths_signature::P256Sha256Suite::new().unwrap()),
        ]
    }

    fn fixture(name: &str) -> CorpusFixture {
        auths_testkit::corpus()
            .into_iter()
            .find(|value| value.name() == name)
            .unwrap_or_else(|| panic!("corpus fixture {name}"))
    }

    fn runtime_for(fixture: &CorpusFixture) -> KernelRuntime {
        let context = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
        let evaluation_time = context.evaluation_time().get();
        KernelRuntime::with_clock(
            NodeKernel::new(context, corpus_methods(), corpus_suites()).unwrap(),
            [7; 32],
            [QualifiedProfile::GitHubIssueAddress].into_iter().collect(),
            Arc::new(FrozenClock(evaluation_time)),
        )
        .unwrap()
    }

    fn execute(fixture: &CorpusFixture, identity: &[u8]) -> ProductionRequest {
        ProductionRequest::new(
            ProductVerb::Execute,
            QualifiedProfile::GitHubIssueAddress,
            identity.to_vec(),
            Some(fixture.proof_bytes().to_vec()),
            Some(auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap()),
            None,
        )
        .unwrap()
    }

    /// `create` previously built `Authority { parent: None, subject:
    /// digest(request.identity()) }` and signed it. `parent: None` is a root,
    /// and `request.identity()` is unauthenticated caller-supplied bytes, so any
    /// caller could mint a root over any subject they named.
    ///
    /// There is no authentication at this call site to require instead: the
    /// production request carries no credential, `api.rs` performs no client
    /// authentication, and the reference ingress does not request client
    /// certificates. The node therefore refuses.
    #[test]
    fn the_node_refuses_to_mint_authority_from_a_self_asserted_identity() {
        let runtime = runtime_for(&fixture("raw-key-chain"));
        for verb in [ProductVerb::Create, ProductVerb::Delegate] {
            let authority = (verb == ProductVerb::Delegate).then(|| vec![1]);
            let request = ProductionRequest::new(
                verb,
                QualifiedProfile::GitHubIssueAddress,
                b"i-am-whoever-i-say-i-am".to_vec(),
                authority,
                Some(vec![2]),
                None,
            )
            .unwrap();
            assert_eq!(
                runtime.handle(request),
                Err(RuntimeFailure::UnauthenticatedPrincipal),
                "{verb:?} issued authority for an unauthenticated identity"
            );
        }
    }

    /// The decision must be a function of the proof, the action, the context,
    /// and the clock alone. The self-asserted identity must not move it.
    #[test]
    fn the_self_asserted_identity_never_changes_the_decision() {
        let authorized = fixture("raw-key-chain");
        for identity in [b"alice".as_slice(), b"root", b"\x00\xff"] {
            let runtime = runtime_for(&authorized);
            assert_eq!(
                runtime
                    .handle(execute(&authorized, identity))
                    .unwrap()
                    .kind(),
                ClientOutcomeKind::Completed
            );
        }
        let denied = fixture("permission-widening");
        for identity in [b"alice".as_slice(), b"root"] {
            let runtime = runtime_for(&denied);
            assert_eq!(
                runtime.handle(execute(&denied, identity)),
                Err(RuntimeFailure::AuthorizationDenied(
                    auths_model::DenialReason::DelegationExpanded
                ))
            );
        }
    }

    /// The kernel proves the budget ceiling never widens; consuming it is
    /// stateful and belongs to the node. One authorized pair, one effect.
    #[test]
    fn exact_action_and_replay_budget_are_enforced() {
        let authorized = fixture("raw-key-chain");
        let runtime = runtime_for(&authorized);
        assert_eq!(
            runtime
                .handle(execute(&authorized, b"caller"))
                .unwrap()
                .kind(),
            ClientOutcomeKind::Completed
        );
        assert_eq!(
            runtime.handle(execute(&authorized, b"caller")),
            Err(RuntimeFailure::ReplayBudgetExhausted)
        );
        // A different action under the same proof is the kernel's question, and
        // the kernel answers it before any budget is claimed.
        let other = fixture("byte-distinct-action");
        let mismatched = ProductionRequest::new(
            ProductVerb::Execute,
            QualifiedProfile::GitHubIssueAddress,
            b"caller".to_vec(),
            Some(authorized.proof_bytes().to_vec()),
            Some(auths_codec::encode_canonical_action(other.canonical_action()).unwrap()),
            None,
        )
        .unwrap();
        assert_eq!(
            runtime.handle(mismatched),
            Err(RuntimeFailure::AuthorizationDenied(
                auths_model::DenialReason::ActionBodyMismatch
            ))
        );
    }

    /// Nothing is claimed and no effect is applied before the kernel authorizes.
    #[test]
    fn a_denied_request_consumes_no_budget_and_leaves_no_receipt() {
        let denied = fixture("permission-widening");
        let runtime = runtime_for(&denied);
        for _ in 0..3 {
            assert_eq!(
                runtime.handle(execute(&denied, b"caller")),
                Err(RuntimeFailure::AuthorizationDenied(
                    auths_model::DenialReason::DelegationExpanded
                )),
                "a denial consumed stateful budget and changed the answer"
            );
        }
    }

    /// Recovery commits exactly once and every later resume replays the same
    /// signed receipt. The subject here is the durable commit, not the
    /// authorization decision, so the pending effect is seeded directly.
    #[test]
    fn recovery_is_committed_once_and_replays_the_same_receipt() {
        let runtime = runtime_for(&fixture("raw-key-chain"));
        let claim = effect_claim(b"proof", b"action");
        let reference = KernelRuntime::recovery_reference(claim).unwrap();
        runtime
            .store
            .put_pending(
                reference.as_str(),
                &PendingEffect {
                    profile: QualifiedProfile::GitHubIssueAddress,
                    authority: claim,
                    action: b"action".to_vec(),
                    created_at: 1,
                },
            )
            .unwrap();
        let resume = || {
            ProductionRequest::new(
                ProductVerb::Resume,
                QualifiedProfile::GitHubIssueAddress,
                b"caller".to_vec(),
                None,
                None,
                Some(reference.clone()),
            )
            .unwrap()
        };
        let first = runtime.handle(resume()).unwrap();
        let replay = runtime.handle(resume()).unwrap();
        assert_eq!(first.kind(), ClientOutcomeKind::Completed);
        assert_eq!(first.receipt(), replay.receipt());
        assert_eq!(first.value(), replay.value());
        let status = runtime.status(&reference).unwrap();
        assert_eq!(status.state, "committed");
        assert_eq!(status.effect, EffectState::Applied);
        assert!(status.receipt_id.is_some());
    }

    /// An unknown receipt and an unauthorized disclosure must be
    /// indistinguishable, or the endpoint is an existence oracle.
    #[test]
    fn disclosure_never_reveals_whether_an_unreadable_receipt_exists() {
        let authorized = fixture("raw-key-chain");
        let runtime = runtime_for(&authorized);
        runtime.handle(execute(&authorized, b"caller")).unwrap();
        let known = runtime
            .store
            .receipt(&hex::encode([0_u8; 32]))
            .unwrap()
            .map_or_else(|| "0".repeat(64), |_| unreachable!());
        assert_eq!(
            runtime.disclose_receipt(&known, b"forged"),
            Err(RuntimeFailure::DisclosureDenied)
        );
        assert_eq!(
            runtime.disclose_receipt(&"f".repeat(64), b"forged"),
            Err(RuntimeFailure::DisclosureDenied)
        );
    }

    /// `/v1/authority/verify` may only claim what the kernel can establish
    /// without an action, and must never answer for a proof the kernel rejects.
    #[test]
    fn verify_reports_the_kernels_staged_result() {
        let authorized = fixture("raw-key-chain");
        let runtime = runtime_for(&authorized);
        let request = |body: Vec<u8>| {
            ProductionRequest::new(
                ProductVerb::Verify,
                QualifiedProfile::GitHubIssueAddress,
                b"caller".to_vec(),
                None,
                Some(body),
                None,
            )
            .unwrap()
        };
        assert_eq!(
            runtime
                .handle(request(authorized.proof_bytes().to_vec()))
                .unwrap()
                .kind(),
            ClientOutcomeKind::Verified
        );
        let malformed = fixture("trailing-bytes");
        assert_eq!(
            runtime.handle(request(malformed.proof_bytes().to_vec())),
            Err(RuntimeFailure::AuthorizationDenied(
                auths_model::DenialReason::MalformedProof
            ))
        );
    }
}
