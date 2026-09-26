//! Remote approval: a portable request an approver opens on its own device,
//! and the approver's signed answer.
//!
//! The requester turns a [`QuorumProposal`] into one [`ApprovalRequest`] per
//! approver with [`requests`]. An approver calls [`open_request`], which runs
//! every structural check in a fixed order and then derives the review only
//! from `review_display(canonical_action)` of a registered profile. The
//! resulting [`ReviewedRequest`] is the only value that can be approved or
//! declined, and it holds the exact envelope the approver signs. The collector
//! calls [`collect`] and assembles through [`QuorumProposal::assemble`].
//!
//! Requests and responses are deterministic CBOR under the core codec rules:
//! canonical integer map keys in ascending order, minimal integers, definite
//! lengths, no tags or floats. A value is accepted only if re-encoding it
//! reproduces the input byte for byte, so unknown keys and non-canonical
//! encodings fail closed. Neither format is a core wire object.
//!
//! Refusals carry one stable [`ApprovalCode`]. Signatures are not checked
//! here; the verifier checks them when the assembled proof is used.

use crate::{
    MAX_APPROVAL_GRANTS, MAX_APPROVERS, QuorumApproval, QuorumError, QuorumProposal,
    member_reference,
};
use auths_author::{ExternalSigningRequest, PlanBuilder, address_evidence, prepare_action};
use auths_codec::{
    body_digest, decode_action_envelope, decode_canonical_action, decode_signed_action,
    decode_signed_grant, encode_action_envelope, encode_authorization_plan,
    encode_canonical_action, encode_signed_action, encode_signed_grant, plan_id,
    transaction_binding,
};
use auths_model::{
    ActionEnvelope, CanonicalAction, EvidenceObject, EvidenceTypeId, MediaType, PrincipalId,
    PrincipalMethodId, ProfileRef, ProofBundle, SignatureBytes, SignatureDescriptor,
    SignatureSuiteId, SignedAction, SignedGrant, VerificationMethod, VerifierLimits,
    profile_ref_equal,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest as _, Sha256};
use std::fmt;

/// Schema identifier carried in every approval request.
pub const APPROVAL_REQUEST_SCHEMA: &str = "auths.approval-request/1";

/// Schema identifier carried in every approval response.
pub const APPROVAL_RESPONSE_SCHEMA: &str = "auths.approval-response/1";

/// Largest encoded request or response, in bytes.
pub const MAX_APPROVAL_MESSAGE_BYTES: usize = 65_536;

/// Prefix of the printable form of a request.
pub const APPROVAL_REQUEST_TEXT_PREFIX: &str = "auths-ar1-";

/// Prefix of the printable form of a response.
pub const APPROVAL_RESPONSE_TEXT_PREFIX: &str = "auths-as1-";

/// Custody object kind under which a decline is signed.
pub const DECLINE_OBJECT_KIND: &str = "approval-decline";

const REQUEST_ID_DOMAIN: &[u8] = b"auths.approval-request/1\0";
const DECLINE_DOMAIN: &[u8] = b"auths.approval-decline/1\0";
const APPROVE: &str = "approve";
const DECLINE: &str = "decline";
const REQUEST_KEYS: u64 = 10;
const RESPONSE_KEYS: u64 = 7;
const DECLINE_KEYS: u64 = 5;
const MAX_STATEMENT_EVIDENCE: usize = crate::MAX_STATEMENT_EVIDENCE;

/// Stable refusal of a remote approval operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ApprovalCode {
    /// Not decodable within limits, non-canonical, or an unknown key.
    Malformed,
    /// A byte or collection limit is exceeded.
    Oversized,
    /// The envelope does not describe the canonical action.
    ActionMismatch,
    /// The plan identifier, approvers, or threshold disagree.
    PlanMismatch,
    /// The envelope actor or the signer is not the request's approver.
    NotAddressed,
    /// The request identifier does not recompute.
    RequestIdMismatch,
    /// The time is outside the window, or the window differs from the envelope.
    OutsideWindow,
    /// No registered profile can render the action.
    ProfileUnregistered,
    /// A response does not match the proposal's envelope for its approver.
    ResponseMismatch,
    /// A second response arrived from one approver.
    DuplicateResponse,
    /// Assembly was attempted before every listed approver approved.
    Incomplete,
}

impl ApprovalCode {
    /// Every code, in the order the specification lists them.
    pub const ALL: [Self; 11] = [
        Self::Malformed,
        Self::Oversized,
        Self::ActionMismatch,
        Self::PlanMismatch,
        Self::NotAddressed,
        Self::RequestIdMismatch,
        Self::OutsideWindow,
        Self::ProfileUnregistered,
        Self::ResponseMismatch,
        Self::DuplicateResponse,
        Self::Incomplete,
    ];

    /// Returns the stable code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "approval.malformed",
            Self::Oversized => "approval.oversized",
            Self::ActionMismatch => "approval.action-mismatch",
            Self::PlanMismatch => "approval.plan-mismatch",
            Self::NotAddressed => "approval.not-addressed",
            Self::RequestIdMismatch => "approval.request-id-mismatch",
            Self::OutsideWindow => "approval.outside-window",
            Self::ProfileUnregistered => "approval.profile-unregistered",
            Self::ResponseMismatch => "approval.response-mismatch",
            Self::DuplicateResponse => "approval.duplicate-response",
            Self::Incomplete => "approval.incomplete",
        }
    }
}

impl fmt::Display for ApprovalCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ApprovalCode {}

/// A profile an approver trusts to render reviews.
///
/// Implemented by [`RegisteredProfile`]; the trait exists so one registry
/// can hold profiles whose command types differ.
pub trait ReviewProfile {
    /// Returns the exact profile and version this entry renders.
    fn profile(&self) -> &ProfileRef;

    /// Renders the review of one canonical action of this profile.
    ///
    /// # Errors
    ///
    /// Returns the profile's closed error when it cannot render the action.
    fn review(&self, action: &CanonicalAction) -> Result<ReviewDisplay, ProfileContractError>;
}

/// One [`ActionProfile`] registered under its exact profile reference.
#[derive(Clone, Debug)]
pub struct RegisteredProfile<P> {
    profile: ProfileRef,
    inner: P,
}

impl<P: ActionProfile> RegisteredProfile<P> {
    /// Registers `inner` as the renderer of `profile`.
    #[must_use]
    pub const fn new(profile: ProfileRef, inner: P) -> Self {
        Self { profile, inner }
    }
}

impl<P: ActionProfile> ReviewProfile for RegisteredProfile<P> {
    fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    fn review(&self, action: &CanonicalAction) -> Result<ReviewDisplay, ProfileContractError> {
        self.inner.review_display(action)
    }
}

/// The approval window, in unix seconds, both ends inclusive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalWindow {
    not_before: u64,
    expires_at: u64,
}

impl ApprovalWindow {
    /// Returns the first second at which approval is valid.
    #[must_use]
    pub const fn not_before(self) -> u64 {
        self.not_before
    }

    /// Returns the last second at which approval is valid.
    #[must_use]
    pub const fn expires_at(self) -> u64 {
        self.expires_at
    }

    const fn contains(self, now: u64) -> bool {
        self.not_before <= now && now <= self.expires_at
    }
}

/// One approval request, addressed to one approver.
///
/// A decoded request has passed only the decoding check. Use
/// [`open_request`] before showing or signing anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequest {
    request_id: [u8; 32],
    canonical_action: Vec<u8>,
    envelope: Vec<u8>,
    plan: Vec<u8>,
    approvers: Vec<PrincipalId>,
    required: u16,
    approver: PrincipalId,
    requester: PrincipalId,
    window: ApprovalWindow,
}

impl ApprovalRequest {
    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 32] {
        self.request_id
    }

    /// Returns the approver this request is addressed to.
    #[must_use]
    pub const fn approver(&self) -> &PrincipalId {
        &self.approver
    }

    /// Returns the deterministic encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalCode::Oversized`] when the encoding exceeds
    /// [`MAX_APPROVAL_MESSAGE_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, ApprovalCode> {
        let mut encoder = Encoder::new(Vec::new());
        write_request(&mut encoder, self).map_err(|_| ApprovalCode::Malformed)?;
        bounded(encoder.into_writer())
    }

    /// Returns the printable form: the prefix and the unpadded base64url
    /// encoding of [`Self::encode`].
    ///
    /// # Errors
    ///
    /// As [`Self::encode`].
    pub fn to_text(&self) -> Result<String, ApprovalCode> {
        Ok(printable(APPROVAL_REQUEST_TEXT_PREFIX, &self.encode()?))
    }
}

/// Emits one request per listed approver, in proposal order.
///
/// `requester` must be one of the proposal's approvers: the envelope actor
/// that built the proposal. The operation is deterministic.
///
/// # Errors
///
/// Returns [`ApprovalCode::PlanMismatch`] when `requester` is not an approver
/// and [`ApprovalCode::Oversized`] when a request would exceed the byte limit.
pub fn requests(
    proposal: &QuorumProposal,
    requester: &PrincipalId,
) -> Result<Vec<ApprovalRequest>, ApprovalCode> {
    if !proposal
        .envelopes()
        .iter()
        .any(|envelope| envelope.actor() == requester)
    {
        return Err(ApprovalCode::PlanMismatch);
    }
    let canonical_action =
        encode_canonical_action(proposal.canonical()).map_err(|_| ApprovalCode::Malformed)?;
    let plan = encode_authorization_plan(proposal.plan()).map_err(|_| ApprovalCode::Malformed)?;
    let approvers: Vec<PrincipalId> = proposal
        .envelopes()
        .iter()
        .map(|envelope| envelope.actor().clone())
        .collect();
    proposal
        .envelopes()
        .iter()
        .map(|envelope| {
            let encoded = encode_action_envelope(envelope).map_err(|_| ApprovalCode::Malformed)?;
            let validity = envelope.validity();
            let request = ApprovalRequest {
                request_id: request_id(&canonical_action, &plan, &encoded, envelope.actor())?,
                canonical_action: canonical_action.clone(),
                envelope: encoded,
                plan: plan.clone(),
                approvers: approvers.clone(),
                required: proposal.required(),
                approver: envelope.actor().clone(),
                requester: requester.clone(),
                window: ApprovalWindow {
                    not_before: validity.not_before().get(),
                    expires_at: validity.expires_at().get(),
                },
            };
            request.encode()?;
            Ok(request)
        })
        .collect()
}

/// Decodes a request given as CBOR bytes or as its printable form.
///
/// Surrounding ASCII whitespace is ignored in the printable form only.
///
/// # Errors
///
/// Returns [`ApprovalCode::Oversized`] or [`ApprovalCode::Malformed`].
pub fn decode_request(input: &[u8]) -> Result<ApprovalRequest, ApprovalCode> {
    let bytes = from_input(input, APPROVAL_REQUEST_TEXT_PREFIX)?;
    let mut decoder = Decoder::new(&bytes);
    let request = read_request(&mut decoder).map_err(|_| ApprovalCode::Malformed)??;
    if decoder.position() != bytes.len() || request.encode()? != bytes {
        return Err(ApprovalCode::Malformed);
    }
    Ok(request)
}

/// A request that passed every check, with the review derived from its
/// canonical action. It holds the exact envelope that [`Self::prepare_approval`]
/// signs; [`open_request`] is the only constructor.
#[derive(Clone, Debug)]
pub struct ReviewedRequest {
    request: ApprovalRequest,
    envelope: ActionEnvelope,
    review: ReviewDisplay,
}

/// Opens one request for an approver.
///
/// Runs, in order, and fails with the first code:
///
/// 1. decoding within limits ([`ApprovalCode::Malformed`],
///    [`ApprovalCode::Oversized`]);
/// 2. the envelope's profile, media type, body digest, permission, and budget
///    equal those of the canonical action, and neither carries attachments or
///    extensions the review cannot show ([`ApprovalCode::ActionMismatch`]);
/// 3. the plan is the `required`-of-N plan over exactly the listed approvers,
///    its identifier is the envelope's, and the requester is listed
///    ([`ApprovalCode::PlanMismatch`]);
/// 4. the envelope's actor and proof reference are the addressed approver's
///    ([`ApprovalCode::NotAddressed`]);
/// 5. the request identifier recomputes ([`ApprovalCode::RequestIdMismatch`]);
/// 6. `now` lies inside the window, which equals the envelope's validity
///    ([`ApprovalCode::OutsideWindow`]);
/// 7. a registered profile renders the action
///    ([`ApprovalCode::ProfileUnregistered`]).
///
/// # Errors
///
/// Returns the first failing check's code.
pub fn open_request(
    input: &[u8],
    profiles: &[&dyn ReviewProfile],
    now: u64,
) -> Result<ReviewedRequest, ApprovalCode> {
    let request = decode_request(input)?;
    let limits = VerifierLimits::default_deployment();
    let canonical = decode_canonical_action(&request.canonical_action, &limits)
        .map_err(|_| ApprovalCode::Malformed)?;
    let envelope =
        decode_action_envelope(&request.envelope, &limits).map_err(|_| ApprovalCode::Malformed)?;

    if !describes(&envelope, &canonical) {
        return Err(ApprovalCode::ActionMismatch);
    }

    let challenge = *envelope.challenge().as_bytes();
    if !plan_matches(&request, &envelope, &challenge)? {
        return Err(ApprovalCode::PlanMismatch);
    }

    let reference =
        member_reference(&challenge, &request.approver).map_err(|_| ApprovalCode::Malformed)?;
    if envelope.actor() != &request.approver
        || !request.approvers.contains(&request.approver)
        || envelope.proof_ref() != reference
    {
        return Err(ApprovalCode::NotAddressed);
    }

    if request_id(
        &request.canonical_action,
        &request.plan,
        &request.envelope,
        &request.approver,
    )? != request.request_id
    {
        return Err(ApprovalCode::RequestIdMismatch);
    }

    let validity = envelope.validity();
    if !request.window.contains(now)
        || request.window.not_before != validity.not_before().get()
        || request.window.expires_at != validity.expires_at().get()
    {
        return Err(ApprovalCode::OutsideWindow);
    }

    let review = profiles
        .iter()
        .find(|entry| profile_ref_equal(entry.profile(), canonical.profile()))
        .ok_or(ApprovalCode::ProfileUnregistered)?
        .review(&canonical)
        .map_err(|_| ApprovalCode::ProfileUnregistered)?;

    Ok(ReviewedRequest {
        request,
        envelope,
        review,
    })
}

impl ReviewedRequest {
    /// Returns the review title from the profile.
    #[must_use]
    pub fn title(&self) -> &str {
        self.review.title()
    }

    /// Returns the ordered review fields from the profile.
    #[must_use]
    pub fn fields(&self) -> &[(String, String)] {
        self.review.fields()
    }

    /// Returns the digest of the bytes the review represents.
    #[must_use]
    pub fn display_digest_hex(&self) -> &str {
        self.review.canonical_digest_hex()
    }

    /// Returns the profile review.
    #[must_use]
    pub const fn review(&self) -> &ReviewDisplay {
        &self.review
    }

    /// Returns who asked. The requester is not authenticated by the request;
    /// its own approval is.
    #[must_use]
    pub const fn requester(&self) -> &PrincipalId {
        &self.request.requester
    }

    /// Returns every listed approver, in proposal order.
    #[must_use]
    pub fn approvers(&self) -> &[PrincipalId] {
        &self.request.approvers
    }

    /// Returns the plan threshold.
    #[must_use]
    pub const fn required(&self) -> u16 {
        self.request.required
    }

    /// Returns the approver this request is addressed to.
    #[must_use]
    pub const fn approver(&self) -> &PrincipalId {
        &self.request.approver
    }

    /// Returns the approval window.
    #[must_use]
    pub const fn window(&self) -> ApprovalWindow {
        self.request.window
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 32] {
        self.request.request_id
    }

    /// Returns the exact canonical action bytes the review was derived from.
    #[must_use]
    pub fn canonical_action(&self) -> &[u8] {
        &self.request.canonical_action
    }

    /// Returns the exact envelope an approval signs.
    #[must_use]
    pub const fn envelope(&self) -> &ActionEnvelope {
        &self.envelope
    }

    /// Prepares the custody signing request for an approval.
    ///
    /// The custody request shows [`Self::fields`] and expires at the window's
    /// end.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalCode::NotAddressed`] when `signer` is not the
    /// addressed approver, and [`ApprovalCode::Malformed`] when the signing
    /// input cannot be derived.
    pub fn prepare_approval(
        &self,
        signer: &PrincipalId,
        descriptor: SignatureDescriptor,
    ) -> Result<PendingApproval, ApprovalCode> {
        self.addressed(signer)?;
        let signing = prepare_action(self.envelope.clone(), descriptor)
            .map_err(|_| ApprovalCode::Malformed)?;
        Ok(PendingApproval {
            request_id: self.request.request_id,
            approver: self.request.approver.clone(),
            display: self.review.fields().to_vec(),
            expires_at: self.request.window.expires_at,
            signing,
        })
    }

    /// Prepares the custody signing request for a decline decided at
    /// `decided_at`.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalCode::NotAddressed`] when `signer` is not the
    /// addressed approver.
    pub fn prepare_decline(
        &self,
        signer: &PrincipalId,
        descriptor: SignatureDescriptor,
        decided_at: u64,
    ) -> Result<PendingDecline, ApprovalCode> {
        self.addressed(signer)?;
        Ok(PendingDecline {
            request_id: self.request.request_id,
            approver: self.request.approver.clone(),
            display: self.review.fields().to_vec(),
            expires_at: self.request.window.expires_at,
            decided_at,
            descriptor,
            preimage: decline_preimage(&self.request.request_id, decided_at),
        })
    }

    fn addressed(&self, signer: &PrincipalId) -> Result<(), ApprovalCode> {
        if signer == &self.request.approver {
            Ok(())
        } else {
            Err(ApprovalCode::NotAddressed)
        }
    }
}

/// The custody request for one approval, awaiting the approver's signature.
#[derive(Clone, Debug)]
pub struct PendingApproval {
    request_id: [u8; 32],
    approver: PrincipalId,
    display: Vec<(String, String)>,
    expires_at: u64,
    signing: ExternalSigningRequest<ActionEnvelope>,
}

impl PendingApproval {
    /// Returns the exact signing request for the custody signer.
    #[must_use]
    pub const fn signing(&self) -> &ExternalSigningRequest<ActionEnvelope> {
        &self.signing
    }

    /// Returns the fields the custody signer shows: the profile review.
    #[must_use]
    pub fn display(&self) -> &[(String, String)] {
        &self.display
    }

    /// Returns when the custody request expires: the window's end.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Completes the approval with the custody signature, the approver's
    /// grant chain (root first), and the evidence controlling the signature.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalCode::Oversized`] for a chain or evidence collection
    /// outside bounds, or an encoding over the byte limit, and
    /// [`ApprovalCode::Malformed`] for empty signature bytes.
    pub fn complete(
        self,
        signature: &[u8],
        grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
        action_evidence: Vec<EvidenceObject>,
    ) -> Result<ApprovalResponse, ApprovalCode> {
        let signature =
            SignatureBytes::new(signature.to_vec()).map_err(|_| ApprovalCode::Malformed)?;
        let action = self.signing.complete(signature);
        let checked = QuorumApproval::new(action.clone(), grants.clone(), action_evidence.clone())
            .map_err(|_| ApprovalCode::Oversized)?;
        drop(checked);
        let response = ApprovalResponse {
            request_id: self.request_id,
            approver: self.approver,
            body: ResponseBody::Approve(action),
            grants,
            action_evidence,
        };
        response.encode()?;
        Ok(response)
    }
}

/// The custody request for one decline, awaiting the approver's signature.
#[derive(Clone, Debug)]
pub struct PendingDecline {
    request_id: [u8; 32],
    approver: PrincipalId,
    display: Vec<(String, String)>,
    expires_at: u64,
    decided_at: u64,
    descriptor: SignatureDescriptor,
    preimage: [u8; 32],
}

impl PendingDecline {
    /// Returns the bytes the approver signs:
    /// `SHA-256("auths.approval-decline/1\0" || request_id || decided_at_be64)`.
    #[must_use]
    pub const fn signing_preimage(&self) -> &[u8; 32] {
        &self.preimage
    }

    /// Returns the custody object identifier: the request identifier.
    #[must_use]
    pub const fn object_id(&self) -> [u8; 32] {
        self.request_id
    }

    /// Returns the transaction binding the custody signer echoes back.
    #[must_use]
    pub fn transaction_digest(&self) -> [u8; 32] {
        *transaction_binding(&self.preimage).as_bytes()
    }

    /// Returns the custody request identifier,
    /// `approval-decline:<hex object id>:<hex transaction binding>`.
    #[must_use]
    pub fn custody_request_id(&self) -> String {
        format!(
            "{DECLINE_OBJECT_KIND}:{}:{}",
            hex(&self.request_id),
            hex(&self.transaction_digest())
        )
    }

    /// Returns the fields the custody signer shows: the profile review.
    #[must_use]
    pub fn display(&self) -> &[(String, String)] {
        &self.display
    }

    /// Returns when the custody request expires: the window's end.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns the decision time.
    #[must_use]
    pub const fn decided_at(&self) -> u64 {
        self.decided_at
    }

    /// Completes the decline. A decline carries no authority.
    ///
    /// # Errors
    ///
    /// As [`PendingApproval::complete`].
    pub fn complete(
        self,
        signature: &[u8],
        grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
        action_evidence: Vec<EvidenceObject>,
    ) -> Result<ApprovalResponse, ApprovalCode> {
        let signature =
            SignatureBytes::new(signature.to_vec()).map_err(|_| ApprovalCode::Malformed)?;
        if grants.len() > MAX_APPROVAL_GRANTS
            || grants.iter().any(|(_, evidence)| bad_evidence(evidence))
            || bad_evidence(&action_evidence)
        {
            return Err(ApprovalCode::Oversized);
        }
        let response = ApprovalResponse {
            request_id: self.request_id,
            approver: self.approver,
            body: ResponseBody::Decline(SignedDecline {
                decided_at: self.decided_at,
                descriptor: self.descriptor,
                signature,
            }),
            grants,
            action_evidence,
        };
        response.encode()?;
        Ok(response)
    }
}

/// A signed refusal: who declined and when. It carries no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedDecline {
    decided_at: u64,
    descriptor: SignatureDescriptor,
    signature: SignatureBytes,
}

impl SignedDecline {
    /// Returns the decision time.
    #[must_use]
    pub const fn decided_at(&self) -> u64 {
        self.decided_at
    }

    /// Returns the signature descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }

    /// Returns the signature over [`decline_preimage`].
    #[must_use]
    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }
}

/// Returns `SHA-256("auths.approval-decline/1\0" || request_id || decided_at_be64)`.
#[must_use]
pub fn decline_preimage(request_id: &[u8; 32], decided_at: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DECLINE_DOMAIN);
    hasher.update(request_id);
    hasher.update(decided_at.to_be_bytes());
    hasher.finalize().into()
}

/// What an approver answered.
#[allow(
    clippy::large_enum_variant,
    reason = "responses are few and short-lived; boxing buys nothing"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseBody {
    /// The signed envelope.
    Approve(SignedAction),
    /// The signed refusal.
    Decline(SignedDecline),
}

/// One approver's signed answer to one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalResponse {
    request_id: [u8; 32],
    approver: PrincipalId,
    body: ResponseBody,
    grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
    action_evidence: Vec<EvidenceObject>,
}

impl ApprovalResponse {
    /// Returns the identifier of the request this answers.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 32] {
        self.request_id
    }

    /// Returns the answering approver.
    #[must_use]
    pub const fn approver(&self) -> &PrincipalId {
        &self.approver
    }

    /// Returns the decision and its signed body.
    #[must_use]
    pub const fn body(&self) -> &ResponseBody {
        &self.body
    }

    /// Returns the deterministic encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalCode::Oversized`] when the encoding exceeds
    /// [`MAX_APPROVAL_MESSAGE_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, ApprovalCode> {
        let mut encoder = Encoder::new(Vec::new());
        write_response(&mut encoder, self)?;
        bounded(encoder.into_writer())
    }

    /// Returns the printable form.
    ///
    /// # Errors
    ///
    /// As [`Self::encode`].
    pub fn to_text(&self) -> Result<String, ApprovalCode> {
        Ok(printable(APPROVAL_RESPONSE_TEXT_PREFIX, &self.encode()?))
    }
}

/// Decodes a response given as CBOR bytes or as its printable form.
///
/// # Errors
///
/// Returns [`ApprovalCode::Oversized`] or [`ApprovalCode::Malformed`].
pub fn decode_response(input: &[u8]) -> Result<ApprovalResponse, ApprovalCode> {
    let bytes = from_input(input, APPROVAL_RESPONSE_TEXT_PREFIX)?;
    let mut decoder = Decoder::new(&bytes);
    let response = read_response(&mut decoder).map_err(|_| ApprovalCode::Malformed)??;
    if decoder.position() != bytes.len() || response.encode()? != bytes {
        return Err(ApprovalCode::Malformed);
    }
    Ok(response)
}

/// Where one listed approver stands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApproverStatus {
    /// No response yet.
    Pending,
    /// A response that matches the proposal's envelope for this approver.
    Approved,
    /// A signed refusal.
    Declined(SignedDecline),
    /// A response attributed to this approver was refused.
    Rejected(ApprovalCode),
}

/// The collector's view of one proposal's responses.
#[derive(Clone, Debug)]
pub struct Collection<'p> {
    proposal: &'p QuorumProposal,
    statuses: Vec<ApproverStatus>,
    approvals: Vec<Option<QuorumApproval>>,
    responses: Vec<ApprovalResponse>,
    unattributed: Vec<(usize, ApprovalCode)>,
}

/// Gathers responses for one proposal.
///
/// Each response is decoded and matched to its request by identifier. A
/// response for an unknown request, or whose signed envelope differs from the
/// proposal's envelope for that approver, is refused as
/// [`ApprovalCode::ResponseMismatch`]; one naming another approver as
/// [`ApprovalCode::NotAddressed`]. Every response attributed to an approver
/// that already has one refuses that approver as
/// [`ApprovalCode::DuplicateResponse`]. Signatures are not checked.
///
/// # Errors
///
/// Returns [`ApprovalCode::Malformed`] if the proposal's own request
/// identifiers cannot be derived.
pub fn collect<'p, R: AsRef<[u8]>>(
    proposal: &'p QuorumProposal,
    responses: &[R],
) -> Result<Collection<'p>, ApprovalCode> {
    let canonical_action =
        encode_canonical_action(proposal.canonical()).map_err(|_| ApprovalCode::Malformed)?;
    let plan = encode_authorization_plan(proposal.plan()).map_err(|_| ApprovalCode::Malformed)?;
    let identifiers = proposal
        .envelopes()
        .iter()
        .map(|envelope| {
            let encoded = encode_action_envelope(envelope).map_err(|_| ApprovalCode::Malformed)?;
            request_id(&canonical_action, &plan, &encoded, envelope.actor())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = identifiers.len();
    let mut statuses = vec![ApproverStatus::Pending; count];
    let mut approvals: Vec<Option<QuorumApproval>> = vec![None; count];
    let mut seen = vec![0_usize; count];
    let mut accepted = Vec::new();
    let mut unattributed = Vec::new();
    for (index, raw) in responses.iter().enumerate() {
        let response = match decode_response(raw.as_ref()) {
            Ok(response) => response,
            Err(code) => {
                unattributed.push((index, code));
                continue;
            }
        };
        let Some(slot) = identifiers
            .iter()
            .position(|identifier| *identifier == response.request_id)
        else {
            unattributed.push((index, ApprovalCode::ResponseMismatch));
            continue;
        };
        seen[slot] += 1;
        if seen[slot] > 1 {
            statuses[slot] = ApproverStatus::Rejected(ApprovalCode::DuplicateResponse);
            approvals[slot] = None;
            continue;
        }
        let envelope = &proposal.envelopes()[slot];
        if &response.approver != envelope.actor() {
            statuses[slot] = ApproverStatus::Rejected(ApprovalCode::NotAddressed);
            continue;
        }
        match &response.body {
            ResponseBody::Approve(action) => {
                if action.envelope() != envelope {
                    statuses[slot] = ApproverStatus::Rejected(ApprovalCode::ResponseMismatch);
                    continue;
                }
                match QuorumApproval::new(
                    action.clone(),
                    response.grants.clone(),
                    response.action_evidence.clone(),
                ) {
                    Ok(approval) => {
                        statuses[slot] = ApproverStatus::Approved;
                        approvals[slot] = Some(approval);
                    }
                    Err(_) => statuses[slot] = ApproverStatus::Rejected(ApprovalCode::Oversized),
                }
            }
            ResponseBody::Decline(decline) => {
                statuses[slot] = ApproverStatus::Declined(decline.clone());
            }
        }
        accepted.push(response);
    }
    Ok(Collection {
        proposal,
        statuses,
        approvals,
        responses: accepted,
        unattributed,
    })
}

impl Collection<'_> {
    /// Returns one status per listed approver, in proposal order.
    #[must_use]
    pub fn statuses(&self) -> &[ApproverStatus] {
        &self.statuses
    }

    /// Returns the listed approvers, in proposal order.
    #[must_use]
    pub fn approvers(&self) -> Vec<&PrincipalId> {
        self.proposal
            .envelopes()
            .iter()
            .map(ActionEnvelope::actor)
            .collect()
    }

    /// Returns the responses matched to an approver on first arrival.
    #[must_use]
    pub fn responses(&self) -> &[ApprovalResponse] {
        &self.responses
    }

    /// Returns responses that could not be attributed to any approver, by
    /// their index in the input, with the refusal.
    #[must_use]
    pub fn unattributed(&self) -> &[(usize, ApprovalCode)] {
        &self.unattributed
    }

    /// Assembles the proof once every listed approver has approved.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalCode::Incomplete`] while any listed approver has not
    /// approved, and [`ApprovalCode::Oversized`] if the bundle exceeds bounds.
    pub fn assemble(&self) -> Result<ProofBundle, ApprovalCode> {
        let approvals = self
            .approvals
            .iter()
            .cloned()
            .collect::<Option<Vec<_>>>()
            .ok_or(ApprovalCode::Incomplete)?;
        self.proposal
            .assemble(&approvals)
            .map_err(|error| match error {
                QuorumError::Incomplete { .. } => ApprovalCode::Incomplete,
                QuorumError::CollectionLimit => ApprovalCode::Oversized,
                QuorumError::UnknownApproval | QuorumError::DuplicateApproval => {
                    ApprovalCode::ResponseMismatch
                }
                _ => ApprovalCode::Malformed,
            })
    }
}

fn describes(envelope: &ActionEnvelope, canonical: &CanonicalAction) -> bool {
    profile_ref_equal(envelope.profile(), canonical.profile())
        && envelope.body_media_type() == canonical.media_type()
        && envelope.canonical_body_digest() == body_digest(canonical.body())
        && envelope.permission() == canonical.permission()
        && envelope.requested_budget() == canonical.requested_budget()
        && envelope.attachments().is_empty()
        && canonical.detached_attachments().is_empty()
        && envelope.extensions().as_slice().is_empty()
}

fn plan_matches(
    request: &ApprovalRequest,
    envelope: &ActionEnvelope,
    challenge: &[u8; 32],
) -> Result<bool, ApprovalCode> {
    let mut distinct = request.approvers.clone();
    distinct.sort();
    distinct.dedup();
    if distinct.len() != request.approvers.len() || !request.approvers.contains(&request.requester)
    {
        return Ok(false);
    }
    let limits = VerifierLimits::default_deployment();
    let builder = PlanBuilder::new(&limits);
    let members = request
        .approvers
        .iter()
        .map(|approver| {
            member_reference(challenge, approver)
                .map(|reference| builder.proof(reference))
                .map_err(|_| ApprovalCode::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Ok(expected) = builder.threshold(request.required, members) else {
        return Ok(false);
    };
    let encoded = encode_authorization_plan(&expected).map_err(|_| ApprovalCode::Malformed)?;
    let identifier = plan_id(&expected).map_err(|_| ApprovalCode::Malformed)?;
    Ok(encoded == request.plan && identifier == envelope.authorization_plan())
}

fn request_id(
    canonical_action: &[u8],
    plan: &[u8],
    envelope: &[u8],
    approver: &PrincipalId,
) -> Result<[u8; 32], ApprovalCode> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(canonical_action))
        .and_then(|encoder| encoder.bytes(plan))
        .and_then(|encoder| encoder.bytes(envelope))
        .map_err(|_| ApprovalCode::Malformed)?;
    let proposal_digest = Sha256::digest(encoder.into_writer());
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_ID_DOMAIN);
    hasher.update(proposal_digest);
    hasher.update(approver.as_str().as_bytes());
    Ok(hasher.finalize().into())
}

fn bad_evidence(evidence: &[EvidenceObject]) -> bool {
    evidence.is_empty() || evidence.len() > MAX_STATEMENT_EVIDENCE
}

fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, ApprovalCode> {
    if bytes.len() > MAX_APPROVAL_MESSAGE_BYTES {
        Err(ApprovalCode::Oversized)
    } else {
        Ok(bytes)
    }
}

fn printable(prefix: &str, bytes: &[u8]) -> String {
    let mut text = String::with_capacity(prefix.len() + bytes.len().div_ceil(3) * 4);
    text.push_str(prefix);
    text.push_str(&Base64UrlUnpadded::encode_string(bytes));
    text
}

fn max_text_bytes(prefix: &str) -> usize {
    prefix.len() + (MAX_APPROVAL_MESSAGE_BYTES * 4).div_ceil(3)
}

fn from_input(input: &[u8], prefix: &str) -> Result<Vec<u8>, ApprovalCode> {
    let trimmed = input.trim_ascii();
    if let Some(encoded) = trimmed.strip_prefix(prefix.as_bytes()) {
        if trimmed.len() > max_text_bytes(prefix) {
            return Err(ApprovalCode::Oversized);
        }
        let text = core::str::from_utf8(encoded).map_err(|_| ApprovalCode::Malformed)?;
        let bytes = Base64UrlUnpadded::decode_vec(text).map_err(|_| ApprovalCode::Malformed)?;
        if Base64UrlUnpadded::encode_string(&bytes) != text {
            return Err(ApprovalCode::Malformed);
        }
        return bounded(bytes);
    }
    if input.is_empty() {
        return Err(ApprovalCode::Malformed);
    }
    bounded(input.to_vec())
}

fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}

type Written = Result<(), minicbor::encode::Error<core::convert::Infallible>>;

fn write_request(encoder: &mut Encoder<Vec<u8>>, request: &ApprovalRequest) -> Written {
    encoder.map(REQUEST_KEYS)?;
    encoder.u8(0)?.str(APPROVAL_REQUEST_SCHEMA)?;
    encoder.u8(1)?.bytes(&request.request_id)?;
    encoder.u8(2)?.bytes(&request.canonical_action)?;
    encoder.u8(3)?.bytes(&request.envelope)?;
    encoder.u8(4)?.bytes(&request.plan)?;
    encoder.u8(5)?.array(request.approvers.len() as u64)?;
    for approver in &request.approvers {
        encoder.str(approver.as_str())?;
    }
    encoder.u8(6)?.u16(request.required)?;
    encoder.u8(7)?.str(request.approver.as_str())?;
    encoder.u8(8)?.str(request.requester.as_str())?;
    encoder.u8(9)?.map(2)?;
    encoder.u8(0)?.u64(request.window.not_before)?;
    encoder.u8(1)?.u64(request.window.expires_at)?;
    Ok(())
}

fn write_evidence(encoder: &mut Encoder<Vec<u8>>, evidence: &[EvidenceObject]) -> Written {
    encoder.array(evidence.len() as u64)?;
    for object in evidence {
        encoder
            .array(3)?
            .str(object.evidence_type().as_str())?
            .str(object.media_type().as_str())?
            .bytes(object.bytes())?;
    }
    Ok(())
}

fn write_response(
    encoder: &mut Encoder<Vec<u8>>,
    response: &ApprovalResponse,
) -> Result<(), ApprovalCode> {
    let (decision, body) = match &response.body {
        ResponseBody::Approve(action) => (
            APPROVE,
            encode_signed_action(action).map_err(|_| ApprovalCode::Malformed)?,
        ),
        ResponseBody::Decline(decline) => (DECLINE, encode_decline(decline)?),
    };
    let grants = response
        .grants
        .iter()
        .map(|(grant, evidence)| {
            encode_signed_grant(grant)
                .map(|bytes| (bytes, evidence))
                .map_err(|_| ApprovalCode::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let written: Written = (|| {
        encoder.map(RESPONSE_KEYS)?;
        encoder.u8(0)?.str(APPROVAL_RESPONSE_SCHEMA)?;
        encoder.u8(1)?.bytes(&response.request_id)?;
        encoder.u8(2)?.str(decision)?;
        encoder.u8(3)?.str(response.approver.as_str())?;
        encoder.u8(4)?.bytes(&body)?;
        encoder.u8(5)?.array(grants.len() as u64)?;
        for (grant, evidence) in &grants {
            encoder.array(2)?.bytes(grant)?;
            write_evidence(encoder, evidence)?;
        }
        encoder.u8(6)?;
        write_evidence(encoder, &response.action_evidence)
    })();
    written.map_err(|_| ApprovalCode::Malformed)
}

fn encode_decline(decline: &SignedDecline) -> Result<Vec<u8>, ApprovalCode> {
    let mut encoder = Encoder::new(Vec::new());
    let written: Written = (|| {
        encoder.map(DECLINE_KEYS)?;
        encoder.u8(0)?.u64(decline.decided_at)?;
        encoder
            .u8(1)?
            .str(decline.descriptor.principal_method().as_str())?;
        encoder
            .u8(2)?
            .str(decline.descriptor.verification_method().as_str())?;
        encoder.u8(3)?.str(decline.descriptor.suite().as_str())?;
        encoder.u8(4)?.bytes(decline.signature.as_slice())?;
        Ok(())
    })();
    written.map_err(|_| ApprovalCode::Malformed)?;
    Ok(encoder.into_writer())
}

type Read<T> = Result<Result<T, ApprovalCode>, minicbor::decode::Error>;

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<bool, minicbor::decode::Error> {
    Ok(decoder.datatype()? == Type::U8 && decoder.u8()? == expected)
}

fn read_map(decoder: &mut Decoder<'_>, keys: u64) -> Result<bool, minicbor::decode::Error> {
    Ok(decoder.map()? == Some(keys))
}

fn principal(text: &str) -> Result<PrincipalId, ApprovalCode> {
    PrincipalId::parse(text).map_err(|_| ApprovalCode::Malformed)
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], ApprovalCode> {
    bytes.try_into().map_err(|_| ApprovalCode::Malformed)
}

fn read_request(decoder: &mut Decoder<'_>) -> Read<ApprovalRequest> {
    if !read_map(decoder, REQUEST_KEYS)?
        || !expect_key(decoder, 0)?
        || decoder.str()? != APPROVAL_REQUEST_SCHEMA
        || !expect_key(decoder, 1)?
    {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let request_id = match digest(decoder.bytes()?) {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    let mut blobs = Vec::with_capacity(3);
    for key in 2..=4 {
        if !expect_key(decoder, key)? {
            return Ok(Err(ApprovalCode::Malformed));
        }
        blobs.push(decoder.bytes()?.to_vec());
    }
    if !expect_key(decoder, 5)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let Some(count) = decoder.array()? else {
        return Ok(Err(ApprovalCode::Malformed));
    };
    if count == 0 {
        return Ok(Err(ApprovalCode::Malformed));
    }
    if count > MAX_APPROVERS as u64 {
        return Ok(Err(ApprovalCode::Oversized));
    }
    let mut approvers = Vec::with_capacity(MAX_APPROVERS);
    for _ in 0..count {
        match principal(decoder.str()?) {
            Ok(value) => approvers.push(value),
            Err(code) => return Ok(Err(code)),
        }
    }
    if !expect_key(decoder, 6)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let required = decoder.u64()?;
    let Ok(required) = u16::try_from(required) else {
        return Ok(Err(ApprovalCode::Malformed));
    };
    if required == 0 || usize::from(required) > approvers.len() || !expect_key(decoder, 7)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let approver = match principal(decoder.str()?) {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    if !expect_key(decoder, 8)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let requester = match principal(decoder.str()?) {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    if !expect_key(decoder, 9)? || !read_map(decoder, 2)? || !expect_key(decoder, 0)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let not_before = decoder.u64()?;
    if !expect_key(decoder, 1)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let expires_at = decoder.u64()?;
    if not_before > expires_at {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let [canonical_action, envelope, plan]: [Vec<u8>; 3] = match blobs.try_into() {
        Ok(value) => value,
        Err(_) => return Ok(Err(ApprovalCode::Malformed)),
    };
    Ok(Ok(ApprovalRequest {
        request_id,
        canonical_action,
        envelope,
        plan,
        approvers,
        required,
        approver,
        requester,
        window: ApprovalWindow {
            not_before,
            expires_at,
        },
    }))
}

fn read_evidence(decoder: &mut Decoder<'_>) -> Read<Vec<EvidenceObject>> {
    let Some(count) = decoder.array()? else {
        return Ok(Err(ApprovalCode::Malformed));
    };
    if count == 0 {
        return Ok(Err(ApprovalCode::Malformed));
    }
    if count > MAX_STATEMENT_EVIDENCE as u64 {
        return Ok(Err(ApprovalCode::Oversized));
    }
    let mut objects = Vec::new();
    for _ in 0..count {
        if decoder.array()? != Some(3) {
            return Ok(Err(ApprovalCode::Malformed));
        }
        let evidence_type = decoder.str()?;
        let media_type = decoder.str()?;
        let bytes = decoder.bytes()?;
        let object = EvidenceTypeId::parse(evidence_type)
            .ok()
            .zip(MediaType::parse(media_type).ok())
            .and_then(|(evidence_type, media_type)| {
                address_evidence(evidence_type, media_type, bytes.to_vec()).ok()
            });
        match object {
            Some(object) => objects.push(object),
            None => return Ok(Err(ApprovalCode::Malformed)),
        }
    }
    Ok(Ok(objects))
}

fn read_response(decoder: &mut Decoder<'_>) -> Read<ApprovalResponse> {
    let limits = VerifierLimits::default_deployment();
    if !read_map(decoder, RESPONSE_KEYS)?
        || !expect_key(decoder, 0)?
        || decoder.str()? != APPROVAL_RESPONSE_SCHEMA
        || !expect_key(decoder, 1)?
    {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let request_id = match digest(decoder.bytes()?) {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    if !expect_key(decoder, 2)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let decision = decoder.str()?;
    let approve = match decision {
        APPROVE => true,
        DECLINE => false,
        _ => return Ok(Err(ApprovalCode::Malformed)),
    };
    if !expect_key(decoder, 3)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let approver = match principal(decoder.str()?) {
        Ok(value) => value,
        Err(code) => return Ok(Err(code)),
    };
    if !expect_key(decoder, 4)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let body_bytes = decoder.bytes()?;
    let body = if approve {
        match decode_signed_action(body_bytes, &limits) {
            Ok(action) => ResponseBody::Approve(action),
            Err(_) => return Ok(Err(ApprovalCode::Malformed)),
        }
    } else {
        match decode_decline(body_bytes) {
            Ok(decline) => ResponseBody::Decline(decline),
            Err(code) => return Ok(Err(code)),
        }
    };
    if !expect_key(decoder, 5)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let Some(count) = decoder.array()? else {
        return Ok(Err(ApprovalCode::Malformed));
    };
    if count > MAX_APPROVAL_GRANTS as u64 {
        return Ok(Err(ApprovalCode::Oversized));
    }
    let mut grants = Vec::new();
    for _ in 0..count {
        if decoder.array()? != Some(2) {
            return Ok(Err(ApprovalCode::Malformed));
        }
        let Ok(grant) = decode_signed_grant(decoder.bytes()?, &limits) else {
            return Ok(Err(ApprovalCode::Malformed));
        };
        match read_evidence(decoder)? {
            Ok(evidence) => grants.push((grant, evidence)),
            Err(code) => return Ok(Err(code)),
        }
    }
    if !expect_key(decoder, 6)? {
        return Ok(Err(ApprovalCode::Malformed));
    }
    let action_evidence = match read_evidence(decoder)? {
        Ok(evidence) => evidence,
        Err(code) => return Ok(Err(code)),
    };
    Ok(Ok(ApprovalResponse {
        request_id,
        approver,
        body,
        grants,
        action_evidence,
    }))
}

fn decode_decline(bytes: &[u8]) -> Result<SignedDecline, ApprovalCode> {
    let mut decoder = Decoder::new(bytes);
    let signed = (|| -> Read<SignedDecline> {
        if !read_map(&mut decoder, DECLINE_KEYS)? || !expect_key(&mut decoder, 0)? {
            return Ok(Err(ApprovalCode::Malformed));
        }
        let decided_at = decoder.u64()?;
        let mut texts = Vec::with_capacity(3);
        for key in 1..=3 {
            if !expect_key(&mut decoder, key)? {
                return Ok(Err(ApprovalCode::Malformed));
            }
            texts.push(decoder.str()?);
        }
        if !expect_key(&mut decoder, 4)? {
            return Ok(Err(ApprovalCode::Malformed));
        }
        let signature = decoder.bytes()?.to_vec();
        let descriptor = PrincipalMethodId::parse(texts[0])
            .ok()
            .zip(VerificationMethod::parse(texts[1]).ok())
            .zip(SignatureSuiteId::parse(texts[2]).ok())
            .map(|((method, verification), suite)| {
                SignatureDescriptor::new(method, verification, suite)
            });
        let (Some(descriptor), Ok(signature)) = (descriptor, SignatureBytes::new(signature)) else {
            return Ok(Err(ApprovalCode::Malformed));
        };
        Ok(Ok(SignedDecline {
            decided_at,
            descriptor,
            signature,
        }))
    })()
    .map_err(|_| ApprovalCode::Malformed)??;
    if decoder.position() != bytes.len() || encode_decline(&signed)? != bytes {
        return Err(ApprovalCode::Malformed);
    }
    Ok(signed)
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
