//! Thin projection of the remote approval operations in
//! `auths-approval-quorum`. Every check, code, and review string is native;
//! a refusal is a JavaScript `Error` named `ApprovalRefused` whose `code` is
//! the stable `approval.*` code.

use super::{addressed_evidence, js_error};
use crate::quorum::McpQuorumV1;
use auths_approval_quorum::remote::{
    ApprovalCode, ApproverStatus, DECLINE_OBJECT_KIND, PendingApproval, PendingDecline,
    RegisteredProfile, ReviewProfile, ReviewedRequest, collect, open_request, requests,
};
use auths_approval_quorum::{MAX_APPROVAL_GRANTS, MAX_APPROVERS, MAX_STATEMENT_EVIDENCE};
use auths_model::{
    EvidenceObject, PrincipalId, ProfileId, ProfileRef, SignedGrant, VerifierLimits,
};
use auths_profile_mcp::{McpProfile, PROFILE_ID, PROFILE_VERSION};
use wasm_bindgen::prelude::*;

fn refusal(code: ApprovalCode) -> JsValue {
    let error = js_sys::Error::new(code.as_str());
    error.set_name("ApprovalRefused");
    let _ = js_sys::Reflect::set(&error, &"code".into(), &code.as_str().into());
    error.into()
}

fn principal(value: &str) -> Result<PrincipalId, JsValue> {
    PrincipalId::parse(value).map_err(js_error)
}

fn descriptor(
    principal_method: &str,
    verification_method: &str,
    suite: &str,
) -> Result<auths_model::SignatureDescriptor, JsValue> {
    Ok(auths_model::SignatureDescriptor::new(
        auths_model::PrincipalMethodId::parse(principal_method).map_err(js_error)?,
        auths_model::VerificationMethod::parse(verification_method).map_err(js_error)?,
        auths_model::SignatureSuiteId::parse(suite).map_err(js_error)?,
    ))
}

fn index(value: u32, length: usize) -> Result<usize, JsValue> {
    usize::try_from(value)
        .ok()
        .filter(|index| *index < length)
        .ok_or_else(|| js_error(crate::EngineError::Abi("index is out of range")))
}

fn fields_js(fields: &[(String, String)]) -> JsValue {
    let array = js_sys::Array::new();
    for (label, value) in fields {
        array.push(&js_sys::Array::of2(&label.into(), &value.into()));
    }
    array.into()
}

/// One request per listed approver, in proposal order.
#[wasm_bindgen]
pub struct ApprovalRequestsV1 {
    issued: Vec<(String, Vec<u8>, String, [u8; 32])>,
}

#[wasm_bindgen]
impl ApprovalRequestsV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> u32 {
        u32::try_from(self.issued.len()).unwrap_or(u32::MAX)
    }

    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    pub fn approver(&self, at: u32) -> Result<String, JsValue> {
        Ok(self.issued[index(at, self.issued.len())?].0.clone())
    }

    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    pub fn data(&self, at: u32) -> Result<Vec<u8>, JsValue> {
        Ok(self.issued[index(at, self.issued.len())?].1.clone())
    }

    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    pub fn text(&self, at: u32) -> Result<String, JsValue> {
        Ok(self.issued[index(at, self.issued.len())?].2.clone())
    }

    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    #[wasm_bindgen(js_name = requestId)]
    pub fn request_id(&self, at: u32) -> Result<Vec<u8>, JsValue> {
        Ok(self.issued[index(at, self.issued.len())?].3.to_vec())
    }
}

/// Emits one request per listed approver; `requester` must be listed.
///
/// # Errors
///
/// Throws `ApprovalRefused` with `approval.plan-mismatch` for an unlisted
/// requester.
#[wasm_bindgen(js_name = approvalRequestsV1)]
pub fn approval_requests_v1(
    quorum: &McpQuorumV1,
    requester: &str,
) -> Result<ApprovalRequestsV1, JsValue> {
    let issued = requests(quorum.proposal(), &principal(requester)?)
        .map_err(refusal)?
        .into_iter()
        .map(|request| {
            Ok((
                request.approver().as_str().to_owned(),
                request.encode().map_err(refusal)?,
                request.to_text().map_err(refusal)?,
                request.request_id(),
            ))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    Ok(ApprovalRequestsV1 { issued })
}

/// A request that passed every native check, with the profile's review.
#[wasm_bindgen]
pub struct ReviewedApprovalRequestV1 {
    inner: ReviewedRequest,
}

/// Opens one request given as CBOR bytes or its printable form (UTF-8).
///
/// # Errors
///
/// Throws `ApprovalRefused` with the first failing check's code.
#[wasm_bindgen(js_name = openApprovalRequestV1)]
pub fn open_approval_request_v1(
    data: &[u8],
    now: u64,
) -> Result<ReviewedApprovalRequestV1, JsValue> {
    let profile = ProfileRef::new(
        ProfileId::parse(PROFILE_ID).map_err(js_error)?,
        PROFILE_VERSION,
    )
    .map_err(js_error)?;
    let mcp = RegisteredProfile::new(profile, McpProfile);
    let profiles: [&dyn ReviewProfile; 1] = [&mcp];
    Ok(ReviewedApprovalRequestV1 {
        inner: open_request(data, &profiles, now).map_err(refusal)?,
    })
}

#[wasm_bindgen]
impl ReviewedApprovalRequestV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn title(&self) -> String {
        self.inner.title().to_owned()
    }

    /// Returns the profile's fields as `[label, value]` pairs.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn fields(&self) -> JsValue {
        fields_js(self.inner.fields())
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = displayDigestHex)]
    pub fn display_digest_hex(&self) -> String {
        self.inner.display_digest_hex().to_owned()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn requester(&self) -> String {
        self.inner.requester().as_str().to_owned()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn approvers(&self) -> Vec<String> {
        self.inner
            .approvers()
            .iter()
            .map(|approver| approver.as_str().to_owned())
            .collect()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn required(&self) -> u16 {
        self.inner.required()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn approver(&self) -> String {
        self.inner.approver().as_str().to_owned()
    }

    /// Returns `[notBefore, expiresAt]`, both inclusive.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn window(&self) -> Vec<u64> {
        let window = self.inner.window();
        vec![window.not_before(), window.expires_at()]
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = requestId)]
    pub fn request_id(&self) -> Vec<u8> {
        self.inner.request_id().to_vec()
    }

    /// Prepares the custody request for an approval by `signer`.
    ///
    /// # Errors
    ///
    /// Throws `ApprovalRefused` with `approval.not-addressed` when `signer`
    /// is not the addressed approver.
    #[wasm_bindgen(js_name = prepareApproval)]
    pub fn prepare_approval(
        &self,
        signer: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
    ) -> Result<PendingApprovalV1, JsValue> {
        let pending = self
            .inner
            .prepare_approval(
                &principal(signer)?,
                descriptor(principal_method, verification_method, suite)?,
            )
            .map_err(refusal)?;
        Ok(PendingApprovalV1::new(Pending::Approve(Box::new(pending))))
    }

    /// Prepares the custody request for a decline by `signer` at `decided_at`.
    ///
    /// # Errors
    ///
    /// As [`Self::prepare_approval`].
    #[wasm_bindgen(js_name = prepareDecline)]
    pub fn prepare_decline(
        &self,
        signer: &str,
        principal_method: &str,
        verification_method: &str,
        suite: &str,
        decided_at: u64,
    ) -> Result<PendingApprovalV1, JsValue> {
        let pending = self
            .inner
            .prepare_decline(
                &principal(signer)?,
                descriptor(principal_method, verification_method, suite)?,
                decided_at,
            )
            .map_err(refusal)?;
        Ok(PendingApprovalV1::new(Pending::Decline(pending)))
    }
}

enum Pending {
    Approve(Box<PendingApproval>),
    Decline(PendingDecline),
}

/// The custody request for one approval or decline, and the approver's
/// grant chain and signature evidence staged for the response.
#[wasm_bindgen]
pub struct PendingApprovalV1 {
    pending: Option<Pending>,
    grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
    action_evidence: Vec<EvidenceObject>,
}

impl PendingApprovalV1 {
    const fn new(pending: Pending) -> Self {
        Self {
            pending: Some(pending),
            grants: Vec::new(),
            action_evidence: Vec::new(),
        }
    }

    fn current(&self) -> Result<&Pending, JsValue> {
        self.pending
            .as_ref()
            .ok_or_else(|| js_error(crate::EngineError::Abi("approval was already completed")))
    }
}

/// One signed response as bytes and printable text.
#[wasm_bindgen]
pub struct ApprovalResponseV1 {
    data: Vec<u8>,
    text: String,
}

#[wasm_bindgen]
impl ApprovalResponseV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.text.clone()
    }
}

#[wasm_bindgen]
impl PendingApprovalV1 {
    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter)]
    pub fn decision(&self) -> Result<String, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(_) => "approve",
            Pending::Decline(_) => "decline",
        }
        .to_owned())
    }

    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter, js_name = objectKind)]
    pub fn object_kind(&self) -> Result<String, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(value) => value.signing().object_id().label(),
            Pending::Decline(_) => DECLINE_OBJECT_KIND,
        }
        .to_owned())
    }

    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter, js_name = requestId)]
    pub fn request_id(&self) -> Result<String, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(value) => value.signing().request_id(),
            Pending::Decline(value) => value.custody_request_id(),
        })
    }

    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter, js_name = objectId)]
    pub fn object_id(&self) -> Result<Vec<u8>, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(value) => value.signing().object_id().as_bytes().to_vec(),
            Pending::Decline(value) => value.object_id().to_vec(),
        })
    }

    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter, js_name = transactionDigest)]
    pub fn transaction_digest(&self) -> Result<Vec<u8>, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(value) => value.signing().transaction_digest().as_bytes().to_vec(),
            Pending::Decline(value) => value.transaction_digest().to_vec(),
        })
    }

    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter, js_name = signingPreimage)]
    pub fn signing_preimage(&self) -> Result<Vec<u8>, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(value) => value.signing().signing_preimage().to_vec(),
            Pending::Decline(value) => value.signing_preimage().to_vec(),
        })
    }

    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter, js_name = expiresAt)]
    pub fn expires_at(&self) -> Result<u64, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(value) => value.expires_at(),
            Pending::Decline(value) => value.expires_at(),
        })
    }

    /// Returns the custody display as `[label, value]` pairs: the review.
    ///
    /// # Errors
    ///
    /// Throws once the response was completed.
    #[wasm_bindgen(getter)]
    pub fn display(&self) -> Result<JsValue, JsValue> {
        Ok(match self.current()? {
            Pending::Approve(value) => fields_js(value.display()),
            Pending::Decline(value) => fields_js(value.display()),
        })
    }

    /// Stages one grant of the approver's chain, root first.
    ///
    /// # Errors
    ///
    /// Rejects a malformed grant or a full chain.
    #[wasm_bindgen(js_name = pushGrant)]
    pub fn push_grant(&mut self, signed_grant_cbor: &[u8]) -> Result<u32, JsValue> {
        if self.grants.len() >= MAX_APPROVAL_GRANTS {
            return Err(js_error(crate::EngineError::Abi(
                "approval grant chain is full",
            )));
        }
        let grant = auths_codec::decode_signed_grant(
            signed_grant_cbor,
            &VerifierLimits::default_deployment(),
        )
        .map_err(js_error)?;
        self.grants.push((grant, Vec::new()));
        u32::try_from(self.grants.len() - 1).map_err(js_error)
    }

    /// Binds public control evidence to one staged grant.
    ///
    /// # Errors
    ///
    /// Rejects an unknown grant, invalid evidence, or a full collection.
    #[wasm_bindgen(js_name = bindGrantEvidence)]
    pub fn bind_grant_evidence(
        &mut self,
        grant: u32,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let evidence = addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?;
        let slot = index(grant, self.grants.len())?;
        push_bounded(&mut self.grants[slot].1, evidence)
    }

    /// Binds public control evidence to the signature.
    ///
    /// # Errors
    ///
    /// Rejects invalid evidence or a full collection.
    #[wasm_bindgen(js_name = bindActionEvidence)]
    pub fn bind_action_evidence(
        &mut self,
        evidence_type: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<(), JsValue> {
        let evidence = addressed_evidence(evidence_type, media_type, bytes).map_err(js_error)?;
        push_bounded(&mut self.action_evidence, evidence)
    }

    /// Completes the response with the custody signature.
    ///
    /// # Errors
    ///
    /// Throws `ApprovalRefused` for material outside bounds, or an error once
    /// the response was completed.
    pub fn complete(&mut self, signature: &[u8]) -> Result<ApprovalResponseV1, JsValue> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| js_error(crate::EngineError::Abi("approval was already completed")))?;
        let grants = std::mem::take(&mut self.grants);
        let evidence = std::mem::take(&mut self.action_evidence);
        let response = match pending {
            Pending::Approve(value) => value.complete(signature, grants, evidence),
            Pending::Decline(value) => value.complete(signature, grants, evidence),
        }
        .map_err(refusal)?;
        Ok(ApprovalResponseV1 {
            data: response.encode().map_err(refusal)?,
            text: response.to_text().map_err(refusal)?,
        })
    }
}

fn push_bounded(
    objects: &mut Vec<EvidenceObject>,
    evidence: EvidenceObject,
) -> Result<(), JsValue> {
    if objects.len() >= MAX_STATEMENT_EVIDENCE {
        return Err(js_error(crate::EngineError::Abi(
            "evidence collection is full",
        )));
    }
    objects.push(evidence);
    Ok(())
}

/// Responses gathered for one proposal before collection.
#[wasm_bindgen]
pub struct ApprovalCollectorV1 {
    responses: Vec<Vec<u8>>,
}

#[wasm_bindgen]
impl ApprovalCollectorV1 {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: Vec::new(),
        }
    }

    /// Adds one response as CBOR bytes or its printable form (UTF-8).
    ///
    /// # Errors
    ///
    /// Rejects more responses than an approver set can answer twice over.
    pub fn add(&mut self, response: &[u8]) -> Result<(), JsValue> {
        if self.responses.len() >= 4 * MAX_APPROVERS {
            return Err(js_error(crate::EngineError::Abi(
                "approval collector is full",
            )));
        }
        self.responses.push(response.to_vec());
        Ok(())
    }

    /// Matches the responses to `quorum`'s requests.
    ///
    /// # Errors
    ///
    /// Throws `ApprovalRefused` if the proposal's requests cannot be derived.
    pub fn collect(&self, quorum: &McpQuorumV1) -> Result<ApprovalCollectionV1, JsValue> {
        let collection = collect(quorum.proposal(), &self.responses).map_err(refusal)?;
        let statuses = collection
            .statuses()
            .iter()
            .zip(collection.approvers())
            .map(|(status, approver)| {
                let approver = approver.as_str().to_owned();
                match status {
                    ApproverStatus::Pending => (approver, "pending", "", 0),
                    ApproverStatus::Approved => (approver, "approved", "", 0),
                    ApproverStatus::Declined(decline) => {
                        (approver, "declined", "", decline.decided_at())
                    }
                    ApproverStatus::Rejected(code) => (approver, "rejected", code.as_str(), 0),
                }
            })
            .collect();
        let proof = match collection.assemble() {
            Ok(bundle) => Ok(auths_codec::encode_bundle(&bundle).map_err(js_error)?),
            Err(code) => Err(code),
        };
        Ok(ApprovalCollectionV1 {
            statuses,
            unattributed: collection
                .unattributed()
                .iter()
                .map(|(index, code)| (*index, code.as_str()))
                .collect(),
            proof,
        })
    }
}

impl Default for ApprovalCollectorV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Where each listed approver stands, in proposal order.
#[wasm_bindgen]
pub struct ApprovalCollectionV1 {
    statuses: Vec<(String, &'static str, &'static str, u64)>,
    unattributed: Vec<(usize, &'static str)>,
    proof: Result<Vec<u8>, ApprovalCode>,
}

#[wasm_bindgen]
impl ApprovalCollectionV1 {
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> u32 {
        u32::try_from(self.statuses.len()).unwrap_or(u32::MAX)
    }

    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    pub fn approver(&self, at: u32) -> Result<String, JsValue> {
        Ok(self.statuses[index(at, self.statuses.len())?].0.clone())
    }

    /// Returns `pending`, `approved`, `declined`, or `rejected`.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    pub fn status(&self, at: u32) -> Result<String, JsValue> {
        Ok(self.statuses[index(at, self.statuses.len())?].1.to_owned())
    }

    /// Returns the refusal code of a rejected approver, or an empty string.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    pub fn code(&self, at: u32) -> Result<String, JsValue> {
        Ok(self.statuses[index(at, self.statuses.len())?].2.to_owned())
    }

    /// Returns the decision time of a declined approver, or zero.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the approver set.
    #[wasm_bindgen(js_name = decidedAt)]
    pub fn decided_at(&self, at: u32) -> Result<u64, JsValue> {
        Ok(self.statuses[index(at, self.statuses.len())?].3)
    }

    #[must_use]
    #[wasm_bindgen(getter, js_name = unattributedCount)]
    pub fn unattributed_count(&self) -> u32 {
        u32::try_from(self.unattributed.len()).unwrap_or(u32::MAX)
    }

    /// Returns the input index of one unattributed response.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the unattributed list.
    #[wasm_bindgen(js_name = unattributedIndex)]
    pub fn unattributed_index(&self, at: u32) -> Result<u32, JsValue> {
        u32::try_from(self.unattributed[index(at, self.unattributed.len())?].0).map_err(js_error)
    }

    /// Returns the refusal code of one unattributed response.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the unattributed list.
    #[wasm_bindgen(js_name = unattributedCode)]
    pub fn unattributed_code(&self, at: u32) -> Result<String, JsValue> {
        Ok(self.unattributed[index(at, self.unattributed.len())?]
            .1
            .to_owned())
    }

    /// Returns the proof once every listed approver approved.
    ///
    /// # Errors
    ///
    /// Throws `ApprovalRefused` with `approval.incomplete` otherwise.
    pub fn assemble(&self) -> Result<Vec<u8>, JsValue> {
        self.proof.clone().map_err(refusal)
    }
}
