use crate::{
    api::NodeRuntime,
    profiles::{ReceiptSummary, RuntimeFailure, WorkflowProjection},
    sandbox_store::{
        MemorySandboxStore, PendingEffect, PostgresSandboxStore, SandboxStore, StoredReceipt,
    },
};
use auths_production_client::{
    ClientOutcomeKind, ProductVerb, ProductionRequest, ProductionResponse, QualifiedProfile,
    RecoveryReference, RetryClass, decode_delegation_body,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const AUTHORITY_DOMAIN: &[u8] = b"AUTHS-SANDBOX-AUTHORITY\x00\x01";
const RECEIPT_DOMAIN: &[u8] = b"AUTHS-SANDBOX-RECEIPT\x00\x01";
const RECOVERY_DOMAIN: &[u8] = b"AUTHS-SANDBOX-RECOVERY\x00\x01";
const DISCLOSURE_DOMAIN: &[u8] = b"AUTHS-SANDBOX-DISCLOSURE\x00\x01";
const MAX_ACTIONS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    expires_at: u64,
    remaining_depth: u16,
    max_uses: u32,
    action_digests: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Authority {
    profile: QualifiedProfile,
    subject: [u8; 32],
    parent: Option<[u8; 32]>,
    scope: Scope,
}

pub struct SandboxRuntime {
    signing: SigningKey,
    verifying: VerifyingKey,
    profiles: BTreeSet<QualifiedProfile>,
    store: Arc<dyn SandboxStore>,
}

impl SandboxRuntime {
    pub fn new(
        seed: [u8; 32],
        profiles: BTreeSet<QualifiedProfile>,
    ) -> Result<Self, RuntimeFailure> {
        Self::with_store(seed, profiles, Arc::new(MemorySandboxStore::default()))
    }

    pub(crate) fn with_store(
        seed: [u8; 32],
        profiles: BTreeSet<QualifiedProfile>,
        store: Arc<dyn SandboxStore>,
    ) -> Result<Self, RuntimeFailure> {
        if seed == [0; 32] || profiles.is_empty() {
            return Err(RuntimeFailure::Malformed);
        }
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Ok(Self {
            signing,
            verifying,
            profiles,
            store,
        })
    }

    pub fn with_postgres(
        seed: [u8; 32],
        profiles: BTreeSet<QualifiedProfile>,
        store: PostgresSandboxStore,
    ) -> Result<Self, RuntimeFailure> {
        Self::with_store(seed, profiles, Arc::new(store))
    }

    fn create(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        self.require_profile(request.profile())?;
        let scope = decode_scope(request.body().ok_or(RuntimeFailure::Malformed)?)?;
        if scope.expires_at <= now() {
            return Err(RuntimeFailure::Denied);
        }
        let authority = Authority {
            profile: request.profile(),
            subject: digest(request.identity()),
            parent: None,
            scope,
        };
        authority_response(self.sign(AUTHORITY_DOMAIN, &encode_authority_payload(&authority)?)?)
    }

    fn delegate(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        self.require_profile(request.profile())?;
        let parent_bytes = request.authority().ok_or(RuntimeFailure::Malformed)?;
        let parent = self.verify_authority(parent_bytes)?;
        if parent.profile != request.profile() || parent.subject != digest(request.identity()) {
            return Err(RuntimeFailure::Denied);
        }
        let (subject, attenuation) =
            decode_delegation_body(request.body().ok_or(RuntimeFailure::Malformed)?)
                .map_err(|_| RuntimeFailure::Malformed)?;
        let scope = decode_scope(&attenuation)?;
        if parent.scope.remaining_depth == 0
            || scope.remaining_depth >= parent.scope.remaining_depth
            || scope.expires_at > parent.scope.expires_at
            || scope.max_uses > parent.scope.max_uses
            || !scope
                .action_digests
                .iter()
                .all(|digest| parent.scope.action_digests.contains(digest))
        {
            return Err(RuntimeFailure::Denied);
        }
        let authority = Authority {
            profile: request.profile(),
            subject: digest(&subject),
            parent: Some(digest(parent_bytes)),
            scope,
        };
        authority_response(self.sign(AUTHORITY_DOMAIN, &encode_authority_payload(&authority)?)?)
    }

    fn execute(&self, request: &ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        self.require_profile(request.profile())?;
        let authority_bytes = request.authority().ok_or(RuntimeFailure::Malformed)?;
        let authority = self.verify_authority(authority_bytes)?;
        let action = request.body().ok_or(RuntimeFailure::Malformed)?;
        let action_digest = digest(action);
        if authority.profile != request.profile()
            || authority.subject != digest(request.identity())
            || authority.scope.expires_at <= now()
            || !authority.scope.action_digests.contains(&action_digest)
        {
            return Err(RuntimeFailure::Denied);
        }
        let authority_digest = digest(authority_bytes);
        self.store
            .claim_use(authority_digest, authority.scope.max_uses)?;
        if action.starts_with(b"AUTHS-SANDBOX-RECOVER") {
            let reference = recovery_reference(authority_digest, action_digest)?;
            self.store.put_pending(
                reference.as_str(),
                &PendingEffect {
                    profile: request.profile(),
                    authority: authority_digest,
                    action: action.to_vec(),
                    created_at: now(),
                },
            )?;
            return ProductionResponse::new(
                ClientOutcomeKind::Recoverable,
                Some("provider.outcome-unknown".into()),
                RetryClass::Resume,
                Some(reference),
                None,
                None,
            )
            .map_err(|_| RuntimeFailure::Malformed);
        }
        let (receipt, value) =
            self.complete_effect(request.profile(), authority_digest, action, now())?;
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
                .ok_or(RuntimeFailure::UnknownWorkflow)?;
            if completed.profile != request.profile() {
                return Err(RuntimeFailure::Denied);
            }
            return completed_response(completed.bytes, completed.value);
        };
        if pending.profile != request.profile() {
            return Err(RuntimeFailure::Denied);
        }
        let (receipt_id, receipt) =
            self.build_effect(pending.profile, pending.authority, &pending.action, now())?;
        let completed =
            self.store
                .finish_pending(reference.as_str(), &pending, &receipt_id, &receipt)?;
        completed_response(completed.bytes, completed.value)
    }

    fn complete_effect(
        &self,
        profile: QualifiedProfile,
        authority: [u8; 32],
        action: &[u8],
        completed_at: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), RuntimeFailure> {
        let (receipt_id, receipt) = self.build_effect(profile, authority, action, completed_at)?;
        self.store.put_receipt(&receipt_id, &receipt)?;
        Ok((receipt.bytes, receipt.value))
    }

    fn build_effect(
        &self,
        profile: QualifiedProfile,
        authority: [u8; 32],
        action: &[u8],
        completed_at: u64,
    ) -> Result<(String, StoredReceipt), RuntimeFailure> {
        let value = effect_value(profile, action);
        let payload = encode_receipt_payload(
            profile,
            authority,
            digest(action),
            digest(&value),
            completed_at,
        )?;
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

    fn verify_authority(&self, bytes: &[u8]) -> Result<Authority, RuntimeFailure> {
        let payload = self.verify_envelope(AUTHORITY_DOMAIN, bytes)?;
        decode_authority_payload(&payload)
    }

    fn sign(&self, domain: &[u8], payload: &[u8]) -> Result<Vec<u8>, RuntimeFailure> {
        let preimage = preimage(domain, payload);
        let signature = self.signing.sign(&preimage).to_bytes();
        encode_envelope(payload, &signature)
    }

    fn verify_envelope(&self, domain: &[u8], bytes: &[u8]) -> Result<Vec<u8>, RuntimeFailure> {
        let (payload, signature) = decode_envelope(bytes)?;
        self.verifying
            .verify(&preimage(domain, &payload), &signature)
            .map_err(|_| RuntimeFailure::Denied)?;
        Ok(payload)
    }

    fn require_profile(&self, profile: QualifiedProfile) -> Result<(), RuntimeFailure> {
        if self.profiles.contains(&profile) {
            Ok(())
        } else {
            Err(RuntimeFailure::ProfileDisabled)
        }
    }
}

impl NodeRuntime for SandboxRuntime {
    fn handle(&self, request: ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
        match request.verb() {
            ProductVerb::Create => self.create(&request),
            ProductVerb::Delegate => self.delegate(&request),
            ProductVerb::Execute => self.execute(&request),
            ProductVerb::Resume => self.resume(&request),
            ProductVerb::Verify => {
                let bytes = request.body().ok_or(RuntimeFailure::Malformed)?;
                let valid = self.verify_authority(bytes).is_ok()
                    || self.verify_envelope(RECEIPT_DOMAIN, bytes).is_ok();
                if !valid {
                    return ProductionResponse::new(
                        ClientOutcomeKind::Rejected,
                        Some("verification.rejected".into()),
                        RetryClass::Never,
                        None,
                        None,
                        None,
                    )
                    .map_err(|_| RuntimeFailure::Malformed);
                }
                ProductionResponse::new(
                    ClientOutcomeKind::Verified,
                    None,
                    RetryClass::Never,
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
                effect: "unknown".into(),
                retry: "resume".into(),
                updated_at: pending.created_at,
                receipt_id: None,
            });
        }
        let completed = self
            .store
            .recovered(reference.as_str())?
            .ok_or(RuntimeFailure::UnknownWorkflow)?;
        Ok(WorkflowProjection {
            reference: reference.as_str().to_owned(),
            profile: completed.profile.as_str().into(),
            state: "committed".into(),
            effect: "succeeded".into(),
            retry: "never".into(),
            updated_at: completed.completed_at,
            receipt_id: Some(hex::encode(digest(&completed.bytes))),
        })
    }

    fn receipt_summary(&self, receipt_id: &str) -> Result<ReceiptSummary, RuntimeFailure> {
        let receipt = self
            .store
            .receipt(receipt_id)?
            .ok_or(RuntimeFailure::UnknownReceipt)?;
        Ok(ReceiptSummary {
            receipt_id: receipt_id.into(),
            profile: receipt.profile.as_str().into(),
            outcome: "succeeded".into(),
            completed_at: receipt.completed_at,
            disclosure: "summary",
        })
    }

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
            .ok_or(RuntimeFailure::UnknownReceipt)
    }

    fn ready(&self) -> bool {
        self.store.ready()
    }
}

pub fn encode_sandbox_authority_request(
    expires_at: u64,
    remaining_depth: u16,
    max_uses: u32,
    actions: &[&[u8]],
) -> Result<Vec<u8>, RuntimeFailure> {
    if actions.is_empty() || actions.len() > MAX_ACTIONS || max_uses == 0 {
        return Err(RuntimeFailure::Malformed);
    }
    let mut action_digests = actions
        .iter()
        .map(|action| digest(action))
        .collect::<Vec<_>>();
    action_digests.sort_unstable();
    action_digests.dedup();
    if action_digests.len() != actions.len() {
        return Err(RuntimeFailure::Malformed);
    }
    encode_scope(&Scope {
        expires_at,
        remaining_depth,
        max_uses,
        action_digests,
    })
}

fn authority_response(value: Vec<u8>) -> Result<ProductionResponse, RuntimeFailure> {
    ProductionResponse::new(
        ClientOutcomeKind::Completed,
        None,
        RetryClass::Never,
        None,
        Some(value),
        Some(b"auths-sandbox-authority-v1".to_vec()),
    )
    .map_err(|_| RuntimeFailure::Malformed)
}

fn completed_response(
    receipt: Vec<u8>,
    value: Vec<u8>,
) -> Result<ProductionResponse, RuntimeFailure> {
    ProductionResponse::new(
        ClientOutcomeKind::Completed,
        None,
        RetryClass::Never,
        None,
        Some(value),
        Some(receipt),
    )
    .map_err(|_| RuntimeFailure::Malformed)
}

fn encode_scope(scope: &Scope) -> Result<Vec<u8>, RuntimeFailure> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.u64(scope.expires_at))
        .and_then(|encoder| encoder.u16(scope.remaining_depth))
        .and_then(|encoder| encoder.u32(scope.max_uses))
        .and_then(|encoder| {
            encoder.array(u64::try_from(scope.action_digests.len()).unwrap_or(u64::MAX))
        })
        .map_err(|_| RuntimeFailure::Malformed)?;
    for digest in &scope.action_digests {
        encoder
            .bytes(digest)
            .map_err(|_| RuntimeFailure::Malformed)?;
    }
    Ok(encoder.into_writer())
}

fn decode_scope(bytes: &[u8]) -> Result<Scope, RuntimeFailure> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().ok().flatten() != Some(5) || decoder.u16().ok() != Some(1) {
        return Err(RuntimeFailure::Malformed);
    }
    let expires_at = decoder.u64().map_err(|_| RuntimeFailure::Malformed)?;
    let remaining_depth = decoder.u16().map_err(|_| RuntimeFailure::Malformed)?;
    let max_uses = decoder.u32().map_err(|_| RuntimeFailure::Malformed)?;
    let count = decoder
        .array()
        .map_err(|_| RuntimeFailure::Malformed)?
        .ok_or(RuntimeFailure::Malformed)?;
    if count == 0 || count > u64::try_from(MAX_ACTIONS).unwrap_or(u64::MAX) || max_uses == 0 {
        return Err(RuntimeFailure::Malformed);
    }
    let mut action_digests =
        Vec::with_capacity(usize::try_from(count).map_err(|_| RuntimeFailure::Malformed)?);
    for _ in 0..count {
        let value: [u8; 32] = decoder
            .bytes()
            .map_err(|_| RuntimeFailure::Malformed)?
            .try_into()
            .map_err(|_| RuntimeFailure::Malformed)?;
        action_digests.push(value);
    }
    let value = Scope {
        expires_at,
        remaining_depth,
        max_uses,
        action_digests,
    };
    if decoder.position() != bytes.len()
        || value
            .action_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || encode_scope(&value)? != bytes
    {
        return Err(RuntimeFailure::Malformed);
    }
    Ok(value)
}

fn encode_authority_payload(authority: &Authority) -> Result<Vec<u8>, RuntimeFailure> {
    let scope = encode_scope(&authority.scope)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.str(authority.profile.as_str()))
        .and_then(|encoder| encoder.bytes(&authority.subject))
        .map_err(|_| RuntimeFailure::Malformed)?;
    match authority.parent {
        Some(parent) => encoder.bytes(&parent),
        None => encoder.null(),
    }
    .map_err(|_| RuntimeFailure::Malformed)?;
    encoder
        .bytes(&scope)
        .map_err(|_| RuntimeFailure::Malformed)?;
    encoder
        .str("sandbox-only")
        .map_err(|_| RuntimeFailure::Malformed)?;
    Ok(encoder.into_writer())
}

fn decode_authority_payload(bytes: &[u8]) -> Result<Authority, RuntimeFailure> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().ok().flatten() != Some(6) || decoder.u16().ok() != Some(1) {
        return Err(RuntimeFailure::Malformed);
    }
    let profile = QualifiedProfile::parse(decoder.str().map_err(|_| RuntimeFailure::Malformed)?)
        .map_err(|_| RuntimeFailure::Malformed)?;
    let subject = decoder
        .bytes()
        .map_err(|_| RuntimeFailure::Malformed)?
        .try_into()
        .map_err(|_| RuntimeFailure::Malformed)?;
    let parent = if decoder.datatype().map_err(|_| RuntimeFailure::Malformed)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| RuntimeFailure::Malformed)?;
        None
    } else {
        Some(
            decoder
                .bytes()
                .map_err(|_| RuntimeFailure::Malformed)?
                .try_into()
                .map_err(|_| RuntimeFailure::Malformed)?,
        )
    };
    let scope = decode_scope(decoder.bytes().map_err(|_| RuntimeFailure::Malformed)?)?;
    if decoder.str().map_err(|_| RuntimeFailure::Malformed)? != "sandbox-only" {
        return Err(RuntimeFailure::Malformed);
    }
    let value = Authority {
        profile,
        subject,
        parent,
        scope,
    };
    if decoder.position() != bytes.len() || encode_authority_payload(&value)? != bytes {
        return Err(RuntimeFailure::Malformed);
    }
    Ok(value)
}

fn encode_receipt_payload(
    profile: QualifiedProfile,
    authority: [u8; 32],
    action: [u8; 32],
    result: [u8; 32],
    completed_at: u64,
) -> Result<Vec<u8>, RuntimeFailure> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.str(profile.as_str()))
        .and_then(|encoder| encoder.bytes(&authority))
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

fn decode_envelope(bytes: &[u8]) -> Result<(Vec<u8>, Signature), RuntimeFailure> {
    let mut decoder = Decoder::new(bytes);
    if decoder.array().ok().flatten() != Some(3) || decoder.u16().ok() != Some(1) {
        return Err(RuntimeFailure::Malformed);
    }
    let payload = decoder
        .bytes()
        .map_err(|_| RuntimeFailure::Malformed)?
        .to_vec();
    let signature = Signature::from_slice(decoder.bytes().map_err(|_| RuntimeFailure::Malformed)?)
        .map_err(|_| RuntimeFailure::Malformed)?;
    if decoder.position() != bytes.len()
        || encode_envelope(&payload, &signature.to_bytes())? != bytes
    {
        return Err(RuntimeFailure::Malformed);
    }
    Ok((payload, signature))
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

fn recovery_reference(
    authority: [u8; 32],
    action: [u8; 32],
) -> Result<RecoveryReference, RuntimeFailure> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| RuntimeFailure::Unavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_DOMAIN);
    hasher.update(authority);
    hasher.update(action);
    hasher.update(nonce);
    RecoveryReference::parse(&Base64UrlUnpadded::encode_string(&hasher.finalize()))
        .map_err(|_| RuntimeFailure::Malformed)
}

fn effect_value(profile: QualifiedProfile, action: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-SANDBOX-EFFECT\x00\x01");
    hasher.update(profile.as_str().as_bytes());
    hasher.update(action);
    hasher.finalize().to_vec()
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_production_client::{ProductionRequest, encode_delegation_body};

    fn runtime() -> SandboxRuntime {
        SandboxRuntime::new(
            [7; 32],
            [QualifiedProfile::GitHubIssueAddress].into_iter().collect(),
        )
        .unwrap()
    }

    #[test]
    fn delegation_can_only_narrow_actions_depth_expiry_and_uses() {
        let runtime = runtime();
        let identity = b"human".to_vec();
        let action_a = b"edit issue";
        let action_b = b"delete repository";
        let parent_scope =
            encode_sandbox_authority_request(now() + 60, 2, 2, &[action_a, action_b]).unwrap();
        let parent = runtime
            .handle(
                ProductionRequest::new(
                    ProductVerb::Create,
                    QualifiedProfile::GitHubIssueAddress,
                    identity.clone(),
                    None,
                    Some(parent_scope),
                    None,
                )
                .unwrap(),
            )
            .unwrap()
            .value()
            .unwrap()
            .to_vec();
        let child_scope = encode_sandbox_authority_request(now() + 30, 1, 1, &[action_a]).unwrap();
        let child = runtime
            .handle(
                ProductionRequest::new(
                    ProductVerb::Delegate,
                    QualifiedProfile::GitHubIssueAddress,
                    identity,
                    Some(parent),
                    Some(encode_delegation_body(b"agent", &child_scope).unwrap()),
                    None,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(child.value().is_some());
    }

    #[test]
    fn exact_action_and_replay_budget_are_enforced() {
        let runtime = runtime();
        let action = b"edit issue";
        let authority = runtime
            .handle(
                ProductionRequest::new(
                    ProductVerb::Create,
                    QualifiedProfile::GitHubIssueAddress,
                    b"agent".to_vec(),
                    None,
                    Some(encode_sandbox_authority_request(now() + 60, 0, 1, &[action]).unwrap()),
                    None,
                )
                .unwrap(),
            )
            .unwrap()
            .value()
            .unwrap()
            .to_vec();
        let request = || {
            ProductionRequest::new(
                ProductVerb::Execute,
                QualifiedProfile::GitHubIssueAddress,
                b"agent".to_vec(),
                Some(authority.clone()),
                Some(action.to_vec()),
                None,
            )
            .unwrap()
        };
        assert_eq!(
            runtime.handle(request()).unwrap().kind(),
            ClientOutcomeKind::Completed
        );
        assert_eq!(runtime.handle(request()), Err(RuntimeFailure::Denied));
    }

    #[test]
    fn recovery_is_committed_once_and_replays_the_same_receipt() {
        let runtime = runtime();
        let action = b"AUTHS-SANDBOX-RECOVER edit issue";
        let authority = runtime
            .handle(
                ProductionRequest::new(
                    ProductVerb::Create,
                    QualifiedProfile::GitHubIssueAddress,
                    b"agent".to_vec(),
                    None,
                    Some(encode_sandbox_authority_request(now() + 60, 0, 1, &[action]).unwrap()),
                    None,
                )
                .unwrap(),
            )
            .unwrap()
            .value()
            .unwrap()
            .to_vec();
        let unknown = runtime
            .handle(
                ProductionRequest::new(
                    ProductVerb::Execute,
                    QualifiedProfile::GitHubIssueAddress,
                    b"agent".to_vec(),
                    Some(authority),
                    Some(action.to_vec()),
                    None,
                )
                .unwrap(),
            )
            .unwrap();
        let reference = unknown.recovery_reference().unwrap().clone();
        let resume = || {
            ProductionRequest::new(
                ProductVerb::Resume,
                QualifiedProfile::GitHubIssueAddress,
                b"agent".to_vec(),
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
        assert_eq!(status.effect, "succeeded");
        assert!(status.receipt_id.is_some());
    }
}
