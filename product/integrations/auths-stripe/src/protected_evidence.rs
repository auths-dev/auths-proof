//! Stable-read protected Stripe refund evidence snapshots.

#![forbid(unsafe_code)]
// Protected evidence codecs intentionally expose one fail-closed store error.
#![allow(clippy::missing_errors_doc)]

use crate::{
    DigestHex, PaymentIntentId, RefundEvidenceV1, StripeRefundEvidenceStoreV1,
    canonical::canonical_json,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::{
    io::{Read as _, Write as _},
    time::Duration,
};

/// Closed purpose for one signed provider reread. Preparation evidence cannot
/// be replayed as the mandatory pre-entry reread.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StripeRefundEvidencePhase {
    Preparation,
    PreEntry,
}

impl StripeRefundEvidencePhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparation => "preparation",
            Self::PreEntry => "pre-entry",
        }
    }
}

/// Canonical artifact written only by the separately credentialed Stripe
/// runtime-read process and consumed read-only by the production agent.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtectedRefundEvidenceSnapshotV1 {
    schema: String,
    store_identity_sha256: DigestHex,
    reader_key_id: String,
    workflow_id: String,
    phase: StripeRefundEvidencePhase,
    sealed_command_sha256: Option<DigestHex>,
    evidence: RefundEvidenceV1,
    signature_base64url: String,
}

/// Closed request sent by the production agent to the separately credentialed
/// runtime-read broker. It contains no credential or signing material.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StripeRefundEvidenceRequestV1 {
    schema: String,
    store_identity_sha256: DigestHex,
    workflow_id: String,
    phase: StripeRefundEvidencePhase,
    sealed_command_sha256: Option<DigestHex>,
    payment_intent_id: String,
    stripe_api_version: String,
    observed_after_unix_seconds: Option<u64>,
}

impl StripeRefundEvidenceRequestV1 {
    pub fn new(
        store: &StripeRefundEvidenceStoreV1,
        workflow_id: &str,
        phase: StripeRefundEvidencePhase,
        sealed_command_sha256: Option<DigestHex>,
        payment_intent_id: &PaymentIntentId,
        stripe_api_version: &str,
        observed_after_unix_seconds: Option<u64>,
    ) -> Result<Self, StripeEvidenceStoreError> {
        let value = Self {
            schema: "auths.stripe.refund-evidence-request/1".into(),
            store_identity_sha256: store.store_identity_sha256().clone(),
            workflow_id: workflow_id.into(),
            phase,
            sealed_command_sha256,
            payment_intent_id: payment_intent_id.as_str().into(),
            stripe_api_version: stripe_api_version.into(),
            observed_after_unix_seconds,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StripeEvidenceStoreError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?;
        value.validate()?;
        if canonical_json(&value).map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)? != bytes {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StripeEvidenceStoreError> {
        self.validate()?;
        canonical_json(self).map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)
    }

    fn validate(&self) -> Result<(), StripeEvidenceStoreError> {
        if self.schema != "auths.stripe.refund-evidence-request/1"
            || !valid_workflow_id(&self.workflow_id)
            || (self.phase == StripeRefundEvidencePhase::Preparation
                && self.sealed_command_sha256.is_some())
            || (self.phase == StripeRefundEvidencePhase::PreEntry
                && self.sealed_command_sha256.is_none())
            || PaymentIntentId::parse(self.payment_intent_id.clone()).is_err()
            || self.stripe_api_version.is_empty()
            || self.stripe_api_version.len() > 64
            || !self
                .stripe_api_version
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || self.observed_after_unix_seconds == Some(0)
        {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn store_identity_sha256(&self) -> &DigestHex {
        &self.store_identity_sha256
    }

    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    #[must_use]
    pub const fn phase(&self) -> StripeRefundEvidencePhase {
        self.phase
    }

    #[must_use]
    pub const fn sealed_command_sha256(&self) -> Option<&DigestHex> {
        self.sealed_command_sha256.as_ref()
    }

    pub fn payment_intent_id(&self) -> Result<PaymentIntentId, StripeEvidenceStoreError> {
        PaymentIntentId::parse(self.payment_intent_id.clone())
            .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)
    }

    #[must_use]
    pub fn stripe_api_version(&self) -> &str {
        &self.stripe_api_version
    }

    #[must_use]
    pub const fn observed_after_unix_seconds(&self) -> Option<u64> {
        self.observed_after_unix_seconds
    }
}

impl ProtectedRefundEvidenceSnapshotV1 {
    /// Constructs one already-normalized snapshot for the protected writer.
    pub fn sign(
        store: &StripeRefundEvidenceStoreV1,
        workflow_id: &str,
        phase: StripeRefundEvidencePhase,
        sealed_command_sha256: Option<DigestHex>,
        evidence: RefundEvidenceV1,
        signing_key: &SigningKey,
    ) -> Result<Self, StripeEvidenceStoreError> {
        if signing_key.verifying_key().to_bytes()
            != store
                .reader_public_key()
                .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?
        {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        let mut value = Self {
            schema: "auths.stripe.protected-refund-evidence-snapshot/1".into(),
            store_identity_sha256: store.store_identity_sha256().clone(),
            reader_key_id: store.reader_key_id().into(),
            workflow_id: workflow_id.into(),
            phase,
            sealed_command_sha256,
            evidence,
            signature_base64url: String::new(),
        };
        let signature = signing_key.sign(&value.signing_preimage()?);
        value.signature_base64url = Base64UrlUnpadded::encode_string(&signature.to_bytes());
        value.validate()?;
        Ok(value)
    }

    /// Decodes and proves canonical equality with retained bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StripeEvidenceStoreError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?;
        value.validate()?;
        if canonical_json(&value).map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)? != bytes {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        Ok(value)
    }

    /// Returns exact canonical bytes for an atomic protected write.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StripeEvidenceStoreError> {
        self.validate()?;
        canonical_json(self).map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)
    }

    fn validate(&self) -> Result<(), StripeEvidenceStoreError> {
        if self.schema != "auths.stripe.protected-refund-evidence-snapshot/1"
            || self.reader_key_id.is_empty()
            || self.reader_key_id.len() > 128
            || !valid_workflow_id(&self.workflow_id)
            || (self.phase == StripeRefundEvidencePhase::Preparation
                && self.sealed_command_sha256.is_some())
            || (self.phase == StripeRefundEvidencePhase::PreEntry
                && self.sealed_command_sha256.is_none())
            || self.signature_base64url.len() != 86
        {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        self.evidence
            .validate()
            .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)
    }

    fn signing_preimage(&self) -> Result<Vec<u8>, StripeEvidenceStoreError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SignedFacts<'a> {
            schema: &'a str,
            store_identity_sha256: &'a DigestHex,
            reader_key_id: &'a str,
            workflow_id: &'a str,
            phase: StripeRefundEvidencePhase,
            sealed_command_sha256: &'a Option<DigestHex>,
            evidence: &'a RefundEvidenceV1,
        }
        let facts = canonical_json(&SignedFacts {
            schema: &self.schema,
            store_identity_sha256: &self.store_identity_sha256,
            reader_key_id: &self.reader_key_id,
            workflow_id: &self.workflow_id,
            phase: self.phase,
            sealed_command_sha256: &self.sealed_command_sha256,
            evidence: &self.evidence,
        })
        .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?;
        let mut preimage = Vec::with_capacity(facts.len() + 48);
        preimage.extend_from_slice(b"AUTHS-STRIPE-RUNTIME-READ-EVIDENCE\x00\x01");
        preimage.extend_from_slice(&(facts.len() as u64).to_be_bytes());
        preimage.extend_from_slice(&facts);
        Ok(preimage)
    }

    fn verify_signature(
        &self,
        store: &StripeRefundEvidenceStoreV1,
    ) -> Result<(), StripeEvidenceStoreError> {
        if self.reader_key_id != store.reader_key_id() {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        let key = VerifyingKey::from_bytes(
            &store
                .reader_public_key()
                .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?,
        )
        .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?;
        let mut signature_bytes = [0_u8; 64];
        Base64UrlUnpadded::decode(&self.signature_base64url, &mut signature_bytes)
            .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?;
        key.verify(
            &self.signing_preimage()?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)
    }

    /// Re-verifies the retained signed envelope against its exact deployment,
    /// workflow, phase, command, and provider target bindings.
    pub fn verify_binding(
        &self,
        store: &StripeRefundEvidenceStoreV1,
        workflow_id: &str,
        phase: StripeRefundEvidencePhase,
        sealed_command_sha256: Option<&DigestHex>,
        payment_intent_id: &PaymentIntentId,
    ) -> Result<(), StripeEvidenceStoreError> {
        self.validate()?;
        self.verify_signature(store)?;
        if self.store_identity_sha256() != store.store_identity_sha256()
            || self.workflow_id() != workflow_id
            || self.phase() != phase
            || self.sealed_command_sha256() != sealed_command_sha256
            || self.evidence().payment_intent_id() != Some(payment_intent_id)
        {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    fn verify_freshness(
        &self,
        stripe_api_version: &str,
        now_unix_seconds: u64,
        observed_after_unix_seconds: Option<u64>,
        maximum_age_seconds: u64,
    ) -> Result<(), StripeEvidenceStoreError> {
        let evidence = self.evidence();
        if now_unix_seconds < evidence.observed_at()
            || now_unix_seconds.saturating_sub(evidence.observed_at()) > maximum_age_seconds
            || observed_after_unix_seconds.is_some_and(|minimum| evidence.observed_at() <= minimum)
            || evidence.stripe_api_version() != stripe_api_version
        {
            return Err(StripeEvidenceStoreError::InvalidSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub const fn store_identity_sha256(&self) -> &DigestHex {
        &self.store_identity_sha256
    }

    #[must_use]
    pub const fn evidence(&self) -> &RefundEvidenceV1 {
        &self.evidence
    }

    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    #[must_use]
    pub const fn phase(&self) -> StripeRefundEvidencePhase {
        self.phase
    }

    #[must_use]
    pub const fn sealed_command_sha256(&self) -> Option<&DigestHex> {
        self.sealed_command_sha256.as_ref()
    }

    /// Consumes the authenticated envelope and returns its validated evidence.
    #[must_use]
    pub fn into_evidence(self) -> RefundEvidenceV1 {
        self.evidence
    }
}

/// Requests one exact, fresh, signed snapshot from the separately credentialed
/// local broker. The caller proves its configured OS identity; the response is
/// independently authenticated by the configured reader public key.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn request_refund_evidence_snapshot(
    store: &StripeRefundEvidenceStoreV1,
    workflow_id: &str,
    phase: StripeRefundEvidencePhase,
    sealed_command_sha256: Option<&DigestHex>,
    payment_intent_id: &PaymentIntentId,
    stripe_api_version: &str,
    _now_unix_seconds: u64,
    observed_after_unix_seconds: Option<u64>,
) -> Result<ProtectedRefundEvidenceSnapshotV1, StripeEvidenceStoreError> {
    use std::net::Shutdown;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    use std::os::unix::net::UnixStream;

    if rustix::process::geteuid().as_raw() != store.agent_uid() {
        return Err(StripeEvidenceStoreError::UnsafeStorage);
    }
    let request = StripeRefundEvidenceRequestV1::new(
        store,
        workflow_id,
        phase,
        sealed_command_sha256.cloned(),
        payment_intent_id,
        stripe_api_version,
        observed_after_unix_seconds,
    )?;
    let request_bytes = request.canonical_bytes()?;
    let timeout = Duration::from_millis(u64::from(store.request_timeout_milliseconds()));
    let socket_metadata = std::fs::symlink_metadata(store.broker_socket_path())
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?;
    let parent = store
        .broker_socket_path()
        .parent()
        .ok_or(StripeEvidenceStoreError::UnsafeStorage)?;
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| StripeEvidenceStoreError::Unavailable)?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != store.broker_uid()
        || socket_metadata.mode() & 0o777 != 0o666
        || !parent_metadata.is_dir()
        || (parent_metadata.uid() != 0 && parent_metadata.uid() != store.broker_uid())
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(StripeEvidenceStoreError::UnsafeStorage);
    }
    let mut stream = UnixStream::connect(store.broker_socket_path())
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?;
    if rustix::net::sockopt::socket_peercred(&stream)
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?
        .uid
        .as_raw()
        != store.broker_uid()
    {
        return Err(StripeEvidenceStoreError::UnsafeStorage);
    }
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?;
    let request_length = u32::try_from(request_bytes.len())
        .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?;
    stream
        .write_all(&request_length.to_be_bytes())
        .and_then(|()| stream.write_all(&request_bytes))
        .and_then(|()| stream.flush())
        .and_then(|()| stream.shutdown(Shutdown::Write))
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?;
    let mut length_bytes = [0_u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > store.maximum_snapshot_bytes() {
        return Err(StripeEvidenceStoreError::InvalidSnapshot);
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?;
    let mut trailing = [0_u8; 1];
    if stream
        .read(&mut trailing)
        .map_err(|_| StripeEvidenceStoreError::Unavailable)?
        != 0
    {
        return Err(StripeEvidenceStoreError::InvalidSnapshot);
    }
    let snapshot = ProtectedRefundEvidenceSnapshotV1::from_canonical_bytes(&bytes)?;
    snapshot.verify_binding(
        store,
        workflow_id,
        phase,
        sealed_command_sha256,
        payment_intent_id,
    )?;
    let now_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StripeEvidenceStoreError::InvalidSnapshot)?
        .as_secs();
    snapshot.verify_freshness(
        stripe_api_version,
        now_unix_seconds,
        observed_after_unix_seconds,
        store.maximum_age_seconds(),
    )?;
    Ok(snapshot)
}

fn valid_workflow_id(value: &str) -> bool {
    value.len() == 67
        && value.starts_with("wf_")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn request_refund_evidence_snapshot(
    _store: &StripeRefundEvidenceStoreV1,
    _workflow_id: &str,
    _phase: StripeRefundEvidencePhase,
    _sealed_command_sha256: Option<&DigestHex>,
    _payment_intent_id: &PaymentIntentId,
    _stripe_api_version: &str,
    _now_unix_seconds: u64,
    _observed_after_unix_seconds: Option<u64>,
) -> Result<ProtectedRefundEvidenceSnapshotV1, StripeEvidenceStoreError> {
    Err(StripeEvidenceStoreError::UnsupportedPlatform)
}

/// Closed protected-evidence storage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StripeEvidenceStoreError {
    #[error("protected Stripe evidence is unavailable")]
    Unavailable,
    #[error("protected Stripe evidence storage is unsafe")]
    UnsafeStorage,
    #[error("protected Stripe evidence changed while being read")]
    UnstableSnapshot,
    #[error("protected Stripe evidence is invalid")]
    InvalidSnapshot,
    #[error("protected Stripe evidence is unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(all(test, unix, any()))]
mod obsolete_file_transport_tests {
    use super::*;
    use crate::{
        StripeRefundLocalAgentConfigurationV1,
        canonical::canonical_json,
        test_support::{NOW, evidence},
    };
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    const WORKFLOW_ID: &str = "wf_1111111111111111111111111111111111111111111111111111111111111111";

    fn configuration_and_key(
        evidence_root: &Path,
    ) -> (StripeRefundLocalAgentConfigurationV1, SigningKey) {
        let key = SigningKey::from_bytes(&[19; 32]);
        let evidence = evidence(10_000, 0);
        let exact = crate::test_support::configuration(2_000);
        let policy = crate::test_support::bounded_policy(
            &evidence,
            2_000,
            10_000,
            crate::RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let bounded = crate::test_support::bounded_configuration(&policy);
        let value = serde_json::json!({
            "schema": "auths.stripe.refund-verifier-configuration/1",
            "policy": policy,
            "requiredExactConfiguration": exact,
            "executedExactConfiguration": exact,
            "requiredBoundedConfiguration": bounded,
            "executedBoundedConfiguration": bounded,
            "evidenceStore": {
                "schema": "auths.stripe.refund-evidence-store/1",
                "rootPath": evidence_root,
                "storeIdentitySha256": sha256(b"protected test evidence store"),
                "readerKeyId": "stripe-runtime-reader-test-v1",
                "readerPublicKeyBase64url": Base64UrlUnpadded::encode_string(
                    &key.verifying_key().to_bytes(),
                ),
                "maximumSnapshotBytes": 65_536,
                "maximumAgeSeconds": 60
            }
        });
        let bytes = canonical_json(&value).unwrap();
        (
            StripeRefundLocalAgentConfigurationV1::from_canonical_bytes(&bytes).unwrap(),
            key,
        )
    }

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn publish_then_read_proves_exact_signed_snapshot() {
        let root = private_root();
        let mutable_root = private_root();
        let (configuration, key) = configuration_and_key(root.path());
        let evidence = evidence(10_000, 0);
        let payment_intent = evidence.payment_intent_id().unwrap().clone();
        let snapshot = ProtectedRefundEvidenceSnapshotV1::sign(
            configuration.evidence_store(),
            WORKFLOW_ID,
            StripeRefundEvidencePhase::Preparation,
            None,
            evidence.clone(),
            &key,
        )
        .unwrap();

        let path =
            publish_refund_evidence_snapshot(configuration.evidence_store(), &snapshot).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            read_refund_evidence_snapshot(
                configuration.evidence_store(),
                mutable_root.path(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::Preparation,
                None,
                &payment_intent,
                NOW,
                None,
            )
            .unwrap()
            .evidence(),
            &evidence,
        );
    }

    #[test]
    fn signature_mutation_and_stale_snapshot_fail_closed() {
        let root = private_root();
        let mutable_root = private_root();
        let (configuration, key) = configuration_and_key(root.path());
        let evidence = evidence(10_000, 0);
        let payment_intent = evidence.payment_intent_id().unwrap().clone();
        let snapshot = ProtectedRefundEvidenceSnapshotV1::sign(
            configuration.evidence_store(),
            WORKFLOW_ID,
            StripeRefundEvidencePhase::Preparation,
            None,
            evidence,
            &key,
        )
        .unwrap();
        let path =
            publish_refund_evidence_snapshot(configuration.evidence_store(), &snapshot).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["evidence"]["amountRefundedMinor"] = serde_json::json!(1);
        value["evidence"]["refundableAmountMinor"] = serde_json::json!(9_999);
        std::fs::write(&path, canonical_json(&value).unwrap()).unwrap();
        assert_eq!(
            read_refund_evidence_snapshot(
                configuration.evidence_store(),
                mutable_root.path(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::Preparation,
                None,
                &payment_intent,
                NOW,
                None,
            ),
            Err(StripeEvidenceStoreError::InvalidSnapshot),
        );

        publish_refund_evidence_snapshot(configuration.evidence_store(), &snapshot).unwrap();
        assert_eq!(
            read_refund_evidence_snapshot(
                configuration.evidence_store(),
                mutable_root.path(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::Preparation,
                None,
                &payment_intent,
                NOW + configuration.evidence_store().maximum_age_seconds() + 1,
                None,
            ),
            Err(StripeEvidenceStoreError::InvalidSnapshot),
        );
    }

    #[test]
    fn pre_entry_snapshot_must_be_command_bound_and_strictly_newer() {
        let root = private_root();
        let mutable_root = private_root();
        let (configuration, key) = configuration_and_key(root.path());
        let evidence = evidence(10_000, 0);
        let observed_at = evidence.observed_at();
        let payment_intent = evidence.payment_intent_id().unwrap().clone();
        let command_sha256 = sha256(b"durable sealed Stripe command");
        let snapshot = ProtectedRefundEvidenceSnapshotV1::sign(
            configuration.evidence_store(),
            WORKFLOW_ID,
            StripeRefundEvidencePhase::PreEntry,
            Some(command_sha256.clone()),
            evidence,
            &key,
        )
        .unwrap();
        publish_refund_evidence_snapshot(configuration.evidence_store(), &snapshot).unwrap();

        assert_eq!(
            read_refund_evidence_snapshot(
                configuration.evidence_store(),
                mutable_root.path(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::PreEntry,
                Some(&command_sha256),
                &payment_intent,
                NOW,
                Some(observed_at),
            ),
            Err(StripeEvidenceStoreError::InvalidSnapshot),
        );
    }

    #[test]
    fn snapshot_reader_rejects_symlink_destination() {
        let root = private_root();
        let mutable_root = private_root();
        let (configuration, _) = configuration_and_key(root.path());
        let evidence = evidence(10_000, 0);
        let payment_intent = evidence.payment_intent_id().unwrap();
        let directory = root.path().join(EVIDENCE_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.path().join("outside.json");
        std::fs::write(&target, b"{}").unwrap();
        let destination = directory.join(
            snapshot_relative_path(
                payment_intent,
                WORKFLOW_ID,
                StripeRefundEvidencePhase::Preparation,
                None,
            )
            .file_name()
            .unwrap(),
        );
        symlink(target, destination).unwrap();
        assert_eq!(
            read_refund_evidence_snapshot(
                configuration.evidence_store(),
                mutable_root.path(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::Preparation,
                None,
                payment_intent,
                NOW,
                None,
            ),
            Err(StripeEvidenceStoreError::Unavailable),
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        StripeRefundLocalAgentConfigurationV1,
        canonical::{canonical_json, sha256},
        test_support::{NOW, evidence},
    };
    use std::path::Path;

    const WORKFLOW_ID: &str = "wf_1111111111111111111111111111111111111111111111111111111111111111";

    fn configuration_and_key(
        socket_path: &Path,
    ) -> (StripeRefundLocalAgentConfigurationV1, SigningKey) {
        let key = SigningKey::from_bytes(&[19; 32]);
        let normalized_evidence = evidence(10_000, 0);
        let exact = crate::test_support::configuration(2_000);
        let policy = crate::test_support::bounded_policy(
            &normalized_evidence,
            2_000,
            10_000,
            crate::RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let bounded = crate::test_support::bounded_configuration(&policy);
        let value = serde_json::json!({
            "schema": "auths.stripe.refund-verifier-configuration/1",
            "policy": policy,
            "requiredExactConfiguration": exact,
            "executedExactConfiguration": exact,
            "requiredBoundedConfiguration": bounded,
            "executedBoundedConfiguration": bounded,
            "evidenceStore": {
                "schema": "auths.stripe.refund-evidence-store/1",
                "brokerSocketPath": socket_path,
                "brokerUid": 1001,
                "agentUid": 1002,
                "storeIdentitySha256": sha256(b"protected test evidence store"),
                "readerKeyId": "stripe-runtime-reader-test-v1",
                "readerPublicKeyBase64url": Base64UrlUnpadded::encode_string(
                    &key.verifying_key().to_bytes(),
                ),
                "maximumSnapshotBytes": 65_536,
                "maximumAgeSeconds": 60,
                "requestTimeoutMilliseconds": 1_000
            }
        });
        let bytes = canonical_json(&value).unwrap();
        (
            StripeRefundLocalAgentConfigurationV1::from_canonical_bytes(&bytes).unwrap(),
            key,
        )
    }

    fn configuration() -> (StripeRefundLocalAgentConfigurationV1, SigningKey) {
        configuration_and_key(Path::new("/run/auths/stripe-refund-evidence-test.sock"))
    }

    #[test]
    fn request_is_canonical_and_phase_bound() {
        let (configuration, _) = configuration();
        let normalized_evidence = evidence(10_000, 0);
        let payment_intent = normalized_evidence.payment_intent_id().unwrap().clone();
        let preparation = StripeRefundEvidenceRequestV1::new(
            configuration.evidence_store(),
            WORKFLOW_ID,
            StripeRefundEvidencePhase::Preparation,
            None,
            &payment_intent,
            normalized_evidence.stripe_api_version(),
            None,
        )
        .unwrap();
        let bytes = preparation.canonical_bytes().unwrap();
        assert_eq!(
            StripeRefundEvidenceRequestV1::from_canonical_bytes(&bytes).unwrap(),
            preparation
        );
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert_eq!(
            StripeRefundEvidenceRequestV1::from_canonical_bytes(&noncanonical),
            Err(StripeEvidenceStoreError::InvalidSnapshot)
        );
        assert!(
            StripeRefundEvidenceRequestV1::new(
                configuration.evidence_store(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::PreEntry,
                None,
                &payment_intent,
                normalized_evidence.stripe_api_version(),
                Some(NOW - 10),
            )
            .is_err()
        );
    }

    #[test]
    fn exact_signed_snapshot_and_mutations_fail_closed() {
        let (configuration, key) = configuration();
        let normalized_evidence = evidence(10_000, 0);
        let payment_intent = normalized_evidence.payment_intent_id().unwrap().clone();
        let snapshot = ProtectedRefundEvidenceSnapshotV1::sign(
            configuration.evidence_store(),
            WORKFLOW_ID,
            StripeRefundEvidencePhase::Preparation,
            None,
            normalized_evidence,
            &key,
        )
        .unwrap();
        let bytes = snapshot.canonical_bytes().unwrap();
        let decoded = ProtectedRefundEvidenceSnapshotV1::from_canonical_bytes(&bytes).unwrap();
        decoded
            .verify_binding(
                configuration.evidence_store(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::Preparation,
                None,
                &payment_intent,
            )
            .unwrap();
        assert_eq!(
            decoded.verify_binding(
                configuration.evidence_store(),
                "wf_2222222222222222222222222222222222222222222222222222222222222222",
                StripeRefundEvidencePhase::Preparation,
                None,
                &payment_intent,
            ),
            Err(StripeEvidenceStoreError::InvalidSnapshot)
        );

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["evidence"]["amount_refunded_minor"] = serde_json::json!(1);
        value["evidence"]["refundable_amount_minor"] = serde_json::json!(9_999);
        let changed = ProtectedRefundEvidenceSnapshotV1::from_canonical_bytes(
            &canonical_json(&value).unwrap(),
        )
        .unwrap();
        assert_eq!(
            changed.verify_binding(
                configuration.evidence_store(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::Preparation,
                None,
                &payment_intent,
            ),
            Err(StripeEvidenceStoreError::InvalidSnapshot),
        );
    }

    #[test]
    fn pre_entry_snapshot_is_command_bound_and_strictly_newer() {
        let (configuration, key) = configuration();
        let normalized_evidence = evidence(10_000, 0);
        let observed_at = normalized_evidence.observed_at();
        let payment_intent = normalized_evidence.payment_intent_id().unwrap().clone();
        let command_sha256 = sha256(b"durable sealed Stripe command");
        let snapshot = ProtectedRefundEvidenceSnapshotV1::sign(
            configuration.evidence_store(),
            WORKFLOW_ID,
            StripeRefundEvidencePhase::PreEntry,
            Some(command_sha256.clone()),
            normalized_evidence,
            &key,
        )
        .unwrap();
        snapshot
            .verify_binding(
                configuration.evidence_store(),
                WORKFLOW_ID,
                StripeRefundEvidencePhase::PreEntry,
                Some(&command_sha256),
                &payment_intent,
            )
            .unwrap();
        assert_eq!(
            snapshot.verify_freshness(
                "2025-04-30.basil",
                NOW,
                Some(observed_at),
                configuration.evidence_store().maximum_age_seconds(),
            ),
            Err(StripeEvidenceStoreError::InvalidSnapshot),
        );
        snapshot
            .verify_freshness(
                "2025-04-30.basil",
                NOW,
                Some(observed_at - 1),
                configuration.evidence_store().maximum_age_seconds(),
            )
            .unwrap();
        assert_eq!(
            snapshot.verify_freshness(
                "2025-04-30.basil",
                NOW + configuration.evidence_store().maximum_age_seconds() + 1,
                None,
                configuration.evidence_store().maximum_age_seconds(),
            ),
            Err(StripeEvidenceStoreError::InvalidSnapshot),
        );
    }
}
