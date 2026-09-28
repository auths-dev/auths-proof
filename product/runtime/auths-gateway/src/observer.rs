//! Gateway observer: the signing identity that turns what the gateway itself
//! saw into observations a grant's observation requirements can consume.
//!
//! The development observer is a self-certifying `raw-key-v1` Ed25519
//! principal. Its 32-byte seed is created by the operator in the gateway's
//! private state directory (mode 0600, never overwritten), loaded only by the
//! gateway process, and zeroized when dropped. A production observer is held
//! behind `auths-custody` (KMS or PKCS#11): the gateway never holds its
//! private key, and every observation goes through the transaction-bound
//! custody request and local verification. Either way the application never
//! reaches the key: the application socket can only ask the gateway to
//! observe and sign.
//!
//! An observer can make facts count; it cannot authorize anything. A trusted
//! context lists it as an observer anchor, and the verifier refuses a proof in
//! which the observer principal is also the root, an issuer, a subject, or the
//! actor. What an observation claims is only that the gateway saw those facts
//! at `observed_at`; observer trust is operator trust.
//!
//! Two schemas are signed:
//!
//! - `auths.gateway-readback/1`, subject the closed observation URL with the
//!   observed JSON pointer as fragment, facts `value` and, when the recipe
//!   declares an echo field and the record carries one, `echo`;
//! - `auths.gateway-outcome/2`, subject
//!   `auths-gateway://<namespace>/operations/<operation-id>`, whose facts
//!   are the stored attempt's commitment, stage (a stored `attempting` is
//!   reported as `unknown`), evaluation time, and recipe digest, and, as the
//!   record holds them, its counter-set digest, refusal, response status and
//!   digest, read-back comparison, evidence digest, pre-entry digest, and
//!   relative-ceiling basis with its response digest. Which facts accompany
//!   which stage is the kernel's presence rule
//!   ([`auths_gateway_kernel::outcome::outcome_facts_present`]); the gateway
//!   refuses to sign, and an auditor refuses to accept, any other set.

use crate::{
    GatewayAttemptSnapshot, GatewayAttemptStage, GatewayObservationFact, GatewayPreEntry,
    LogicalOperationId, OperatorNamespace,
};
use auths_codec::{encode_signed_observation, evidence_id, observation_signing_preimage};
use auths_custody::{CustodyError, CustodyKey, CustodyKind};
use auths_gateway_kernel::outcome::{OutcomeFacts, outcome_facts_present};
use auths_gateway_kernel::transition::Stage;
use auths_model::{
    EvidenceId, EvidenceObject, EvidenceTypeId, FactBytes, FactName, FactText, FactValue,
    MediaType, ObservationFact, ObservationFacts, ObservationSchemaId, ObservationStatement,
    PrincipalId, PrincipalMethodId, ResourceId, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignatureSuiteId, SignedObservation, Timestamp, VerificationMethod,
};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, io::Write as _, path::Path};
use thiserror::Error;
use zeroize::Zeroizing;

/// Schema of an observation of a provider record the gateway read.
pub const READ_BACK_SCHEMA: &str = "auths.gateway-readback/1";
/// Schema of an observation of the gateway's own stored attempt record.
pub const OUTCOME_SCHEMA: &str = "auths.gateway-outcome/2";
/// Domain of the counter-set digest an outcome carries.
const COUNTER_SET_DOMAIN: &[u8] = b"auths.gateway-counter-set/1\0";
/// Largest integer a JSON reader represents exactly.
const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;
/// Largest refusal code an outcome carries, in bytes.
const MAX_REFUSAL_BYTES: usize = 128;
/// Scheme of logical-operation subjects.
pub const OPERATION_SUBJECT_SCHEME: &str = "auths-gateway";
/// Media type an agent gives the attachment descriptor of a signed observation.
pub const OBSERVATION_MEDIA_TYPE: &str = auths_model::OBSERVATION_MEDIA_TYPE;

/// Why an observer key could not be provisioned or an observation signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayObserverError {
    /// A seed already exists; it is never overwritten.
    #[error("an observer key already exists")]
    Exists,
    /// The seed file is missing or unreadable.
    #[error("the observer key is unavailable")]
    Unreadable,
    /// The seed file is accessible to group or other users.
    #[error("the observer key must be readable only by its owner")]
    Permissions,
    /// The seed file does not hold exactly one 32-byte seed.
    #[error("the observer key is malformed")]
    Malformed,
    /// Randomness or file creation failed.
    #[error("the observer key could not be created")]
    Create,
    /// The observer principal could not be derived.
    #[error("the observer identity could not be derived")]
    Identity,
    /// The subject or facts exceed the observation model's bounds.
    #[error("the observation is not representable")]
    Unrepresentable,
    /// The custody boundary refused to sign, or its response did not bind to
    /// the exact observation.
    #[error("custody refused the observation: {0}")]
    Custody(CustodyError),
}

impl GatewayObserverError {
    /// Returns a stable non-secret diagnostic code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Exists => "gateway.observer.key-exists",
            Self::Unreadable => "gateway.observer.key-unavailable",
            Self::Permissions => "gateway.observer.key-permissions",
            Self::Malformed => "gateway.observer.key-malformed",
            Self::Create => "gateway.observer.key-create-failed",
            Self::Identity => "gateway.observer.identity",
            Self::Unrepresentable => "gateway.observer.unrepresentable",
            Self::Custody(error) => error.stable_code(),
        }
    }
}

/// Where the observer's private key is held.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverCustody {
    /// A seed file in the gateway's private state; development only.
    Software,
    /// An external custody provider; the gateway never holds the key.
    External(CustodyKind),
}

impl ObserverCustody {
    /// Returns the stable custody label the observer reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::External(kind) => kind.label(),
        }
    }
}

enum ObserverKey {
    Software(Box<SigningKey>),
    Custody(Box<CustodyKey>),
}

/// The gateway's observer signing key and its public identity.
pub struct GatewayObserver {
    key: ObserverKey,
    principal: PrincipalId,
    descriptor: SignatureDescriptor,
    control: EvidenceObject,
}

impl std::fmt::Debug for GatewayObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayObserver")
            .field("principal", &self.principal)
            .finish_non_exhaustive()
    }
}

impl GatewayObserver {
    /// Generates a new seed and writes it to `path` with mode 0600.
    ///
    /// # Errors
    /// Returns [`GatewayObserverError::Exists`] rather than overwrite a key,
    /// and [`GatewayObserverError::Create`] when randomness or the file fails.
    pub fn generate(path: &Path) -> Result<Self, GatewayObserverError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| GatewayObserverError::Create)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                GatewayObserverError::Exists
            } else {
                GatewayObserverError::Create
            }
        })?;
        file.write_all(seed.as_ref())
            .and_then(|()| file.sync_all())
            .map_err(|_| GatewayObserverError::Create)?;
        Self::from_seed(&seed)
    }

    /// Loads the seed stored at `path`.
    ///
    /// # Errors
    /// Refuses a file group or other can access, and any file that does not
    /// hold exactly 32 bytes.
    pub fn load(path: &Path) -> Result<Self, GatewayObserverError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| GatewayObserverError::Unreadable)?;
        if !metadata.file_type().is_file() {
            return Err(GatewayObserverError::Unreadable);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(GatewayObserverError::Permissions);
            }
        }
        if metadata.len() != 32 {
            return Err(GatewayObserverError::Malformed);
        }
        let bytes = Zeroizing::new(fs::read(path).map_err(|_| GatewayObserverError::Unreadable)?);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| GatewayObserverError::Malformed)?,
        );
        Self::from_seed(&seed)
    }

    fn from_seed(seed: &[u8; 32]) -> Result<Self, GatewayObserverError> {
        let key = SigningKey::from_bytes(seed);
        let raw =
            RawKeyDescriptor::new(RawKeyType::Ed25519, key.verifying_key().to_bytes().to_vec())
                .map_err(|_| GatewayObserverError::Identity)?;
        let principal = raw
            .principal()
            .map_err(|_| GatewayObserverError::Identity)?;
        let descriptor = SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).map_err(|_| GatewayObserverError::Identity)?,
            VerificationMethod::parse(principal.as_str())
                .map_err(|_| GatewayObserverError::Identity)?,
            SignatureSuiteId::parse(auths_signature::ED25519_V1)
                .map_err(|_| GatewayObserverError::Identity)?,
        );
        let evidence_type =
            EvidenceTypeId::parse(RAW_KEY_V1).map_err(|_| GatewayObserverError::Identity)?;
        let media_type =
            MediaType::parse(RAW_KEY_MEDIA_TYPE).map_err(|_| GatewayObserverError::Identity)?;
        let unaddressed = EvidenceObject::new(
            EvidenceId::new([0; 32]),
            evidence_type.clone(),
            media_type.clone(),
            raw.encode(),
        )
        .map_err(|_| GatewayObserverError::Identity)?;
        let control = EvidenceObject::new(
            evidence_id(&unaddressed).map_err(|_| GatewayObserverError::Identity)?,
            evidence_type,
            media_type,
            raw.encode(),
        )
        .map_err(|_| GatewayObserverError::Identity)?;
        Ok(Self {
            key: ObserverKey::Software(Box::new(key)),
            principal,
            descriptor,
            control,
        })
    }

    /// Uses a custody-held key. The gateway process never holds its private
    /// key; each observation is a transaction-bound custody request whose
    /// signature is verified locally before it is returned.
    ///
    /// # Errors
    /// Returns [`GatewayObserverError::Identity`] unless the key presents a
    /// `raw-key-v1` principal, the only method gateway observer anchors
    /// accept.
    pub fn from_custody(key: CustodyKey) -> Result<Self, GatewayObserverError> {
        let identity = key.identity();
        if identity.signature().principal_method().as_str() != RAW_KEY_V1 {
            return Err(GatewayObserverError::Identity);
        }
        Ok(Self {
            principal: identity.principal().clone(),
            descriptor: identity.signature().clone(),
            control: identity.control_evidence().clone(),
            key: ObserverKey::Custody(Box::new(key)),
        })
    }

    /// Returns where the observer key is held.
    #[must_use]
    pub fn custody(&self) -> ObserverCustody {
        match &self.key {
            ObserverKey::Software(_) => ObserverCustody::Software,
            ObserverKey::Custody(key) => ObserverCustody::External(key.kind()),
        }
    }

    /// Builds an observer from a fixed seed so tests reproduce exactly.
    #[cfg(any(test, feature = "testkit-harness", feature = "fuzzing"))]
    // INVARIANT: every 32-byte seed is an Ed25519 key with a raw-key
    // principal, so derivation from a fixed seed cannot fail.
    #[allow(clippy::expect_used)]
    pub(crate) fn from_test_seed(seed: u8) -> Self {
        Self::from_seed(&[seed; 32]).expect("a fixed seed yields an observer")
    }

    /// The principal of the observer [`Self::from_test_seed`] builds.
    #[cfg(feature = "fuzzing")]
    pub(crate) fn test_principal(seed: u8) -> PrincipalId {
        Self::from_test_seed(seed).principal
    }

    /// Returns the observer principal an operator puts in an observer anchor.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the public facts an operator needs to write the observer
    /// anchor of a trusted context. The anchor's identifier and validity are
    /// the operator's choice.
    #[must_use]
    pub fn anchor_template(
        &self,
        origin: &str,
        namespace: &OperatorNamespace,
    ) -> ObserverAnchorTemplate {
        ObserverAnchorTemplate {
            principal: self.principal.as_str().to_owned(),
            principal_method: self.descriptor.principal_method().as_str().to_owned(),
            verification_method: self.descriptor.verification_method().as_str().to_owned(),
            signature_suite: self.descriptor.suite().as_str().to_owned(),
            schemas: vec![READ_BACK_SCHEMA.to_owned(), OUTCOME_SCHEMA.to_owned()],
            subject_namespaces: vec![
                format!("{}/", origin.trim_end_matches('/')),
                format!(
                    "{OPERATION_SUBJECT_SCHEME}://{}/operations/",
                    namespace.as_str()
                ),
            ],
        }
    }

    /// Signs one observation of `subject` at `observed_at` and returns its
    /// canonical bytes, ready to attach to an action.
    ///
    /// # Errors
    /// Returns [`GatewayObserverError::Unrepresentable`] for an invalid
    /// subject, schema, or fact set.
    pub(crate) fn sign(
        &self,
        schema: &str,
        subject: &str,
        observed_at: u64,
        facts: Vec<ObservationFact>,
    ) -> Result<GatewaySignedObservation, GatewayObserverError> {
        let statement = ObservationStatement::new(
            self.principal.clone(),
            ObservationSchemaId::parse(schema)
                .map_err(|_| GatewayObserverError::Unrepresentable)?,
            ResourceId::parse(subject).map_err(|_| GatewayObserverError::Unrepresentable)?,
            Timestamp::new(observed_at),
            ObservationFacts::new(facts).map_err(|_| GatewayObserverError::Unrepresentable)?,
        );
        let signed = match &self.key {
            ObserverKey::Software(key) => {
                let preimage = observation_signing_preimage(&statement, &self.descriptor)
                    .map_err(|_| GatewayObserverError::Unrepresentable)?;
                let signature = SignatureBytes::new(key.sign(&preimage).to_bytes().to_vec())
                    .map_err(|_| GatewayObserverError::Unrepresentable)?;
                SignedObservation::new(
                    statement,
                    SignatureEnvelope::new(self.descriptor.clone(), signature),
                    vec![self.control.clone()],
                )
                .map_err(|_| GatewayObserverError::Unrepresentable)?
            }
            ObserverKey::Custody(key) => {
                let request = auths_author::prepare_observation(statement, self.descriptor.clone())
                    .map_err(|_| GatewayObserverError::Unrepresentable)?;
                key.sign_observation(request)
                    .map_err(GatewayObserverError::Custody)?
            }
        };
        let bytes = encode_signed_observation(&signed)
            .map_err(|_| GatewayObserverError::Unrepresentable)?;
        if bytes.len() > auths_model::MAX_OBSERVATION_BYTES {
            return Err(GatewayObserverError::Unrepresentable);
        }
        Ok(GatewaySignedObservation {
            schema: schema.to_owned(),
            subject: subject.to_owned(),
            observed_at,
            bytes,
        })
    }
}

/// Public observer facts an operator copies into an observer anchor.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverAnchorTemplate {
    /// Observer principal.
    pub principal: String,
    /// Principal method the anchor must accept.
    pub principal_method: String,
    /// Verification method of the observer's signatures.
    pub verification_method: String,
    /// Signature suite of the observer's signatures.
    pub signature_suite: String,
    /// Schemas this gateway signs.
    pub schemas: Vec<String>,
    /// Subject namespaces covering this gateway's read-back and outcome subjects.
    pub subject_namespaces: Vec<String>,
}

/// One canonical signed observation and its secret-free summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySignedObservation {
    schema: String,
    subject: String,
    observed_at: u64,
    bytes: Vec<u8>,
}

impl GatewaySignedObservation {
    /// Returns the observation schema.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }
    /// Returns the observed subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Returns the gateway clock time the observation asserts.
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }
    /// Returns the canonical signed observation bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Returns the canonical subject naming one logical operation.
#[must_use]
pub fn operation_subject(
    namespace: &OperatorNamespace,
    operation_id: &LogicalOperationId,
) -> String {
    format!(
        "{OPERATION_SUBJECT_SCHEME}://{}/operations/{}",
        namespace.as_str(),
        operation_id.as_str()
    )
}

fn fact(name: &str, value: FactValue) -> Result<ObservationFact, GatewayObserverError> {
    Ok(ObservationFact::new(
        FactName::parse(name).map_err(|_| GatewayObserverError::Unrepresentable)?,
        value,
    ))
}

fn text(value: &str) -> Result<FactValue, GatewayObserverError> {
    FactText::new(value)
        .map(FactValue::Text)
        .map_err(|_| GatewayObserverError::Unrepresentable)
}

/// Maps a JSON value to a fact value with the same rules as the
/// `mcp-arguments-v1` action facts, so an observed field and the verified
/// argument it is compared with have the same typed form.
fn json_fact(value: &Value) -> Option<FactValue> {
    match value {
        Value::String(value) => FactText::new(value).ok().map(FactValue::Text),
        Value::Number(number) => number.as_u64().map(FactValue::Uint),
        _ => None,
    }
}

/// Facts of a read-back observation. The observed value must have a fact
/// form; an echo value without one is omitted rather than coerced.
///
/// # Errors
/// Returns [`GatewayObserverError::Unrepresentable`] when the observed value
/// is not a bounded string or unsigned integer.
pub(crate) fn read_back_facts(
    value: &Value,
    echo: Option<&Value>,
) -> Result<Vec<ObservationFact>, GatewayObserverError> {
    let mut facts = vec![fact(
        "value",
        json_fact(value).ok_or(GatewayObserverError::Unrepresentable)?,
    )?];
    if let Some(echo) = echo.and_then(json_fact) {
        facts.push(fact("echo", echo)?);
    }
    Ok(facts)
}

/// The counter-set digest: SHA-256 of `auths.gateway-counter-set/1`, NUL,
/// and the sorted keys of every count and sum counter a claim reserved.
/// `None` when nothing was reserved. The two kinds hash under distinct
/// domains, so their keys never collide.
#[must_use]
pub(crate) fn counter_set_digest(keys: impl IntoIterator<Item = [u8; 32]>) -> Option<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = keys.into_iter().collect();
    if keys.is_empty() {
        return None;
    }
    keys.sort_unstable();
    let mut hash = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hash, COUNTER_SET_DOMAIN);
    for key in &keys {
        sha2::Digest::update(&mut hash, key);
    }
    Some(sha2::Digest::finalize(hash).into())
}

fn bytes_fact(value: &[u8; 32]) -> Result<FactValue, GatewayObserverError> {
    FactBytes::new(value.to_vec())
        .map(FactValue::Bytes)
        .map_err(|_| GatewayObserverError::Unrepresentable)
}

/// The stage an outcome names for a stored stage: a stored `attempting`
/// record is reported as `unknown`, because transport may have been entered.
const fn outcome_stage(stage: GatewayAttemptStage) -> GatewayAttemptStage {
    match stage {
        GatewayAttemptStage::Attempting => GatewayAttemptStage::Unknown,
        other => other,
    }
}

const fn kernel_stage(stage: GatewayAttemptStage) -> Stage {
    match stage {
        GatewayAttemptStage::NotEntered => Stage::NotEntered,
        GatewayAttemptStage::Attempting => Stage::Attempting,
        GatewayAttemptStage::ResponseRecorded => Stage::ResponseRecorded,
        GatewayAttemptStage::Unknown => Stage::Unknown,
        GatewayAttemptStage::Observed => Stage::Observed,
        GatewayAttemptStage::ObservedByProvider => Stage::ObservedByProvider,
    }
}

fn stage_name(stage: GatewayAttemptStage) -> &'static str {
    match stage {
        GatewayAttemptStage::NotEntered => "not-entered",
        GatewayAttemptStage::Attempting => "attempting",
        GatewayAttemptStage::ResponseRecorded => "response-recorded",
        GatewayAttemptStage::Unknown => "unknown",
        GatewayAttemptStage::Observed => "observed",
        GatewayAttemptStage::ObservedByProvider => "observed-by-provider",
    }
}

fn parse_stage(name: &str) -> Option<GatewayAttemptStage> {
    Some(match name {
        "not-entered" => GatewayAttemptStage::NotEntered,
        "unknown" => GatewayAttemptStage::Unknown,
        "response-recorded" => GatewayAttemptStage::ResponseRecorded,
        "observed" => GatewayAttemptStage::Observed,
        "observed-by-provider" => GatewayAttemptStage::ObservedByProvider,
        _ => return None,
    })
}

/// Everything a signed outcome states about one stored attempt, in typed
/// form. Building it from a record and reading it back from verified bytes
/// meet in the same value, so signing and verification cannot drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutcomeRecord {
    /// Lowercase hex of the stored action commitment.
    pub(crate) commitment: String,
    /// The stage the outcome names; never `attempting`.
    pub(crate) stage: GatewayAttemptStage,
    /// The gateway clock when native verification ran.
    pub(crate) evaluated_at: u64,
    /// Lowercase hex of the installed recipe digest.
    pub(crate) recipe_digest: String,
    /// The counter-set digest, when a slot was reserved.
    pub(crate) counters_digest: Option<[u8; 32]>,
    /// The stable refusal code, exactly when `not-entered`.
    pub(crate) refusal: Option<String>,
    /// The response status, when a complete response was recorded.
    pub(crate) http_status: Option<u16>,
    /// SHA-256 of that response.
    pub(crate) response_digest: Option<[u8; 32]>,
    /// `match`, `mismatch`, or `echo-mismatch`, exactly when `observed`.
    pub(crate) observation: Option<&'static str>,
    /// SHA-256 of the provider evidence, exactly when
    /// `observed-by-provider`.
    pub(crate) evidence_digest: Option<[u8; 32]>,
    /// The pre-entry digest, when pre-entry observations were recorded.
    pub(crate) pre_entry_digest: Option<[u8; 32]>,
    /// The relative-ceiling basis, when one was recorded.
    pub(crate) relative_basis: Option<u64>,
    /// SHA-256 of the basis response, with the basis.
    pub(crate) relative_basis_digest: Option<[u8; 32]>,
}

impl OutcomeRecord {
    /// The outcome a stored attempt signs.
    pub(crate) fn from_snapshot(snapshot: &GatewayAttemptSnapshot) -> Self {
        let stage = outcome_stage(snapshot.stage());
        let observation = (stage == GatewayAttemptStage::Observed).then(|| {
            match (snapshot.observation_match(), snapshot.observation_fact()) {
                (_, Some(GatewayObservationFact::EchoMismatch)) => "echo-mismatch",
                (Some(true), None) => "match",
                (Some(false) | None, None) => "mismatch",
            }
        });
        let pre_entry = snapshot.pre_entry();
        let basis = pre_entry.and_then(|record| record.basis);
        Self {
            commitment: hex::encode(snapshot.action_commitment()),
            stage,
            evaluated_at: snapshot.evaluated_at(),
            recipe_digest: hex::encode(snapshot.recipe_digest()),
            counters_digest: counter_set_digest(
                snapshot.counters().iter().map(|entry| entry.counter),
            ),
            refusal: snapshot.refusal().map(str::to_owned),
            http_status: snapshot.response_status(),
            response_digest: snapshot.response_digest().copied(),
            observation,
            evidence_digest: snapshot
                .provider_evidence()
                .map(|evidence| *evidence.evidence_digest()),
            pre_entry_digest: pre_entry.and_then(GatewayPreEntry::digest),
            relative_basis: basis.map(|basis| basis.value),
            relative_basis_digest: basis.map(|basis| basis.response_digest),
        }
    }

    /// Whether this fact set is one an outcome of its stage may carry, and
    /// every value is inside its bound.
    pub(crate) fn well_formed(&self) -> bool {
        let present = OutcomeFacts {
            counters_digest: self.counters_digest.is_some(),
            refusal: self.refusal.is_some(),
            http_status: self.http_status.is_some(),
            response_digest: self.response_digest.is_some(),
            observation: self.observation.is_some(),
            evidence_digest: self.evidence_digest.is_some(),
            pre_entry_digest: self.pre_entry_digest.is_some(),
            relative_basis: self.relative_basis.is_some(),
            relative_basis_digest: self.relative_basis_digest.is_some(),
        };
        outcome_facts_present(kernel_stage(self.stage), present)
            && lower_hex_digest(&self.commitment)
            && lower_hex_digest(&self.recipe_digest)
            && self
                .refusal
                .as_deref()
                .is_none_or(|code| !code.is_empty() && code.len() <= MAX_REFUSAL_BYTES)
            && self
                .http_status
                .is_none_or(|status| (100..=599).contains(&status))
            && self
                .relative_basis
                .is_none_or(|basis| basis <= MAX_JSON_INTEGER)
    }

    /// The observation facts, in the model's canonical order.
    ///
    /// # Errors
    /// Returns [`GatewayObserverError::Unrepresentable`] for a fact set the
    /// presence rule refuses or a value outside its bound.
    pub(crate) fn facts(&self) -> Result<Vec<ObservationFact>, GatewayObserverError> {
        if !self.well_formed() {
            return Err(GatewayObserverError::Unrepresentable);
        }
        let mut facts = vec![
            fact("commitment", text(&self.commitment)?)?,
            fact("stage", text(stage_name(self.stage))?)?,
            fact("evaluated-at", FactValue::Uint(self.evaluated_at))?,
            fact("recipe-digest", text(&self.recipe_digest)?)?,
        ];
        let digests = [
            ("counters-digest", self.counters_digest),
            ("response-digest", self.response_digest),
            ("evidence-digest", self.evidence_digest),
            ("pre-entry-digest", self.pre_entry_digest),
            ("relative-basis-digest", self.relative_basis_digest),
        ];
        for (name, value) in digests {
            if let Some(value) = value {
                facts.push(fact(name, bytes_fact(&value)?)?);
            }
        }
        if let Some(code) = &self.refusal {
            facts.push(fact("refusal", text(code)?)?);
        }
        if let Some(status) = self.http_status {
            facts.push(fact("http-status", FactValue::Uint(u64::from(status)))?);
        }
        if let Some(observation) = self.observation {
            facts.push(fact("observation", text(observation)?)?);
        }
        if let Some(basis) = self.relative_basis {
            facts.push(fact("relative-basis", FactValue::Uint(basis))?);
        }
        Ok(facts)
    }

    /// Reads the typed record back from verified observation facts. Every
    /// fact must be registered, of its registered type, and present at most
    /// once; the set must satisfy the presence rule.
    fn from_facts(facts: &[ObservationFact]) -> Option<Self> {
        let mut record = Self {
            commitment: String::new(),
            stage: GatewayAttemptStage::Attempting,
            evaluated_at: 0,
            recipe_digest: String::new(),
            counters_digest: None,
            refusal: None,
            http_status: None,
            response_digest: None,
            observation: None,
            evidence_digest: None,
            pre_entry_digest: None,
            relative_basis: None,
            relative_basis_digest: None,
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut evaluated = false;
        for item in facts {
            let name = item.name().as_str();
            if !seen.insert(name.to_owned()) {
                return None;
            }
            let digest = || match item.value() {
                FactValue::Bytes(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).ok(),
                FactValue::Text(_) | FactValue::Uint(_) => None,
            };
            let text = || match item.value() {
                FactValue::Text(value) => Some(value.as_str().to_owned()),
                FactValue::Uint(_) | FactValue::Bytes(_) => None,
            };
            let uint = || match item.value() {
                FactValue::Uint(value) => Some(*value),
                FactValue::Text(_) | FactValue::Bytes(_) => None,
            };
            match name {
                "commitment" => record.commitment = text()?,
                "stage" => record.stage = parse_stage(&text()?)?,
                "evaluated-at" => {
                    record.evaluated_at = uint()?;
                    evaluated = true;
                }
                "recipe-digest" => record.recipe_digest = text()?,
                "counters-digest" => record.counters_digest = Some(digest()?),
                "refusal" => record.refusal = Some(text()?),
                "http-status" => record.http_status = Some(u16::try_from(uint()?).ok()?),
                "response-digest" => record.response_digest = Some(digest()?),
                "observation" => {
                    record.observation = Some(match text()?.as_str() {
                        "match" => "match",
                        "mismatch" => "mismatch",
                        "echo-mismatch" => "echo-mismatch",
                        _ => return None,
                    });
                }
                "evidence-digest" => record.evidence_digest = Some(digest()?),
                "pre-entry-digest" => record.pre_entry_digest = Some(digest()?),
                "relative-basis" => record.relative_basis = Some(uint()?),
                "relative-basis-digest" => record.relative_basis_digest = Some(digest()?),
                _ => return None,
            }
        }
        (evaluated && record.well_formed()).then_some(record)
    }
}

/// The facts of `record` in the vector notation: `{"text": ...}`,
/// `{"uint": ...}`, or `{"bytes_hex": ...}` by fact name.
#[cfg(test)]
pub(crate) fn outcome_record_json(record: &OutcomeRecord) -> serde_json::Map<String, Value> {
    record
        .facts()
        .unwrap_or_default()
        .iter()
        .map(|fact| {
            let value = match fact.value() {
                FactValue::Text(text) => serde_json::json!({"text": text.as_str()}),
                FactValue::Uint(value) => serde_json::json!({"uint": value}),
                FactValue::Bytes(bytes) => {
                    serde_json::json!({"bytes_hex": hex::encode(bytes.as_slice())})
                }
            };
            (fact.name().as_str().to_owned(), value)
        })
        .collect()
}

fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Facts of an outcome observation of one stored attempt.
///
/// # Errors
/// Returns [`GatewayObserverError::Unrepresentable`] only for a stored record
/// whose fields the presence rule refuses, which a store never returns.
pub(crate) fn outcome_facts(
    snapshot: &GatewayAttemptSnapshot,
) -> Result<Vec<ObservationFact>, GatewayObserverError> {
    OutcomeRecord::from_snapshot(snapshot).facts()
}

/// A signed outcome observation whose signature verified under a pinned
/// observer principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedOutcome {
    pub(crate) subject: String,
    pub(crate) observed_at: u64,
    pub(crate) record: OutcomeRecord,
}

impl VerifiedOutcome {
    /// Lowercase hex of the attested action commitment.
    pub(crate) fn commitment(&self) -> &str {
        &self.record.commitment
    }

    /// The attested stage, kebab-case.
    pub(crate) fn stage(&self) -> &'static str {
        stage_name(self.record.stage)
    }

    /// Whether the gateway entered provider transport, or may have.
    pub(crate) fn entered(&self) -> bool {
        self.record.stage != GatewayAttemptStage::NotEntered
    }
}

/// Verifies one signed observation of `schema` offline: canonical bytes,
/// the pinned observer as signer, raw-key control evidence opening to that
/// principal, and the Ed25519 signature over the canonical preimage. `None`
/// on any failure, because every failure means the observer did not sign
/// these bytes.
pub(crate) fn verify_signed(
    bytes: &[u8],
    observer: &PrincipalId,
    schema: &str,
) -> Option<SignedObservation> {
    use auths_ports::{SignatureInput, SignatureSuite as _};
    let signed =
        auths_codec::decode_signed_observation(bytes, &auths_model::VerifierLimits::default())
            .ok()?;
    if auths_codec::encode_signed_observation(&signed).ok()? != bytes {
        return None;
    }
    let statement = signed.statement();
    let descriptor = signed.signature().descriptor();
    if statement.observer() != observer
        || statement.schema().as_str() != schema
        || descriptor.principal_method().as_str() != RAW_KEY_V1
        || descriptor.verification_method().as_str() != observer.as_str()
        || descriptor.suite().as_str() != auths_signature::ED25519_V1
    {
        return None;
    }
    let key = signed
        .evidence()
        .iter()
        .filter(|object| object.evidence_type().as_str() == RAW_KEY_V1)
        .find_map(|object| {
            RawKeyDescriptor::decode(object.bytes())
                .ok()
                .filter(|key| key.principal().is_ok_and(|found| &found == observer))
        })?;
    let preimage = observation_signing_preimage(statement, descriptor).ok()?;
    auths_signature::Ed25519Suite::new()
        .ok()?
        .verify(SignatureInput {
            verification_key: key.public_key(),
            signing_preimage: &preimage,
            signature: signed.signature().signature().as_slice(),
        })
        .ok()?;
    Some(signed)
}

/// Verifies one `auths.gateway-outcome/2` observation offline: a valid
/// signature of the pinned observer (see [`verify_signed`]) over a fact set
/// the presence rule accepts, with every value in its bound.
///
/// # Errors
/// Returns `audit.outcome-invalid` for any failure; the reason is not
/// distinguished because every failure means the gateway did not sign it.
pub(crate) fn verify_outcome(
    bytes: &[u8],
    observer: &PrincipalId,
) -> Result<VerifiedOutcome, &'static str> {
    let invalid = "audit.outcome-invalid";
    let signed = verify_signed(bytes, observer, OUTCOME_SCHEMA).ok_or(invalid)?;
    let statement = signed.statement();
    let record = OutcomeRecord::from_facts(statement.facts().as_slice()).ok_or(invalid)?;
    Ok(VerifiedOutcome {
        subject: statement.subject().as_str().to_owned(),
        observed_at: statement.observed_at().get(),
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::VerifierLimits;
    use serde_json::json;

    #[cfg(unix)]
    #[test]
    fn observer_seed_is_owner_only_never_overwritten_and_never_printed() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("observer.seed");
        let created = GatewayObserver::generate(&path).expect("generate");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            GatewayObserver::generate(&path).err(),
            Some(GatewayObserverError::Exists)
        );
        let loaded = GatewayObserver::load(&path).expect("load");
        assert_eq!(loaded.principal(), created.principal());
        let seed = fs::read(&path).expect("seed");
        let debug = format!("{loaded:?}");
        assert!(!debug.contains(&hex::encode(&seed)));
        assert!(debug.contains(loaded.principal().as_str()));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
        assert_eq!(
            GatewayObserver::load(&path).err(),
            Some(GatewayObserverError::Permissions)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::write(&path, [0_u8; 31]).expect("truncate");
        assert_eq!(
            GatewayObserver::load(&path).err(),
            Some(GatewayObserverError::Malformed)
        );
    }

    #[test]
    fn signed_read_back_decodes_with_exact_schema_subject_and_facts() {
        let observer = GatewayObserver::from_test_seed(0x33);
        let subject = "https://api.airtable.com/v0/app/tbl/rec#/fields/DemoStatus";
        let facts = read_back_facts(&json!("Pending"), Some(&json!("auths-e1-00"))).expect("facts");
        let signed = observer
            .sign(READ_BACK_SCHEMA, subject, 1_790_000_000, facts)
            .expect("signed");
        let decoded =
            auths_codec::decode_signed_observation(signed.bytes(), &VerifierLimits::default())
                .expect("canonical observation");
        let statement = decoded.statement();
        assert_eq!(statement.observer(), observer.principal());
        assert_eq!(statement.schema().as_str(), READ_BACK_SCHEMA);
        assert_eq!(statement.subject().as_str(), subject);
        assert_eq!(statement.observed_at().get(), 1_790_000_000);
        let names: Vec<_> = statement
            .facts()
            .as_slice()
            .iter()
            .map(|fact| fact.name().as_str().to_owned())
            .collect();
        assert_eq!(names, ["echo", "value"]);
        assert_eq!(decoded.evidence().len(), 1);
    }

    #[test]
    fn unrepresentable_values_and_subjects_are_refused_not_coerced() {
        let observer = GatewayObserver::from_test_seed(0x33);
        for value in [
            json!(true),
            json!(-1),
            json!(1.5),
            json!({"a": 1}),
            json!("x".repeat(257)),
        ] {
            assert_eq!(
                read_back_facts(&value, None).err(),
                Some(GatewayObserverError::Unrepresentable)
            );
        }
        assert_eq!(
            read_back_facts(&json!(7), Some(&json!(false)))
                .expect("facts")
                .len(),
            1
        );
        let facts = read_back_facts(&json!("Pending"), None).expect("facts");
        assert_eq!(
            observer.sign(READ_BACK_SCHEMA, "has space", 1, facts).err(),
            Some(GatewayObserverError::Unrepresentable)
        );
    }

    #[test]
    fn anchor_template_covers_both_subject_families() {
        let observer = GatewayObserver::from_test_seed(0x33);
        let namespace = OperatorNamespace::parse("airtable-demo").expect("namespace");
        let template = observer.anchor_template("https://api.airtable.com", &namespace);
        assert_eq!(template.principal_method, RAW_KEY_V1);
        assert_eq!(template.schemas, [READ_BACK_SCHEMA, OUTCOME_SCHEMA]);
        assert_eq!(
            template.subject_namespaces,
            [
                "https://api.airtable.com/",
                "auths-gateway://airtable-demo/operations/"
            ]
        );
        let operation = LogicalOperationId::parse("step-1").expect("operation");
        assert!(
            operation_subject(&namespace, &operation).starts_with(&template.subject_namespaces[1])
        );
    }
}
