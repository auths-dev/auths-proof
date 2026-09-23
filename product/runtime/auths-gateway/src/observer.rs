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
//! - `auths.gateway-outcome/1`, subject
//!   `auths-gateway://<namespace>/operations/<operation-id>`, facts
//!   `commitment` (lowercase hex of the stored action commitment) and `stage`
//!   (the stored attempt stage, kebab-case).

use crate::{GatewayAttemptSnapshot, LogicalOperationId, OperatorNamespace};
use auths_codec::{encode_signed_observation, evidence_id, observation_signing_preimage};
use auths_custody::{CustodyError, CustodyKey, CustodyKind};
use auths_model::{
    EvidenceId, EvidenceObject, EvidenceTypeId, FactName, FactText, FactValue, MediaType,
    ObservationFact, ObservationFacts, ObservationSchemaId, ObservationStatement, PrincipalId,
    PrincipalMethodId, ResourceId, SignatureBytes, SignatureDescriptor, SignatureEnvelope,
    SignatureSuiteId, SignedObservation, Timestamp, VerificationMethod,
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
/// Schema of an observation of the gateway's own stored attempt stage.
pub const OUTCOME_SCHEMA: &str = "auths.gateway-outcome/1";
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
    #[cfg(test)]
    pub(crate) fn from_test_seed(seed: u8) -> Self {
        Self::from_seed(&[seed; 32]).expect("a fixed seed yields an observer")
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

/// Facts of an outcome observation: the stored commitment and stage.
///
/// # Errors
/// Returns [`GatewayObserverError::Unrepresentable`] only if a stage has no
/// kebab-case spelling.
pub(crate) fn outcome_facts(
    snapshot: &GatewayAttemptSnapshot,
) -> Result<Vec<ObservationFact>, GatewayObserverError> {
    let stage = serde_json::to_value(snapshot.stage())
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(GatewayObserverError::Unrepresentable)?;
    Ok(vec![
        fact(
            "commitment",
            text(&hex::encode(snapshot.action_commitment()))?,
        )?,
        fact("stage", text(&stage)?)?,
    ])
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
