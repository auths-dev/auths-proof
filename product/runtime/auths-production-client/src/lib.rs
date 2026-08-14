use base64ct::{Base64UrlUnpadded, Encoding as _};
use minicbor::{Decoder, Encoder, data::Type};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

pub const PRODUCTION_CLIENT_CONTRACT_VERSION: u16 = 1;
pub const PRODUCTION_CLIENT_CONTENT_TYPE: &str = "application/auths+cbor";
pub const MAX_PRODUCTION_REQUEST_BYTES: usize = 1_048_576;
pub const MAX_PRODUCTION_RESPONSE_BYTES: usize = 1_048_576;

const ALLOWED_EVENT_ATTRIBUTES: &[&str] = &[
    "abi.version",
    "adapter.id",
    "adapter.kind",
    "chunk.size",
    "code",
    "contract_version",
    "item.count",
    "profile",
    "profile.id",
    "profile_version",
    "profile.version",
    "runtime.family",
    "stage",
    "work.units",
];

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SdkEventV2 {
    name: String,
    timestamp: u64,
    correlation_id: String,
    operation: String,
    stage: SdkEventStage,
    outcome: SdkEventOutcome,
    duration_ms: Option<f64>,
    #[serde(default)]
    attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SdkEventStage {
    Acquisition,
    Construction,
    Approval,
    Signing,
    Verification,
    Reservation,
    Execution,
    Receipt,
    Open,
    Authority,
    Cleanup,
    Telemetry,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SdkEventOutcome {
    Started,
    Succeeded,
    Failed,
    Denied,
    Indeterminate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SdkEventProjection<'a> {
    schema_version: &'static str,
    #[serde(flatten)]
    event: &'a SdkEventV2,
}

pub fn project_sdk_event_v2(input: &str) -> Result<String, ProductionClientError> {
    if input.len() > 16_384 {
        return Err(ProductionClientError::LimitExceeded);
    }
    let event: SdkEventV2 =
        serde_json::from_str(input).map_err(|_| ProductionClientError::Malformed)?;
    if !valid_event_text(&event.name, 96)
        || !valid_event_text(&event.operation, 96)
        || !valid_event_text(&event.correlation_id, 128)
        || event
            .duration_ms
            .is_some_and(|value| !value.is_finite() || value < 0.0)
        || event.attributes.len() > 32
    {
        return Err(ProductionClientError::InvalidBody);
    }
    for (key, value) in &event.attributes {
        if !ALLOWED_EVENT_ATTRIBUTES.contains(&key.as_str())
            || !valid_event_text(key, 64)
            || !valid_event_attribute(value)
        {
            return Err(ProductionClientError::InvalidBody);
        }
    }
    serde_json::to_string(&SdkEventProjection {
        schema_version: "auths.telemetry/2",
        event: &event,
    })
    .map_err(|_| ProductionClientError::Malformed)
}

fn valid_event_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_event_attribute(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => valid_event_text(value, 256),
        serde_json::Value::Number(value) => value.as_i64().is_some() || value.as_u64().is_some(),
        serde_json::Value::Bool(_) => true,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductVerb {
    Create,
    Delegate,
    Execute,
    Resume,
    Verify,
}

impl ProductVerb {
    pub fn parse(value: &str) -> Result<Self, ProductionClientError> {
        match value {
            "create" => Ok(Self::Create),
            "delegate" => Ok(Self::Delegate),
            "execute" => Ok(Self::Execute),
            "resume" => Ok(Self::Resume),
            "verify" => Ok(Self::Verify),
            _ => Err(ProductionClientError::UnknownVerb),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Delegate => "delegate",
            Self::Execute => "execute",
            Self::Resume => "resume",
            Self::Verify => "verify",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum QualifiedProfile {
    OpenTofuSavedPlanApply,
    PostgreSqlBoundedUpdate,
    GitHubIssueAddress,
}

impl QualifiedProfile {
    pub fn parse(value: &str) -> Result<Self, ProductionClientError> {
        match value {
            "auths.opentofu.saved-plan-apply/1" => Ok(Self::OpenTofuSavedPlanApply),
            "auths.postgresql.bounded-update/1" => Ok(Self::PostgreSqlBoundedUpdate),
            "auths.github.issue-address/1" => Ok(Self::GitHubIssueAddress),
            _ => Err(ProductionClientError::UnknownProfile),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenTofuSavedPlanApply => "auths.opentofu.saved-plan-apply/1",
            Self::PostgreSqlBoundedUpdate => "auths.postgresql.bounded-update/1",
            Self::GitHubIssueAddress => "auths.github.issue-address/1",
        }
    }

    #[must_use]
    pub const fn execute_path(self) -> &'static str {
        match self {
            Self::OpenTofuSavedPlanApply => "/v1/profiles/opentofu/saved-plan-apply/execute",
            Self::PostgreSqlBoundedUpdate => "/v1/profiles/postgresql/bounded-update/execute",
            Self::GitHubIssueAddress => "/v1/profiles/github/issue-address/execute",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReference(String);

impl RecoveryReference {
    pub fn parse(value: &str) -> Result<Self, ProductionClientError> {
        if value.len() != 43 {
            return Err(ProductionClientError::InvalidRecoveryReference);
        }
        let mut bytes = [0_u8; 32];
        Base64UrlUnpadded::decode(value, &mut bytes)
            .map_err(|_| ProductionClientError::InvalidRecoveryReference)?;
        if bytes == [0; 32] {
            return Err(ProductionClientError::InvalidRecoveryReference);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionRequest {
    verb: ProductVerb,
    profile: QualifiedProfile,
    identity: Vec<u8>,
    authority: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
    recovery_reference: Option<RecoveryReference>,
}

impl ProductionRequest {
    pub fn new(
        verb: ProductVerb,
        profile: QualifiedProfile,
        identity: Vec<u8>,
        authority: Option<Vec<u8>>,
        body: Option<Vec<u8>>,
        recovery_reference: Option<RecoveryReference>,
    ) -> Result<Self, ProductionClientError> {
        if identity.is_empty() || identity.len() > 65_536 {
            return Err(ProductionClientError::InvalidIdentity);
        }
        if authority
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_PRODUCTION_REQUEST_BYTES)
            || body
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_PRODUCTION_REQUEST_BYTES)
        {
            return Err(ProductionClientError::InvalidBody);
        }
        let valid_shape = match verb {
            ProductVerb::Create => {
                authority.is_none() && body.is_some() && recovery_reference.is_none()
            }
            ProductVerb::Delegate | ProductVerb::Execute => {
                authority.is_some() && body.is_some() && recovery_reference.is_none()
            }
            ProductVerb::Resume => {
                authority.is_none() && body.is_none() && recovery_reference.is_some()
            }
            ProductVerb::Verify => {
                authority.is_none() && body.is_some() && recovery_reference.is_none()
            }
        };
        if !valid_shape {
            return Err(ProductionClientError::InvalidShape);
        }
        Ok(Self {
            verb,
            profile,
            identity,
            authority,
            body,
            recovery_reference,
        })
    }

    #[must_use]
    pub const fn verb(&self) -> ProductVerb {
        self.verb
    }

    #[must_use]
    pub const fn profile(&self) -> QualifiedProfile {
        self.profile
    }

    #[must_use]
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    #[must_use]
    pub fn authority(&self) -> Option<&[u8]> {
        self.authority.as_deref()
    }

    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    #[must_use]
    pub fn recovery_reference(&self) -> Option<&RecoveryReference> {
        self.recovery_reference.as_ref()
    }

    #[must_use]
    pub const fn endpoint_path(&self) -> &'static str {
        match self.verb {
            ProductVerb::Create => "/v1/authority/create",
            ProductVerb::Delegate => "/v1/authority/delegate",
            ProductVerb::Execute => self.profile.execute_path(),
            ProductVerb::Resume => "/v1/workflows/resume",
            ProductVerb::Verify => "/v1/authority/verify",
        }
    }

    pub fn projection_json(&self) -> Result<String, ProductionClientError> {
        serde_json::to_string(&ProductionRequestProjection {
            contract_version: PRODUCTION_CLIENT_CONTRACT_VERSION,
            verb: self.verb.as_str(),
            profile: self.profile.as_str(),
            endpoint_path: self.endpoint_path(),
            identity: Base64UrlUnpadded::encode_string(&self.identity),
            authority: self
                .authority
                .as_deref()
                .map(Base64UrlUnpadded::encode_string),
            body: self.body.as_deref().map(Base64UrlUnpadded::encode_string),
            recovery_reference: self
                .recovery_reference
                .as_ref()
                .map(RecoveryReference::as_str),
        })
        .map_err(|_| ProductionClientError::Malformed)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProductionRequestProjection<'a> {
    contract_version: u16,
    verb: &'a str,
    profile: &'a str,
    endpoint_path: &'a str,
    identity: String,
    authority: Option<String>,
    body: Option<String>,
    recovery_reference: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientOutcomeKind {
    Completed,
    Denied,
    Indeterminate,
    Recoverable,
    Verified,
    Rejected,
}

impl ClientOutcomeKind {
    fn parse(value: &str) -> Result<Self, ProductionClientError> {
        match value {
            "completed" => Ok(Self::Completed),
            "denied" => Ok(Self::Denied),
            "indeterminate" => Ok(Self::Indeterminate),
            "recoverable" => Ok(Self::Recoverable),
            "verified" => Ok(Self::Verified),
            "rejected" => Ok(Self::Rejected),
            _ => Err(ProductionClientError::UnknownOutcome),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Denied => "denied",
            Self::Indeterminate => "indeterminate",
            Self::Recoverable => "recoverable",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetryClass {
    Never,
    Backoff,
    Resume,
    Reconcile,
}

impl RetryClass {
    fn parse(value: &str) -> Result<Self, ProductionClientError> {
        match value {
            "never" => Ok(Self::Never),
            "backoff" => Ok(Self::Backoff),
            "resume" => Ok(Self::Resume),
            "reconcile" => Ok(Self::Reconcile),
            _ => Err(ProductionClientError::UnknownRetryClass),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Backoff => "backoff",
            Self::Resume => "resume",
            Self::Reconcile => "reconcile",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionResponse {
    kind: ClientOutcomeKind,
    code: Option<String>,
    retry: RetryClass,
    recovery_reference: Option<RecoveryReference>,
    value: Option<Vec<u8>>,
    receipt: Option<Vec<u8>>,
}

impl ProductionResponse {
    pub fn new(
        kind: ClientOutcomeKind,
        code: Option<String>,
        retry: RetryClass,
        recovery_reference: Option<RecoveryReference>,
        value: Option<Vec<u8>>,
        receipt: Option<Vec<u8>>,
    ) -> Result<Self, ProductionClientError> {
        if code.as_ref().is_some_and(|value| !valid_code(value))
            || value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_PRODUCTION_RESPONSE_BYTES)
            || receipt.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > MAX_PRODUCTION_RESPONSE_BYTES
            })
        {
            return Err(ProductionClientError::InvalidBody);
        }
        let valid_shape = match kind {
            ClientOutcomeKind::Completed => {
                code.is_none()
                    && recovery_reference.is_none()
                    && receipt.is_some()
                    && retry == RetryClass::Never
            }
            ClientOutcomeKind::Denied | ClientOutcomeKind::Rejected => {
                code.is_some()
                    && recovery_reference.is_none()
                    && value.is_none()
                    && receipt.is_none()
                    && retry == RetryClass::Never
            }
            ClientOutcomeKind::Indeterminate => {
                code.is_some()
                    && recovery_reference.is_none()
                    && value.is_none()
                    && receipt.is_none()
                    && matches!(retry, RetryClass::Backoff | RetryClass::Reconcile)
            }
            ClientOutcomeKind::Recoverable => {
                code.is_some()
                    && recovery_reference.is_some()
                    && value.is_none()
                    && receipt.is_none()
                    && retry == RetryClass::Resume
            }
            ClientOutcomeKind::Verified => {
                code.is_none()
                    && recovery_reference.is_none()
                    && receipt.is_none()
                    && retry == RetryClass::Never
            }
        };
        if !valid_shape {
            return Err(ProductionClientError::InvalidShape);
        }
        Ok(Self {
            kind,
            code,
            retry,
            recovery_reference,
            value,
            receipt,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> ClientOutcomeKind {
        self.kind
    }

    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    #[must_use]
    pub const fn retry(&self) -> RetryClass {
        self.retry
    }

    #[must_use]
    pub fn recovery_reference(&self) -> Option<&RecoveryReference> {
        self.recovery_reference.as_ref()
    }

    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    #[must_use]
    pub fn receipt(&self) -> Option<&[u8]> {
        self.receipt.as_deref()
    }

    pub fn projection_json(&self) -> Result<String, ProductionClientError> {
        serde_json::to_string(&ProductionResponseProjection {
            contract_version: PRODUCTION_CLIENT_CONTRACT_VERSION,
            kind: self.kind,
            code: self.code.as_deref(),
            retry: self.retry,
            recovery_reference: self
                .recovery_reference
                .as_ref()
                .map(RecoveryReference::as_str),
            value: self.value.as_deref().map(Base64UrlUnpadded::encode_string),
            receipt: self
                .receipt
                .as_deref()
                .map(Base64UrlUnpadded::encode_string),
        })
        .map_err(|_| ProductionClientError::Malformed)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProductionResponseProjection<'a> {
    contract_version: u16,
    kind: ClientOutcomeKind,
    code: Option<&'a str>,
    retry: RetryClass,
    recovery_reference: Option<&'a str>,
    value: Option<String>,
    receipt: Option<String>,
}

pub fn encode_request(request: &ProductionRequest) -> Result<Vec<u8>, ProductionClientError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(7)
        .map_err(|_| ProductionClientError::Malformed)?;
    encoder
        .u16(PRODUCTION_CLIENT_CONTRACT_VERSION)
        .map_err(|_| ProductionClientError::Malformed)?;
    encoder
        .str(request.verb.as_str())
        .map_err(|_| ProductionClientError::Malformed)?;
    encoder
        .str(request.profile.as_str())
        .map_err(|_| ProductionClientError::Malformed)?;
    encoder
        .bytes(&request.identity)
        .map_err(|_| ProductionClientError::Malformed)?;
    encode_optional_bytes(&mut encoder, request.authority.as_deref())?;
    encode_optional_bytes(&mut encoder, request.body.as_deref())?;
    encode_optional_str(
        &mut encoder,
        request
            .recovery_reference
            .as_ref()
            .map(RecoveryReference::as_str),
    )?;
    let encoded = encoder.into_writer();
    if encoded.len() > MAX_PRODUCTION_REQUEST_BYTES {
        return Err(ProductionClientError::LimitExceeded);
    }
    Ok(encoded)
}

pub fn decode_request(input: &[u8]) -> Result<ProductionRequest, ProductionClientError> {
    if input.len() > MAX_PRODUCTION_REQUEST_BYTES {
        return Err(ProductionClientError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    exact_array(&mut decoder, 7)?;
    version(&mut decoder)?;
    let verb = ProductVerb::parse(
        decoder
            .str()
            .map_err(|_| ProductionClientError::Malformed)?,
    )?;
    let profile = QualifiedProfile::parse(
        decoder
            .str()
            .map_err(|_| ProductionClientError::Malformed)?,
    )?;
    let identity = decoder
        .bytes()
        .map_err(|_| ProductionClientError::Malformed)?
        .to_vec();
    let authority = decode_optional_bytes(&mut decoder)?;
    let body = decode_optional_bytes(&mut decoder)?;
    let recovery_reference = decode_optional_str(&mut decoder)?
        .map(|value| RecoveryReference::parse(&value))
        .transpose()?;
    finish(&decoder, input)?;
    let request =
        ProductionRequest::new(verb, profile, identity, authority, body, recovery_reference)?;
    if encode_request(&request)?.as_slice() != input {
        return Err(ProductionClientError::NonCanonical);
    }
    Ok(request)
}

pub fn encode_response(response: &ProductionResponse) -> Result<Vec<u8>, ProductionClientError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(7)
        .map_err(|_| ProductionClientError::Malformed)?;
    encoder
        .u16(PRODUCTION_CLIENT_CONTRACT_VERSION)
        .map_err(|_| ProductionClientError::Malformed)?;
    encoder
        .str(response.kind.as_str())
        .map_err(|_| ProductionClientError::Malformed)?;
    encode_optional_str(&mut encoder, response.code.as_deref())?;
    encoder
        .str(response.retry.as_str())
        .map_err(|_| ProductionClientError::Malformed)?;
    encode_optional_str(
        &mut encoder,
        response
            .recovery_reference
            .as_ref()
            .map(RecoveryReference::as_str),
    )?;
    encode_optional_bytes(&mut encoder, response.value.as_deref())?;
    encode_optional_bytes(&mut encoder, response.receipt.as_deref())?;
    let encoded = encoder.into_writer();
    if encoded.len() > MAX_PRODUCTION_RESPONSE_BYTES {
        return Err(ProductionClientError::LimitExceeded);
    }
    Ok(encoded)
}

pub fn decode_response(input: &[u8]) -> Result<ProductionResponse, ProductionClientError> {
    if input.len() > MAX_PRODUCTION_RESPONSE_BYTES {
        return Err(ProductionClientError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    exact_array(&mut decoder, 7)?;
    version(&mut decoder)?;
    let kind = ClientOutcomeKind::parse(
        decoder
            .str()
            .map_err(|_| ProductionClientError::Malformed)?,
    )?;
    let code = decode_optional_str(&mut decoder)?;
    let retry = RetryClass::parse(
        decoder
            .str()
            .map_err(|_| ProductionClientError::Malformed)?,
    )?;
    let reference = decode_optional_str(&mut decoder)?
        .map(|value| RecoveryReference::parse(&value))
        .transpose()?;
    let value = decode_optional_bytes(&mut decoder)?;
    let receipt = decode_optional_bytes(&mut decoder)?;
    finish(&decoder, input)?;
    let response = ProductionResponse::new(kind, code, retry, reference, value, receipt)?;
    if encode_response(&response)?.as_slice() != input {
        return Err(ProductionClientError::NonCanonical);
    }
    Ok(response)
}

pub fn encode_delegation_body(
    subject: &[u8],
    attenuation: &[u8],
) -> Result<Vec<u8>, ProductionClientError> {
    if subject.is_empty()
        || subject.len() > 65_536
        || attenuation.is_empty()
        || attenuation.len() > 65_536
    {
        return Err(ProductionClientError::InvalidBody);
    }
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.bytes(subject))
        .and_then(|encoder| encoder.bytes(attenuation))
        .map_err(|_| ProductionClientError::Malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_delegation_body(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProductionClientError> {
    let mut decoder = Decoder::new(input);
    exact_array(&mut decoder, 2)?;
    let subject = decoder
        .bytes()
        .map_err(|_| ProductionClientError::Malformed)?
        .to_vec();
    let attenuation = decoder
        .bytes()
        .map_err(|_| ProductionClientError::Malformed)?
        .to_vec();
    finish(&decoder, input)?;
    let encoded = encode_delegation_body(&subject, &attenuation)?;
    if encoded != input {
        return Err(ProductionClientError::NonCanonical);
    }
    Ok((subject, attenuation))
}

fn encode_optional_bytes(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<&[u8]>,
) -> Result<(), ProductionClientError> {
    if let Some(value) = value {
        encoder.bytes(value)
    } else {
        encoder.null()
    }
    .map(|_| ())
    .map_err(|_| ProductionClientError::Malformed)
}

fn encode_optional_str(
    encoder: &mut Encoder<Vec<u8>>,
    value: Option<&str>,
) -> Result<(), ProductionClientError> {
    if let Some(value) = value {
        encoder.str(value)
    } else {
        encoder.null()
    }
    .map(|_| ())
    .map_err(|_| ProductionClientError::Malformed)
}

fn decode_optional_bytes(
    decoder: &mut Decoder<'_>,
) -> Result<Option<Vec<u8>>, ProductionClientError> {
    if decoder
        .datatype()
        .map_err(|_| ProductionClientError::Malformed)?
        == Type::Null
    {
        decoder
            .null()
            .map_err(|_| ProductionClientError::Malformed)?;
        Ok(None)
    } else {
        Ok(Some(
            decoder
                .bytes()
                .map_err(|_| ProductionClientError::Malformed)?
                .to_vec(),
        ))
    }
}

fn decode_optional_str(decoder: &mut Decoder<'_>) -> Result<Option<String>, ProductionClientError> {
    if decoder
        .datatype()
        .map_err(|_| ProductionClientError::Malformed)?
        == Type::Null
    {
        decoder
            .null()
            .map_err(|_| ProductionClientError::Malformed)?;
        Ok(None)
    } else {
        Ok(Some(
            decoder
                .str()
                .map_err(|_| ProductionClientError::Malformed)?
                .to_owned(),
        ))
    }
}

fn exact_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), ProductionClientError> {
    match decoder
        .array()
        .map_err(|_| ProductionClientError::Malformed)?
    {
        Some(value) if value == expected => Ok(()),
        _ => Err(ProductionClientError::Malformed),
    }
}

fn version(decoder: &mut Decoder<'_>) -> Result<(), ProductionClientError> {
    match decoder
        .u16()
        .map_err(|_| ProductionClientError::Malformed)?
    {
        PRODUCTION_CLIENT_CONTRACT_VERSION => Ok(()),
        _ => Err(ProductionClientError::UnsupportedVersion),
    }
}

fn finish(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), ProductionClientError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(ProductionClientError::Malformed)
    }
}

fn valid_code(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionClientError {
    Malformed,
    NonCanonical,
    UnsupportedVersion,
    UnknownVerb,
    UnknownProfile,
    UnknownOutcome,
    UnknownRetryClass,
    InvalidIdentity,
    InvalidBody,
    InvalidShape,
    InvalidRecoveryReference,
    LimitExceeded,
}

impl ProductionClientError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "client.malformed",
            Self::NonCanonical => "client.non-canonical",
            Self::UnsupportedVersion => "client.unsupported-version",
            Self::UnknownVerb => "client.unknown-verb",
            Self::UnknownProfile => "client.unknown-profile",
            Self::UnknownOutcome => "client.unknown-outcome",
            Self::UnknownRetryClass => "client.unknown-retry-class",
            Self::InvalidIdentity => "client.invalid-identity",
            Self::InvalidBody => "client.invalid-body",
            Self::InvalidShape => "client.invalid-shape",
            Self::InvalidRecoveryReference => "client.invalid-recovery-reference",
            Self::LimitExceeded => "client.limit-exceeded",
        }
    }
}

impl fmt::Display for ProductionClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProductionClientError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Vec<u8> {
        vec![1; 32]
    }
    fn reference() -> RecoveryReference {
        RecoveryReference::parse(&Base64UrlUnpadded::encode_string(&[7; 32])).unwrap()
    }

    #[test]
    fn every_request_shape_round_trips_canonically() {
        let cases = [
            ProductionRequest::new(
                ProductVerb::Create,
                QualifiedProfile::GitHubIssueAddress,
                identity(),
                None,
                Some(vec![2]),
                None,
            )
            .unwrap(),
            ProductionRequest::new(
                ProductVerb::Delegate,
                QualifiedProfile::GitHubIssueAddress,
                identity(),
                Some(vec![3]),
                Some(vec![4]),
                None,
            )
            .unwrap(),
            ProductionRequest::new(
                ProductVerb::Execute,
                QualifiedProfile::OpenTofuSavedPlanApply,
                identity(),
                Some(vec![3]),
                Some(vec![4]),
                None,
            )
            .unwrap(),
            ProductionRequest::new(
                ProductVerb::Resume,
                QualifiedProfile::PostgreSqlBoundedUpdate,
                identity(),
                None,
                None,
                Some(reference()),
            )
            .unwrap(),
            ProductionRequest::new(
                ProductVerb::Verify,
                QualifiedProfile::GitHubIssueAddress,
                identity(),
                None,
                Some(vec![5]),
                None,
            )
            .unwrap(),
        ];
        for value in cases {
            let encoded = encode_request(&value).unwrap();
            assert_eq!(decode_request(&encoded).unwrap(), value);
        }
    }

    #[test]
    fn response_shapes_are_finite_and_canonical() {
        let cases = [
            ProductionResponse::new(
                ClientOutcomeKind::Completed,
                None,
                RetryClass::Never,
                None,
                Some(vec![1]),
                Some(vec![2]),
            )
            .unwrap(),
            ProductionResponse::new(
                ClientOutcomeKind::Denied,
                Some("authority.denied".into()),
                RetryClass::Never,
                None,
                None,
                None,
            )
            .unwrap(),
            ProductionResponse::new(
                ClientOutcomeKind::Indeterminate,
                Some("provider.unknown".into()),
                RetryClass::Reconcile,
                None,
                None,
                None,
            )
            .unwrap(),
            ProductionResponse::new(
                ClientOutcomeKind::Recoverable,
                Some("workflow.recoverable".into()),
                RetryClass::Resume,
                Some(reference()),
                None,
                None,
            )
            .unwrap(),
            ProductionResponse::new(
                ClientOutcomeKind::Verified,
                None,
                RetryClass::Never,
                None,
                Some(vec![3]),
                None,
            )
            .unwrap(),
            ProductionResponse::new(
                ClientOutcomeKind::Rejected,
                Some("verification.rejected".into()),
                RetryClass::Never,
                None,
                None,
                None,
            )
            .unwrap(),
        ];
        for value in cases {
            let encoded = encode_response(&value).unwrap();
            assert_eq!(decode_response(&encoded).unwrap(), value);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&value.projection_json().unwrap())
                    .unwrap()["contractVersion"],
                1
            );
        }
    }

    #[test]
    fn mutation_and_unknown_values_fail_closed() {
        let request = ProductionRequest::new(
            ProductVerb::Create,
            QualifiedProfile::GitHubIssueAddress,
            identity(),
            None,
            Some(vec![2]),
            None,
        )
        .unwrap();
        let mut encoded = encode_request(&request).unwrap();
        encoded[1] = 2;
        assert!(decode_request(&encoded).is_err());

        let mut oversized = vec![0; MAX_PRODUCTION_RESPONSE_BYTES + 1];
        assert_eq!(
            decode_response(&oversized),
            Err(ProductionClientError::LimitExceeded)
        );
        oversized.clear();
    }

    #[test]
    fn endpoint_routes_are_closed_per_profile() {
        assert_eq!(
            QualifiedProfile::OpenTofuSavedPlanApply.execute_path(),
            "/v1/profiles/opentofu/saved-plan-apply/execute"
        );
        assert_eq!(
            QualifiedProfile::PostgreSqlBoundedUpdate.execute_path(),
            "/v1/profiles/postgresql/bounded-update/execute"
        );
        assert_eq!(
            QualifiedProfile::GitHubIssueAddress.execute_path(),
            "/v1/profiles/github/issue-address/execute"
        );
    }

    #[test]
    fn delegation_body_is_rust_owned_and_canonical() {
        let encoded = encode_delegation_body(&[1, 2], &[3, 4]).unwrap();
        assert_eq!(
            decode_delegation_body(&encoded).unwrap(),
            (vec![1, 2], vec![3, 4])
        );
    }

    #[test]
    fn sdk_events_are_rust_owned_and_secret_free() {
        let event = project_sdk_event_v2(
            r#"{"name":"auths.execute","timestamp":1,"correlationId":"request-1","operation":"execute","stage":"execution","outcome":"succeeded","attributes":{"profile.id":"auths.github"}}"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&event).unwrap()["schemaVersion"],
            "auths.telemetry/2"
        );
        assert_eq!(
            project_sdk_event_v2(
                r#"{"name":"auths.execute","timestamp":1,"correlationId":"request-1","operation":"execute","stage":"execution","outcome":"succeeded","attributes":{"token":"secret"}}"#,
            ),
            Err(ProductionClientError::InvalidBody)
        );
    }
}
