//! The gateway's counting-provider test harness.
//!
//! It follows the engine's post-verification dispatch exactly: native
//! verification with the gateway registries at an explicit gateway clock,
//! then a durable claim, then one credential lease, then provider entry. A
//! synthetic provider counts every write entry, read-only observation, and
//! lease, and holds the records in memory so a test can change them the way
//! another writer would. Everything here is test infrastructure: the root
//! and observer keys come from public fixed seeds.

use crate::engine::{
    GatewayObserveRequest, GatewayObserveResult, GatewaySubmitResult, execute_claimed,
    gateway_verifier_configuration, not_entered, observe_outcome, observe_read_back, reobserve,
    replay_refused, reserve_bound, verify_command,
};
use crate::observer::{OUTCOME_SCHEMA, READ_BACK_SCHEMA};
use crate::transport::{GatewayTransportError, ProviderPort, WriteTransportOutcome};
use crate::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, FileGatewayAttemptStore,
    GatewayAttemptError, GatewayAttempts, GatewayObserver,
};
use auths_codec::{encode_observation_requirements, evidence_id, grant_signing_preimage};
use auths_model::{
    AcceptedRegistries, ActionConstraint, AssuranceClaimId, AssurancePolicy, AssurancePolicyId,
    Audience, AudienceSet, Challenge, ChannelBindingId, CompositionRequirement, ConditionTest,
    CriticalExtension, CriticalExtensions, EvidenceId, EvidenceObject, EvidenceTypeId, ExtensionId,
    FactName, GrantStatement, GrantStatusSnapshot, MediaType, ObservationCondition,
    ObservationRequirement, ObservationRequirements, ObservationSchemaId, ObservationSubject,
    ObserverAnchor, ObserverAnchorId, PermissionSet, PrincipalId, PrincipalMethodId,
    PrincipalStatusSnapshot, ProfilePolicyId, ResourceId, ResourceMatcherId, SignatureBytes,
    SignatureDescriptor, SignatureEnvelope, SignatureSuiteId, SignedGrant, StatusPolicy,
    StatusSnapshotId, Timestamp, TrustAnchor, TrustAnchorId, TrustedContext, ValidityWindow,
    VerificationMethod, VerifierLimits,
};
use auths_profile_mcp::{MCP_ARGUMENTS_V1, McpToolCall};
use auths_raw_key::{RAW_KEY_MEDIA_TYPE, RAW_KEY_V1, RawKeyDescriptor, RawKeyType};
use auths_registries::OBSERVATION_REQUIREMENT_EXTENSION_V1;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const SERVICE: &str = "gateway-observer-test";
pub(crate) const TOOL: &str = "set_status_v1";
pub(crate) const NAMESPACE: &str = "observer-demo";
pub(crate) const ORIGIN: &str = "https://api.airtable.com";
pub(crate) const RECORD: &str = "recTEST0000000001";
pub(crate) const OTHER_RECORD: &str = "recTEST0000000002";
pub(crate) const ANCHOR: &str = "gateway-observer";
pub(crate) const ASSURANCE: &str = "gateway-observer-test-v1";
pub(crate) const ROOT_SEED: u8 = 0x11;
pub(crate) const OBSERVER_SEED: u8 = 0x33;

/// Failure to build a harness value from fixed fixture inputs or to open its
/// attempt store. Carries no secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HarnessError {
    /// A fixture value violated a model bound.
    #[error("harness fixture is invalid: {0}")]
    Fixture(&'static str),
    /// The attempt store could not be opened.
    #[error("harness attempt store is unavailable")]
    Store,
}

fn fixture<T, E>(value: Result<T, E>, what: &'static str) -> Result<T, HarnessError> {
    value.map_err(|_| HarnessError::Fixture(what))
}

/// Raw-key Ed25519 principal used for the root, the agent, and forgeries.
pub(crate) struct Signer {
    pub(crate) key: SigningKey,
    pub(crate) raw: RawKeyDescriptor,
    pub(crate) principal: PrincipalId,
}

// INVARIANT: every value below is derived from a fixed 32-byte seed and
// compiled identifiers, so construction cannot fail; the expectations name
// the constant that would have to be wrong.
#[allow(clippy::expect_used)]
impl Signer {
    pub(crate) fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let raw =
            RawKeyDescriptor::new(RawKeyType::Ed25519, key.verifying_key().to_bytes().to_vec())
                .expect("a 32-byte Ed25519 key is a raw-key descriptor");
        let principal = raw
            .principal()
            .expect("a raw-key descriptor has a principal");
        Self {
            key,
            raw,
            principal,
        }
    }

    pub(crate) fn descriptor(&self) -> SignatureDescriptor {
        SignatureDescriptor::new(
            PrincipalMethodId::parse(RAW_KEY_V1).expect("raw-key method identifier"),
            VerificationMethod::parse(self.principal.as_str())
                .expect("a principal is a verification method"),
            SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("Ed25519 suite identifier"),
        )
    }

    pub(crate) fn evidence(&self) -> EvidenceObject {
        let object = |id| {
            EvidenceObject::new(
                id,
                EvidenceTypeId::parse(RAW_KEY_V1).expect("raw-key evidence type"),
                MediaType::parse(RAW_KEY_MEDIA_TYPE).expect("raw-key media type"),
                self.raw.encode(),
            )
            .expect("raw-key evidence")
        };
        object(evidence_id(&object(EvidenceId::new([0; 32]))).expect("evidence identifier"))
    }

    pub(crate) fn sign(&self, preimage: &[u8]) -> SignatureBytes {
        SignatureBytes::new(self.key.sign(preimage).to_bytes().to_vec())
            .expect("an Ed25519 signature is 64 bytes")
    }
}

pub(crate) fn window(from: u64, until: u64) -> Result<ValidityWindow, HarnessError> {
    fixture(
        ValidityWindow::new(Timestamp::new(from), Timestamp::new(until)),
        "window",
    )
}

pub(crate) fn audience() -> Result<Audience, HarnessError> {
    fixture(Audience::parse(&format!("mcp://{SERVICE}")), "audience")
}

pub(crate) fn call(arguments: &Map<String, Value>) -> Result<McpToolCall, HarnessError> {
    fixture(McpToolCall::new(SERVICE, TOOL, arguments.clone()), "call")
}

pub(crate) fn name(value: &str) -> Result<FactName, HarnessError> {
    fixture(FactName::parse(value), "fact name")
}

#[cfg(test)]
pub(crate) fn text(value: &str) -> Result<auths_model::FactValue, HarnessError> {
    Ok(auths_model::FactValue::Text(fixture(
        auths_model::FactText::new(value),
        "fact text",
    )?))
}

/// The read-back subject the gateway signs for `record`.
#[must_use]
pub fn read_back_subject(record: &str) -> String {
    format!("{ORIGIN}/v0/appTEST0000000001/tblTEST0000000001/{record}#/fields/DemoStatus")
}

#[cfg(test)]
pub(crate) fn namespace() -> Result<crate::OperatorNamespace, HarnessError> {
    fixture(crate::OperatorNamespace::parse(NAMESPACE), "namespace")
}

/// Compiles a recipe for `extra` profile fields and its precondition block.
pub(crate) fn recipe(extra: &Value, preconditions: &Value) -> Result<CompiledRecipe, HarnessError> {
    let (source, lock) = recipe_sources(extra, preconditions)?;
    fixture(CompiledRecipe::compile(&source, &lock), "recipe")
}

/// The recipe source and profile lock bytes [`recipe`] compiles.
pub(crate) fn recipe_sources(
    extra: &Value,
    preconditions: &Value,
) -> Result<(Vec<u8>, Vec<u8>), HarnessError> {
    let mut fields = json!({
        "operation_id": {"kind": "string", "minimum": 1, "maximum": 128},
        "operator_namespace": {"type": "enum", "variants": [NAMESPACE]},
        "recipe_digest": {"kind": "string", "minimum": 64, "maximum": 64},
        "record_id": {"kind": "string", "minimum": 17, "maximum": 43},
        "replacement": {"type": "enum", "variants": ["Approved", "Pending"]}
    });
    for (key, value) in extra
        .as_object()
        .ok_or(HarnessError::Fixture("extra fields"))?
    {
        fields[key] = value.clone();
    }
    let schema = json!({"kind": "object", "fields": fields});
    let digest = hex::encode(Sha256::digest(fixture(
        serde_json_canonicalizer::to_vec(&schema),
        "canonical schema",
    )?));
    let lock = json!({
        "command_schema": schema, "generator_format": 2, "profile": "gateway-observer-test",
        "schema": "auths.self-hosted-profile-lock/1", "schema_digest": digest,
        "service": SERVICE, "tool": TOOL, "version": 1
    });
    let path = json!([
        {"kind": "fixed", "value": "v0"},
        {"kind": "fixed", "value": "appTEST0000000001"},
        {"kind": "fixed", "value": "tblTEST0000000001"},
        {"kind": "field", "name": "record_id"}
    ]);
    let source = json!({
        "schema": "auths.gateway-recipe-source/1", "profile_schema_digest": digest,
        "service": SERVICE, "tool": TOOL, "operator_namespace": NAMESPACE,
        "credential": {"kind": "bearer"}, "origin": ORIGIN,
        "write": {"method": "PATCH", "path": path, "body": {"kind": "json", "value": {
            "kind": "object", "fields": {"fields": {"kind": "object", "fields": {
                "DemoStatus": {"kind": "field", "name": "replacement"}}}}}}},
        "observation": {"path": path, "json_pointer": "/fields/DemoStatus",
            "expected_field": "replacement", "maximum_response_bytes": 16384},
        "echo": {"write": "/fields/auths_echo", "observe": "/fields/auths_echo"},
        "preconditions": preconditions
    });
    Ok((
        fixture(serde_json::to_vec(&source), "source")?,
        fixture(serde_json::to_vec(&lock), "lock")?,
    ))
}

/// The expected-before-replacement recipe: `record_uri` must equal this
/// request's read-back subject and `expected` is compared only by
/// observation requirements.
pub(crate) fn update_recipe() -> Result<CompiledRecipe, HarnessError> {
    recipe(
        &json!({
            "expected": {"type": "enum", "variants": ["Approved", "Pending"]},
            "record_uri": {"kind": "string", "minimum": 1, "maximum": 256}
        }),
        &json!({"read_back_subject": "record_uri", "verified": ["expected"]}),
    )
}

pub(crate) fn observer_anchor(
    observer: &PrincipalId,
    now: u64,
) -> Result<ObserverAnchor, HarnessError> {
    fixture(
        ObserverAnchor::new(
            fixture(ObserverAnchorId::parse(ANCHOR), "observer anchor ID")?,
            observer.clone(),
            vec![fixture(PrincipalMethodId::parse(RAW_KEY_V1), "method")?],
            vec![
                fixture(ObservationSchemaId::parse(READ_BACK_SCHEMA), "schema")?,
                fixture(ObservationSchemaId::parse(OUTCOME_SCHEMA), "schema")?,
            ],
            vec![
                fixture(ResourceId::parse(&format!("{ORIGIN}/")), "namespace")?,
                fixture(
                    ResourceId::parse(&format!("auths-gateway://{NAMESPACE}/operations/")),
                    "namespace",
                )?,
            ],
            window(now - 86_400, now + 86_400)?,
        ),
        "observer anchor",
    )
}

pub(crate) fn accepted_registries() -> Result<AcceptedRegistries, HarnessError> {
    fixture(
        AcceptedRegistries::new(
            auths_registries::TARGET_V1_REGISTRY_MANIFEST,
            vec![fixture(PrincipalMethodId::parse(RAW_KEY_V1), "method")?],
            vec![
                fixture(
                    SignatureSuiteId::parse(auths_signature::ED25519_V1),
                    "suite",
                )?,
                fixture(SignatureSuiteId::parse("p256-sha256-v1"), "suite")?,
            ],
            vec![fixture(EvidenceTypeId::parse(RAW_KEY_V1), "evidence type")?],
            Vec::new(),
            Vec::new(),
            vec![
                fixture(AssuranceClaimId::parse("offline-verifiable"), "claim")?,
                fixture(
                    AssuranceClaimId::parse("self-certifying-identifier"),
                    "claim",
                )?,
            ],
            Vec::new(),
            vec![fixture(
                ResourceMatcherId::parse("uri-namespace-v1"),
                "matcher",
            )?],
            Vec::new(),
            vec![
                fixture(
                    ExtensionId::parse(auths_registries::BOUNDED_POLICY_COMMITMENT_EXTENSION_V1),
                    "extension",
                )?,
                fixture(
                    ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1),
                    "extension",
                )?,
            ],
            vec![fixture(call(&Map::new())?.profile_ref(), "profile")?],
            vec![fixture(ProfilePolicyId::parse(MCP_ARGUMENTS_V1), "policy")?],
        ),
        "registries",
    )
}

/// Trust pinned to `root` around `now`, with one observer anchor for
/// `observer`, pinning `configuration` or the gateway's own.
pub(crate) fn context(
    root: &Signer,
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
    now: u64,
) -> Result<TrustedContext, HarnessError> {
    context_with_depth(root, observer, configuration, now, 1)
}

/// Trust as in [`context`] that permits `depth` delegation edges.
pub(crate) fn context_with_depth(
    root: &Signer,
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
    now: u64,
    depth: u16,
) -> Result<TrustedContext, HarnessError> {
    context_with_roots(
        &[root],
        observer,
        configuration,
        now,
        depth,
        fixture(CompositionRequirement::new(None, 1, 1, 1), "composition")?,
    )
}

/// Trust with one anchor per root in `roots` under one composition
/// requirement, such as two authorized branches from two distinct roots.
pub(crate) fn context_with_roots(
    roots: &[&Signer],
    observer: &PrincipalId,
    configuration: Option<[u8; 32]>,
    now: u64,
    depth: u16,
    composition: CompositionRequirement,
) -> Result<TrustedContext, HarnessError> {
    let configuration = match configuration {
        Some(value) => auths_model::VerifierConfigurationId::new(value),
        None => fixture(gateway_verifier_configuration(), "configuration")?,
    };
    let assurance = fixture(AssurancePolicyId::parse(ASSURANCE), "assurance")?;
    let unbound = call(&Map::new())?;
    let mut anchors = Vec::with_capacity(roots.len());
    for (index, root) in roots.iter().enumerate() {
        let id = if roots.len() == 1 {
            "root".to_owned()
        } else {
            format!("root-{index}")
        };
        anchors.push(fixture(
            TrustAnchor::new(
                fixture(TrustAnchorId::parse(&id), "anchor ID")?,
                root.principal.clone(),
                vec![fixture(PrincipalMethodId::parse(RAW_KEY_V1), "method")?],
                vec![fixture(unbound.profile_ref(), "profile")?],
                fixture(
                    PermissionSet::new(vec![fixture(unbound.permission(), "permission")?]),
                    "permissions",
                )?,
                vec![fixture(
                    ResourceId::parse(&format!("mcp://{SERVICE}/")),
                    "namespace",
                )?],
                fixture(AudienceSet::new(vec![audience()?]), "audiences")?,
                window(now - 86_400, now + 86_400)?,
                None,
                depth,
                assurance.clone(),
                StatusPolicy::ExpiryOnly,
            ),
            "trust anchor",
        )?);
    }
    let context = fixture(
        TrustedContext::new(
            configuration,
            composition,
            anchors,
            accepted_registries()?,
            audience()?,
            Challenge::new([0; 32]),
            Timestamp::new(now),
            fixture(
                AssurancePolicy::new(assurance, Vec::new()),
                "assurance policy",
            )?,
            fixture(
                PrincipalStatusSnapshot::new(
                    StatusSnapshotId::new([0x63; 32]),
                    Timestamp::new(now - 86_400),
                    Timestamp::new(now + 86_400),
                    Vec::new(),
                    Vec::new(),
                ),
                "principal status",
            )?,
            fixture(
                GrantStatusSnapshot::new(
                    StatusSnapshotId::new([0x64; 32]),
                    Timestamp::new(now - 86_400),
                    Timestamp::new(now + 86_400),
                    Vec::new(),
                    Vec::new(),
                ),
                "grant status",
            )?,
            fixture(ResourceMatcherId::parse("uri-namespace-v1"), "matcher")?,
            fixture(ProfilePolicyId::parse(MCP_ARGUMENTS_V1), "policy")?,
            fixture(ChannelBindingId::parse("none-v1"), "channel")?,
            VerifierLimits::default(),
        ),
        "context",
    )?;
    fixture(
        context.with_observer_anchors(vec![observer_anchor(observer, now)?]),
        "observer anchors",
    )
}

/// The recorded value must equal the action's `expected` argument, read by
/// the gateway observer about the action's `record_uri`, at most 60 s ago.
pub(crate) fn read_back_requirement() -> Result<ObservationRequirement, HarnessError> {
    fixture(
        ObservationRequirement::new(
            fixture(ObserverAnchorId::parse(ANCHOR), "anchor")?,
            fixture(ObservationSchemaId::parse(READ_BACK_SCHEMA), "schema")?,
            ObservationSubject::ActionFact(name("record_uri")?),
            60,
            vec![ObservationCondition::new(
                name("value")?,
                ConditionTest::EqAction(name("expected")?),
            )],
        ),
        "requirement",
    )
}

/// A root grant to `subject` for the harness tool, carrying `requirement`.
pub(crate) fn grant(
    root: &Signer,
    subject: &PrincipalId,
    requirement: Option<ObservationRequirement>,
    now: u64,
) -> Result<SignedGrant, HarnessError> {
    grant_within(
        root,
        subject,
        requirement,
        window(now - 3_600, now + 86_400)?,
    )
}

/// A root grant to `subject` valid over `validity`.
pub(crate) fn grant_within(
    root: &Signer,
    subject: &PrincipalId,
    requirement: Option<ObservationRequirement>,
    validity: ValidityWindow,
) -> Result<SignedGrant, HarnessError> {
    let extensions = match requirement {
        None => CriticalExtensions::empty(),
        Some(requirement) => {
            let bytes = fixture(
                encode_observation_requirements(&fixture(
                    ObservationRequirements::new(vec![requirement]),
                    "requirements",
                )?),
                "requirement bytes",
            )?;
            fixture(
                CriticalExtensions::new(vec![fixture(
                    CriticalExtension::new(
                        fixture(
                            ExtensionId::parse(OBSERVATION_REQUIREMENT_EXTENSION_V1),
                            "extension",
                        )?,
                        bytes,
                    ),
                    "extension",
                )?]),
                "extensions",
            )?
        }
    };
    let unbound = call(&Map::new())?;
    let statement = GrantStatement::new(
        root.principal.clone(),
        subject.clone(),
        fixture(unbound.profile_ref(), "profile")?,
        fixture(
            PermissionSet::new(vec![fixture(unbound.permission(), "permission")?]),
            "permissions",
        )?,
        validity,
        fixture(AudienceSet::new(vec![audience()?]), "audiences")?,
        ActionConstraint::AnyBody,
        None,
        0,
        None,
        StatusPolicy::ExpiryOnly,
        fixture(AssurancePolicyId::parse(ASSURANCE), "assurance")?,
        extensions,
    );
    let descriptor = root.descriptor();
    let signature = root.sign(&fixture(
        grant_signing_preimage(&statement, &descriptor),
        "preimage",
    )?);
    Ok(SignedGrant::new(
        statement,
        SignatureEnvelope::new(descriptor, signature),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Delivery {
    Respond,
    #[cfg(test)]
    TimeoutAfterApplying,
}

/// Write entries, read-only observations, and credential leases so far.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCounts {
    /// Provider write entries.
    pub writes: usize,
    /// Read-only provider observations.
    pub reads: usize,
    /// Credential leases.
    pub leases: usize,
}

/// Synthetic provider that counts every write entry, read, and lease.
pub(crate) struct CountingProvider {
    delivery: Mutex<Delivery>,
    records: Mutex<Map<String, Value>>,
    writes: AtomicUsize,
    reads: AtomicUsize,
    pub(crate) leases: AtomicUsize,
}

impl CountingProvider {
    pub(crate) fn new() -> Self {
        let mut records = Map::new();
        for record in [RECORD, OTHER_RECORD] {
            records.insert(record.to_owned(), json!({"DemoStatus": "Pending"}));
        }
        Self {
            delivery: Mutex::new(Delivery::Respond),
            records: Mutex::new(records),
            writes: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            leases: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_delivery(&self, delivery: Delivery) {
        if let Ok(mut current) = self.delivery.lock() {
            *current = delivery;
        }
    }

    /// Another party with write access changes a known record.
    pub(crate) fn overwrite(&self, record: &str, status: &str) -> bool {
        self.records
            .lock()
            .ok()
            .and_then(|mut records| {
                records
                    .get_mut(record)
                    .map(|fields| fields["DemoStatus"] = json!(status))
            })
            .is_some()
    }

    fn record_of(url: &str) -> String {
        url.rsplit('/').next().unwrap_or_default().to_owned()
    }

    pub(crate) fn counts(&self) -> (usize, usize, usize) {
        (
            self.writes.load(Ordering::SeqCst),
            self.reads.load(Ordering::SeqCst),
            self.leases.load(Ordering::SeqCst),
        )
    }
}

impl ProviderPort for CountingProvider {
    async fn write(
        &self,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let body: Value = serde_json::from_slice(request.body())
            .map_err(|_| GatewayTransportError::NotEntered)?;
        let update = body["fields"].as_object().cloned().unwrap_or_default();
        let record = Self::record_of(request.url());
        let mut records = self
            .records
            .lock()
            .map_err(|_| GatewayTransportError::NotEntered)?;
        records
            .get_mut(&record)
            .and_then(Value::as_object_mut)
            .ok_or(GatewayTransportError::NotEntered)?
            .extend(update);
        let delivery = self
            .delivery
            .lock()
            .map_or(Delivery::Respond, |value| *value);
        Ok(match delivery {
            Delivery::Respond => WriteTransportOutcome::ResponseRecorded {
                status: 200,
                digest: [4; 32],
            },
            #[cfg(test)]
            Delivery::TimeoutAfterApplying => WriteTransportOutcome::Unknown,
        })
    }

    async fn read_back(&self, request: &ClosedObservationRequest) -> Option<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let record = Self::record_of(request.url());
        let fields = self.records.lock().ok()?.get(&record)?.clone();
        serde_json::to_vec(&json!({"id": record, "fields": fields})).ok()
    }
}

/// One installed recipe, its trust, attempt store, observer, and counting
/// provider.
pub(crate) struct Harness {
    pub(crate) recipe: CompiledRecipe,
    pub(crate) context: TrustedContext,
    pub(crate) store: GatewayAttempts,
    pub(crate) provider: CountingProvider,
    pub(crate) observer: GatewayObserver,
}

impl Harness {
    /// Keeps attempts in a single-host file store under `state`.
    pub(crate) fn with(
        recipe: CompiledRecipe,
        context: TrustedContext,
        observer: GatewayObserver,
        state: &Path,
    ) -> Result<Self, HarnessError> {
        let store = FileGatewayAttemptStore::open(state.join("attempts"))
            .map_err(|_| HarnessError::Store)?;
        Ok(Self::with_attempts(
            recipe,
            context,
            observer,
            GatewayAttempts::new(std::sync::Arc::new(store)),
        ))
    }

    /// Keeps attempts in `store`, such as the multi-host `PostgreSQL` store.
    pub(crate) fn with_attempts(
        recipe: CompiledRecipe,
        context: TrustedContext,
        observer: GatewayObserver,
        store: GatewayAttempts,
    ) -> Self {
        Self {
            recipe,
            context,
            store,
            provider: CountingProvider::new(),
            observer,
        }
    }

    /// Mirrors the engine: verify at `now`, claim, reserve any bounded-policy
    /// window slot, lease, then enter the provider. A replay never writes
    /// again.
    pub(crate) async fn submit(
        &self,
        proof: &[u8],
        action: &[u8],
        now: u64,
    ) -> GatewaySubmitResult {
        let (request, bound) = match verify_command(&self.recipe, &self.context, now, proof, action)
        {
            Ok(value) => value,
            Err(result) => return result,
        };
        match self.store.claim(&request, *self.recipe.digest()).await {
            Ok(claim) => {
                let claim = match reserve_bound(&self.store, bound.as_ref(), &request, claim).await
                {
                    Ok(value) => value,
                    Err(result) => return result,
                };
                self.provider.leases.fetch_add(1, Ordering::SeqCst);
                execute_claimed(claim, &request, &self.provider).await
            }
            Err(GatewayAttemptError::Replay) => {
                match self
                    .store
                    .resume_observable(&request, *self.recipe.digest())
                    .await
                {
                    Ok(Some(attempt)) => {
                        self.provider.leases.fetch_add(1, Ordering::SeqCst);
                        reobserve(attempt, &request, &self.provider).await
                    }
                    _ => replay_refused(),
                }
            }
            Err(_) => not_entered("gateway.attempt.unavailable"),
        }
    }

    /// Mirrors the engine's observation request at `now`: a read-back leases
    /// the credential for one read-only GET; an outcome reads only the store.
    pub(crate) async fn observe(
        &self,
        request: &GatewayObserveRequest,
        now: u64,
    ) -> GatewayObserveResult {
        match request {
            GatewayObserveRequest::Outcome { operation_id } => {
                observe_outcome(
                    &self.store,
                    self.recipe.namespace(),
                    &self.observer,
                    operation_id,
                    now,
                )
                .await
            }
            GatewayObserveRequest::ReadBack { arguments } => {
                let Ok(target) = self.recipe.read_back_target(arguments) else {
                    return GatewayObserveResult::Refused {
                        code: "gateway.observer.invalid-read-back".to_owned(),
                    };
                };
                self.provider.leases.fetch_add(1, Ordering::SeqCst);
                observe_read_back(&target, &self.observer, &self.provider, || Some(now)).await
            }
        }
    }
}

#[cfg(all(unix, feature = "testkit-harness"))]
pub use process::{HarnessSetup, serve};

#[cfg(all(unix, feature = "testkit-harness"))]
mod process {
    //! The harness as a process behind the gateway's own application socket
    //! protocol, plus a private control socket that changes a record,
    //! advances the gateway clock, and reports provider counts.

    use super::{
        Harness, HarnessError, OBSERVER_SEED, OTHER_RECORD, ProviderCounts, RECORD, ROOT_SEED,
        SERVICE, Signer, TOOL, context, grant, read_back_requirement, read_back_subject,
        update_recipe,
    };
    use crate::GatewayObserver;
    use crate::app::{GatewayApplication, app_session, read_frame, write_frame};
    use crate::engine::{GatewayObserveRequest, GatewayObserveResult, GatewaySubmitResult};
    use auths_model::PrincipalId;
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use serde::{Deserialize, Serialize};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::{UnixListener, UnixStream};

    /// Public facts a harness client needs: the sockets, the trust the
    /// harness gateway verifies with, the agent's grant, and the clock.
    #[derive(Debug, Serialize)]
    pub struct HarnessSetup {
        schema: &'static str,
        app_socket: PathBuf,
        control_socket: PathBuf,
        now: u64,
        challenge_b64: String,
        trusted_context_b64: String,
        signed_grant_b64: String,
        root_evidence: Evidence,
        service: &'static str,
        tool: &'static str,
        operator_namespace: &'static str,
        recipe_digest: String,
        records: [Record; 2],
        observer: String,
    }

    #[derive(Debug, Serialize)]
    struct Evidence {
        #[serde(rename = "evidence_type")]
        kind: String,
        media_type: String,
        bytes_b64: String,
    }

    #[derive(Debug, Serialize)]
    struct Record {
        record_id: &'static str,
        read_back_subject: String,
    }

    #[derive(Deserialize)]
    #[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
    enum Control {
        SetRecord { record_id: String, status: String },
        AdvanceClock { seconds: u64 },
        Counts,
    }

    #[derive(Serialize)]
    struct ControlResponse {
        ok: bool,
        now: u64,
        writes: usize,
        reads: usize,
        leases: usize,
    }

    struct Application {
        harness: Harness,
        clock: AtomicU64,
    }

    impl GatewayApplication for Application {
        async fn submit(&self, proof: &[u8], action: &[u8]) -> GatewaySubmitResult {
            self.harness
                .submit(proof, action, self.clock.load(Ordering::SeqCst))
                .await
        }

        async fn observe(&self, request: &GatewayObserveRequest) -> GatewayObserveResult {
            self.harness
                .observe(request, self.clock.load(Ordering::SeqCst))
                .await
        }
    }

    impl Application {
        fn counts(&self) -> ProviderCounts {
            let (writes, reads, leases) = self.harness.provider.counts();
            ProviderCounts {
                writes,
                reads,
                leases,
            }
        }

        fn control(&self, bytes: &[u8]) -> ControlResponse {
            let ok = match serde_json::from_slice::<Control>(bytes) {
                Ok(Control::SetRecord { record_id, status }) => {
                    matches!(status.as_str(), "Approved" | "Pending")
                        && self.harness.provider.overwrite(&record_id, &status)
                }
                Ok(Control::AdvanceClock { seconds }) => {
                    seconds <= 86_400
                        && self
                            .clock
                            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                                now.checked_add(seconds)
                            })
                            .is_ok()
                }
                Ok(Control::Counts) => true,
                Err(_) => false,
            };
            let counts = self.counts();
            ControlResponse {
                ok,
                now: self.clock.load(Ordering::SeqCst),
                writes: counts.writes,
                reads: counts.reads,
                leases: counts.leases,
            }
        }
    }

    async fn control_session(mut stream: UnixStream, application: &Application) {
        if let Ok(bytes) = read_frame(&mut stream).await
            && let Ok(response) = serde_json::to_vec(&application.control(&bytes))
        {
            let _ = write_frame(&mut stream, &response).await;
        }
    }

    fn encode(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    /// Binds the harness sockets in `state`, then returns the setup facts
    /// and a future that serves both sockets until the process ends.
    ///
    /// The root and observer keys are public fixed seeds, and `agent` is the
    /// principal the harness grants the expected-before-replacement
    /// requirement to. Nothing here is production trust.
    ///
    /// # Errors
    ///
    /// Returns a [`HarnessError`] when a fixture cannot be built, the state
    /// directory cannot hold the attempt store, or a socket cannot bind.
    pub async fn serve(
        state: &Path,
        agent: &str,
        now: u64,
    ) -> Result<
        (
            HarnessSetup,
            impl std::future::Future<Output = Result<(), HarnessError>>,
        ),
        HarnessError,
    > {
        let agent =
            PrincipalId::parse(agent).map_err(|_| HarnessError::Fixture("agent principal"))?;
        if !(86_400..u64::MAX - 172_800).contains(&now) {
            return Err(HarnessError::Fixture("clock"));
        }
        let state = std::fs::canonicalize(state).map_err(|_| HarnessError::Store)?;
        let state = state.as_path();
        let root = Signer::new(ROOT_SEED);
        let observer = GatewayObserver::from_test_seed(OBSERVER_SEED);
        let context = context(&root, observer.principal(), None, now)?;
        let context_bytes = auths_codec::encode_verifier_context(&context)
            .map_err(|_| HarnessError::Fixture("context bytes"))?;
        let signed = grant(&root, &agent, Some(read_back_requirement()?), now)?;
        let grant_bytes = auths_codec::encode_signed_grant(&signed)
            .map_err(|_| HarnessError::Fixture("grant bytes"))?;
        let evidence = root.evidence();
        let recipe = update_recipe()?;
        let setup = HarnessSetup {
            schema: "auths.gateway-harness/1",
            app_socket: state.join("app.sock"),
            control_socket: state.join("control.sock"),
            now,
            challenge_b64: encode(&[0; 32]),
            trusted_context_b64: encode(&context_bytes),
            signed_grant_b64: encode(&grant_bytes),
            root_evidence: Evidence {
                kind: evidence.evidence_type().as_str().to_owned(),
                media_type: evidence.media_type().as_str().to_owned(),
                bytes_b64: encode(evidence.bytes()),
            },
            service: SERVICE,
            tool: TOOL,
            operator_namespace: super::NAMESPACE,
            recipe_digest: recipe.digest_hex(),
            records: [
                Record {
                    record_id: RECORD,
                    read_back_subject: read_back_subject(RECORD),
                },
                Record {
                    record_id: OTHER_RECORD,
                    read_back_subject: read_back_subject(OTHER_RECORD),
                },
            ],
            observer: observer.principal().as_str().to_owned(),
        };
        let application = Arc::new(Application {
            harness: Harness::with(recipe, context, observer, state)?,
            clock: AtomicU64::new(now),
        });
        let bind =
            |path: &Path| UnixListener::bind(path).map_err(|_| HarnessError::Fixture("socket"));
        let app = bind(&setup.app_socket)?;
        let control = bind(&setup.control_socket)?;
        let running = async move {
            loop {
                tokio::select! {
                    accepted = app.accept() => {
                        let (stream, _) = accepted.map_err(|_| HarnessError::Fixture("accept"))?;
                        let application = Arc::clone(&application);
                        tokio::spawn(async move { app_session(stream, application.as_ref()).await; });
                    }
                    accepted = control.accept() => {
                        let (stream, _) = accepted.map_err(|_| HarnessError::Fixture("accept"))?;
                        let application = Arc::clone(&application);
                        tokio::spawn(async move { control_session(stream, &application).await; });
                    }
                }
            }
        };
        Ok((setup, running))
    }
}
