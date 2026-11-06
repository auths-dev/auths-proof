//! ADR0022 conformance resource. This adapter lives only in the test executable;
//! the gateway interprets its approved recipe as data and knows no records fields.
use super::*;
use auths_records_api::{
    BoundedRecordApiPolicyV1, CreateRecordProfile, CreateRecordV1, CustomerRecordV1,
    DeliveryAdapter, DeliveryReceipt, ExecutionClassification, PersistentRecordsLedger,
    PresentationClaimsV1, ReadField, ReadRecordProfile, ReadRecordV1, RecordIdentifier,
    RecordsActionV1, RecordsApiVerifierConfigurationV1, RecordsError, RecordsExecutionRequest,
    RecordsLedger, RecordsPresentationV1, RecordsRequestEnvelopeV1, RecordsService,
    RecordsWorkflowOutcome, SdkRecordsProofVerifier, demo_configuration,
    testkit::{
        AuthorizationFixture, PersistentRecordsLifecycleRegistry, authorization_fixture,
        authorization_fixture_with_signers,
    },
};
use std::sync::atomic::AtomicUsize;

const AUDIENCE: &str = "https://native-records.example.invalid";
const NAMESPACE: &str = "ap073_native_records";

type Service = RecordsService<
    SdkRecordsProofVerifier,
    Arc<PersistentRecordsLedger>,
    Arc<PersistentRecordsLifecycleRegistry>,
>;
struct NativeAction {
    envelope: RecordsRequestEnvelopeV1,
    service: Service,
    policy: BoundedRecordApiPolicyV1,
    configuration: RecordsApiVerifierConfigurationV1,
    challenge: [u8; 32],
}
impl NativeAction {
    fn try_execute(
        &self,
        envelope: RecordsRequestEnvelopeV1,
        now: u64,
        required: RecordsApiVerifierConfigurationV1,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        self.service.execute(&RecordsExecutionRequest {
            envelope,
            policy: self.policy.clone(),
            required_configuration: required,
            auths_request: auths_sdk::RequestContext::new(AUDIENCE, self.challenge, now)
                .expect("native server context"),
            challenge: self.challenge,
            delivery: DeliveryReceipt {
                schema: "auths.records-delivery-receipt/1".into(),
                delivery_id: format!("native-delivery-{now}"),
                adapter: DeliveryAdapter::Https,
                adapter_identity: "loopback-native-resource-conformance".into(),
                protocol: "auths.records-api/1".into(),
                received_at: now,
            },
            now,
        })
    }
    fn execute(&self, envelope: RecordsRequestEnvelopeV1, now: u64) -> RecordsWorkflowOutcome {
        self.try_execute(envelope, now, self.configuration.clone())
            .expect("valid native resource request")
    }
    fn current(&self) -> RecordsWorkflowOutcome {
        self.execute(self.envelope.clone(), server_time())
    }
}
fn server_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("resource server clock")
        .as_secs()
}
fn policy(principal: &str, scope: &str, now: u64) -> BoundedRecordApiPolicyV1 {
    let mut policy: BoundedRecordApiPolicyV1 = serde_json::from_slice(include_bytes!(
        "../../../../../../product/fixtures/v1/records-api/policy.json"
    ))
    .expect("records policy");
    policy.policy_id = format!("native-{scope}");
    policy.namespace_id = RecordIdentifier::parse(NAMESPACE).unwrap();
    policy.presenter_principal = principal.into();
    policy.executor_audience = AUDIENCE.into();
    policy.valid_from = now - 1;
    policy.expires_at = now + 300;
    policy.allowed_record_id_prefixes = Vec::new();
    policy.allowed_record_ids = [RECORD, CREATED_RESOURCE]
        .map(|id| RecordIdentifier::parse(id).unwrap())
        .to_vec();
    policy.allowed_record_ids.sort();
    policy.maximum_creates = 1;
    policy.maximum_reads = 2;
    policy.maximum_created_bytes = 4096;
    policy.maximum_disclosed_bytes = 8192;
    policy.maximum_value_bytes = 4096;
    policy.maximum_response_bytes = 4096;
    policy.validate().expect("native resource policy");
    policy
}
fn customer(content: &[u8], occupation: &str) -> CustomerRecordV1 {
    CustomerRecordV1 {
        age: 31,
        name: "Private native fixture".into(),
        notes: String::from_utf8(content.to_vec()).unwrap(),
        occupation: occupation.into(),
    }
}
fn create(
    policy: &BoundedRecordApiPolicyV1,
    configuration: &RecordsApiVerifierConfigurationV1,
    record: &str,
    content: &[u8],
    now: u64,
) -> RecordsActionV1 {
    RecordsActionV1::Create(CreateRecordV1 {
        profile: "auths.demo.records.create/1".into(),
        namespace_id: policy.namespace_id.clone(),
        record_id: RecordIdentifier::parse(record).unwrap(),
        customer: customer(
            content,
            if record == RECORD {
                "Pending"
            } else {
                "Approved"
            },
        ),
        value_encoding: "auths.demo.customer-record/1".into(),
        expected_absent: true,
        policy_digest: policy.digest().unwrap(),
        required_evaluator: "auths.records.create-evaluator/1".into(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: AUDIENCE.into(),
        expires_at: now + 250,
        nonce: format!("native-create-{record}"),
    })
}
fn read(
    policy: &BoundedRecordApiPolicyV1,
    configuration: &RecordsApiVerifierConfigurationV1,
    record: &str,
    now: u64,
) -> RecordsActionV1 {
    RecordsActionV1::Read(ReadRecordV1 {
        profile: "auths.demo.records.read/1".into(),
        namespace_id: policy.namespace_id.clone(),
        record_id: RecordIdentifier::parse(record).unwrap(),
        allowed_fields: vec![ReadField::Customer, ReadField::RecordId, ReadField::Version],
        maximum_response_bytes: 4096,
        expected_record_version: 1,
        policy_digest: policy.digest().unwrap(),
        required_evaluator: "auths.records.read-evaluator/1".into(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: AUDIENCE.into(),
        expires_at: now + 250,
        nonce: format!("native-read-{record}"),
    })
}
#[allow(
    clippy::too_many_arguments,
    reason = "explicit native authoring inputs and the existing two resource store owners"
)]
fn prepared(
    fixture: AuthorizationFixture,
    action: RecordsActionV1,
    policy: BoundedRecordApiPolicyV1,
    configuration: &RecordsApiVerifierConfigurationV1,
    challenge: [u8; 32],
    signer: &mut Actor,
    ledger: &Arc<PersistentRecordsLedger>,
    registry: &Arc<PersistentRecordsLifecycleRegistry>,
    now: u64,
) -> NativeAction {
    let presentation = RecordsPresentationV1::prepare(
        signer.public.key,
        &fixture.proof,
        &PresentationClaimsV1 {
            operation_id: action.operation_id().into(),
            canonical_action_digest: action.digest().unwrap(),
            challenge,
            executor_audience: AUDIENCE.into(),
            created_at: now,
            expires_at: now + 120,
            presentation_nonce: format!("native-{}", action.digest().unwrap()),
        },
    )
    .unwrap();
    let signature = signer.sign(presentation.signing_message());
    let signature: [u8; 64] = signature.as_slice().try_into().unwrap();
    let envelope = RecordsRequestEnvelopeV1 {
        envelope_version: "auths.records-envelope/1".into(),
        operation_id: action.operation_id().into(),
        canonical_action: action,
        proof_hex: hex::encode(fixture.proof),
        presentation: presentation.complete(signature),
    };
    NativeAction {
        envelope,
        service: RecordsService::new(
            SdkRecordsProofVerifier::new(fixture.verifier),
            Arc::clone(ledger),
            Arc::clone(registry),
            configuration.clone(),
        ),
        policy,
        configuration: configuration.clone(),
        challenge,
    }
}

pub(super) struct NativeFixture {
    child: NativeAction,
    parent_read: NativeAction,
    child_read: NativeAction,
    ledger: Arc<PersistentRecordsLedger>,
    native_policy: BoundedRecordApiPolicyV1,
    preflight_refusals: Vec<String>,
}
impl NativeFixture {
    #[allow(
        clippy::too_many_lines,
        reason = "one complete native fixture and independent refusal batch before construction"
    )]
    pub(super) fn new(
        operator: &Path,
        owner: &mut Actor,
        a: &mut Actor,
        b: &mut Actor,
        content: &[u8],
        now: u64,
    ) -> Self {
        let directory = operator.join("native-records");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ledger =
            Arc::new(PersistentRecordsLedger::open(directory.join("records.json")).unwrap());
        let registry = Arc::new(PersistentRecordsLifecycleRegistry::new(directory.clone()));
        let configuration = demo_configuration(AUDIENCE);
        // Existing parent state is independent operator setup, not a B effect or
        // a newly inferred allowance. It has a separate exact native policy.
        let bootstrap_principal = RecordsPresentationV1::signer_principal(
            &SigningKey::from_bytes(&[0xa3; 32])
                .verifying_key()
                .to_bytes(),
        );
        let bootstrap_policy = policy(&bootstrap_principal, "operator-setup", now);
        let action = create(&bootstrap_policy, &configuration, RECORD, content, now);
        let challenge = [0xA1; 32];
        let bytes = action.canonical_bytes().unwrap();
        let fixture = authorization_fixture(
            &CreateRecordProfile,
            &bytes,
            AUDIENCE,
            NAMESPACE,
            now,
            challenge,
        );
        let presentation = RecordsPresentationV1::sign(
            &SigningKey::from_bytes(&[0xa3; 32]),
            &fixture.proof,
            &PresentationClaimsV1 {
                operation_id: action.operation_id().into(),
                canonical_action_digest: action.digest().unwrap(),
                challenge,
                executor_audience: AUDIENCE.into(),
                created_at: now,
                expires_at: now + 120,
                presentation_nonce: "native-operator-setup".into(),
            },
        )
        .unwrap();
        let outcome = RecordsService::new(
            SdkRecordsProofVerifier::new(fixture.verifier),
            Arc::clone(&ledger),
            Arc::clone(&registry),
            configuration.clone(),
        )
        .execute(&RecordsExecutionRequest {
            envelope: RecordsRequestEnvelopeV1 {
                envelope_version: "auths.records-envelope/1".into(),
                operation_id: action.operation_id().into(),
                canonical_action: action,
                proof_hex: hex::encode(fixture.proof),
                presentation,
            },
            policy: bootstrap_policy,
            required_configuration: configuration.clone(),
            auths_request: fixture.request,
            challenge,
            delivery: DeliveryReceipt {
                schema: "auths.records-delivery-receipt/1".into(),
                delivery_id: "operator-setup".into(),
                adapter: DeliveryAdapter::File,
                adapter_identity: "independent-native-parent-setup".into(),
                protocol: "auths.records-api/1".into(),
                received_at: now,
            },
            now,
        })
        .unwrap();
        assert_eq!(
            outcome.receipt.execution,
            ExecutionClassification::Executed,
            "operator setup refused: {} / {}",
            outcome.receipt.decision.decision.code,
            outcome.receipt.decision.auths_code
        );
        let native_policy = policy(
            &RecordsPresentationV1::signer_principal(&b.public.key),
            "delegated-child",
            now,
        );
        let mut make = |action: RecordsActionV1, challenge: [u8; 32]| {
            let bytes = action.canonical_bytes().unwrap();
            let fixture = match &action {
                RecordsActionV1::Create(_) => authorization_fixture_with_signers(
                    &CreateRecordProfile,
                    &bytes,
                    AUDIENCE,
                    NAMESPACE,
                    now,
                    challenge,
                    owner,
                    a,
                    b,
                ),
                RecordsActionV1::Read(_) => authorization_fixture_with_signers(
                    &ReadRecordProfile,
                    &bytes,
                    AUDIENCE,
                    NAMESPACE,
                    now,
                    challenge,
                    owner,
                    a,
                    b,
                ),
            };
            assert_eq!(fixture.agent_principal, b.public.principal.as_str());
            prepared(
                fixture,
                action,
                native_policy.clone(),
                &configuration,
                challenge,
                b,
                &ledger,
                &registry,
                now,
            )
        };
        let child = make(
            create(
                &native_policy,
                &configuration,
                CREATED_RESOURCE,
                b"AUTHORIZED_NATIVE_CHILD_CONTENT",
                now,
            ),
            [0xB1; 32],
        );
        let parent_read = make(
            read(&native_policy, &configuration, RECORD, now),
            [0xB2; 32],
        );
        let child_read = make(
            read(&native_policy, &configuration, CREATED_RESOURCE, now),
            [0xB3; 32],
        );
        drop(make);
        let mut preflight_refusals = Vec::new();
        for name in [
            "native-proof",
            "native-presentation",
            "native-action",
            "native-audience",
            "native-stale-presentation",
            "native-configuration",
        ] {
            let mut envelope = child.envelope.clone();
            let mut required = configuration.clone();
            match name {
                "native-proof" => {
                    let mut proof = hex::decode(&envelope.proof_hex).unwrap();
                    let last = proof.last_mut().unwrap();
                    *last ^= 1;
                    let input = &envelope.presentation.input;
                    let prepared = RecordsPresentationV1::prepare(
                        b.public.key,
                        &proof,
                        &PresentationClaimsV1 {
                            operation_id: input.operation_id.clone(),
                            canonical_action_digest: input.canonical_action_digest.clone(),
                            challenge: child.challenge,
                            executor_audience: AUDIENCE.into(),
                            created_at: input.created_at,
                            expires_at: input.expires_at,
                            presentation_nonce: input.presentation_nonce.clone(),
                        },
                    )
                    .unwrap();
                    let signature = b.sign(prepared.signing_message());
                    envelope.presentation =
                        prepared.complete(signature.as_slice().try_into().unwrap());
                    envelope.proof_hex = hex::encode(proof);
                }
                "native-presentation" => envelope.presentation.signature = "00".repeat(64),
                "native-action" => {
                    let RecordsActionV1::Create(action) = &mut envelope.canonical_action else {
                        unreachable!()
                    };
                    action.customer.occupation = "Substituted".into();
                }
                "native-audience" => {
                    envelope.presentation.input.executor_audience =
                        "https://wrong.example.invalid".into()
                }
                "native-stale-presentation" => envelope.presentation.input.expires_at = now - 1,
                "native-configuration" => required.maximum_evaluator_work += 1,
                _ => unreachable!(),
            }
            if let Ok(result) = child.try_execute(envelope, now, required) {
                assert_eq!(
                    result.receipt.execution,
                    ExecutionClassification::NotAuthorized,
                    "{name}"
                );
                assert!(!result.receipt.decision.protected_storage_accessed);
                assert!(result.projection.is_none());
            }
            let usage = ledger.usage(&native_policy.digest().unwrap()).unwrap();
            assert_eq!(
                (usage.create_units, usage.read_units),
                (0, 0),
                "native refusal changed protected usage: {name}"
            );
            preflight_refusals.push(name.into());
        }
        // Refusal receipts may be appended, so compare protected policy usage,
        // not the complete audit-store hash, which legitimately records denial.
        let usage = ledger.usage(&native_policy.digest().unwrap()).unwrap();
        assert_eq!((usage.create_units, usage.read_units), (0, 0));
        Self {
            child,
            parent_read,
            child_read,
            ledger,
            native_policy,
            preflight_refusals,
        }
    }
    pub(super) fn action(&self) -> String {
        String::from_utf8(
            self.child
                .envelope
                .canonical_action
                .canonical_bytes()
                .unwrap(),
        )
        .unwrap()
    }
    pub(super) fn proof_commitment(&self) -> String {
        auths_records_api::canonical::canonical_digest(&self.child.envelope).unwrap()
    }
    fn report(&self) -> Value {
        let usage = self
            .ledger
            .usage(&self.native_policy.digest().unwrap())
            .unwrap();
        assert_eq!(usage.create_units, 1);
        assert_eq!(usage.read_units, 2);
        json!({"native_profile":"auths.records-api/1","protected_entry_requires_dispatch_credential":true,
            "independent_native_proof_and_presentation":true,"externally_held_owner_a_b_keys":true,
            "native_preflight_refusals":self.preflight_refusals,"preflight_protected_effects":0,
            "native_child_create_units":usage.create_units,"native_unique_read_units":usage.read_units,
            "parent_is_independent_operator_setup":true,"read_proofs_separately_installed_by_exact_action":true,
            "ap073_state_owner":"existing-gateway","native_ledger_is_provider_state":true,"native_proof_reverified_at_fresh_resource_time":true,
            "not_established":["production-recipe-qualification","provider-process-crash","provider-https","native-proof-exchange-transport","independent-human-operator-consent"]})
    }
}

pub(super) struct InstalledProvider {
    pub(super) port: u16,
    inner: Kind,
}
enum Kind {
    Standard(Provider),
    Native(NativeProvider),
}
impl InstalledProvider {
    pub(super) fn standard(
        secret: Vec<u8>,
        content: Vec<u8>,
        creation: Option<CreatedListing>,
    ) -> Self {
        let provider = match creation {
            None => Provider::with_content(secret, true, content),
            Some(listing) => Provider::with_created_content(secret, content, listing),
        };
        Self {
            port: provider.port,
            inner: Kind::Standard(provider),
        }
    }
    pub(super) fn native(secret: Vec<u8>, fixture: NativeFixture) -> Self {
        let provider = NativeProvider::start(secret, fixture);
        Self {
            port: provider.port,
            inner: Kind::Native(provider),
        }
    }
    pub(super) fn calls(&self) -> Vec<String> {
        match &self.inner {
            Kind::Standard(p) => p.calls(),
            Kind::Native(p) => p.calls.lock().unwrap().clone(),
        }
    }
    pub(super) fn hold_write_response(&self) {
        match &self.inner {
            Kind::Standard(p) => p.hold_write_response(),
            Kind::Native(p) => {
                p.applied.store(false, Ordering::SeqCst);
                p.hold.store(true, Ordering::SeqCst);
            }
        }
    }
    pub(super) fn wait_for_applied_write(&self) {
        match &self.inner {
            Kind::Standard(p) => p.wait_for_applied_write(),
            Kind::Native(p) => {
                let deadline = Instant::now() + Duration::from_secs(10);
                while !p.applied.load(Ordering::SeqCst) {
                    assert!(Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
    pub(super) fn drop_write_response(&self) {
        match &self.inner {
            Kind::Standard(p) => p.drop_write_response(),
            Kind::Native(p) => p.hold.store(false, Ordering::SeqCst),
        }
    }
    pub(super) fn native_report(&self) -> Value {
        match &self.inner {
            Kind::Standard(_) => Value::Null,
            Kind::Native(p) => {
                let mut report = p.fixture.report();
                let denials = p.denied.load(Ordering::SeqCst);
                assert_eq!(
                    denials, 6,
                    "five installed roles and the substituted credential must each be refused"
                );
                report["dispatch_credential_refusals"] = json!(denials);
                report
            }
        }
    }
}
struct NativeProvider {
    port: u16,
    denied: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<String>>>,
    fixture: Arc<NativeFixture>,
    stop: Arc<AtomicBool>,
    hold: Arc<AtomicBool>,
    applied: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCreateWrapper {
    parent_id: String,
    fields: NativeCreateFields,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCreateFields {
    #[serde(rename = "DemoStatus")]
    status: String,
    auths_echo: String,
    native_action: String,
    native_proof_commitment: String,
}
fn refuse_native(stream: &mut std::net::TcpStream) {
    stream
        .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        .expect("fixed native refusal");
}
impl NativeProvider {
    #[allow(
        clippy::too_many_lines,
        reason = "bounded reference HTTP framing keeps native verification and actual resource facts visible"
    )]
    fn start(secret: Vec<u8>, fixture: NativeFixture) -> Self {
        let fixture = Arc::new(fixture);
        let shared = Arc::clone(&fixture);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&calls);
        let denied = Arc::new(AtomicUsize::new(0));
        let refused = Arc::clone(&denied);
        let stop = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&stop);
        let hold = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&hold);
        let applied = Arc::new(AtomicBool::new(false));
        let entered = Arc::clone(&applied);
        let secret = Zeroizing::new(secret);
        let worker = thread::spawn(move || {
            let mut marker = None;
            while !finished.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("native resource accept: {e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16384);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                if !Provider::authenticated(&header, &secret) {
                    refused.fetch_add(1, Ordering::SeqCst);
                    stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap();
                    continue;
                }
                let line = header.lines().next().unwrap().to_owned();
                let length = header
                    .lines()
                    .find_map(|l| {
                        l.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length <= 16384);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                captured.lock().unwrap().push(line.clone());
                let (media, response) = if line
                    == format!("GET /documents/{RECORD}?format=text%2Fplain HTTP/1.1")
                    || line
                        == format!("GET /documents/{CREATED_RESOURCE}?format=text%2Fplain HTTP/1.1")
                {
                    let action = if line.contains(CREATED_RESOURCE) {
                        &shared.child_read
                    } else {
                        &shared.parent_read
                    };
                    let result = action.current();
                    assert!(matches!(
                        result.receipt.execution,
                        ExecutionClassification::Executed | ExecutionClassification::ReplayEffect
                    ));
                    let projection = result.projection.unwrap();
                    let customer = projection.customer.unwrap();
                    ("text/plain", customer.notes.into_bytes())
                } else if line == format!("POST /parents/{RECORD}/children HTTP/1.1") {
                    let Ok(wrapper) = serde_json::from_slice::<NativeCreateWrapper>(&body) else {
                        refuse_native(&mut stream);
                        continue;
                    };
                    if wrapper.parent_id != RECORD
                        || wrapper.fields.status != "Approved"
                        || wrapper.fields.native_proof_commitment != shared.proof_commitment()
                        || !wrapper.fields.auths_echo.starts_with("auths-e1-")
                        || wrapper.fields.auths_echo.len() != 73
                    {
                        refuse_native(&mut stream);
                        continue;
                    }
                    let Ok(action) = CreateRecordV1::from_canonical_bytes(
                        wrapper.fields.native_action.as_bytes(),
                    ) else {
                        refuse_native(&mut stream);
                        continue;
                    };
                    let mut envelope = shared.child.envelope.clone();
                    envelope.canonical_action = RecordsActionV1::Create(action);
                    let Ok(result) = shared.child.try_execute(
                        envelope,
                        server_time(),
                        shared.child.configuration.clone(),
                    ) else {
                        refuse_native(&mut stream);
                        continue;
                    };
                    if result.receipt.execution != ExecutionClassification::Executed {
                        refuse_native(&mut stream);
                        continue;
                    }
                    marker = Some(wrapper.fields.auths_echo);
                    entered.store(true, Ordering::SeqCst);
                    if held.load(Ordering::SeqCst) {
                        while held.load(Ordering::SeqCst) && !finished.load(Ordering::SeqCst) {
                            thread::sleep(Duration::from_millis(5));
                        }
                        continue;
                    }
                    ("application/json", body)
                } else if line == format!("GET /parents/{RECORD}/children HTTP/1.1") {
                    let result = shared.child_read.current();
                    assert!(matches!(
                        result.receipt.execution,
                        ExecutionClassification::Executed | ExecutionClassification::ReplayEffect
                    ));
                    let projection = result.projection.unwrap();
                    assert_eq!(projection.record_id.as_deref(), Some(CREATED_RESOURCE));
                    assert_eq!(projection.version, Some(1));
                    ("application/json",serde_json::to_vec(&json!({"records":[{"id":projection.record_id,"parent_id":RECORD,"auths_echo":marker.as_ref().unwrap()}]})).unwrap())
                } else {
                    panic!("unexpected native resource request: {line}")
                };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",response.len()).as_bytes()).unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        let mut probe = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        probe
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        probe.write_all(format!("GET /documents/{RECORD}?format=text%2Fplain HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer invalid-native-dispatch-credential\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        let mut response = String::new();
        probe.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 401"));
        assert!(calls.lock().unwrap().is_empty());
        Self {
            port,
            denied,
            calls,
            fixture,
            stop,
            hold,
            applied,
            worker: Some(worker),
        }
    }
}
impl Drop for NativeProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.hold.store(false, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}
