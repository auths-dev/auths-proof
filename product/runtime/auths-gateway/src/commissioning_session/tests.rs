//! Synthetic authority over the installed engine I/O boundary, with real
//! native quorum proof verification and counted custody. No provider I/O,
//! production deployment or protected qualification is claimed here.

use super::*;
use crate::engine::tests::administration::{Installation, installation};
use crate::harness::Signer;
use crate::submit::SubmitIo as _;
use crate::{
    FixedClock, OperatorAttestation, OperatorEvidence, OperatorStatement, QualificationGate,
    QualificationPolicy,
};
use auths_recipe_qualification::{
    QualificationCommissioningPermit, QualificationTrustRoot, SignatureB64, VerifierState,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::Value;
use std::{os::unix::fs::PermissionsExt as _, sync::atomic::Ordering};

const NOW: u64 = 1_790_000_000;

struct Setup {
    installation: Installation,
    directory: tempfile::TempDir,
    clock: Arc<FixedClock>,
    permit: QualificationCommissioningPermit,
    certificate: Vec<u8>,
    revocations: Vec<u8>,
    attestation: Vec<u8>,
    resources: Vec<u8>,
    proof: Vec<u8>,
    action: Vec<u8>,
}

impl Setup {
    #[allow(
        clippy::too_many_lines,
        reason = "one explicit fixture binds native proof, operator signature and permit to the same installed engine"
    )]
    async fn new() -> Self {
        let mut installation = installation(8).await;
        let document: Value = serde_json::from_slice(include_bytes!(
            "../../../../../bindings/fixtures/gateway/approval-quorum.json"
        ))
        .expect("quorum fixture");
        let decode = |value: &Value| {
            Base64UrlUnpadded::decode_vec(value.as_str().expect("base64")).expect("fixture bytes")
        };
        let trust = decode(&document["trusted_context_b64"]);
        let proof = decode(&document["cases"][0]["proof_b64"]);
        let action = decode(&document["cases"][0]["action_b64"]);
        let engine = &mut installation.first.engine;
        engine.trusted_context = auths_codec::decode_verifier_context(&trust).expect("trust");
        engine.trusted_context_sha256 = Sha256Digest::from_bytes(Sha256::digest(&trust).into());
        let verified = super::super::verify_detailed(
            &engine.recipe,
            &engine.trusted_context,
            NOW,
            &proof,
            &action,
        )
        .expect("native fixture authorization");
        assert_eq!(verified.actors.len(), 1);
        let artifacts: Value = serde_json::from_slice(include_bytes!(
            "../../../../../bindings/fixtures/qualification/commissioning-v1.json"
        ))
        .expect("authority fixture");
        let text = |name: &str| artifacts[name].as_str().expect("artifact").as_bytes();
        let original =
            QualificationCommissioningPermit::from_canonical_json(text("permit")).expect("permit");
        let mut body = original.body().clone();
        let resources = br#"{"schema":"synthetic-resources/1"}"#.to_vec();
        body.statement.binding.tuple.compiled_recipe_sha256 =
            Sha256Digest::from_bytes(*engine.recipe.digest());
        body.statement.binding.tuple.target.store_schema =
            BoundedText::parse(crate::POSTGRES_STORE_SCHEMA).expect("schema");
        body.statement.binding.trusted_context_sha256 = engine.trusted_context_sha256;
        body.statement.binding.principal_sha256 =
            commissioning_principal_sha256(&verified.actors[0]);
        body.statement.binding.resources_sha256 =
            Sha256Digest::from_bytes(Sha256::digest(&resources).into());
        body.statement.binding.allowed_actions = vec![Sha256Digest::from_bytes(
            *verified.request.action_commitment(),
        )];
        body.statement.binding.maximum_credential_leases = 1;
        let permit = signed(body);
        let clock = Arc::new(FixedClock::at(NOW));
        let root = QualificationTrustRoot::from_canonical_json(text("trust_root")).expect("root");
        engine.qualification = Arc::new(QualificationGate::new(
            QualificationPolicy::Required,
            Some(root),
            Some(permit.body().statement.binding.tuple.clone()),
            Box::new(clock.clone()),
            VerifierState::default(),
        ));
        let operator = Signer::new(0x44);
        let statement = OperatorStatement {
            schema: crate::OPERATOR_ATTESTATION_SCHEMA.to_owned(),
            operator_principal: operator.principal.as_str().to_owned(),
            principal_method: "raw-key-v1".to_owned(),
            verification_method: operator.principal.as_str().to_owned(),
            signature_suite: "ed25519-v1".to_owned(),
            installation: crate::OperatorInstallation {
                recipe_digest: engine.recipe.digest_hex(),
                profile_lock_sha256: permit
                    .body()
                    .statement
                    .binding
                    .tuple
                    .profile_lock_sha256
                    .to_hex(),
                trusted_context_sha256: engine.trusted_context_sha256.to_hex(),
                provider: engine.connection.provider().as_str().to_owned(),
                alias: engine.connection.alias().as_str().to_owned(),
                deployment: "production".to_owned(),
            },
            issued_at: NOW,
        };
        let evidence = operator.evidence();
        let attestation = OperatorAttestation {
            signature_b64: Base64UrlUnpadded::encode_string(
                operator
                    .sign(&statement.preimage().expect("operator preimage"))
                    .as_slice(),
            ),
            statement,
            evidence: vec![OperatorEvidence {
                evidence_type: evidence.evidence_type().as_str().to_owned(),
                media_type: evidence.media_type().as_str().to_owned(),
                bytes_b64: Base64UrlUnpadded::encode_string(evidence.bytes()),
            }],
        };
        let directory = tempfile::tempdir().expect("retained witness");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private");
        Self {
            installation,
            directory,
            clock,
            permit,
            certificate: text("signer_certificate").to_vec(),
            revocations: text("revocation_list").to_vec(),
            attestation: serde_json::to_vec(&attestation).expect("operator bytes"),
            resources,
            proof,
            action,
        }
    }

    fn inputs(&self) -> CommissioningSessionInputs<'_> {
        CommissioningSessionInputs {
            artifacts: CommissioningInputs {
                signer_certificate: &self.certificate,
                revocation_list: &self.revocations,
                permit: self.permit.canonical_bytes(),
            },
            operator_attestation: &self.attestation,
            protected_run: &self.permit.body().statement.binding.protected_run,
            resources: &self.resources,
            floor_directory: self.directory.path(),
        }
    }

    fn engine(&self) -> &GatewayEngine {
        &self.installation.first.engine
    }
    fn leases(&self) -> u64 {
        self.installation.first.leases.load(Ordering::SeqCst)
    }
}

fn signed(
    mut body: auths_recipe_qualification::CommissioningPermitBody,
) -> QualificationCommissioningPermit {
    // Public deterministic test key from the frozen commissioning corpus.
    body.signature_b64 = SignatureB64::from_bytes(
        &SigningKey::from_bytes(&[0x22; 32])
            .sign(&body.signing_preimage().expect("preimage"))
            .to_bytes(),
    );
    QualificationCommissioningPermit::from_body(&body).expect("signed synthetic permit")
}

fn io<'a>(setup: &'a Setup, session: Option<&'a CommissioningSession<'a>>) -> EngineIo<'a> {
    EngineIo {
        engine: setup.engine(),
        proof: &setup.proof,
        action: &setup.action,
        started: Instant::now(),
        prepared: OnceLock::new(),
        commissioning: session,
        commissioned_action: OnceLock::new(),
        commissioning_refusal: OnceLock::new(),
    }
}

#[tokio::test]
async fn ordinary_submission_cannot_select_commissioning_authority() {
    let setup = Setup::new().await;
    let session = setup
        .engine()
        .commissioning_session(&setup.inputs())
        .expect("operator");
    session.initialize_budget().await.expect("registered");
    let ordinary = io(&setup, None);
    ordinary.verify(NOW).expect("native proof");
    assert_eq!(
        ordinary.prepare().await,
        Err("gateway.qualification.unavailable")
    );
    assert!(ordinary.lease().await.is_none());
    assert_eq!(setup.leases(), 0);
    assert_eq!(
        session
            .floor
            .load()
            .expect("floor")
            .consumed_credential_leases(),
        0
    );
    assert!(!setup.engine().qualification().status().permits_lease());
}

#[tokio::test]
async fn exact_native_actor_and_action_require_a_durable_unit_before_custody() {
    let setup = Setup::new().await;
    let session = setup
        .engine()
        .commissioning_session(&setup.inputs())
        .expect("operator");
    session.initialize_budget().await.expect("registered");
    let commissioned = io(&setup, Some(&session));
    commissioned.verify(NOW).expect("exact native actor/action");
    commissioned
        .prepare()
        .await
        .expect("same connection and transport");
    assert!(commissioned.lease().await.is_some());
    assert_eq!(setup.leases(), 1);
    assert_eq!(
        session
            .floor
            .load()
            .expect("durable floor")
            .consumed_credential_leases(),
        1
    );
    assert!(
        commissioned.lease().await.is_none(),
        "one-unit lifetime ceiling"
    );
    assert_eq!(
        commissioned.authority_refusal(),
        Some("gateway.commissioning.exhausted")
    );
    assert_eq!(setup.leases(), 1);
    assert!(!setup.engine().qualification().status().permits_lease());
}

#[tokio::test]
async fn absent_registration_and_expiry_after_preparation_never_lease() {
    for initialized in [false, true] {
        let setup = Setup::new().await;
        let session = setup
            .engine()
            .commissioning_session(&setup.inputs())
            .expect("operator");
        if initialized {
            session.initialize_budget().await.expect("registered");
        }
        let commissioned = io(&setup, Some(&session));
        commissioned.verify(NOW).expect("native proof");
        commissioned.prepare().await.expect("prepared");
        if initialized {
            setup.clock.set(setup.permit.body().statement.not_after);
        }
        assert!(commissioned.lease().await.is_none());
        assert_eq!(setup.leases(), 0);
    }
}

#[tokio::test]
async fn another_signed_actor_or_action_is_refused_before_custody() {
    for wrong_actor in [true, false] {
        let mut setup = Setup::new().await;
        let mut body = setup.permit.body().clone();
        if wrong_actor {
            body.statement.binding.principal_sha256 =
                commissioning_principal_sha256(&Signer::new(0x45).principal);
        } else {
            body.statement.binding.allowed_actions = vec![Sha256Digest::from_bytes([0x61; 32])];
        }
        setup.permit = signed(body);
        let session = setup
            .engine()
            .commissioning_session(&setup.inputs())
            .expect("operator");
        session.initialize_budget().await.expect("registered");
        let commissioned = io(&setup, Some(&session));
        assert_eq!(
            commissioned.verify(NOW).map(|_| ()),
            Err(super::super::not_entered(
                "gateway.commissioning.binding-mismatch"
            ))
        );
        assert!(commissioned.lease().await.is_none());
        assert_eq!(setup.leases(), 0);
        assert_eq!(
            session
                .floor
                .load()
                .expect("floor")
                .consumed_credential_leases(),
            0
        );
    }
}

#[tokio::test]
async fn changed_resources_run_operator_or_context_cannot_open_a_session() {
    let setup = Setup::new().await;
    let another_run = BoundedText::parse("another-protected-run:1").expect("run");
    for change in ["resources", "run", "operator", "context"] {
        let mut inputs = setup.inputs();
        let mut changed = setup.permit.body().clone();
        changed.statement.binding.trusted_context_sha256 = Sha256Digest::from_bytes([0x61; 32]);
        let different_context = signed(changed);
        match change {
            "resources" => inputs.resources = b"different resources",
            "run" => inputs.protected_run = &another_run,
            "operator" => inputs.operator_attestation = b"{}",
            "context" => inputs.artifacts.permit = different_context.canonical_bytes(),
            _ => unreachable!(),
        }
        assert!(
            setup.engine().commissioning_session(&inputs).is_err(),
            "{change}"
        );
        assert_eq!(setup.leases(), 0);
    }
}
