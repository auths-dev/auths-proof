//! Fixture generators for the qualification artifacts.
//!
//! Each submodule generates one fixture under `bindings/fixtures/qualification/`
//! from fixed inputs and requires the committed file to be byte-identical;
//! `AUTHS_UPDATE_FIXTURES=1` rewrites it. `schemas` drives every structural
//! case through the decoders. `verification` freezes what a release verifier
//! must conclude from signed inputs; no verifier exists yet, so its test
//! asserts exactly that shortfall and is expected to fail when one lands.

mod schemas;
mod verification;

use crate::{
    ATTESTATION_SCHEMA, AttestationBody, AttestationStatement, BoundedText, CapabilityKind,
    CapabilityResult, ContractDeclarations, EvidenceMember, EvidenceMemberKind, EvidenceResult,
    ExercisedCapability, GitCommit, InstalledPackage, LifecycleStoreKind, LiveEffects,
    PROVIDER_CONTRACT_SCHEMA, Provenance, ProviderContract, ProviderContractBody,
    ProviderEnvironmentClass, PublicKeyB64, QUALIFICATION_RECORD_SCHEMA, QualificationArtifactKind,
    QualificationId, QualificationRootId, QualificationSignatureSuite, QualificationSignerId,
    QualificationSignerKind, QualificationTarget, QualificationTuple, RELEASE_INDEX_SCHEMA,
    REVOCATION_LIST_SCHEMA, RecipeFamilyId, RecordBody, ReleaseIndexBody, ReleaseIndexEntry,
    ReleaseIndexStatement, RevocationListBody, RevocationListStatement, SIGNER_CERTIFICATE_SCHEMA,
    Sha256Digest, SignatureB64, SignerCertificateBody, SignerCertificateStatement,
    TRUST_ROOT_SCHEMA, TargetArch, TargetOs, TrustRootBody,
};
use auths_connections::{CredentialStoreKind, ProviderKind};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

/// Fixed evaluation time shared by the vectors, as in the gateway fixtures.
pub(super) const NOW: u64 = 1_790_000_000;
pub(super) const HOUR: u64 = 60 * 60;
pub(super) const DAY: u64 = 24 * HOUR;

fn fixture_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/qualification")
}

/// Requires the committed fixture `name` to equal `document`, or rewrites it
/// when `AUTHS_UPDATE_FIXTURES` is set.
fn require_current(name: &str, document: &Value) {
    let path = fixture_directory().join(name);
    let mut generated = serde_json::to_string_pretty(document).expect("fixture JSON");
    generated.push('\n');
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &generated).expect("write fixture");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "{name} is stale; rerun with AUTHS_UPDATE_FIXTURES=1"
    );
}

/// Reads a committed fixture.
fn load(name: &str) -> Value {
    let bytes = std::fs::read(fixture_directory().join(name)).expect("committed fixture");
    serde_json::from_slice(&bytes).expect("fixture JSON")
}

/// The canonical text of `value`.
pub(super) fn text<T: Serialize>(value: &T) -> String {
    String::from_utf8(serde_json_canonicalizer::to_vec(value).expect("canonical")).expect("UTF-8")
}

/// Replaces every `{}` in every string of `template` with `index` as
/// `width` lowercase hexadecimal digits.
fn fill_template(template: &Value, index: usize, width: usize) -> Value {
    match template {
        Value::String(text) => Value::String(text.replace("{}", &format!("{index:0width$x}"))),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| fill_template(item, index, width))
                .collect(),
        ),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, member)| (key.clone(), fill_template(member, index, width)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Applies one mutation: `set` replaces the value at `pointer` or adds it to
/// the existing parent object, `remove` deletes the object member or array
/// element, and `fill` replaces the value at `pointer` with `count` copies of
/// `template`, each with `{}` replaced by its index as `width` hexadecimal
/// digits.
pub(super) fn apply_mutation(document: &mut Value, mutation: &Value) {
    let op = mutation["op"].as_str().expect("op");
    let pointer = mutation["pointer"].as_str().expect("pointer");
    let value = match op {
        "set" => mutation["value"].clone(),
        "fill" => {
            let count = usize::try_from(mutation["count"].as_u64().expect("count")).expect("count");
            let width = usize::try_from(mutation["width"].as_u64().expect("width")).expect("width");
            Value::Array(
                (0..count)
                    .map(|index| fill_template(&mutation["template"], index, width))
                    .collect(),
            )
        }
        "remove" => {
            let (parent, key) = pointer.rsplit_once('/').expect("child pointer");
            match document.pointer_mut(parent).expect("existing parent") {
                Value::Object(object) => {
                    object.remove(key).expect("existing member");
                }
                Value::Array(array) => {
                    array.remove(key.parse().expect("array index"));
                }
                _ => panic!("remove needs an object or array parent"),
            }
            return;
        }
        _ => panic!("unknown mutation {op}"),
    };
    if let Some(existing) = document.pointer_mut(pointer) {
        *existing = value;
    } else {
        let (parent, key) = pointer.rsplit_once('/').expect("child pointer");
        document
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .expect("existing parent object")
            .insert(key.to_owned(), value);
    }
}

/// Every Rust source file of this crate outside this module, with its text.
fn crate_sources() -> Vec<(PathBuf, String)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&directory)
        .expect("source directory")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("rs"))
        .collect();
    entries.sort();
    entries
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("source text");
            (path, text)
        })
        .collect()
}

/// A digest that names what it stands for and is plainly not a secret.
pub(super) fn digest_of(label: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(format!("auths fixture {label}")).into())
}

pub(super) fn bounded<const MAX: usize>(value: &str) -> BoundedText<MAX> {
    BoundedText::parse(value).expect("bounded text")
}

/// Fixed test keys. The seeds are constants of this test module and protect
/// nothing.
pub(super) struct Keys {
    pub(super) root: SigningKey,
    pub(super) signer: SigningKey,
    pub(super) outsider: SigningKey,
}

impl Keys {
    pub(super) fn fixed() -> Self {
        Self {
            root: SigningKey::from_bytes(&[0x11; 32]),
            signer: SigningKey::from_bytes(&[0x22; 32]),
            outsider: SigningKey::from_bytes(&[0x33; 32]),
        }
    }
}

pub(super) fn public_key(key: &SigningKey) -> PublicKeyB64 {
    PublicKeyB64::from_bytes(&key.verifying_key().to_bytes())
}

pub(super) fn sign(key: &SigningKey, preimage: &[u8]) -> SignatureB64 {
    SignatureB64::from_bytes(&key.sign(preimage).to_bytes())
}

pub(super) fn root_id() -> QualificationRootId {
    QualificationRootId::parse("auths-qualification-root-1").expect("root")
}

pub(super) fn signer_id() -> QualificationSignerId {
    QualificationSignerId::parse("release-signer-2026-10").expect("signer")
}

pub(super) fn qualification_id(index: u8) -> QualificationId {
    QualificationId::parse(format!("qlf_{}", hex::encode([index; 16]))).expect("qualification")
}

pub(super) fn trust_root(keys: &Keys) -> TrustRootBody {
    TrustRootBody {
        schema: TRUST_ROOT_SCHEMA.to_owned(),
        root_id: root_id(),
        signature_suite: QualificationSignatureSuite::Ed25519V1,
        public_key_b64: public_key(&keys.root),
    }
}

pub(super) fn certificate_statement(keys: &Keys) -> SignerCertificateStatement {
    SignerCertificateStatement {
        schema: SIGNER_CERTIFICATE_SCHEMA.to_owned(),
        signer_id: signer_id(),
        signer_kind: QualificationSignerKind::ProtectedSoftwareReleaseKeyV1,
        signature_suite: QualificationSignatureSuite::Ed25519V1,
        public_key_b64: public_key(&keys.signer),
        issued_at: NOW - DAY,
        not_before: NOW - DAY,
        not_after: NOW - DAY + 180 * DAY,
        permitted_artifact_kinds: vec![
            QualificationArtifactKind::QualificationReleaseIndex,
            QualificationArtifactKind::RecipeQualificationAttestation,
        ],
        root_id: root_id(),
    }
}

/// Signs a certificate statement with `key`; the trust root's key makes it
/// valid.
pub(super) fn certificate(
    statement: SignerCertificateStatement,
    key: &SigningKey,
) -> SignerCertificateBody {
    let mut body = SignerCertificateBody {
        statement,
        root_signature_b64: SignatureB64::from_bytes(&[0; 64]),
    };
    body.root_signature_b64 = sign(key, &body.signing_preimage().expect("preimage"));
    body
}

pub(super) fn revocation_statement(issued_at: u64) -> RevocationListStatement {
    RevocationListStatement {
        schema: REVOCATION_LIST_SCHEMA.to_owned(),
        sequence: 7,
        issued_at,
        next_update: issued_at + 72 * HOUR,
        revoked_signers: Vec::new(),
        revoked_qualifications: Vec::new(),
        root_id: root_id(),
    }
}

pub(super) fn revocation(
    statement: RevocationListStatement,
    key: &SigningKey,
) -> RevocationListBody {
    let mut body = RevocationListBody {
        statement,
        root_signature_b64: SignatureB64::from_bytes(&[0; 64]),
    };
    body.root_signature_b64 = sign(key, &body.signing_preimage().expect("preimage"));
    body
}

pub(super) fn contract() -> ProviderContractBody {
    ProviderContractBody {
        schema: PROVIDER_CONTRACT_SCHEMA.to_owned(),
        provider: bounded("example-payments"),
        api_release: bounded("2026-09-01.fixture"),
        openapi_slice_sha256: Some(digest_of("openapi slice")),
        manual_assumptions: vec![
            bounded("a refund of a refunded payment is rejected, not repeated"),
            bounded("the idempotency key is honored for at least 24 hours"),
        ],
        environment_class: ProviderEnvironmentClass::ProviderTestMode,
        corpus_manifest_sha256: digest_of("corpus manifest"),
        oracle_version: bounded("oracle-1"),
        declarations: ContractDeclarations {
            idempotency_sha256: digest_of("idempotency declaration"),
            observation_sha256: digest_of("observation declaration"),
            recovery_sha256: digest_of("recovery declaration"),
            retention_sha256: digest_of("retention declaration"),
        },
    }
}

pub(super) fn decoded_contract(body: &ProviderContractBody) -> ProviderContract {
    ProviderContract::from_canonical_json(text(body).as_bytes()).expect("contract")
}

pub(super) fn target() -> QualificationTarget {
    QualificationTarget {
        os: TargetOs::Linux,
        arch: TargetArch::X86_64,
        gateway_package: bounded("auths-gateway"),
        gateway_version: bounded("1.0.0-rc.1"),
        gateway_build_sha256: digest_of("gateway build"),
        store_kind: LifecycleStoreKind::PostgresqlV1,
        store_schema: bounded("auths.lifecycle.postgresql/5"),
        credential_store_kind: CredentialStoreKind::AwsSecretsManagerV1,
    }
}

pub(super) fn tuple() -> QualificationTuple {
    QualificationTuple {
        recipe_family: RecipeFamilyId::parse("example-refund-v1").expect("family"),
        compiled_recipe_sha256: digest_of("compiled recipe"),
        profile_lock_sha256: digest_of("profile lock"),
        provider_contract_id: decoded_contract(&contract()).contract_id(),
        gateway_semantic_closure_sha256: digest_of("gateway semantic closure"),
        target: target(),
    }
}

fn evidence() -> Vec<EvidenceMember> {
    EvidenceMemberKind::ALL
        .into_iter()
        .map(|member| EvidenceMember {
            member,
            result: EvidenceResult::Passed,
            evidence_sha256: digest_of(&format!("evidence {member:?}")),
            cases: 12,
            unauthorized_provider_entries: 0,
        })
        .collect()
}

fn capabilities() -> Vec<ExercisedCapability> {
    CapabilityKind::ALL
        .into_iter()
        .map(|capability| {
            let absent = matches!(
                capability,
                CapabilityKind::AccountBinding | CapabilityKind::ObserverRotation
            );
            ExercisedCapability {
                capability,
                result: if absent {
                    CapabilityResult::NotApplicable
                } else {
                    CapabilityResult::Exercised
                },
                reason: absent.then(|| bounded("the qualified recipe and target declare none")),
            }
        })
        .collect()
}

pub(super) fn record(index: u8, tuple: QualificationTuple) -> RecordBody {
    RecordBody {
        schema: QUALIFICATION_RECORD_SCHEMA.to_owned(),
        qualification_id: qualification_id(index),
        provider_kind: ProviderKind::parse("example-payments").expect("provider"),
        tuple,
        not_before: NOW - 2 * HOUR,
        not_after: NOW - 2 * HOUR + 90 * DAY,
        provenance: Provenance {
            repository: bounded("github.com/auths-dev/auths-proof"),
            commit: GitCommit::parse("0123456789abcdef0123456789abcdef01234567").expect("commit"),
            workflow: bounded(".github/workflows/recipe-qualification.yml"),
            environment: bounded("recipe-qualification"),
        },
        source_closure_sha256: digest_of("source closure"),
        generated_artifacts_sha256: digest_of("generated artifacts"),
        installed_packages: vec![
            InstalledPackage {
                name: bounded("auths-gateway"),
                version: bounded("1.0.0-rc.1"),
                sha256: digest_of("gateway package"),
            },
            InstalledPackage {
                name: bounded("auths-python"),
                version: bounded("1.0.0rc1"),
                sha256: digest_of("python package"),
            },
        ],
        recipe_decision_record_sha256: digest_of("recipe decision record"),
        corpus_manifest_sha256: digest_of("corpus manifest"),
        evidence: evidence(),
        capabilities: capabilities(),
        live_effects: LiveEffects {
            entered: 4,
            confirmed_by_read_back: 4,
        },
        provider_resources: vec![
            bounded("refund:fixture-0001"),
            bounded("refund:fixture-0002"),
        ],
        custody_descriptor: bounded("aws-secrets-manager-v1 with workload identity"),
        store_descriptor: bounded("postgresql 16 with TLS"),
        residual_assumptions: vec![bounded(
            "the provider keeps its test mode separate from live data",
        )],
        excluded_claims: vec![bounded(
            "the provider performed or settled the business effect",
        )],
    }
}

pub(super) fn attestation_statement(record_text: &str, index: u8) -> AttestationStatement {
    AttestationStatement {
        schema: ATTESTATION_SCHEMA.to_owned(),
        qualification_id: qualification_id(index),
        record_sha256: crate::canonical::domain_digest(
            QUALIFICATION_RECORD_SCHEMA,
            record_text.as_bytes(),
        ),
        signer_id: signer_id(),
        signature_suite: QualificationSignatureSuite::Ed25519V1,
        issued_at: NOW - 2 * HOUR,
        not_before: NOW - 2 * HOUR,
        not_after: NOW - 2 * HOUR + 90 * DAY,
    }
}

pub(super) fn attestation(statement: AttestationStatement, key: &SigningKey) -> AttestationBody {
    let mut body = AttestationBody {
        statement,
        signature_b64: SignatureB64::from_bytes(&[0; 64]),
    };
    body.signature_b64 = sign(key, &body.signing_preimage().expect("preimage"));
    body
}

/// An index entry for one record and attestation, by their canonical texts.
pub(super) fn index_entry(
    index: u8,
    record_text: &str,
    attestation_text: &str,
) -> ReleaseIndexEntry {
    ReleaseIndexEntry {
        qualification_id: qualification_id(index),
        record_sha256: crate::canonical::domain_digest(
            QUALIFICATION_RECORD_SCHEMA,
            record_text.as_bytes(),
        ),
        attestation_sha256: crate::canonical::domain_digest(
            ATTESTATION_SCHEMA,
            attestation_text.as_bytes(),
        ),
    }
}

pub(super) fn index_statement(entries: Vec<ReleaseIndexEntry>) -> ReleaseIndexStatement {
    ReleaseIndexStatement {
        schema: RELEASE_INDEX_SCHEMA.to_owned(),
        issued_at: NOW - HOUR,
        entries,
        signer_id: signer_id(),
        signature_suite: QualificationSignatureSuite::Ed25519V1,
    }
}

pub(super) fn index(statement: ReleaseIndexStatement, key: &SigningKey) -> ReleaseIndexBody {
    let mut body = ReleaseIndexBody {
        statement,
        signature_b64: SignatureB64::from_bytes(&[0; 64]),
    };
    body.signature_b64 = sign(key, &body.signing_preimage().expect("preimage"));
    body
}

#[test]
fn mutations_follow_their_documented_semantics() {
    let mut document = serde_json::json!({"a": {"b": [1, 2]}, "c": 3});
    for mutation in [
        serde_json::json!({"op": "set", "pointer": "/c", "value": 4}),
        serde_json::json!({"op": "set", "pointer": "/a/d", "value": 5}),
        serde_json::json!({"op": "remove", "pointer": "/a/b/0"}),
        serde_json::json!({"op": "fill", "pointer": "/a/d", "count": 2, "width": 2,
            "template": {"id": "x{}", "n": 1}}),
    ] {
        apply_mutation(&mut document, &mutation);
    }
    assert_eq!(
        document,
        serde_json::json!({"a": {"b": [2], "d": [{"id": "x00", "n": 1}, {"id": "x01", "n": 1}]}, "c": 4})
    );
}
