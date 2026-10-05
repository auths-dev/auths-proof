//! Verification vectors: signed inputs and what a release verifier must
//! conclude from them.
//!
//! Every artifact here is structurally valid and really signed with the
//! fixed test keys; each case replaces named inputs of the base and has one
//! intended fault. `precedence` is the order in which a verifier reports
//! when several faults hold.
//!
//! Two inputs are verifier state, not artifacts. `accepted_revocation_sequence`
//! is the highest revocation-list sequence already accepted; an older list
//! is refused. `known_revocations` holds every signer and qualification a
//! verified list has ever named: revocation is permanent, so a later list
//! that omits one does not restore it.
//!
//! The release verifier is driven through every case: its verdict must equal
//! the frozen state, reason, and lease decision.

#![allow(clippy::too_many_lines, reason = "case tables read top to bottom")]

use super::{
    DAY, HOUR, Keys, NOW, attestation, attestation_statement, certificate, certificate_statement,
    digest_of, index, index_entry, index_statement, load, qualification_id, record,
    require_current, revocation, revocation_statement, signer_id, text, trust_root, tuple,
};
use crate::{
    AttestationStatement, LifecycleStoreKind, QualificationArtifactKind, QualificationInputs,
    QualificationRootId, QualificationSignerId, QualificationTrustRoot, QualificationTuple,
    RecipeQualificationState, RevocationListStatement, SignatureB64, SignerCertificateStatement,
    TargetArch, TargetOs, VerifiedQualifications, VerifierState,
};
use auths_connections::CredentialStoreKind;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) const FILE: &str = "verification-vectors.json";
const SCHEMA: &str = "auths.qualification-verification-vectors/1";

const MISSING: &str = "gateway.qualification.missing";
const EXPIRED: &str = "gateway.qualification.expired";
const REVOKED: &str = "gateway.qualification.revoked";
const DIGEST_MISMATCH: &str = "gateway.qualification.digest-mismatch";
const TARGET_MISMATCH: &str = "gateway.qualification.target-mismatch";
const UNAVAILABLE: &str = "gateway.qualification.unavailable";
const REVOCATION_STALE: &str = "gateway.qualification.revocation-stale";
const CLOCK_UNTRUSTED: &str = "gateway.qualification.clock-untrusted";

/// The order in which a verifier reports when several faults hold: each
/// condition with the code it reports. Nothing about a recipe is
/// authenticated while the certificate or index is unusable, so that comes
/// first; a revocation the verifier has authenticated comes before every
/// other fault, including an unusable or stale revocation list.
const PRECEDENCE: [(&str, &str); 9] = [
    (
        "the signer certificate or release index is unusable",
        UNAVAILABLE,
    ),
    (
        "a verified revocation list, now or earlier, names the qualification or its signer",
        REVOKED,
    ),
    (
        "the revocation list is unusable or older than one already accepted",
        UNAVAILABLE,
    ),
    (
        "the clock is untrusted, or local time is before a signed issue time",
        CLOCK_UNTRUSTED,
    ),
    (
        "the revocation list is past its next update",
        REVOCATION_STALE,
    ),
    (
        "no usable attestation exists for the recipe family",
        MISSING,
    ),
    (
        "the attestation's or the signer certificate's window has ended",
        EXPIRED,
    ),
    ("a digest member of the tuple differs", DIGEST_MISMATCH),
    ("a target member of the tuple differs", TARGET_MISMATCH),
];

/// The base inputs and the statements the cases rebuild from.
struct Parts {
    keys: Keys,
    record_text: String,
    attestation_text: String,
    attestation_statement: AttestationStatement,
    certificate_statement: SignerCertificateStatement,
    revocation_statement: RevocationListStatement,
}

impl Parts {
    fn new() -> Self {
        let keys = Keys::fixed();
        let record_text = text(&record(1, tuple()));
        let attestation_statement = attestation_statement(&record_text, 1);
        let attestation_text = text(&attestation(attestation_statement.clone(), &keys.signer));
        Self {
            certificate_statement: certificate_statement(&keys),
            revocation_statement: revocation_statement(NOW - HOUR),
            keys,
            record_text,
            attestation_text,
            attestation_statement,
        }
    }

    /// An index the release signer issued for `attestation_text`.
    fn index_for(&self, attestation_text: &str) -> String {
        let entries = vec![index_entry(1, &self.record_text, attestation_text)];
        text(&index(index_statement(entries), &self.keys.signer))
    }

    /// The attestation and the index that lists it, for a changed statement
    /// the release signer signed.
    fn reattested(&self, statement: AttestationStatement) -> Value {
        let attestation_text = text(&attestation(statement, &self.keys.signer));
        json!({"attestations": [attestation_text], "release_index": self.index_for(&attestation_text)})
    }

    fn certificate(&self, change: impl FnOnce(&mut SignerCertificateStatement)) -> String {
        let mut statement = self.certificate_statement.clone();
        change(&mut statement);
        text(&certificate(statement, &self.keys.root))
    }

    fn revocation(&self, change: impl FnOnce(&mut RevocationListStatement)) -> String {
        let mut statement = self.revocation_statement.clone();
        change(&mut statement);
        text(&revocation(statement, &self.keys.root))
    }

    fn deployment(change: impl FnOnce(&mut QualificationTuple)) -> Value {
        let mut deployed = tuple();
        change(&mut deployed);
        serde_json::to_value(deployed).expect("tuple")
    }

    fn base(&self) -> Value {
        json!({
            "now": NOW,
            "clock": "trusted",
            "accepted_revocation_sequence": self.revocation_statement.sequence,
            "known_revocations": {"signers": [], "qualifications": []},
            "trust_root": text(&trust_root(&self.keys)),
            "signer_certificate": self.certificate(|_| {}),
            "revocation_list": self.revocation(|_| {}),
            "release_index": self.index_for(&self.attestation_text),
            "records": [self.record_text],
            "attestations": [self.attestation_text],
            "deployment": Self::deployment(|_| {}),
        })
    }
}

/// The same artifact with one bit of its signature changed.
fn with_forged_signature(artifact_text: &str) -> String {
    let mut artifact: Value = serde_json::from_str(artifact_text).expect("artifact JSON");
    let member = ["signature_b64", "root_signature_b64"]
        .into_iter()
        .find(|member| artifact.get(member).is_some())
        .expect("signature member");
    let signature =
        SignatureB64::try_from(artifact[member].as_str().expect("signature").to_owned())
            .expect("signature");
    let mut bytes = signature.to_bytes();
    bytes[0] ^= 1;
    artifact[member] = json!(SignatureB64::from_bytes(&bytes).as_str());
    text(&artifact)
}

fn case(
    id: &str,
    class: &str,
    replace: Value,
    state: RecipeQualificationState,
    code: Option<&str>,
) -> Value {
    let mut case = json!({"id": id, "class": class});
    case["replace"] = replace;
    case["expect"] = json!({"state": state.as_str(), "code": code, "lease": state.permits_lease()});
    case
}

fn trust_cases(parts: &Parts) -> Vec<Value> {
    use RecipeQualificationState::{Candidate, Stale, Unqualified};
    let keys = &parts.keys;
    let outsider_attestation = text(&attestation(
        parts.attestation_statement.clone(),
        &keys.outsider,
    ));
    let outsider_index = text(&index(
        index_statement(vec![index_entry(
            1,
            &parts.record_text,
            &parts.attestation_text,
        )]),
        &keys.outsider,
    ));
    let only = |kind: QualificationArtifactKind| {
        parts.certificate(|statement| statement.permitted_artifact_kinds = vec![kind])
    };
    let forged_attestation = with_forged_signature(&parts.attestation_text);
    // Really signed by the release signer, but not the attestation the index lists.
    let reissued_attestation = {
        let mut statement = parts.attestation_statement.clone();
        statement.issued_at += 1;
        text(&attestation(statement, &keys.signer))
    };
    vec![
        case(
            "attestation-signature-forged",
            "forged",
            json!({"attestations": [forged_attestation], "release_index": parts.index_for(&forged_attestation)}),
            Candidate,
            Some(MISSING),
        ),
        case(
            "attestation-not-the-indexed-one",
            "forged",
            json!({"attestations": [reissued_attestation]}),
            Candidate,
            Some(MISSING),
        ),
        case(
            "attestation-signed-by-outsider",
            "forged",
            json!({"attestations": [outsider_attestation], "release_index": parts.index_for(&outsider_attestation)}),
            Candidate,
            Some(MISSING),
        ),
        case(
            "index-signature-forged",
            "forged",
            json!({"release_index": with_forged_signature(&parts.index_for(&parts.attestation_text))}),
            Unqualified,
            Some(UNAVAILABLE),
        ),
        case(
            "index-signed-by-outsider",
            "forged",
            json!({"release_index": outsider_index}),
            Unqualified,
            Some(UNAVAILABLE),
        ),
        case(
            "certificate-signed-by-release-signer",
            "signer-signed-root-artifact",
            json!({"signer_certificate": text(&certificate(parts.certificate_statement.clone(), &keys.signer))}),
            Unqualified,
            Some(UNAVAILABLE),
        ),
        case(
            "certificate-names-another-root",
            "forged",
            json!({"signer_certificate": parts.certificate(|statement| {
                statement.root_id = QualificationRootId::parse("another-root").expect("root");
            })}),
            Unqualified,
            Some(UNAVAILABLE),
        ),
        case(
            "revocation-list-signed-by-release-signer",
            "signer-signed-root-artifact",
            json!({"revocation_list": text(&revocation(parts.revocation_statement.clone(), &keys.signer))}),
            Stale,
            Some(UNAVAILABLE),
        ),
        case(
            "revocation-list-rolled-back",
            "rollback",
            json!({"revocation_list": parts.revocation(|statement| statement.sequence -= 1)}),
            Stale,
            Some(UNAVAILABLE),
        ),
        case(
            "certificate-lacks-attestation-permission",
            "wrong-artifact-kind",
            json!({"signer_certificate": only(QualificationArtifactKind::QualificationReleaseIndex)}),
            Candidate,
            Some(MISSING),
        ),
        case(
            "certificate-lacks-index-permission",
            "wrong-artifact-kind",
            json!({"signer_certificate": only(QualificationArtifactKind::RecipeQualificationAttestation)}),
            Unqualified,
            Some(UNAVAILABLE),
        ),
    ]
}

fn attestation_cases(parts: &Parts) -> Vec<Value> {
    use RecipeQualificationState::Candidate;
    let changed = |change: fn(&mut AttestationStatement)| {
        let mut statement = parts.attestation_statement.clone();
        change(&mut statement);
        parts.reattested(statement)
    };
    vec![
        case(
            "attestation-names-another-signer",
            "forged",
            changed(|statement| {
                statement.signer_id =
                    QualificationSignerId::parse("another-signer").expect("signer");
            }),
            Candidate,
            Some(MISSING),
        ),
        case(
            "attestation-names-another-record",
            "wrong-recipe",
            changed(|statement| statement.record_sha256 = digest_of("another record")),
            Candidate,
            Some(MISSING),
        ),
        case(
            "attestation-outlives-record",
            "widened-time-bound",
            outlives_record(parts),
            Candidate,
            Some(MISSING),
        ),
        case(
            "attestation-not-yet-valid",
            "not-yet-valid",
            changed(|statement| {
                statement.not_before = NOW + HOUR;
                statement.not_after = NOW + HOUR + 30 * DAY;
            }),
            Candidate,
            Some(MISSING),
        ),
        case(
            "index-omits-qualification",
            "missing",
            json!({"release_index": text(&index(index_statement(Vec::new()), &parts.keys.signer))}),
            RecipeQualificationState::Unqualified,
            Some(MISSING),
        ),
    ]
}

/// A record valid for 60 days with an attestation valid for 90: the signer
/// claims a longer life than the evidence has. Every window has started.
fn outlives_record(parts: &Parts) -> Value {
    let mut short = record(1, tuple());
    short.not_after = short.not_before + 60 * DAY;
    let record_text = text(&short);
    let attestation_text = text(&attestation(
        attestation_statement(&record_text, 1),
        &parts.keys.signer,
    ));
    let entries = vec![index_entry(1, &record_text, &attestation_text)];
    json!({
        "records": [record_text],
        "attestations": [attestation_text],
        "release_index": text(&index(index_statement(entries), &parts.keys.signer)),
    })
}

/// Two faults at once, one case for each adjacent pair of the precedence,
/// so the order itself is pinned and not only each fault alone.
fn precedence_cases(parts: &Parts) -> Vec<Value> {
    use RecipeQualificationState::{Candidate, Revoked, Stale, Unqualified};
    let keys = &parts.keys;
    let naming_qualification =
        parts.revocation(|statement| statement.revoked_qualifications = vec![qualification_id(1)]);
    let outsider_attestation = text(&attestation(
        parts.attestation_statement.clone(),
        &keys.outsider,
    ));
    let outsider = json!({
        "attestations": [outsider_attestation],
        "release_index": parts.index_for(&outsider_attestation),
    });
    let with = |mut replace: Value, member: &str, value: Value| {
        replace[member] = value;
        replace
    };
    let past_next_update = parts.revocation_statement.next_update + 1;
    let expiry = parts.attestation_statement.not_after;
    let fresh_at_expiry = parts.revocation(|statement| {
        statement.issued_at = expiry + 1 - HOUR;
        statement.next_update = expiry + 1 - HOUR + 72 * HOUR;
    });
    let expired_certificate = parts.certificate(|statement| {
        statement.issued_at = NOW - 30 * DAY;
        statement.not_before = NOW - 30 * DAY;
        statement.not_after = NOW - 1;
    });
    vec![
        case(
            "unusable-index-before-revocation",
            "precedence",
            json!({
                "release_index": with_forged_signature(&parts.index_for(&parts.attestation_text)),
                "revocation_list": naming_qualification,
            }),
            Unqualified,
            Some(UNAVAILABLE),
        ),
        case(
            "known-revocation-before-unusable-list",
            "precedence",
            json!({
                "known_revocations": {"signers": [], "qualifications": [qualification_id(1)]},
                "revocation_list": text(&revocation(parts.revocation_statement.clone(), &keys.signer)),
            }),
            Revoked,
            Some(REVOKED),
        ),
        case(
            "unusable-list-before-untrusted-clock",
            "precedence",
            json!({
                "clock": "untrusted",
                "revocation_list": text(&revocation(parts.revocation_statement.clone(), &keys.signer)),
            }),
            Stale,
            Some(UNAVAILABLE),
        ),
        case(
            "untrusted-clock-before-stale-list",
            "precedence",
            json!({"clock": "untrusted", "now": past_next_update}),
            Stale,
            Some(CLOCK_UNTRUSTED),
        ),
        case(
            "stale-list-before-missing",
            "precedence",
            with(outsider.clone(), "now", json!(past_next_update)),
            Candidate,
            Some(REVOCATION_STALE),
        ),
        case(
            "missing-before-expired",
            "precedence",
            with(outsider, "signer_certificate", json!(expired_certificate)),
            Candidate,
            Some(MISSING),
        ),
        case(
            "expired-before-digest-mismatch",
            "precedence",
            json!({
                "now": expiry + 1,
                "revocation_list": fresh_at_expiry,
                "deployment": Parts::deployment(|deployed| {
                    deployed.compiled_recipe_sha256 = digest_of("another compiled recipe");
                }),
            }),
            Stale,
            Some(EXPIRED),
        ),
    ]
}

fn time_cases(parts: &Parts) -> Vec<Value> {
    use RecipeQualificationState::Stale;
    let expiry = parts.attestation_statement.not_after;
    let mut ahead_attestation = parts.attestation_statement.clone();
    ahead_attestation.issued_at = NOW + 60;
    let ahead_index = {
        let mut statement = index_statement(vec![index_entry(
            1,
            &parts.record_text,
            &parts.attestation_text,
        )]);
        statement.issued_at = NOW + 60;
        text(&index(statement, &parts.keys.signer))
    };
    vec![
        case(
            "certificate-expired",
            "expired",
            json!({"signer_certificate": parts.certificate(|statement| {
                statement.issued_at = NOW - 30 * DAY;
                statement.not_before = NOW - 30 * DAY;
                statement.not_after = NOW - 1;
            })}),
            Stale,
            Some(EXPIRED),
        ),
        case(
            "attestation-expired",
            "expired",
            json!({"now": expiry + 1, "revocation_list": parts.revocation(|statement| {
                statement.issued_at = expiry + 1 - HOUR;
                statement.next_update = expiry + 1 - HOUR + 72 * HOUR;
            })}),
            Stale,
            Some(EXPIRED),
        ),
        case(
            "revocation-list-past-next-update",
            "elapsed-next-update",
            json!({"now": parts.revocation_statement.next_update + 1}),
            Stale,
            Some(REVOCATION_STALE),
        ),
        case(
            "revocation-list-issued-ahead",
            "future-issued-at",
            json!({"revocation_list": parts.revocation(|statement| {
                statement.issued_at = NOW + 60;
                statement.next_update = NOW + 60 + 72 * HOUR;
            })}),
            Stale,
            Some(CLOCK_UNTRUSTED),
        ),
        case(
            "certificate-issued-ahead",
            "future-issued-at",
            json!({"signer_certificate": parts.certificate(|statement| statement.issued_at = NOW + 60)}),
            Stale,
            Some(CLOCK_UNTRUSTED),
        ),
        case(
            "index-issued-ahead",
            "future-issued-at",
            json!({"release_index": ahead_index}),
            Stale,
            Some(CLOCK_UNTRUSTED),
        ),
        case(
            "attestation-issued-ahead",
            "future-issued-at",
            parts.reattested(ahead_attestation),
            Stale,
            Some(CLOCK_UNTRUSTED),
        ),
        case(
            "clock-untrusted",
            "untrusted-clock",
            json!({"clock": "untrusted"}),
            Stale,
            Some(CLOCK_UNTRUSTED),
        ),
    ]
}

fn revocation_cases(parts: &Parts) -> Vec<Value> {
    use RecipeQualificationState::{Qualified, Revoked};
    let expiry = parts.attestation_statement.not_after;
    let naming_qualification =
        parts.revocation(|statement| statement.revoked_qualifications = vec![qualification_id(1)]);
    let revoked = |id: &str, mut replace: Value| {
        replace["revocation_list"] = json!(naming_qualification);
        case(id, "revoked", replace, Revoked, Some(REVOKED))
    };
    vec![
        revoked("qualification-revoked", json!({})),
        case(
            "signer-revoked",
            "revoked",
            json!({"revocation_list": parts.revocation(|statement| statement.revoked_signers = vec![signer_id()])}),
            Revoked,
            Some(REVOKED),
        ),
        case(
            "revoked-and-expired",
            "revoked",
            json!({"now": expiry + 1, "revocation_list": parts.revocation(|statement| {
                statement.issued_at = expiry + 1 - HOUR;
                statement.next_update = expiry + 1 - HOUR + 72 * HOUR;
                statement.revoked_qualifications = vec![qualification_id(1)];
            })}),
            Revoked,
            Some(REVOKED),
        ),
        revoked(
            "revoked-and-wrong-target",
            json!({"deployment": Parts::deployment(|deployed| deployed.target.os = TargetOs::Macos)}),
        ),
        revoked(
            "revoked-under-untrusted-clock",
            json!({"clock": "untrusted"}),
        ),
        revoked(
            "revoked-in-list-past-next-update",
            json!({"now": parts.revocation_statement.next_update + 1}),
        ),
        case(
            "revocation-dropped-by-later-list",
            "revoked",
            json!({
                "known_revocations": {"signers": [], "qualifications": [qualification_id(1)]},
                "revocation_list": parts.revocation(|statement| statement.sequence += 1),
            }),
            Revoked,
            Some(REVOKED),
        ),
        case(
            "signer-revocation-dropped-by-later-list",
            "revoked",
            json!({
                "known_revocations": {"signers": [signer_id()], "qualifications": []},
                "revocation_list": parts.revocation(|statement| statement.sequence += 1),
            }),
            Revoked,
            Some(REVOKED),
        ),
        case(
            "another-qualification-revoked",
            "valid",
            json!({"revocation_list": parts.revocation(|statement| {
                statement.revoked_qualifications = vec![qualification_id(2)];
            })}),
            Qualified,
            None,
        ),
    ]
}

fn digest_cases() -> Vec<Value> {
    use RecipeQualificationState::{Stale, Unqualified};
    let drifted = |id: &str, class: &str, change: fn(&mut QualificationTuple)| {
        case(
            id,
            class,
            json!({"deployment": Parts::deployment(change)}),
            Stale,
            Some(DIGEST_MISMATCH),
        )
    };
    vec![
        drifted("wrong-recipe", "wrong-recipe", |deployed| {
            deployed.compiled_recipe_sha256 = digest_of("another compiled recipe");
        }),
        drifted("wrong-profile-lock", "wrong-recipe", |deployed| {
            deployed.profile_lock_sha256 = digest_of("another profile lock");
        }),
        drifted("wrong-contract", "wrong-contract", |deployed| {
            let mut drifted = super::contract();
            drifted.api_release = super::bounded("2026-10-01.fixture");
            deployed.provider_contract_id = super::decoded_contract(&drifted).contract_id();
        }),
        drifted("wrong-semantic-closure", "wrong-closure", |deployed| {
            deployed.gateway_semantic_closure_sha256 = digest_of("another semantic closure");
        }),
        drifted("digest-and-target-differ", "wrong-recipe", |deployed| {
            deployed.compiled_recipe_sha256 = digest_of("another compiled recipe");
            deployed.target.arch = TargetArch::Aarch64;
        }),
        case(
            "wrong-family",
            "wrong-recipe",
            json!({"deployment": Parts::deployment(|deployed| {
                deployed.recipe_family = crate::RecipeFamilyId::parse("another-family-v1").expect("family");
            })}),
            Unqualified,
            Some(MISSING),
        ),
    ]
}

fn target_cases() -> Vec<Value> {
    let drifted = |id: &str, class: &str, change: fn(&mut QualificationTuple)| {
        case(
            id,
            class,
            json!({"deployment": Parts::deployment(change)}),
            RecipeQualificationState::Stale,
            Some(TARGET_MISMATCH),
        )
    };
    vec![
        drifted("wrong-target-os", "wrong-target", |deployed| {
            deployed.target.os = TargetOs::Macos;
        }),
        drifted("wrong-target-architecture", "wrong-target", |deployed| {
            deployed.target.arch = TargetArch::Aarch64;
        }),
        drifted("wrong-gateway-build", "wrong-target", |deployed| {
            deployed.target.gateway_build_sha256 = digest_of("another gateway build");
        }),
        drifted("wrong-gateway-version", "wrong-target", |deployed| {
            deployed.target.gateway_version = super::bounded("1.0.0-rc.2");
        }),
        drifted("wrong-store-kind", "wrong-store", |deployed| {
            deployed.target.store_kind = LifecycleStoreKind::SharedFileV1;
        }),
        drifted("wrong-store-schema", "wrong-store", |deployed| {
            deployed.target.store_schema = super::bounded("auths.lifecycle.postgresql/6");
        }),
        drifted(
            "wrong-credential-store",
            "wrong-credential-store",
            |deployed| {
                deployed.target.credential_store_kind = CredentialStoreKind::LocalFileV1;
            },
        ),
    ]
}

fn presence_cases(parts: &Parts) -> Vec<Value> {
    use RecipeQualificationState::{Qualified, Unqualified};
    let keys = &parts.keys;
    let empty_index = text(&index(index_statement(Vec::new()), &keys.signer));
    let mut second = tuple();
    second.target.arch = TargetArch::Aarch64;
    let second_record = text(&record(2, second.clone()));
    let second_attestation = text(&attestation(
        attestation_statement(&second_record, 2),
        &keys.signer,
    ));
    let both = text(&index(
        index_statement(vec![
            index_entry(1, &parts.record_text, &parts.attestation_text),
            index_entry(2, &second_record, &second_attestation),
        ]),
        &keys.signer,
    ));
    vec![
        case("current", "valid", json!({}), Qualified, None),
        case(
            "second-target-attested",
            "valid",
            json!({
                "records": [parts.record_text, second_record],
                "attestations": [parts.attestation_text, second_attestation],
                "release_index": both,
                "deployment": serde_json::to_value(second).expect("tuple"),
            }),
            Qualified,
            None,
        ),
        case(
            "nothing-attested",
            "missing",
            json!({"records": [], "attestations": [], "release_index": empty_index}),
            Unqualified,
            Some(MISSING),
        ),
        case(
            "record-absent",
            "missing",
            json!({"records": []}),
            Unqualified,
            Some(MISSING),
        ),
    ]
}

fn document() -> Value {
    let parts = Parts::new();
    let cases: Vec<Value> = [
        presence_cases(&parts),
        trust_cases(&parts),
        attestation_cases(&parts),
        precedence_cases(&parts),
        time_cases(&parts),
        revocation_cases(&parts),
        digest_cases(),
        target_cases(),
    ]
    .concat();
    json!({
        "schema": SCHEMA,
        "status": "driven: the release verifier decides every case as frozen",
        "precedence": PRECEDENCE
            .iter()
            .map(|(condition, code)| json!({"when": condition, "code": code}))
            .collect::<Vec<_>>(),
        "base": parts.base(),
        "cases": cases,
    })
}

#[test]
fn verification_vectors_are_current() {
    require_current(FILE, &document());
}

/// One input of a case: the replacement when the case names one, the
/// base's otherwise.
fn input<'corpus>(corpus: &'corpus Value, case: &'corpus Value, member: &str) -> &'corpus Value {
    case["replace"]
        .get(member)
        .unwrap_or(&corpus["base"][member])
}

fn texts(value: &Value) -> Vec<&[u8]> {
    value
        .as_array()
        .expect("texts")
        .iter()
        .map(|text| text.as_str().expect("text").as_bytes())
        .collect()
}

/// Every frozen case, decided by the verifier exactly as frozen: the state,
/// the first reason, and whether a credential may be leased.
#[test]
fn every_verification_case_is_decided_as_frozen() {
    let corpus = load(FILE);
    let root = QualificationTrustRoot::from_canonical_json(
        corpus["base"]["trust_root"]
            .as_str()
            .expect("root")
            .as_bytes(),
    )
    .expect("trust root");
    let mut ids = BTreeSet::new();
    let mut codes = BTreeSet::new();
    let mut states = BTreeSet::new();
    for case in corpus["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        assert!(ids.insert(id), "duplicate case {id}");
        let text = |member: &str| {
            input(&corpus, case, member)
                .as_str()
                .expect("text")
                .as_bytes()
        };
        let records = texts(input(&corpus, case, "records"));
        let attestations = texts(input(&corpus, case, "attestations"));
        let verified = VerifiedQualifications::verify(
            &root,
            &QualificationInputs {
                signer_certificate: text("signer_certificate"),
                revocation_list: text("revocation_list"),
                release_index: text("release_index"),
                records: &records,
                attestations: &attestations,
            },
        );
        let known = input(&corpus, case, "known_revocations");
        let state = VerifierState {
            accepted_revocation_sequence: input(&corpus, case, "accepted_revocation_sequence")
                .as_u64()
                .expect("sequence"),
            revoked_signers: serde_json::from_value(known["signers"].clone()).expect("signers"),
            revoked_qualifications: serde_json::from_value(known["qualifications"].clone())
                .expect("qualifications"),
            ..VerifierState::default()
        };
        let deployment: QualificationTuple =
            serde_json::from_value(input(&corpus, case, "deployment").clone()).expect("tuple");
        let verdict = verified.evaluate(
            &deployment,
            input(&corpus, case, "now").as_u64().expect("now"),
            input(&corpus, case, "clock") == "trusted",
            &state,
        );
        let code = verdict
            .refusal
            .map(|refusal| format!("gateway.qualification.{}", refusal.as_str()));
        assert_eq!(
            verdict.state.as_str(),
            case["expect"]["state"],
            "case {id}: state"
        );
        assert_eq!(json!(code), case["expect"]["code"], "case {id}: code");
        assert_eq!(
            json!(verdict.permits_lease()),
            case["expect"]["lease"],
            "case {id}: lease"
        );
        states.insert(verdict.state.as_str().to_owned());
        codes.extend(code);
    }
    let every_state: BTreeSet<String> = RecipeQualificationState::ALL
        .iter()
        .map(|state| state.as_str().to_owned())
        .collect();
    assert_eq!(states, every_state, "every state is reached by some case");
    let every_code: BTreeSet<String> = PRECEDENCE
        .iter()
        .map(|(_, code)| (*code).to_owned())
        .collect();
    assert_eq!(codes, every_code, "every reason is reached by some case");
}

/// Revocation outlives the list that carried it, and an older list is not
/// accepted after a newer one.
#[test]
fn what_a_verified_list_revoked_is_remembered() {
    let parts = Parts::new();
    let keys = &parts.keys;
    let root = QualificationTrustRoot::from_canonical_json(text(&trust_root(keys)).as_bytes())
        .expect("trust root");
    let certificate = parts.certificate(|_| {});
    let index = parts.index_for(&parts.attestation_text);
    let verify = |revocation_list: &str| {
        VerifiedQualifications::verify(
            &root,
            &QualificationInputs {
                signer_certificate: certificate.as_bytes(),
                revocation_list: revocation_list.as_bytes(),
                release_index: index.as_bytes(),
                records: &[parts.record_text.as_bytes()],
                attestations: &[parts.attestation_text.as_bytes()],
            },
        )
    };
    let mut state = VerifierState::default();
    let naming = parts.revocation(|statement| {
        statement.sequence = 8;
        statement.revoked_qualifications = vec![qualification_id(1)];
    });
    verify(&naming).remember(&mut state);
    assert_eq!(state.accepted_revocation_sequence, 8);
    assert!(state.revoked_qualifications.contains(&qualification_id(1)));

    // A later list that omits the qualification does not restore it.
    let later = verify(&parts.revocation(|statement| statement.sequence = 9));
    later.remember(&mut state);
    let verdict = later.evaluate(&tuple(), NOW, true, &state);
    assert_eq!(verdict.state, RecipeQualificationState::Revoked);
    assert!(!verdict.permits_lease());

    // The original list, presented again, is older than the accepted one.
    let mut fresh = VerifierState {
        accepted_revocation_sequence: 9,
        ..VerifierState::default()
    };
    let replayed = verify(&parts.revocation(|_| {}));
    let verdict = replayed.evaluate(&tuple(), NOW, true, &fresh);
    assert_eq!(
        verdict.refusal,
        Some(crate::QualificationRefusal::Unavailable)
    );
    replayed.remember(&mut fresh);
    assert_eq!(
        fresh.accepted_revocation_sequence, 9,
        "an older list lowers nothing"
    );
}
