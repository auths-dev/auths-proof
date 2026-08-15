//! Machine-readable adversarial conformance inventory.

use crate::{
    CorpusFixture, Expected, Identity, PrincipalKind, action_channel_mismatch,
    did_web_history_without_statement_existence, missing_principal_status, raw_key_chain,
    spiffe_material_with_client_auth, stale_grant_status, unknown_principal_method,
    unsupported_assurance_claim, unsupported_profile_policy, unsupported_resource_matcher,
    wrong_audience, wrong_challenge,
};
use auths_codec::{decode_verifier_context, encode_verifier_context, evidence_id};
use auths_did_keri::{DidKeriMethod, KelEvent, KeriEvidence};
use auths_did_key::DidKeyMethod;
use auths_hsm_attested::HsmAttestedMethod;
use auths_model::{
    CompositionRequirement, DenialReason, EvidenceId, EvidenceObject, EvidenceTypeId, MediaType,
    ModelError, PrincipalStatusSnapshot, Requirement, Timestamp, TrustedContext,
};
use auths_ports::{
    ControlPurpose, PrincipalControlError, PrincipalControlInput, PrincipalMethod, SignatureSuite,
};
use auths_raw_key::RawKeyMethod;
use auths_spiffe_x509::SpiffeX509Method;
use auths_webauthn::WebAuthnMethod;
use serde::{Deserialize, Serialize};
use std::{boxed::Box, collections::BTreeSet};

/// Versioned adversarial conformance manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceManifest {
    /// Schema identifier.
    pub schema: String,
    /// Protocol major version.
    pub protocol: u16,
    /// Deterministic cases.
    pub cases: Vec<ConformanceCase>,
}

/// One deterministic mutation and exact boundary oracle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceCase {
    /// Stable `<surface>/<seed>/<mutation>/<boundary>` identifier.
    pub case: String,
    /// Semantic requirements exercised by this case.
    pub requirements: Vec<String>,
    /// Boundary under test.
    pub boundary: String,
    /// Expected portable or adapter-local code.
    pub expected_code: String,
}

/// Result of executing one named boundary recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundaryExecution {
    /// A constructor or principal-method boundary returned this exact code.
    Completed(&'static str),
    /// The recipe produced immutable inputs for execution by the full verifier.
    FullVerifier(Box<CorpusFixture>),
}

impl ConformanceManifest {
    /// Parses and validates a conformance manifest.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic for schema, identifier, duplicate, or
    /// coverage errors.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|error| format!("invalid JSON: {error}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates deterministic identifiers and required coverage families.
    ///
    /// # Errors
    ///
    /// Returns a stable diagnostic naming the missing or malformed item.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != "auths-proof-adversarial-conformance/v1" || self.protocol != 1 {
            return Err("unsupported adversarial conformance schema".to_owned());
        }
        let mut ids = BTreeSet::new();
        let mut requirements = BTreeSet::new();
        for case in &self.cases {
            if case.case.split('/').count() != 4
                || !case.case.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'/')
                })
            {
                return Err(format!("invalid conformance case identifier {}", case.case));
            }
            if !ids.insert(case.case.as_str()) {
                return Err(format!("duplicate conformance case {}", case.case));
            }
            if case.requirements.is_empty() {
                return Err(format!("case {} has no requirements", case.case));
            }
            requirements.extend(case.requirements.iter().map(String::as_str));
        }
        for family in [
            "CONTEXT.",
            "ADAPTER.COMMON.",
            "ADAPTER.RAW_KEY.",
            "ADAPTER.DID_KEY.",
            "ADAPTER.DID_KERI.",
            "ADAPTER.DID_WEB.",
            "ADAPTER.WEBAUTHN.",
            "ADAPTER.HSM.",
            "ADAPTER.SPIFFE.",
            "VERIFIER.MAPPING.",
        ] {
            if !requirements
                .iter()
                .any(|requirement| requirement.starts_with(family))
            {
                return Err(format!("missing requirement family {family}"));
            }
        }
        Ok(())
    }
}

/// Executes one deterministic recipe or returns its full-verifier inputs.
///
/// # Errors
///
/// Returns a bounded diagnostic when a repository-owned seed cannot be
/// constructed, the named mutation target cannot be found, or the boundary
/// unexpectedly accepts an adversarial input.
///
/// # Panics
///
/// Panics only when compiled synthetic fixture constants violate their own
/// model invariants. User-selected case names and adversarial bytes are
/// otherwise handled as typed failures.
pub fn execute_case(case: &str) -> Result<BoundaryExecution, String> {
    match case {
        "context/raw-key-chain/configuration-bitflip/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(configuration_bitflip())),
        ),
        "context/threshold/composition-zero/context-constructor" => {
            let result = CompositionRequirement::new(None, 0, 1, 1);
            Ok(BoundaryExecution::Completed(model_error_code(
                result.expect_err("zero composition minimum must fail"),
            )))
        }
        "context/raw-key-chain/duplicate-trust-anchor/context-constructor" => {
            Ok(BoundaryExecution::Completed(duplicate_anchor_code()?))
        }
        "context/raw-key-chain/registry-method-missing/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(unknown_principal_method())),
        ),
        "context/raw-key-chain/audience-bitflip/full-verifier" => {
            Ok(BoundaryExecution::FullVerifier(Box::new(wrong_audience())))
        }
        "context/raw-key-chain/challenge-bitflip/full-verifier" => {
            Ok(BoundaryExecution::FullVerifier(Box::new(wrong_challenge())))
        }
        "context/raw-key-chain/time-after-validity/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(time_after_validity())),
        ),
        "context/raw-key-chain/unsupported-assurance/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(unsupported_assurance_claim())),
        ),
        "context/raw-key-chain/principal-status-stale/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(stale_principal_status()?)),
        ),
        "context/raw-key-chain/grant-status-stale/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(stale_grant_status())),
        ),
        "context/raw-key-chain/resource-matcher-missing/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(unsupported_resource_matcher())),
        ),
        "context/raw-key-chain/profile-policy-missing/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(unsupported_profile_policy())),
        ),
        "context/raw-key-chain/channel-mismatch/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(action_channel_mismatch())),
        ),
        "context/raw-key-chain/work-limit-minus-one/full-verifier" => Ok(
            BoundaryExecution::FullVerifier(Box::new(work_limit_minus_one())),
        ),
        "raw-key/ed25519-valid/signature-suite-substitution/verify-control" => {
            Ok(BoundaryExecution::Completed(raw_key_suite_substitution()?))
        }
        "did-key/ed25519-valid/multicodec-substitution/verify-control" => Ok(
            BoundaryExecution::Completed(did_key_multicodec_substitution()?),
        ),
        "did-keri/rotated-valid/prior-link-bitflip/verify-control" => {
            Ok(BoundaryExecution::Completed(keri_prior_link_bitflip()?))
        }
        "did-web/historical-valid/remove-statement-pin/full-verifier" => {
            Ok(BoundaryExecution::FullVerifier(Box::new(
                did_web_history_without_statement_existence(),
            )))
        }
        "webauthn/p256-user-verified/client-challenge-bitflip/verify-control" => {
            Ok(BoundaryExecution::Completed(webauthn_challenge_bitflip()?))
        }
        "hsm-attested/reviewed-valid/transaction-digest-bitflip/verify-control" => Ok(
            BoundaryExecution::Completed(hsm_transaction_digest_bitflip()?),
        ),
        "spiffe-x509/valid/missing-client-auth-eku/verify-control" => {
            Ok(BoundaryExecution::Completed(spiffe_missing_client_eku()?))
        }
        _ => Err(format!("no executable conformance recipe for {case}")),
    }
}

fn model_error_code(error: ModelError) -> &'static str {
    match error {
        ModelError::InvalidVerifierContext => "invalid-verifier-context",
        ModelError::DuplicateObject => "duplicate-object",
        ModelError::CollectionLimitExceeded => "collection-limit-exceeded",
        _ => "unexpected-model-error",
    }
}

fn control_error_code(error: PrincipalControlError) -> &'static str {
    match error {
        PrincipalControlError::PrincipalMethodMismatch => "principal-method-mismatch",
        PrincipalControlError::VerificationMethodMismatch => "verification-method-mismatch",
        PrincipalControlError::InvalidEvidence => "invalid-evidence",
        PrincipalControlError::SignatureSuiteMismatch => "signature-suite-mismatch",
        PrincipalControlError::MissingEvidence => "missing-evidence",
        PrincipalControlError::ResourceLimitExceeded => "resource-limit-exceeded",
        PrincipalControlError::ExternalFactUnavailable => "external-fact-unavailable",
        PrincipalControlError::HistoricalStateUnavailable => "historical-state-unavailable",
        PrincipalControlError::PrincipalRevoked => "principal-revoked",
    }
}

#[cfg(test)]
fn expected_code(expected: Expected) -> &'static str {
    match expected {
        Expected::Authorized => "authorized",
        Expected::Denied(reason) => reason.code(),
        Expected::Indeterminate(requirement) => requirement.code(),
    }
}

fn duplicate_anchor_code() -> Result<&'static str, String> {
    let fixture = raw_key_chain();
    let context =
        decode_verifier_context(fixture.context_bytes()).map_err(|error| error.to_string())?;
    let mut anchors = context.trust_anchors().to_vec();
    anchors.push(
        anchors
            .first()
            .cloned()
            .ok_or_else(|| "raw-key seed has no trust anchor".to_owned())?,
    );
    let result = rebuild_context(&context, context.composition(), anchors, None);
    Ok(model_error_code(
        result.expect_err("duplicate trust-anchor ID must fail"),
    ))
}

fn configuration_bitflip() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context =
        decode_verifier_context(fixture.context_bytes()).expect("repository-owned raw-key context");
    let mut configuration = *context.configuration().as_bytes();
    configuration[0] ^= 1;
    let replacement = context
        .with_configuration(auths_model::VerifierConfigurationId::new(configuration))
        .expect("configuration commitment is an opaque digest");
    fixture.name = "conformance-configuration-bitflip";
    fixture.class = "denied";
    fixture.context_bytes =
        encode_verifier_context(&replacement).expect("canonical conformance context");
    fixture.expected = Expected::Denied(DenialReason::VerifierConfigurationMismatch);
    fixture
}

fn time_after_validity() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context =
        decode_verifier_context(fixture.context_bytes()).expect("repository-owned raw-key context");
    let replacement = context
        .for_request(
            context.expected_audience().clone(),
            context.expected_challenge(),
            Timestamp::new(61),
        )
        .expect("evaluation time remains inside context snapshot bounds");
    fixture.name = "conformance-time-after-validity";
    fixture.class = "denied";
    fixture.context_bytes =
        encode_verifier_context(&replacement).expect("canonical conformance context");
    fixture.expected = Expected::Denied(DenialReason::ActionOutsideValidity);
    fixture
}

fn stale_principal_status() -> Result<CorpusFixture, String> {
    let mut fixture = missing_principal_status();
    let context =
        decode_verifier_context(fixture.context_bytes()).map_err(|error| error.to_string())?;
    let source = context.principal_status_snapshot();
    let stale = PrincipalStatusSnapshot::with_trust(
        source.id(),
        source.observed_at(),
        Timestamp::new(49),
        source.statements().to_vec(),
        source.checkpoints().to_vec(),
        source.trust().to_vec(),
    )
    .map_err(|error| error.to_string())?;
    let replacement = rebuild_context(
        &context,
        context.composition(),
        context.trust_anchors().to_vec(),
        Some(stale),
    )
    .map_err(|error| error.to_string())?;
    fixture.name = "conformance-stale-principal-status";
    fixture.class = "indeterminate";
    fixture.context_bytes =
        encode_verifier_context(&replacement).map_err(|error| error.to_string())?;
    fixture.expected = Expected::Indeterminate(Requirement::StaleStatus);
    Ok(fixture)
}

fn work_limit_minus_one() -> CorpusFixture {
    let mut fixture = raw_key_chain();
    let context =
        decode_verifier_context(fixture.context_bytes()).expect("repository-owned raw-key context");
    let method = RawKeyMethod::new().expect("compiled raw-key method");
    let suite = auths_signature::Ed25519Suite::new().expect("compiled Ed25519 suite");
    let first_control_reservation = method
        .maximum_work_units()
        .checked_add(suite.work_units())
        .expect("fixed work reservations fit u64");
    let limits = context
        .limits()
        .clone()
        .with_work_units(first_control_reservation - 1)
        .expect("work limit remains inside protocol bounds");
    let replacement = context
        .with_limits(limits)
        .expect("lower work limit does not invalidate context collections");
    fixture.name = "conformance-work-limit-minus-one";
    fixture.class = "denied";
    fixture.context_bytes =
        encode_verifier_context(&replacement).expect("canonical conformance context");
    fixture.expected = Expected::Denied(DenialReason::ResourceLimitExceeded);
    fixture
}

fn rebuild_context(
    context: &TrustedContext,
    composition: CompositionRequirement,
    anchors: Vec<auths_model::TrustAnchor>,
    principal_status: Option<PrincipalStatusSnapshot>,
) -> Result<TrustedContext, ModelError> {
    TrustedContext::new(
        context.configuration(),
        composition,
        anchors,
        context.accepted_registries().clone(),
        context.expected_audience().clone(),
        context.expected_challenge(),
        context.evaluation_time(),
        context.assurance_policy().clone(),
        principal_status.unwrap_or_else(|| context.principal_status_snapshot().clone()),
        context.grant_status_snapshot().clone(),
        context.resource_matcher().clone(),
        context.profile_policy().clone(),
        context.channel_policy().clone(),
        context.limits().clone(),
    )
}

fn addressed_evidence(
    evidence_type: &str,
    media_type: &str,
    bytes: Vec<u8>,
) -> Result<EvidenceObject, String> {
    let evidence_type = EvidenceTypeId::parse(evidence_type).map_err(|error| error.to_string())?;
    let media_type = MediaType::parse(media_type).map_err(|error| error.to_string())?;
    let unaddressed = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        evidence_type.clone(),
        media_type.clone(),
        bytes,
    )
    .map_err(|error| error.to_string())?;
    EvidenceObject::new(
        evidence_id(&unaddressed).map_err(|error| error.to_string())?,
        evidence_type,
        media_type,
        unaddressed.bytes().to_vec(),
    )
    .map_err(|error| error.to_string())
}

fn run_control(
    method: &dyn PrincipalMethod,
    identity: &Identity,
    evidence: &EvidenceObject,
    suite: &str,
    signing_preimage: &[u8],
) -> Result<&'static str, String> {
    let verification_method = identity.verification_method();
    let suite = auths_model::SignatureSuiteId::parse(suite).map_err(|error| error.to_string())?;
    let evidence_refs = [evidence];
    match method.verify_control(PrincipalControlInput {
        principal: &identity.principal,
        verification_method: &verification_method,
        signature_suite: &suite,
        purpose: ControlPurpose::CapabilityInvocation,
        signing_preimage,
        asserted_signing_time: Timestamp::new(50),
        evidence: &evidence_refs,
        evaluation_time: Timestamp::new(50),
    }) {
        Ok(_) => Err("adversarial principal-control input unexpectedly succeeded".to_owned()),
        Err(error) => Ok(control_error_code(error)),
    }
}

fn raw_key_suite_substitution() -> Result<&'static str, String> {
    let identity = Identity::ed25519(201);
    let evidence = identity.evidence();
    let method = RawKeyMethod::new().map_err(|error| error.to_string())?;
    run_control(
        &method,
        &identity,
        &evidence,
        auths_signature::P256_SHA256_V1,
        b"raw-key-conformance",
    )
}

fn did_key_multicodec_substitution() -> Result<&'static str, String> {
    let identity = Identity::did_key_ed25519(202);
    let PrincipalKind::DidKey(seed) = &identity.principal_kind else {
        return Err("did:key seed selected the wrong principal kind".to_owned());
    };
    let mut bytes = seed.encode().map_err(|error| error.to_string())?;
    let multikey_length = seed.multikey().encoded().len();
    let payload_start = bytes
        .len()
        .checked_sub(multikey_length)
        .and_then(|offset| offset.checked_add(1))
        .ok_or_else(|| "did:key framing offset overflow".to_owned())?;
    let byte = bytes
        .get_mut(payload_start)
        .ok_or_else(|| "did:key multicodec payload is empty".to_owned())?;
    *byte = if *byte == b'1' { b'2' } else { b'1' };
    let evidence = addressed_evidence(
        auths_did_key::DID_KEY_V1,
        auths_did_key::DID_KEY_MEDIA_TYPE,
        bytes,
    )?;
    let method = DidKeyMethod::new().map_err(|error| error.to_string())?;
    run_control(
        &method,
        &identity,
        &evidence,
        auths_signature::ED25519_V1,
        b"did-key-conformance",
    )
}

fn keri_prior_link_bitflip() -> Result<&'static str, String> {
    let identity = Identity::did_keri_ed25519(203);
    let PrincipalKind::DidKeri { evidence: seed, .. } = &identity.principal_kind else {
        return Err("did:keri seed selected the wrong principal kind".to_owned());
    };
    let mut events = seed.events().to_vec();
    let rotation = events
        .get_mut(1)
        .ok_or_else(|| "rotated KERI seed has no rotation event".to_owned())?;
    let mut json = rotation.event_json().to_vec();
    let prior_start = json
        .windows(5)
        .position(|window| window == b"\"p\":\"")
        .and_then(|offset| offset.checked_add(5))
        .ok_or_else(|| "rotation event has no prior link".to_owned())?;
    let byte = json
        .get_mut(prior_start)
        .ok_or_else(|| "rotation prior link is empty".to_owned())?;
    *byte = if *byte == b'A' { b'B' } else { b'A' };
    *rotation =
        KelEvent::new(json, rotation.attachment().to_vec()).map_err(|error| error.to_string())?;
    let bytes = KeriEvidence::new(events)
        .and_then(|evidence| evidence.encode())
        .map_err(|error| error.to_string())?;
    let evidence = addressed_evidence(
        auths_did_keri::ADAPTER_ID,
        auths_did_keri::EVIDENCE_MEDIA_TYPE,
        bytes,
    )?;
    let method = DidKeriMethod::new().map_err(|error| error.to_string())?;
    run_control(
        &method,
        &identity,
        &evidence,
        auths_signature::ED25519_V1,
        b"did-keri-conformance",
    )
}

fn webauthn_challenge_bitflip() -> Result<&'static str, String> {
    let seed_preimage = b"webauthn-conformance";
    let identity = Identity::webauthn_p256(204, seed_preimage);
    let evidence = identity.evidence();
    let mut mutated = seed_preimage.to_vec();
    mutated[0] ^= 1;
    let PrincipalKind::WebAuthn { credential, .. } = &identity.principal_kind else {
        return Err("WebAuthn seed selected the wrong principal kind".to_owned());
    };
    let method =
        WebAuthnMethod::new(vec![credential.clone()]).map_err(|error| error.to_string())?;
    run_control(
        &method,
        &identity,
        &evidence,
        auths_signature::P256_SHA256_V1,
        &mutated,
    )
}

fn hsm_transaction_digest_bitflip() -> Result<&'static str, String> {
    let seed_preimage = b"hsm-conformance";
    let identity = Identity::hsm_ed25519(205, seed_preimage);
    let evidence = identity.evidence();
    let mut mutated = seed_preimage.to_vec();
    mutated[0] ^= 1;
    let PrincipalKind::Hsm { record, .. } = &identity.principal_kind else {
        return Err("HSM seed selected the wrong principal kind".to_owned());
    };
    let method = HsmAttestedMethod::new(vec![record.clone()]).map_err(|error| error.to_string())?;
    run_control(
        &method,
        &identity,
        &evidence,
        auths_signature::ED25519_V1,
        &mutated,
    )
}

fn spiffe_missing_client_eku() -> Result<&'static str, String> {
    let material = spiffe_material_with_client_auth(206, false);
    let method = SpiffeX509Method::new(vec![material.trust.clone()], vec![material.status])
        .map_err(|error| error.to_string())?;
    let identity = Identity {
        key: crate::TestKey::Ed25519(material.key),
        principal: material.principal,
        principal_kind: PrincipalKind::Spiffe {
            evidence: material.evidence,
            verification_method: material.verification_method,
        },
    };
    let evidence = identity.evidence();
    run_control(
        &method,
        &identity,
        &evidence,
        auths_signature::ED25519_V1,
        b"spiffe-conformance",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{adversarial::assert_canonical_context, corpus};

    #[test]
    fn adversarial_manifest_is_valid_and_deterministic() {
        let bytes = include_bytes!("../../../conformance/v1/manifest.json");
        let manifest = ConformanceManifest::parse(bytes).expect("valid conformance manifest");
        let reparsed = serde_json::to_vec(&manifest).expect("serializable conformance manifest");
        let second: ConformanceManifest =
            serde_json::from_slice(&reparsed).expect("round-trip manifest");
        assert_eq!(manifest, second);
    }

    #[test]
    fn every_canonical_context_round_trips_exactly() {
        for fixture in corpus() {
            assert_canonical_context(fixture.context_bytes()).unwrap_or_else(|error| {
                panic!(
                    "{} context failed canonical round trip: {error}",
                    fixture.name()
                )
            });
        }
    }

    #[test]
    fn every_manifest_case_has_an_executable_recipe_and_exact_local_oracle() {
        let bytes = include_bytes!("../../../conformance/v1/manifest.json");
        let manifest = ConformanceManifest::parse(bytes).expect("valid conformance manifest");
        for case in &manifest.cases {
            match execute_case(&case.case)
                .unwrap_or_else(|error| panic!("{} has no executable recipe: {error}", case.case))
            {
                BoundaryExecution::Completed(actual) => {
                    assert_eq!(actual, case.expected_code, "{}", case.case);
                }
                BoundaryExecution::FullVerifier(fixture) => {
                    assert_eq!(
                        expected_code(fixture.expected()),
                        case.expected_code,
                        "{}",
                        case.case
                    );
                }
            }
        }
    }
}
