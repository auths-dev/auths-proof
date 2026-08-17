//! Differential test: `auths-node` and the verified kernel must reach the same
//! authorization decision on identical inputs.
//!
//! The inputs are the canonical target V1 corpus in `core/fixtures/v1`, reached
//! through `auths_testkit::corpus()`. Every case supplies one exact
//! `(proof, canonical action, trusted context)` triple and the normative
//! decision. The reference side is `auths_verifier::verify` called directly.
//! The subject side is `auths-node`'s public decision path reached through
//! `NodeRuntime::handle`. Nothing is translated between the two sides: both
//! receive the same proof bytes, the same canonical action, the same trusted
//! context, and the same principal-method and signature-suite registries.
//!
//! The corpus exercises every one of the eleven generated attenuation
//! dimensions declared in `core/crates/auths-algebra-kernel/src/generated.rs`.
//! `dimension_coverage_is_complete` fails if a dimension loses its case.

use auths_model::{CanonicalAction, DenialReason, Requirement, TrustedContext};
use auths_node::{KernelRuntime, NodeClock, NodeKernel, NodeRuntime, RuntimeFailure};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_production_client::{
    ClientOutcomeKind, ProductVerb, ProductionRequest, QualifiedProfile,
};
use auths_registries::ImmutableRegistries;
use auths_testkit::{CorpusFixture, Expected};
use auths_verifier::VerificationOutcome;
use std::collections::BTreeSet;

/// The closed decision both sides must agree on.
#[derive(Debug, Eq, PartialEq)]
enum Decision {
    Authorized,
    Denied(DenialReason),
    Indeterminate(Requirement),
    /// Any answer that is not an authorization decision at all.
    NotAnAuthorizationAnswer(String),
}

/// One corpus case and the dimension it pins, for the coverage assertion.
///
/// The names are the eleven `AttenuationProjection` methods.
const DIMENSION_CASES: &[(&str, &str)] = &[
    ("root_preserved", "untrusted-root"),
    ("depth_decreases", "depth-widening"),
    ("profile_attenuates", "unsupported-action-profile"),
    ("permissions_attenuate", "permission-widening"),
    ("validity_attenuates", "validity-widening"),
    ("audiences_attenuate", "audience-widening"),
    ("action_constraint_attenuates", "action-constraint-mismatch"),
    ("budget_attenuates", "budget-widening"),
    ("status_attenuates", "revoked-grant-status"),
    ("assurance_attenuates", "assurance-policy-change"),
    ("extensions_attenuate", "critical-extension-attenuation"),
];

fn methods() -> Vec<Box<dyn PrincipalMethod + Send + Sync>> {
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    vec![
        Box::new(auths_raw_key::RawKeyMethod::new().expect("raw key method")),
        Box::new(auths_did_key::DidKeyMethod::new().expect("did:key method")),
        Box::new(auths_did_keri::DidKeriMethod::new().expect("did:keri method")),
        Box::new(
            auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
                .expect("did:web method"),
        ),
        Box::new(
            auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials())
                .expect("webauthn method"),
        ),
        Box::new(
            auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
                .expect("hsm method"),
        ),
        Box::new(
            auths_spiffe_x509::SpiffeX509Method::new(spiffe_trust, spiffe_status)
                .expect("spiffe method"),
        ),
    ]
}

fn suites() -> Vec<Box<dyn SignatureSuite + Send + Sync>> {
    vec![
        Box::new(auths_signature::Ed25519Suite::new().expect("ed25519 suite")),
        Box::new(auths_signature::P256Sha256Suite::new().expect("p256 suite")),
    ]
}

/// Reference decision: the kernel verifier, called directly.
fn kernel_decision(proof: &[u8], action: &CanonicalAction, context: &TrustedContext) -> Decision {
    let owned_methods = methods();
    let owned_suites = suites();
    let borrowed: Vec<&dyn PrincipalMethod> = owned_methods
        .iter()
        .map(|method| method.as_ref() as &dyn PrincipalMethod)
        .collect();
    let borrowed_suites: Vec<&dyn SignatureSuite> = owned_suites
        .iter()
        .map(|suite| suite.as_ref() as &dyn SignatureSuite)
        .collect();
    let registries =
        ImmutableRegistries::new(&borrowed, &borrowed_suites).expect("corpus registries");
    match auths_verifier::verify(proof, action, context, &registries) {
        VerificationOutcome::Authorized(_) => Decision::Authorized,
        VerificationOutcome::Denied(reason) => Decision::Denied(reason),
        VerificationOutcome::Indeterminate(requirement) => Decision::Indeterminate(requirement),
    }
}

/// Subject decision: `auths-node`'s public decision path on the same triple.
///
/// The request identity is deliberately a self-asserted string with no relation
/// to any principal in the proof. If it influenced the decision at all this
/// differential would diverge.
fn node_decision(context: &TrustedContext, proof: &[u8], action_bytes: &[u8]) -> Decision {
    let runtime = node_runtime(context);
    let request = ProductionRequest::new(
        ProductVerb::Execute,
        QualifiedProfile::GitHubIssueAddress,
        b"self-asserted-caller".to_vec(),
        Some(proof.to_vec()),
        Some(action_bytes.to_vec()),
        None,
    )
    .expect("execute request shape");
    match runtime.handle(request) {
        Ok(response) if response.kind() == ClientOutcomeKind::Completed => Decision::Authorized,
        Ok(response) => Decision::NotAnAuthorizationAnswer(format!("{:?}", response.kind())),
        Err(RuntimeFailure::AuthorizationDenied(reason)) => Decision::Denied(reason),
        Err(RuntimeFailure::AuthorizationIndeterminate(requirement)) => {
            Decision::Indeterminate(requirement)
        }
        Err(other) => Decision::NotAnAuthorizationAnswer(other.code().to_owned()),
    }
}

/// A clock frozen at the trusted context's own evaluation instant.
///
/// Time is one of the inputs. Handing the node a different instant than the
/// reference verifier would make this a comparison of two different questions.
struct FrozenClock(u64);

impl NodeClock for FrozenClock {
    fn now_unix_seconds(&self) -> u64 {
        self.0
    }
}

fn node_runtime(context: &TrustedContext) -> KernelRuntime {
    KernelRuntime::with_clock(
        NodeKernel::new(context.clone(), methods(), suites()).expect("node kernel"),
        [7; 32],
        [QualifiedProfile::GitHubIssueAddress].into_iter().collect(),
        std::sync::Arc::new(FrozenClock(context.evaluation_time().get())),
    )
    .expect("node runtime")
}

fn fixture_context(fixture: &CorpusFixture) -> TrustedContext {
    auths_codec::decode_verifier_context(fixture.context_bytes()).expect("corpus context")
}

fn fixture_action_bytes(fixture: &CorpusFixture) -> Vec<u8> {
    auths_codec::encode_canonical_action(fixture.canonical_action()).expect("corpus action bytes")
}

/// The corpus expectation and the reference verifier must agree before the
/// reference is used to judge `auths-node`. Without this the differential could
/// be green against a drifted reference.
#[test]
fn reference_side_matches_the_normative_corpus() {
    for fixture in auths_testkit::corpus() {
        let context = fixture_context(&fixture);
        let actual = kernel_decision(fixture.proof_bytes(), fixture.canonical_action(), &context);
        let expected = match fixture.expected() {
            Expected::Authorized => Decision::Authorized,
            Expected::Denied(reason) => Decision::Denied(reason),
            Expected::Indeterminate(requirement) => Decision::Indeterminate(requirement),
        };
        assert_eq!(
            actual,
            expected,
            "reference verifier drifted from the corpus on {}",
            fixture.name()
        );
    }
}

#[test]
fn node_and_kernel_agree_on_every_startable_canonical_corpus_input() {
    let mut disagreements = Vec::new();
    let mut compared = 0_usize;
    for fixture in auths_testkit::corpus() {
        let context = fixture_context(&fixture);
        if context.configuration() != auths_testkit::corpus_configuration_id() {
            assert_eq!(
                fixture.name(),
                "verifier-configuration-mismatch",
                "only the deliberate startup mismatch may carry another configuration"
            );
            continue;
        }
        let action_bytes = fixture_action_bytes(&fixture);
        let kernel = kernel_decision(fixture.proof_bytes(), fixture.canonical_action(), &context);
        let node = node_decision(&context, fixture.proof_bytes(), &action_bytes);
        compared += 1;
        if node != kernel {
            disagreements.push(format!(
                "{}: kernel={kernel:?} node={node:?}",
                fixture.name()
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "auths-node disagreed with the kernel on {} of {compared} canonical corpus inputs:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
}

#[test]
fn a_mismatched_corpus_configuration_is_rejected_before_the_node_can_serve() {
    let fixture = auths_testkit::corpus()
        .into_iter()
        .find(|fixture| fixture.name() == "verifier-configuration-mismatch")
        .expect("configuration mismatch fixture");
    let context = fixture_context(&fixture);
    assert!(matches!(
        NodeKernel::new(context, methods(), suites()),
        Err(RuntimeFailure::Malformed)
    ));
}

#[test]
fn dimension_coverage_is_complete() {
    let names: BTreeSet<&str> = auths_testkit::corpus()
        .iter()
        .map(CorpusFixture::name)
        .collect();
    let missing: Vec<&str> = DIMENSION_CASES
        .iter()
        .filter(|(_, case)| !names.contains(case))
        .map(|(dimension, _)| *dimension)
        .collect();
    assert!(
        missing.is_empty(),
        "these attenuation dimensions lost their corpus case: {missing:?}"
    );
    assert_eq!(
        DIMENSION_CASES.len(),
        11,
        "the generated kernel declares eleven attenuation dimensions"
    );
}
