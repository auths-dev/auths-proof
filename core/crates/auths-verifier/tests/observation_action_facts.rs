//! Observation requirements that use profile action facts.
//!
//! The core registry's `exact-v1` policy defines no action facts, so the
//! corpus can only show those requirements as indeterminate. These tests
//! install a profile policy that defines the facts and check both verdicts.

use auths_model::{
    AdapterConfigurationId, CanonicalAction, DenialReason, FactName, FactText, FactValue,
    ProfilePolicyId,
};
use auths_ports::{
    PrincipalMethod, ProfileDecision, ProfilePolicy, RegistryOperationError, SignatureSuite,
};
use auths_registries::{ImmutableRegistries, PureRegistrySet};
use auths_verifier::{VerificationOutcome, verify};

struct FactsPolicy {
    id: ProfilePolicyId,
}

impl ProfilePolicy for FactsPolicy {
    fn id(&self) -> &ProfilePolicyId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(self.id.as_str().as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self, action: &CanonicalAction) -> u64 {
        u64::try_from(action.body().len()).unwrap_or(u64::MAX)
    }

    fn evaluate(
        &self,
        _action: &CanonicalAction,
    ) -> Result<ProfileDecision, RegistryOperationError> {
        Ok(ProfileDecision::Accept)
    }

    fn action_fact(
        &self,
        _action: &CanonicalAction,
        name: &FactName,
    ) -> Result<Option<FactValue>, RegistryOperationError> {
        let value = match name.as_str() {
            "record_uri" => "mcp://reports/read",
            "expected" => "observed-by-provider",
            _ => return Ok(None),
        };
        FactText::new(value)
            .map(|text| Some(FactValue::Text(text)))
            .map_err(|_| RegistryOperationError::InvalidInput)
    }
}

fn run(observed_stage: &str) -> VerificationOutcome {
    let policy = FactsPolicy {
        id: ProfilePolicyId::parse("observation-facts-test-v1").unwrap(),
    };
    let method = auths_raw_key::RawKeyMethod::new().unwrap();
    let suite = auths_signature::Ed25519Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 1] = [&method];
    let suites: [&dyn SignatureSuite; 1] = [&suite];
    let policies: [&dyn ProfilePolicy; 1] = [&policy];
    let registries = ImmutableRegistries::with_pure(
        &methods,
        &suites,
        PureRegistrySet {
            resource_matchers: &[],
            profile_policies: &policies,
            budget_algebras: &[],
            extension_handlers: &[],
            status_methods: &[],
            assurance_claims: &[],
            assurance_implications: &[],
        },
    )
    .unwrap();
    let fixture = auths_testkit::observation_action_fact_fixture(&policy.id, observed_stage);
    let context = auths_codec::decode_verifier_context(fixture.context_bytes())
        .unwrap()
        .with_configuration(registries.configuration_id())
        .unwrap();
    verify(
        fixture.proof_bytes(),
        fixture.canonical_action(),
        &context,
        &registries,
    )
}

#[test]
fn action_fact_subject_and_equality_authorize_a_matching_observation() {
    let VerificationOutcome::Authorized(action) = run("observed-by-provider") else {
        panic!("matching observation must authorize");
    };
    assert_eq!(action.observation_satisfactions().len(), 1);
}

#[test]
fn a_changed_expected_value_is_denied() {
    assert_eq!(
        run("replaced-in-between"),
        VerificationOutcome::Denied(DenialReason::ObservationConditionFalse)
    );
}
