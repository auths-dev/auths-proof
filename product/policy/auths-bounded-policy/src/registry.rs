use crate::{CanonicalizationId, EvaluatorSemanticId, ImplementationId, PolicyTypeId, ProfileId};

/// Closed conformance registration for one typed domain evaluator.
///
/// The record names concrete symbols and schemas. It intentionally carries no
/// callback and performs no type erasure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorRegistrationV1 {
    /// Cargo package that owns the evaluator.
    pub owning_package: &'static str,
    /// Must be exactly `product`.
    pub layer: &'static str,
    /// Exact action profile.
    pub profile_id: ProfileId,
    /// Exact policy schema.
    pub policy_type: PolicyTypeId,
    /// Immutable evaluator semantics.
    pub evaluator_semantic_id: EvaluatorSemanticId,
    /// Concrete implementation/build family.
    pub implementation_id: ImplementationId,
    /// Policy/action canonicalization.
    pub canonicalization_id: CanonicalizationId,
    /// Concrete Rust entry point, not a callback.
    pub rust_symbol: &'static str,
    /// Lean claim or refinement artifact.
    pub lean_artifact: &'static str,
    /// Machine-owned fixture manifest.
    pub fixture_manifest: &'static str,
    /// Whether production has migrated to the shared contract.
    pub migrated: bool,
}

/// Validates a closed, canonical evaluator inventory.
pub fn validate_registry(registrations: &[EvaluatorRegistrationV1]) -> Result<(), RegistryError> {
    let mut previous: Option<(&ProfileId, &PolicyTypeId, &EvaluatorSemanticId)> = None;
    for registration in registrations {
        if registration.layer != "product" {
            return Err(RegistryError::WrongLayer);
        }
        if registration.owning_package.is_empty()
            || registration.rust_symbol.is_empty()
            || registration.lean_artifact.is_empty()
            || registration.fixture_manifest.is_empty()
        {
            return Err(RegistryError::MissingEvidence);
        }
        let key = (
            &registration.profile_id,
            &registration.policy_type,
            &registration.evaluator_semantic_id,
        );
        if previous.is_some_and(|prior| prior >= key) {
            return Err(RegistryError::OrderingOrDuplicate);
        }
        previous = Some(key);
    }
    Ok(())
}

/// Closed registry validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A shared evaluator was registered outside the product layer.
    WrongLayer,
    /// A concrete symbol, formal artifact, or fixture manifest is absent.
    MissingEvidence,
    /// Entries are duplicated or not in canonical tuple order.
    OrderingOrDuplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(profile: &str) -> EvaluatorRegistrationV1 {
        EvaluatorRegistrationV1 {
            owning_package: "auths-test",
            layer: "product",
            profile_id: ProfileId::parse(profile).unwrap(),
            policy_type: PolicyTypeId::parse("auths.test.policy/1").unwrap(),
            evaluator_semantic_id: EvaluatorSemanticId::parse("auths.test.evaluate/1").unwrap(),
            implementation_id: ImplementationId::parse("auths-test/0.1.0").unwrap(),
            canonicalization_id: CanonicalizationId::parse("canonical-cbor/1").unwrap(),
            rust_symbol: "auths_test::evaluate",
            lean_artifact: "Auths.Product.Test",
            fixture_manifest: "product/fixtures/v1/test/manifest.json",
            migrated: false,
        }
    }

    #[test]
    fn registry_is_closed_ordered_and_evidence_bearing() {
        assert_eq!(
            validate_registry(&[
                registration("auths.test.alpha/1"),
                registration("auths.test.beta/1")
            ]),
            Ok(())
        );
        assert_eq!(
            validate_registry(&[
                registration("auths.test.beta/1"),
                registration("auths.test.alpha/1")
            ]),
            Err(RegistryError::OrderingOrDuplicate)
        );
    }
}
