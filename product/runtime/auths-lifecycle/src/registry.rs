//! Closed lifecycle registration metadata.

use alloc::collections::BTreeSet;

use crate::{DomainId, ProviderContractId, ProviderRetryClass, ReservationAlgebraId};

/// One immutable domain registration against the shared lifecycle mechanics.
///
/// Every value is declarative. Provider functions, credentials, requests,
/// evidence interpretation, and callbacks are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRegistrationV1 {
    /// Domain vertical.
    pub domain_id: DomainId,
    /// Closed reservation algebra.
    pub reservation_algebra_id: ReservationAlgebraId,
    /// Closed provider execution contract.
    pub provider_contract_id: ProviderContractId,
    /// Provider retry semantics.
    pub retry_class: ProviderRetryClass,
    /// Canonical reservation-key fixture path.
    pub reservation_fixture: &'static str,
    /// Canonical lifecycle fixture path.
    pub lifecycle_fixture: &'static str,
    /// Lean theorem namespace.
    pub formal_namespace: &'static str,
    /// Rust/Kani harness path.
    pub kani_harness: &'static str,
    /// Store conformance suite path.
    pub store_conformance: &'static str,
    /// Domain production path has migrated through differential evidence.
    pub production_migrated: bool,
}

/// Invalid closed lifecycle registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRegistryError {
    /// The registry is empty.
    Empty,
    /// A domain, reservation algebra, or provider contract is registered twice.
    DuplicateIdentity,
    /// A required evidence path or namespace is empty.
    MissingEvidence,
}

/// Validates uniqueness and complete evidence pointers.
///
/// # Errors
///
/// Returns [`LifecycleRegistryError`] when the registry is empty, duplicates a
/// closed identity, or omits any required evidence path.
pub fn validate_lifecycle_registry(
    registrations: &[LifecycleRegistrationV1],
) -> Result<(), LifecycleRegistryError> {
    if registrations.is_empty() {
        return Err(LifecycleRegistryError::Empty);
    }
    let mut domains = BTreeSet::new();
    let mut algebras = BTreeSet::new();
    let mut providers = BTreeSet::new();
    for registration in registrations {
        if !domains.insert(registration.domain_id.as_str())
            || !algebras.insert(registration.reservation_algebra_id.as_str())
            || !providers.insert(registration.provider_contract_id.as_str())
        {
            return Err(LifecycleRegistryError::DuplicateIdentity);
        }
        if [
            registration.reservation_fixture,
            registration.lifecycle_fixture,
            registration.formal_namespace,
            registration.kani_harness,
            registration.store_conformance,
        ]
        .iter()
        .any(|value| value.is_empty())
        {
            return Err(LifecycleRegistryError::MissingEvidence);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn registration(domain: &str, suffix: &str) -> LifecycleRegistrationV1 {
        LifecycleRegistrationV1 {
            domain_id: DomainId::parse(domain).unwrap(),
            reservation_algebra_id: ReservationAlgebraId::parse(&format!("algebra-{suffix}"))
                .unwrap(),
            provider_contract_id: ProviderContractId::parse(&format!("provider-{suffix}")).unwrap(),
            retry_class: ProviderRetryClass::NonRetryable,
            reservation_fixture: "fixture.cbor",
            lifecycle_fixture: "lifecycle.cbor",
            formal_namespace: "Auths.Product.Lifecycle",
            kani_harness: "kernel.rs",
            store_conformance: "stores.rs",
            production_migrated: false,
        }
    }

    #[test]
    fn registry_is_closed_and_unique() {
        let first = registration("stripe", "stripe");
        let second = registration("stripe", "postgresql");
        assert_eq!(
            validate_lifecycle_registry(&[first, second]),
            Err(LifecycleRegistryError::DuplicateIdentity)
        );
    }
}
