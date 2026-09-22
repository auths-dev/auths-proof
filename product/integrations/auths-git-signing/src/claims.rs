//! Assurance claims that enabled principal methods emit.
//!
//! The kernel rejects an emitted claim unless the trusted context accepts it
//! and an executable rule for it is registered. Adapters for workload
//! identities emit their own claims (issuer, subject, transparency, ...), so
//! each enabled method brings the exact claim identifiers it may emit. The
//! rule only checks that a claim is of its exact kind; what the claim asserts
//! was verified by the adapter that produced it.

use auths_model::{AdapterConfigurationId, AssuranceClaim, AssuranceClaimId, ModelError};
use auths_ports::{AssuranceClaimRule, PrincipalMethod, RegistryOperationError, SignatureSuite};
use auths_registries::{ImmutableRegistries, PureRegistrySet, RegistryError};

/// Domain separator of a registered claim's configuration commitment.
const CONFIGURATION_DOMAIN: &[u8] = b"auths.git-signature/registered-claim/1\0";

/// A rule accepting exactly one adapter-emitted claim kind.
pub struct RegisteredClaim {
    id: AssuranceClaimId,
}

impl RegisteredClaim {
    /// Registers `id`.
    ///
    /// # Errors
    ///
    /// Returns a [`ModelError`] for an invalid claim identifier.
    pub fn new(id: &str) -> Result<Self, ModelError> {
        Ok(Self {
            id: AssuranceClaimId::parse(id)?,
        })
    }
}

/// Assembles executable registries from the enabled methods, suites, and
/// their claim rules. Trust construction and verification both use this, so
/// they always compute the same configuration commitment.
///
/// # Errors
///
/// Returns a [`RegistryError`] for duplicate or conflicting identifiers.
pub fn registries<'a>(
    methods: &'a [&'a dyn PrincipalMethod],
    suites: &'a [&'a dyn SignatureSuite],
    claims: &'a [&'a dyn AssuranceClaimRule],
) -> Result<ImmutableRegistries<'a>, RegistryError> {
    ImmutableRegistries::with_pure(
        methods,
        suites,
        PureRegistrySet {
            resource_matchers: &[],
            profile_policies: &[],
            budget_algebras: &[],
            extension_handlers: &[],
            status_methods: &[],
            assurance_claims: claims,
            assurance_implications: &[],
        },
    )
}

impl AssuranceClaimRule for RegisteredClaim {
    fn id(&self) -> &AssuranceClaimId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        let mut material = CONFIGURATION_DOMAIN.to_vec();
        material.extend_from_slice(self.id.as_str().as_bytes());
        auths_ports::configuration_id(&material, core::iter::empty())
    }

    fn maximum_work_units(&self, claim: &AssuranceClaim) -> u64 {
        u64::try_from(claim.parameters().len().saturating_add(1)).unwrap_or(u64::MAX)
    }

    fn validate(&self, claim: &AssuranceClaim) -> Result<(), RegistryOperationError> {
        if claim.kind() == &self.id {
            Ok(())
        } else {
            Err(RegistryOperationError::InvalidInput)
        }
    }
}
