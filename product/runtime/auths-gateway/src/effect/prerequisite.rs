//! Closed prerequisite acquisitions derived from a verified mutation and recipe.
//! These declarations are committed by the parent effect and displayed by its
//! native review. They grant neither read entry nor disclosure; the journal must
//! independently acknowledge each one-use acquisition before transport.

use super::{EffectBindingError, canonical};
use crate::engine::VerifiedCommand;
use crate::{ClosedActionRead, ClosedCredentialRead, CompiledRecipe};
use serde::{Serialize, Serializer};
use serde_json::Value;

/// Account, four denied-capability reads, pre-entry and relative ceiling.
const MAX_PREREQUISITES: usize = 7;
const MAX_RESPONSE_BYTES: usize = 65_536;

/// The complete ordered set for one mutation. Construction is private to the
/// native compiler; an application cannot append a request or select a purpose.
#[derive(Serialize)]
pub(super) struct Prerequisites(Vec<Prerequisite>);

#[derive(Serialize)]
struct Prerequisite {
    purpose: Purpose,
    request: Read,
    maximum_calls: u64,
    maximum_transport_seconds: u64,
    maximum_evidence_age_seconds: u64,
    disclosure: Disclosure,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum Disclosure {
    None,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Purpose {
    Account {
        json_pointer: String,
        expected_account_commitment: [u8; 32],
        commitment_domain: &'static str,
    },
    DeniedCapability {
        index: u8,
        refused_statuses: Vec<u16>,
    },
    PreEntry {
        json_pointers: Vec<String>,
        /// All selected native branches, evidence and conditions remain pinned.
        native_authority: [u8; 32],
    },
    RelativeCeiling {
        argument: u64,
        basis_points: u16,
        json_pointer: String,
        subtract_pointer: Option<String>,
        /// The exact verified values, rather than names to resolve later.
        binds: Vec<(String, Value)>,
    },
}

/// Retain the compiler's sealed read, not separately reconstructed URL data.
enum Read {
    Credential(ClosedCredentialRead),
    Action(ClosedActionRead),
}

impl Serialize for Read {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Request<'a> {
            method: &'a str,
            url: &'a str,
            headers: Vec<(&'a str, &'a str)>,
            maximum_response_bytes: usize,
        }
        let (method, url, headers, maximum_response_bytes) = match self {
            Self::Credential(read) => (
                read.method().as_str(),
                read.url(),
                read.headers(),
                read.maximum_response_bytes(),
            ),
            Self::Action(read) => (
                "GET",
                read.url(),
                read.headers(),
                read.maximum_response_bytes(),
            ),
        };
        Request {
            method,
            url,
            headers: headers.iter().map(|h| (h.name(), h.value())).collect(),
            maximum_response_bytes,
        }
        .serialize(serializer)
    }
}

impl Prerequisites {
    /// Synthetic store/driver oracles have no installed recipe/connection and
    /// make no claim that they bind or authorize actual prerequisite reads.
    #[cfg(any(test, feature = "testkit-harness"))]
    pub(super) const fn oracle_empty() -> Self {
        Self(Vec::new())
    }

    pub(super) fn compile(
        recipe: &CompiledRecipe,
        command: &VerifiedCommand,
        account: [u8; 32],
    ) -> Result<Self, EffectBindingError> {
        let mut plan = Self(Vec::new());
        let reads = recipe
            .credential_reads()
            .map_err(|_| EffectBindingError::Invalid)?;
        // The onboarding probe is not a mutation prerequisite. Commissioning
        // must acquire its own separately bound probe, never inherit this plan.
        if let Some(guard) = recipe.guard_checks() {
            match (reads.account(), guard.account_pointer) {
                (Some(read), Some(json_pointer)) => plan.push(
                    Purpose::Account {
                        json_pointer,
                        expected_account_commitment: account,
                        commitment_domain: "auths.gateway-account/1",
                    },
                    Read::Credential(read.clone()),
                )?,
                (None, None) => {}
                _ => return Err(EffectBindingError::Invalid),
            }
            if reads.denied().len() != guard.denied_refused.len() {
                return Err(EffectBindingError::Invalid);
            }
            for (index, (read, refused_statuses)) in
                reads.denied().iter().zip(guard.denied_refused).enumerate()
            {
                plan.push(
                    Purpose::DeniedCapability {
                        index: u8::try_from(index).map_err(|_| EffectBindingError::Invalid)?,
                        refused_statuses,
                    },
                    Read::Credential(read.clone()),
                )?;
            }
        } else if reads.account().is_some() || !reads.denied().is_empty() {
            return Err(EffectBindingError::Invalid);
        }
        match (
            command.request.pre_entry_read(),
            recipe.pre_entry_pointers(),
        ) {
            (Some(read), Some(pointers)) => plan.push(
                Purpose::PreEntry {
                    json_pointers: pointers.to_vec(),
                    native_authority: command.native_authority,
                },
                Read::Action(read.clone()),
            )?,
            (None, None) => {}
            _ => return Err(EffectBindingError::Invalid),
        }
        match (
            command.request.relative_ceiling_read(),
            recipe.ceiling_check(),
        ) {
            (Some(read), Some(ceiling)) => {
                let argument = ceiling
                    .argument_value(&command.arguments)
                    .ok_or(EffectBindingError::Invalid)?;
                let binds = ceiling
                    .binds
                    .into_iter()
                    .map(|(pointer, field)| {
                        command
                            .arguments
                            .get(&field)
                            .cloned()
                            .map(|value| (pointer, value))
                            .ok_or(EffectBindingError::Invalid)
                    })
                    .collect::<Result<_, _>>()?;
                plan.push(
                    Purpose::RelativeCeiling {
                        argument,
                        basis_points: ceiling.basis_points,
                        json_pointer: ceiling.json_pointer,
                        subtract_pointer: ceiling.subtract_pointer,
                        binds,
                    },
                    Read::Action(read.clone()),
                )?;
            }
            (None, None) => {}
            _ => return Err(EffectBindingError::Invalid),
        }
        canonical(&plan)?;
        Ok(plan)
    }

    fn push(&mut self, purpose: Purpose, request: Read) -> Result<(), EffectBindingError> {
        let maximum = match &request {
            Read::Credential(read) => read.maximum_response_bytes(),
            Read::Action(read) => read.maximum_response_bytes(),
        };
        if self.0.len() >= MAX_PREREQUISITES || !(1..=MAX_RESPONSE_BYTES).contains(&maximum) {
            return Err(EffectBindingError::Invalid);
        }
        self.0.push(Prerequisite {
            purpose,
            request,
            maximum_calls: 1,
            maximum_transport_seconds: 15,
            maximum_evidence_age_seconds: 30,
            disclosure: Disclosure::None,
        });
        Ok(())
    }
}
