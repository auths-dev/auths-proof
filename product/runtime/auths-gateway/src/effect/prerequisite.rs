//! Closed prerequisite acquisitions derived from a verified effect and recipe.
//! These declarations are committed by the parent effect and displayed by its
//! native review. They grant neither read entry nor disclosure; the journal must
//! independently acknowledge each one-use acquisition before transport.

use super::{EffectBindingError, canonical};
use crate::engine::VerifiedCommand;
use crate::{ClosedActionRead, ClosedCredentialRead, CompiledRecipe};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

/// Account, four denied-capability reads, pre-entry and relative ceiling.
const MAX_PREREQUISITES: usize = 7;
const MAX_RESPONSE_BYTES: usize = 65_536;
pub(crate) const MAX_PREREQUISITE_EVIDENCE_AGE_SECONDS: u64 = 30;

/// The complete ordered set for one mutation or independent recovery read. Construction is private to the
/// native compiler; an application cannot append a request or select a purpose.
#[derive(Serialize)]
pub(super) struct Prerequisites(Vec<Prerequisite>);

#[derive(Serialize)]
struct Prerequisite {
    purpose: Purpose,
    request: ClosedPrerequisiteRead,
    maximum_calls: u64,
    maximum_transport_seconds: u64,
    maximum_evidence_age_seconds: u64,
    disclosure: Disclosure,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Disclosure {
    None,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Purpose {
    Account {
        json_pointer: String,
        expected_account_commitment: [u8; 32],
        commitment_domain: String,
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
#[derive(Clone)]
pub(crate) enum ClosedPrerequisiteRead {
    Credential(ClosedCredentialRead),
    Action(ClosedActionRead),
}

impl Serialize for ClosedPrerequisiteRead {
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
    pub(super) fn kinds(&self) -> impl Iterator<Item = PrerequisiteKind> + '_ {
        self.0.iter().map(|declaration| declaration.purpose.kind())
    }

    pub(super) fn select(
        &self,
        kind: PrerequisiteKind,
    ) -> Result<(u8, &ClosedPrerequisiteRead), EffectBindingError> {
        let (index, declaration) = self
            .0
            .iter()
            .enumerate()
            .find(|(_, declaration)| declaration.purpose.kind() == kind)
            .ok_or(EffectBindingError::Invalid)?;
        Ok((
            u8::try_from(index).map_err(|_| EffectBindingError::Invalid)?,
            &declaration.request,
        ))
    }

    /// Synthetic store/driver oracles have no installed recipe/connection and
    /// make no claim that they bind or authorize actual prerequisite reads.
    #[cfg(any(test, feature = "testkit-harness"))]
    pub(super) const fn oracle_empty() -> Self {
        Self(Vec::new())
    }

    pub(super) fn credentials(
        recipe: &CompiledRecipe,
        account: [u8; 32],
    ) -> Result<Self, EffectBindingError> {
        let mut plan = Self(Vec::new());
        let reads = recipe
            .credential_reads()
            .map_err(|_| EffectBindingError::Invalid)?;
        // The onboarding probe is not an installed mutation/recovery prerequisite.
        // Candidate checks need their own authority, never inherit this plan.
        if let Some(guard) = recipe.guard_checks() {
            match (reads.account(), guard.account_pointer) {
                (Some(read), Some(json_pointer)) => plan.push(
                    Purpose::Account {
                        json_pointer,
                        expected_account_commitment: account,
                        commitment_domain: "auths.gateway-account/1".to_owned(),
                    },
                    ClosedPrerequisiteRead::Credential(read.clone()),
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
                    ClosedPrerequisiteRead::Credential(read.clone()),
                )?;
            }
        } else if reads.account().is_some() || !reads.denied().is_empty() {
            return Err(EffectBindingError::Invalid);
        }
        canonical(&plan)?;
        Ok(plan)
    }

    pub(super) fn compile(
        recipe: &CompiledRecipe,
        command: &VerifiedCommand,
        account: [u8; 32],
    ) -> Result<Self, EffectBindingError> {
        let mut plan = Self::credentials(recipe, account)?;
        match (
            command.request.pre_entry_read(),
            recipe.pre_entry_pointers(),
        ) {
            (Some(read), Some(pointers)) => plan.push(
                Purpose::PreEntry {
                    json_pointers: pointers.to_vec(),
                    native_authority: command.native_authority,
                },
                ClosedPrerequisiteRead::Action(read.clone()),
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
                    ClosedPrerequisiteRead::Action(read.clone()),
                )?;
            }
            (None, None) => {}
            _ => return Err(EffectBindingError::Invalid),
        }
        canonical(&plan)?;
        Ok(plan)
    }

    fn push(
        &mut self,
        purpose: Purpose,
        request: ClosedPrerequisiteRead,
    ) -> Result<(), EffectBindingError> {
        let maximum = match &request {
            ClosedPrerequisiteRead::Credential(read) => read.maximum_response_bytes(),
            ClosedPrerequisiteRead::Action(read) => read.maximum_response_bytes(),
        };
        if self.0.len() >= MAX_PREREQUISITES || !(1..=MAX_RESPONSE_BYTES).contains(&maximum) {
            return Err(EffectBindingError::Invalid);
        }
        self.0.push(Prerequisite {
            purpose,
            request,
            maximum_calls: 1,
            maximum_transport_seconds: 15,
            maximum_evidence_age_seconds: MAX_PREREQUISITE_EVIDENCE_AGE_SECONDS,
            disclosure: Disclosure::None,
        });
        Ok(())
    }
}

/// Closed selectors address compiler-owned declarations, never caller URLs.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PrerequisiteKind {
    Account,
    DeniedCapability(u8),
    PreEntry,
    RelativeCeiling,
}

impl Purpose {
    const fn kind(&self) -> PrerequisiteKind {
        match self {
            Self::Account { .. } => PrerequisiteKind::Account,
            Self::DeniedCapability { index, .. } => PrerequisiteKind::DeniedCapability(*index),
            Self::PreEntry { .. } => PrerequisiteKind::PreEntry,
            Self::RelativeCeiling { .. } => PrerequisiteKind::RelativeCeiling,
        }
    }
}

/// Private membership witness for one read in the exact approved parent effect.
/// Audit decoding cannot construct the sealed request or grant transport entry.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrerequisitePlan {
    source_binding: String,
    transport_canonical: String,
    index: u8,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    purpose: Purpose,
    request: RequestAudit,
    maximum_calls: u64,
    maximum_transport_seconds: u64,
    maximum_evidence_age_seconds: u64,
    disclosure: Disclosure,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestAudit {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    maximum_response_bytes: u64,
}

impl PrerequisitePlan {
    pub(super) fn new(
        source: &super::EffectBinding,
        index: u8,
        transport: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<Self, EffectBindingError> {
        let plan = Self {
            source_binding: String::from_utf8(source.to_private_bytes()?.to_vec())
                .map_err(|_| EffectBindingError::Invalid)?,
            transport_canonical: String::from_utf8(transport.to_vec())
                .map_err(|_| EffectBindingError::Invalid)?,
            index,
        };
        plan.validate(source)?;
        Ok(plan)
    }

    pub(crate) const fn index(&self) -> u8 {
        self.index
    }

    pub(crate) fn source(&self) -> Result<super::EffectBinding, EffectBindingError> {
        super::EffectBinding::from_private_bytes(self.source_binding.as_bytes())
    }

    fn declaration(&self) -> Result<Declaration, EffectBindingError> {
        let source = self.source()?;
        let (request, domain) = match source.wire.protocol {
            super::Protocol::Mutation { request } => (request, "auths.effect-transport/1"),
            super::Protocol::Acquisition { request, .. } => {
                (request, "auths.effect-acquisition-request/2")
            }
            super::Protocol::Disclosure { .. } => return Err(EffectBindingError::Invalid),
        };
        let bytes = self.transport_canonical.as_bytes();
        if bytes.len() > super::MAX_EFFECT_BYTES || request != super::commitment(domain, bytes)? {
            return Err(EffectBindingError::Invalid);
        }
        // This bounded value is only an authenticated membership witness. It
        // never supplies a URL, header or body to the transport implementation.
        let witness: Value =
            serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        if canonical(&witness)?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        let declarations = witness
            .get("prerequisite_acquisitions")
            .and_then(Value::as_array)
            .ok_or(EffectBindingError::Invalid)?;
        if declarations.len() > MAX_PREREQUISITES {
            return Err(EffectBindingError::Invalid);
        }
        let declaration: Declaration = serde_json::from_value(
            declarations
                .get(usize::from(self.index))
                .ok_or(EffectBindingError::Invalid)?
                .clone(),
        )
        .map_err(|_| EffectBindingError::Invalid)?;
        if declaration.maximum_calls != 1
            || declaration.maximum_transport_seconds != 15
            || declaration.maximum_evidence_age_seconds != MAX_PREREQUISITE_EVIDENCE_AGE_SECONDS
            || declaration.disclosure != Disclosure::None
            || !matches!(declaration.request.method.as_str(), "GET" | "HEAD")
            || !(1..=MAX_RESPONSE_BYTES as u64)
                .contains(&declaration.request.maximum_response_bytes)
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(declaration)
    }

    pub(crate) fn kind(&self) -> Result<PrerequisiteKind, EffectBindingError> {
        Ok(self.declaration()?.purpose.kind())
    }

    pub(crate) fn capacity(&self) -> Result<super::AcquisitionCapacity, EffectBindingError> {
        let source = self.source()?;
        let declaration = self.declaration()?;
        let key = |unit| {
            super::commitment(
                "auths.prerequisite-capacity/1",
                &canonical(&(source.id().as_bytes(), self.index, unit))?,
            )
        };
        Ok(super::AcquisitionCapacity {
            count_key: key(super::Unit::AcquisitionCount)?,
            bytes_key: key(super::Unit::ResponseBytes)?,
            maximum_bytes: declaration.request.maximum_response_bytes,
            attempts: 1,
        })
    }

    pub(crate) fn validate(
        &self,
        effect: &super::EffectBinding,
    ) -> Result<super::AcquisitionCapacity, EffectBindingError> {
        if self.source()? != *effect {
            return Err(EffectBindingError::Invalid);
        }
        self.capacity()
    }
}
