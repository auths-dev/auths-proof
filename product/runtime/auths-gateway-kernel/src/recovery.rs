//! What a recipe can prove after an ambiguous write, derived only from its
//! declarations.
//!
//! This module is a translated leaf: it uses closed enums, no loops, no
//! references into other gateway state, and no standard-library calls, so the
//! pinned Charon/Aeneas route translates it without external models.

/// How the gateway can read provider state after the write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateObservation {
    /// The recipe declares no observation.
    None,
    /// Every non-fixed observation segment is a verified field.
    VerifiedLocator,
    /// An observation segment comes from the recorded write response.
    ResponseLocator,
}

/// The declared idempotency mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyKind {
    /// The gateway sends the derived `Idempotency-Key` on the write.
    DerivedHeader,
    /// The body already carries the verified logical operation ID.
    OperationIdField,
}

/// What a re-entry after a lost claim can rely on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LostClaimReentry {
    /// No de-duplication is declared.
    None,
    /// The author declares a de-duplication mechanism and its retention.
    Declared {
        /// The declared mechanism.
        kind: IdempotencyKind,
        /// The provider retention the author declares, in seconds.
        retention_seconds: u64,
    },
}

/// The declarations a recipe's recovery capability depends on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDeclarations {
    /// The observation locator, or none.
    pub observation: StateObservation,
    /// Whether an echo is declared.
    pub echo: bool,
    /// The idempotency declaration.
    pub idempotency: LostClaimReentry,
    /// Whether a pre-entry re-read is declared.
    pub pre_entry: bool,
}

/// The recovery class a recipe's declarations determine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryClass {
    /// A read-back at a verified locator can find this action's token.
    Linked,
    /// A read-back at a locator from the recorded response can find the token.
    LinkedAfterResponse,
    /// A read-back compares state but cannot link it to the action.
    Observed,
    /// Only the response status and digest are recorded.
    Recorded,
}

/// How an `unknown` write can resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownResolution {
    /// A later read-back from the stored plan can record provider evidence.
    GatewayReobservation,
    /// `unknown` stays `unknown`.
    None,
}

/// `auths.gateway-recovery-capability/1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCapability {
    /// The derived class.
    pub class: RecoveryClass,
    /// The observation locator, or none.
    pub state_observation: StateObservation,
    /// The locator of a provider link, or none without an echo.
    pub provider_link: StateObservation,
    /// How `unknown` resolves.
    pub unknown_resolution: UnknownResolution,
    /// What a re-entry after a lost claim relies on.
    pub lost_claim_reentry: LostClaimReentry,
    /// Whether a pre-entry re-read is declared.
    pub pre_entry_reread: bool,
    /// Always `false`: no declaration makes the write conditional.
    pub write_is_conditional: bool,
}

/// The provider link: the observation locator when an echo is declared.
#[must_use]
pub const fn provider_link(observation: StateObservation, echo: bool) -> StateObservation {
    if echo {
        observation
    } else {
        StateObservation::None
    }
}

/// The class a link and an observation determine.
#[must_use]
pub const fn recovery_class(
    observation: StateObservation,
    link: StateObservation,
) -> RecoveryClass {
    match link {
        StateObservation::VerifiedLocator => RecoveryClass::Linked,
        StateObservation::ResponseLocator => RecoveryClass::LinkedAfterResponse,
        StateObservation::None => match observation {
            StateObservation::None => RecoveryClass::Recorded,
            StateObservation::VerifiedLocator | StateObservation::ResponseLocator => {
                RecoveryClass::Observed
            }
        },
    }
}

/// Only a verified-locator link lets the gateway resolve `unknown`.
#[must_use]
pub const fn unknown_resolution(class: RecoveryClass) -> UnknownResolution {
    match class {
        RecoveryClass::Linked => UnknownResolution::GatewayReobservation,
        RecoveryClass::LinkedAfterResponse | RecoveryClass::Observed | RecoveryClass::Recorded => {
            UnknownResolution::None
        }
    }
}

/// Derives the recovery capability from the declarations. Total: every
/// declaration set maps to exactly one capability, and `write_is_conditional`
/// is always `false`.
#[must_use]
pub const fn recovery_capability(declarations: RecoveryDeclarations) -> RecoveryCapability {
    let link = provider_link(declarations.observation, declarations.echo);
    let class = recovery_class(declarations.observation, link);
    RecoveryCapability {
        class,
        state_observation: declarations.observation,
        provider_link: link,
        unknown_resolution: unknown_resolution(class),
        lost_claim_reentry: declarations.idempotency,
        pre_entry_reread: declarations.pre_entry,
        write_is_conditional: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_capability_matches_its_table_for_every_declaration() {
        let reentries = [
            LostClaimReentry::None,
            LostClaimReentry::Declared {
                kind: IdempotencyKind::DerivedHeader,
                retention_seconds: 86_400,
            },
            LostClaimReentry::Declared {
                kind: IdempotencyKind::OperationIdField,
                retention_seconds: 2_592_000,
            },
        ];
        for observation in [
            StateObservation::None,
            StateObservation::VerifiedLocator,
            StateObservation::ResponseLocator,
        ] {
            for echo in [false, true] {
                for idempotency in reentries {
                    for pre_entry in [false, true] {
                        let capability = recovery_capability(RecoveryDeclarations {
                            observation,
                            echo,
                            idempotency,
                            pre_entry,
                        });
                        let expected = match (observation, echo) {
                            (StateObservation::VerifiedLocator, true) => RecoveryClass::Linked,
                            (StateObservation::ResponseLocator, true) => {
                                RecoveryClass::LinkedAfterResponse
                            }
                            (StateObservation::None, _) => RecoveryClass::Recorded,
                            (_, false) => RecoveryClass::Observed,
                        };
                        assert_eq!(capability.class, expected);
                        assert_eq!(capability.state_observation, observation);
                        assert_eq!(
                            capability.provider_link,
                            if echo {
                                observation
                            } else {
                                StateObservation::None
                            }
                        );
                        assert_eq!(
                            capability.unknown_resolution,
                            if expected == RecoveryClass::Linked {
                                UnknownResolution::GatewayReobservation
                            } else {
                                UnknownResolution::None
                            }
                        );
                        assert_eq!(capability.lost_claim_reentry, idempotency);
                        assert_eq!(capability.pre_entry_reread, pre_entry);
                        assert!(!capability.write_is_conditional);
                    }
                }
            }
        }
    }
}
