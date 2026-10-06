//! Operator-facing readiness types: the fixed credential retirement delay,
//! the deployment clock's trust state, and the conjunction that decides
//! whether a production gateway is ready.
//!
//! Nothing here performs a check. Each precondition is decided by its own
//! owner (the store, the credential store, the qualification gate, the
//! deployment clock adapter) and reported here as a closed state, so that
//! "ready" can only ever mean that every required check was made and passed.

use crate::MAX_TRANSPORT_DURATION;
use auths_connections::CredentialStoreKind;
use std::time::Duration;

/// Decides which credential store an operator's token selects.
///
/// The token must be exactly a maintained kind; nothing is defaulted or
/// guessed. Under production policy the development local file is refused:
/// it keeps the provider secret as plaintext on the gateway host.
///
/// # Errors
///
/// Returns `gateway.credential.adapter-unsupported` for any token outside
/// the closed set, and `gateway.credential.production-plaintext-refused`
/// for the local file under production policy.
pub fn credential_store_policy(
    token: &str,
    production: bool,
) -> Result<CredentialStoreKind, &'static str> {
    let kind =
        CredentialStoreKind::parse(token).map_err(|_| "gateway.credential.adapter-unsupported")?;
    if production && !kind.is_production() {
        return Err("gateway.credential.production-plaintext-refused");
    }
    Ok(kind)
}

/// How long a superseded credential generation is kept after the shared
/// record commits its successor.
///
/// Invariant `outlives-entered-transport`: the delay is a fixed 20 seconds
/// and exceeds [`MAX_TRANSPORT_DURATION`], so an attempt that entered
/// transport under the old generation finishes before that generation may be
/// revoked, on every gateway host. There is no constructor for another
/// value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialRetirementDelay(Duration);

impl CredentialRetirementDelay {
    /// The only retirement delay.
    pub const FIXED: Self = Self(Duration::from_secs(20));

    /// Returns the delay.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// The first gateway-clock second at which a generation superseded at
    /// `committed_at_unix_seconds` may be revoked, or `None` when that time
    /// is not representable.
    #[must_use]
    pub const fn earliest_revocation(self, committed_at_unix_seconds: u64) -> Option<u64> {
        committed_at_unix_seconds.checked_add(self.0.as_secs())
    }
}

// A retirement delay no longer than the transport bound would let a
// superseded credential be revoked under a request that is still running.
const _: () = assert!(
    CredentialRetirementDelay::FIXED.0.as_secs() > MAX_TRANSPORT_DURATION.as_secs(),
    "the credential retirement delay must exceed the transport bound"
);

/// Whether the deployment's clock may be used to judge signed time bounds.
///
/// Invariant `closed-clock-readiness`: the state is exactly trusted or
/// untrusted, and only a maintained deployment adapter produces it. The type
/// has no parser, so a recipe, an application, an SDK, or a configuration
/// value cannot supply one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClockTrustState {
    /// The deployment's time synchronization reports a usable clock.
    Trusted,
    /// The clock is unsynchronized or its state is unknown.
    Untrusted,
}

impl ClockTrustState {
    /// Returns the canonical token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }
}

/// One typed precondition of production readiness.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ReadinessPrecondition {
    /// The installed trust is present and pinned.
    Trust,
    /// The lifecycle store is reachable at its expected schema.
    Store,
    /// The approved recipe digest and profile lock rederive.
    Recipe,
    /// The recipe's qualification is current for this deployment.
    Qualification,
    /// The provider secret is held by a production credential store.
    ProviderSecretCustody,
    /// The connection generation is enabled and its credential is held.
    ConnectionGeneration,
    /// The deployment clock is trusted.
    Clock,
    /// The pinned transport policy is in force.
    TransportPolicy,
    /// The operator plane is isolated from the application plane.
    OperatorPlaneIsolation,
    /// The observer signing key is held by custody. Required only when the
    /// deployment configures signed observer outcomes.
    ObserverCustody,
}

impl ReadinessPrecondition {
    /// Stable reason when this typed check failed or could not be made.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Trust => "gateway.readiness.trust-unavailable",
            Self::Store => "gateway.readiness.store-unavailable",
            Self::Recipe => "gateway.readiness.recipe-drift",
            Self::Qualification => "gateway.qualification.unavailable",
            Self::ProviderSecretCustody => "gateway.credential.unavailable",
            Self::ConnectionGeneration => "gateway.readiness.connection-disabled",
            Self::Clock => "gateway.qualification.clock-untrusted",
            Self::TransportPolicy => "gateway.readiness.transport-unavailable",
            Self::OperatorPlaneIsolation => "gateway.doctor.isolation-not-established",
            Self::ObserverCustody => "gateway.readiness.observer-unavailable",
        }
    }

    /// The preconditions every production deployment requires, in the order
    /// they are reported.
    pub const REQUIRED: [Self; 9] = [
        Self::Trust,
        Self::Store,
        Self::Recipe,
        Self::Qualification,
        Self::ProviderSecretCustody,
        Self::ConnectionGeneration,
        Self::Clock,
        Self::TransportPolicy,
        Self::OperatorPlaneIsolation,
    ];

    /// Returns the canonical token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trust => "trust",
            Self::Store => "store",
            Self::Recipe => "recipe",
            Self::Qualification => "qualification",
            Self::ProviderSecretCustody => "provider-secret-custody",
            Self::ConnectionGeneration => "connection-generation",
            Self::Clock => "clock",
            Self::TransportPolicy => "transport-policy",
            Self::OperatorPlaneIsolation => "operator-plane-isolation",
            Self::ObserverCustody => "observer-custody",
        }
    }
}

/// The outcome of one required check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreconditionState {
    /// The check was made and passed.
    Ready,
    /// The check failed or could not be made.
    NotReady,
}

/// The state of observer signing custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverCustodyState {
    /// No observer is configured. Signed observer outcomes are unavailable,
    /// which is reported and does not make the deployment unready.
    NotConfigured,
    /// An observer is configured and its key is held by custody.
    Ready,
    /// An observer is configured and its custody check failed.
    NotReady,
}

/// The state of every required precondition. Each one must be named: there
/// is no default, so a check that was never made cannot be read as passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredPreconditions {
    /// See [`ReadinessPrecondition::Trust`].
    pub trust: PreconditionState,
    /// See [`ReadinessPrecondition::Store`].
    pub store: PreconditionState,
    /// See [`ReadinessPrecondition::Recipe`].
    pub recipe: PreconditionState,
    /// See [`ReadinessPrecondition::Qualification`].
    pub qualification: PreconditionState,
    /// See [`ReadinessPrecondition::ProviderSecretCustody`].
    pub provider_secret_custody: PreconditionState,
    /// See [`ReadinessPrecondition::ConnectionGeneration`].
    pub connection_generation: PreconditionState,
    /// See [`ReadinessPrecondition::Clock`].
    pub clock: PreconditionState,
    /// See [`ReadinessPrecondition::TransportPolicy`].
    pub transport_policy: PreconditionState,
    /// See [`ReadinessPrecondition::OperatorPlaneIsolation`].
    pub operator_plane_isolation: PreconditionState,
}

impl RequiredPreconditions {
    const fn state(&self, precondition: ReadinessPrecondition) -> Option<PreconditionState> {
        match precondition {
            ReadinessPrecondition::Trust => Some(self.trust),
            ReadinessPrecondition::Store => Some(self.store),
            ReadinessPrecondition::Recipe => Some(self.recipe),
            ReadinessPrecondition::Qualification => Some(self.qualification),
            ReadinessPrecondition::ProviderSecretCustody => Some(self.provider_secret_custody),
            ReadinessPrecondition::ConnectionGeneration => Some(self.connection_generation),
            ReadinessPrecondition::Clock => Some(self.clock),
            ReadinessPrecondition::TransportPolicy => Some(self.transport_policy),
            ReadinessPrecondition::OperatorPlaneIsolation => Some(self.operator_plane_isolation),
            ReadinessPrecondition::ObserverCustody => None,
        }
    }
}

/// Whether a production gateway is ready, and which preconditions are not.
///
/// Invariant `fail-closed-conjunction`: the deployment is ready only when
/// every required precondition is ready and a configured observer's custody
/// is ready. The value reports which typed precondition failed and never the
/// value that failed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionReadiness {
    required: RequiredPreconditions,
    observer: ObserverCustodyState,
}

impl ProductionReadiness {
    /// Secret-free machine-readable diagnostic projection. Every required
    /// check is present, including failures; optional observer custody is
    /// explicitly reported. A failed qualification retains its precise code.
    #[must_use]
    pub fn report(&self, qualification_code: Option<&'static str>) -> serde_json::Value {
        let mut checks: Vec<_> = ReadinessPrecondition::REQUIRED.into_iter().map(|check| {
            let ready = self.required.state(check) == Some(PreconditionState::Ready);
            serde_json::json!({
                "check": check.as_str(), "ready": ready,
                "code": if ready { None } else if check == ReadinessPrecondition::Qualification {
                    Some(qualification_code.unwrap_or(check.code()))
                } else { Some(check.code()) }
            })
        }).collect();
        checks.push(
            serde_json::json!({"check": "observer-custody", "state": match self.observer {
                ObserverCustodyState::NotConfigured => "not-configured",
                ObserverCustodyState::Ready => "ready",
                ObserverCustodyState::NotReady => "not-ready",
            }}),
        );
        serde_json::json!({"schema": "auths.gateway-readiness/1", "ready": self.is_ready(), "checks": checks})
    }

    /// Combines the outcome of every check.
    #[must_use]
    pub const fn new(required: RequiredPreconditions, observer: ObserverCustodyState) -> Self {
        Self { required, observer }
    }

    /// Whether every required precondition holds.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.failed().is_empty()
    }

    /// The preconditions that do not hold, in reporting order.
    #[must_use]
    pub fn failed(&self) -> Vec<ReadinessPrecondition> {
        let mut failed: Vec<ReadinessPrecondition> = ReadinessPrecondition::REQUIRED
            .into_iter()
            .filter(|precondition| {
                self.required.state(*precondition) != Some(PreconditionState::Ready)
            })
            .collect();
        if self.observer == ObserverCustodyState::NotReady {
            failed.push(ReadinessPrecondition::ObserverCustody);
        }
        failed
    }

    /// The observer custody state, reported whether or not it is required.
    #[must_use]
    pub const fn observer(&self) -> ObserverCustodyState {
        self.observer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required(failing: u16) -> RequiredPreconditions {
        let state = |bit: u16| {
            if failing & (1 << bit) == 0 {
                PreconditionState::Ready
            } else {
                PreconditionState::NotReady
            }
        };
        RequiredPreconditions {
            trust: state(0),
            store: state(1),
            recipe: state(2),
            qualification: state(3),
            provider_secret_custody: state(4),
            connection_generation: state(5),
            clock: state(6),
            transport_policy: state(7),
            operator_plane_isolation: state(8),
        }
    }

    #[test]
    fn the_projection_names_every_check_and_retains_precise_qualification_failure() {
        let readiness = ProductionReadiness::new(
            required((1 << 3) | (1 << 5)),
            ObserverCustodyState::NotConfigured,
        );
        let report = readiness.report(Some("gateway.qualification.revoked"));
        assert_eq!(report["ready"], false);
        let checks = report["checks"].as_array().expect("checks");
        assert_eq!(checks.len(), 10);
        assert_eq!(checks[3]["code"], "gateway.qualification.revoked");
        assert_eq!(checks[5]["code"], "gateway.readiness.connection-disabled");
        assert_eq!(checks[9]["state"], "not-configured");
        for bit in 0..9 {
            let report = ProductionReadiness::new(required(1 << bit), ObserverCustodyState::Ready)
                .report(None);
            assert_eq!(report["ready"], false);
            assert!(report["checks"][bit]["code"].is_string());
        }
    }

    #[test]
    fn retirement_delay_outlives_entered_transport() {
        let delay = CredentialRetirementDelay::FIXED.as_duration();
        assert_eq!(delay, Duration::from_secs(20));
        assert_eq!(MAX_TRANSPORT_DURATION, Duration::from_secs(15));
        assert!(delay > MAX_TRANSPORT_DURATION);
        assert_eq!(
            CredentialRetirementDelay::FIXED.earliest_revocation(100),
            Some(120)
        );
        assert_eq!(
            CredentialRetirementDelay::FIXED.earliest_revocation(u64::MAX - 19),
            None
        );
    }

    #[test]
    fn closed_clock_readiness_has_two_distinct_tokens() {
        assert_eq!(ClockTrustState::Trusted.as_str(), "trusted");
        assert_eq!(ClockTrustState::Untrusted.as_str(), "untrusted");
    }

    #[test]
    fn readiness_is_the_conjunction_of_every_required_precondition() {
        for failing in 0_u16..(1 << 9) {
            for observer in [
                ObserverCustodyState::NotConfigured,
                ObserverCustodyState::Ready,
                ObserverCustodyState::NotReady,
            ] {
                let readiness = ProductionReadiness::new(required(failing), observer);
                let mut expected: Vec<ReadinessPrecondition> = ReadinessPrecondition::REQUIRED
                    .into_iter()
                    .enumerate()
                    .filter(|(bit, _)| failing & (1 << bit) != 0)
                    .map(|(_, precondition)| precondition)
                    .collect();
                if observer == ObserverCustodyState::NotReady {
                    expected.push(ReadinessPrecondition::ObserverCustody);
                }
                assert_eq!(readiness.failed(), expected);
                assert_eq!(readiness.is_ready(), expected.is_empty());
                assert_eq!(readiness.observer(), observer);
            }
        }
    }

    #[test]
    fn an_absent_observer_is_reported_and_does_not_block() {
        let readiness = ProductionReadiness::new(required(0), ObserverCustodyState::NotConfigured);
        assert!(readiness.is_ready());
        assert_eq!(readiness.observer(), ObserverCustodyState::NotConfigured);
    }

    #[test]
    fn precondition_tokens_are_distinct() {
        let mut tokens: Vec<&str> = ReadinessPrecondition::REQUIRED
            .iter()
            .map(|precondition| precondition.as_str())
            .chain([ReadinessPrecondition::ObserverCustody.as_str()])
            .collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), 10);
    }
}
