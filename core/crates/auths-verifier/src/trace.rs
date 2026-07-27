//! Bounded, deterministic verification trace.

use alloc::vec::Vec;
use auths_model::{VerificationCode, VerificationStage};

/// Hard diagnostic event ceiling, independent of protocol work charging.
pub const HARD_MAX_TRACE_EVENTS: usize = 4096;

/// Closed target V1 fact inventory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FactKind {
    ContextConfigurationMatches,
    RegistryManifestAccepted,
    ExpectedPlanMatches,
    TrustAnchorAcceptedMethod,
    TrustAnchorProfile,
    TrustAnchorPermission,
    TrustAnchorResourceNamespace,
    GrantLinkage,
    GrantDepth,
    GrantPermissionAttenuation,
    GrantValidityAttenuation,
    GrantAudienceAttenuation,
    GrantBodyAttenuation,
    GrantBudgetAttenuation,
    GrantStatusAttenuation,
    GrantAssurancePolicy,
    ActionActor,
    ActionTerminalGrant,
    ActionProfile,
    ActionPermission,
    ActionValidity,
    ActionAudience,
    ActionChallenge,
    ActionBodyDigest,
    ActionBudget,
    ChannelBinding,
    PrincipalControl,
    PrincipalStatus,
    GrantStatus,
    AssuranceRequirement,
    ResourceNamespace,
    ProfilePolicy,
    CriticalExtension,
    Attachment,
    PlanNode,
    MinimumAuthorizedBranches,
    MinimumDistinctActors,
    MinimumDistinctRoots,
    WorkReservation,
}

impl FactKind {
    /// Stable kebab-case identifier.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ContextConfigurationMatches => "context-configuration-matches",
            Self::RegistryManifestAccepted => "registry-manifest-accepted",
            Self::ExpectedPlanMatches => "expected-plan-matches",
            Self::TrustAnchorAcceptedMethod => "trust-anchor-accepted-method",
            Self::TrustAnchorProfile => "trust-anchor-profile",
            Self::TrustAnchorPermission => "trust-anchor-permission",
            Self::TrustAnchorResourceNamespace => "trust-anchor-resource-namespace",
            Self::GrantLinkage => "grant-linkage",
            Self::GrantDepth => "grant-depth",
            Self::GrantPermissionAttenuation => "grant-permission-attenuation",
            Self::GrantValidityAttenuation => "grant-validity-attenuation",
            Self::GrantAudienceAttenuation => "grant-audience-attenuation",
            Self::GrantBodyAttenuation => "grant-body-attenuation",
            Self::GrantBudgetAttenuation => "grant-budget-attenuation",
            Self::GrantStatusAttenuation => "grant-status-attenuation",
            Self::GrantAssurancePolicy => "grant-assurance-policy",
            Self::ActionActor => "action-actor",
            Self::ActionTerminalGrant => "action-terminal-grant",
            Self::ActionProfile => "action-profile",
            Self::ActionPermission => "action-permission",
            Self::ActionValidity => "action-validity",
            Self::ActionAudience => "action-audience",
            Self::ActionChallenge => "action-challenge",
            Self::ActionBodyDigest => "action-body-digest",
            Self::ActionBudget => "action-budget",
            Self::ChannelBinding => "channel-binding",
            Self::PrincipalControl => "principal-control",
            Self::PrincipalStatus => "principal-status",
            Self::GrantStatus => "grant-status",
            Self::AssuranceRequirement => "assurance-requirement",
            Self::ResourceNamespace => "resource-namespace",
            Self::ProfilePolicy => "profile-policy",
            Self::CriticalExtension => "critical-extension",
            Self::Attachment => "attachment",
            Self::PlanNode => "plan-node",
            Self::MinimumAuthorizedBranches => "minimum-authorized-branches",
            Self::MinimumDistinctActors => "minimum-distinct-actors",
            Self::MinimumDistinctRoots => "minimum-distinct-roots",
            Self::WorkReservation => "work-reservation",
        }
    }
}

/// Immutable source class for a fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactOrigin {
    TrustedContext,
    Proof,
    ExecutableRegistry,
    Derived,
}

/// Bounded value summary. Raw cryptographic or request material is impossible
/// to represent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactValue {
    Present(bool),
    Equal(bool),
    Count { actual: u64, required: u64 },
    Redacted,
}

/// Result of evaluating a fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactResult {
    Satisfied,
    Contradicted,
    Unavailable,
    NotEvaluated,
}

/// One deterministic fact evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactEvaluation {
    sequence: u32,
    stage: VerificationStage,
    kind: FactKind,
    origin: FactOrigin,
    value: FactValue,
    result: FactResult,
    code: Option<VerificationCode>,
    parents: Vec<u32>,
}

impl FactEvaluation {
    /// Sequence number and graph node identity.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }
    /// Verification stage.
    #[must_use]
    pub const fn stage(&self) -> VerificationStage {
        self.stage
    }
    /// Stable fact kind.
    #[must_use]
    pub const fn kind(&self) -> FactKind {
        self.kind
    }
    /// Immutable origin class.
    #[must_use]
    pub const fn origin(&self) -> FactOrigin {
        self.origin
    }
    /// Sanitized fact value.
    #[must_use]
    pub const fn value(&self) -> FactValue {
        self.value
    }
    /// Fact result.
    #[must_use]
    pub const fn result(&self) -> FactResult {
        self.result
    }
    /// Stable code emitted at this node.
    #[must_use]
    pub const fn code(&self) -> Option<VerificationCode> {
        self.code
    }
    /// Causal parent node identities.
    #[must_use]
    pub fn parents(&self) -> &[u32] {
        &self.parents
    }
}

/// Complete bounded trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationTrace {
    events: Vec<FactEvaluation>,
    final_node: u32,
}

impl VerificationTrace {
    /// Canonically ordered events.
    #[must_use]
    pub fn events(&self) -> &[FactEvaluation] {
        &self.events
    }
    /// Final causal node.
    #[must_use]
    pub const fn final_node(&self) -> u32 {
        self.final_node
    }
}

/// Trace allocation or capacity failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceError {
    CapacityExceeded,
}

pub(crate) struct TraceCollector {
    collect: bool,
    events: Vec<FactEvaluation>,
}

impl TraceCollector {
    pub(crate) fn discard() -> Self {
        Self {
            collect: false,
            events: Vec::new(),
        }
    }

    pub(crate) fn collect(capacity: usize) -> Result<Self, TraceError> {
        if capacity > HARD_MAX_TRACE_EVENTS {
            return Err(TraceError::CapacityExceeded);
        }
        let mut events = Vec::new();
        events
            .try_reserve_exact(capacity)
            .map_err(|_| TraceError::CapacityExceeded)?;
        Ok(Self {
            collect: true,
            events,
        })
    }

    pub(crate) fn record(
        &mut self,
        stage: VerificationStage,
        kind: FactKind,
        origin: FactOrigin,
        value: FactValue,
        result: FactResult,
        code: Option<VerificationCode>,
    ) {
        if !self.collect || self.events.len() >= self.events.capacity() {
            return;
        }
        let sequence = u32::try_from(self.events.len()).unwrap_or(u32::MAX);
        let parents = sequence.checked_sub(1).into_iter().collect();
        self.events.push(FactEvaluation {
            sequence,
            stage,
            kind,
            origin,
            value,
            result,
            code,
            parents,
        });
    }

    pub(crate) fn finish(self) -> VerificationTrace {
        VerificationTrace {
            final_node: u32::try_from(self.events.len().saturating_sub(1)).unwrap_or(u32::MAX),
            events: self.events,
        }
    }
}
