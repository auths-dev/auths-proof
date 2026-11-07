//! Installed native participant controls. Root/context/time are never selected
//! by a request. Receipts are historical facts, never enrollment/entry permits.
use crate::{
    EngagementConfiguration, EngagementConfigurationError, EngagementControlEvidence, GatewayEngine,
};
use serde::{Deserialize, Serialize};

/// Redacted outcome of native control processing. A recorded revision means
/// only that exact original evidence was retained; it may since be withdrawn.
/// Current effect eligibility is always checked separately at native entry.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ParticipantControlOutcome {
    /// Exact original evidence exists at this historical configuration revision.
    Recorded {
        /// Original acknowledged revision; never refreshed by a retry.
        revision: u64,
    },
    /// No additional control revision was created. A fresh native withdrawal
    /// may find an already removed subtree; operator bootstrap never reactivates
    /// an existing immutable root. This is no claim of current eligibility.
    Unchanged {
        /// Current acknowledged revision after that native decision.
        revision: u64,
    },
    /// No new control authorization was established by this request.
    Refused {
        /// Stable code, without private evidence or principal identities.
        code: String,
    },
    /// State may have committed; retry exact evidence or inspect private audit.
    /// This result never authorizes repeating an external effect.
    Indeterminate {
        /// Stable persistence/availability error class.
        code: String,
    },
}
impl ParticipantControlOutcome {
    pub(crate) fn refused(code: &str) -> Self {
        Self::Refused {
            code: code.to_owned(),
        }
    }
    fn error(error: &EngagementConfigurationError) -> Self {
        match error {
            EngagementConfigurationError::Store(_)
            | EngagementConfigurationError::Corrupt
            | EngagementConfigurationError::MissingEvidence => Self::Indeterminate {
                code: error.code().to_owned(),
            },
            _ => Self::refused(error.code()),
        }
    }
}

fn apply(
    controller: &EngagementConfiguration,
    evidence: EngagementControlEvidence,
) -> ParticipantControlOutcome {
    let result = (|| {
        let bytes = evidence.to_private_bytes()?;
        if let Some(revision) = controller.recorded_control(&evidence)? {
            return Ok(ParticipantControlOutcome::Recorded { revision });
        }
        let snapshot = controller.apply_control(evidence)?;
        let evidence = EngagementControlEvidence::from_private_bytes(&bytes)?;
        Ok(match controller.recorded_control(&evidence)? {
            Some(revision) => ParticipantControlOutcome::Recorded { revision },
            None => ParticipantControlOutcome::Unchanged {
                revision: snapshot.revision(),
            },
        })
    })();
    result.unwrap_or_else(|error| ParticipantControlOutcome::error(&error))
}

impl GatewayEngine {
    /// Private operator export of this installed root's original native history
    /// and matching checkpoint. The operator must protect/authenticate the head
    /// independently; export alone is not a trust anchor or current eligibility.
    /// This synchronous I/O must run off an async executor.
    /// # Errors
    /// Refuses an absent installation or unavailable/corrupt original evidence.
    pub fn export_engagement_audit(
        &self,
    ) -> Result<
        (crate::EngagementAudit, crate::EngagementAuditCheckpoint),
        EngagementConfigurationError,
    > {
        self.installed_engagement()
            .map_err(|_| EngagementConfigurationError::Installation)?
            .ok_or(EngagementConfigurationError::Installation)?
            .export_audit_checkpointed()
    }
    /// Processes agent enrollment/withdrawal only within this installed root.
    /// Parent control, child acceptance and resource proofs are verified by the
    /// existing native owner/fence. Exact retries return retained original facts
    /// without renewing authority, time, capacity or any permit. Performs no
    /// credential lease, provider request or disclosure.
    /// Root bootstrap is refused here and belongs to the trusted operator path.
    pub async fn participant_control(
        &self,
        evidence: EngagementControlEvidence,
    ) -> ParticipantControlOutcome {
        if evidence.is_root() {
            return ParticipantControlOutcome::refused("gateway.engagement.operator-required");
        }
        let Ok(Some(controller)) = self.installed_engagement() else {
            return ParticipantControlOutcome::refused("gateway.engagement.installation");
        };
        tokio::task::spawn_blocking(move || apply(&controller, evidence))
            .await
            .unwrap_or_else(|_| ParticipantControlOutcome::Indeterminate {
                code: "gateway.engagement.state-unavailable".into(),
            })
    }

    /// Trusted operator bootstrap of the independently installed engagement.
    /// It accepts root evidence only and is absent from the application route.
    /// Original root proofs/context are retained by the same configuration owner;
    /// no credential, resource authority or entry capability follows from a receipt.
    pub async fn bootstrap_engagement(
        &self,
        evidence: EngagementControlEvidence,
    ) -> ParticipantControlOutcome {
        if !evidence.is_root() {
            return ParticipantControlOutcome::refused("gateway.engagement.root-required");
        }
        let Ok(Some(controller)) = self.installed_engagement() else {
            return ParticipantControlOutcome::refused("gateway.engagement.installation");
        };
        tokio::task::spawn_blocking(move || apply(&controller, evidence))
            .await
            .unwrap_or_else(|_| ParticipantControlOutcome::Indeterminate {
                code: "gateway.engagement.state-unavailable".into(),
            })
    }
}
