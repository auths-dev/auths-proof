//! Deterministic principal and grant status policy evaluation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use auths_model::{
    DenialReason, GrantId, GrantState, GrantStatusSnapshot, PrincipalId, PrincipalState,
    PrincipalStatusSnapshot, Requirement, StatusPolicy, Timestamp,
};

/// Status evaluation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusError {
    /// Supplied status proves revocation or supersession.
    Denied(DenialReason),
    /// Required trustworthy status is unavailable or stale.
    Indeterminate(Requirement),
}

/// Evaluates principal status for an exact method/purpose.
///
/// # Errors
///
/// Returns a denial for revoked/superseded state and indeterminate for absent
/// or stale required state.
pub fn principal(
    policy: &StatusPolicy,
    snapshot: &PrincipalStatusSnapshot,
    principal: &PrincipalId,
    evaluation_time: Timestamp,
) -> Result<(), StatusError> {
    let StatusPolicy::SnapshotRequired { method, max_age } = policy else {
        return Ok(());
    };
    if snapshot.observed_at() > evaluation_time || snapshot.valid_until() < evaluation_time {
        return Err(StatusError::Indeterminate(Requirement::StaleStatus));
    }
    let statement = snapshot
        .statements()
        .iter()
        .map(auths_model::SignedPrincipalStatus::statement)
        .find(|statement| {
            statement.principal() == principal && statement.purpose().as_str() == method.as_str()
        })
        .ok_or(StatusError::Indeterminate(
            Requirement::MissingPrincipalStatus,
        ))?;
    if statement.observed_at() > evaluation_time
        || evaluation_time.get() - statement.observed_at().get() > max_age.get()
    {
        return Err(StatusError::Indeterminate(Requirement::StaleStatus));
    }
    match statement.state() {
        PrincipalState::Active => Ok(()),
        PrincipalState::Revoked | PrincipalState::Superseded => {
            Err(StatusError::Denied(DenialReason::PrincipalRevoked))
        }
    }
}

/// Evaluates grant status for an exact grant identifier.
///
/// # Errors
///
/// Returns a denial for revoked/superseded state and indeterminate for absent
/// or stale required state.
pub fn grant(
    policy: &StatusPolicy,
    snapshot: &GrantStatusSnapshot,
    grant_id: GrantId,
    evaluation_time: Timestamp,
) -> Result<(), StatusError> {
    let StatusPolicy::SnapshotRequired { max_age, .. } = policy else {
        return Ok(());
    };
    if snapshot.observed_at() > evaluation_time || snapshot.valid_until() < evaluation_time {
        return Err(StatusError::Indeterminate(Requirement::StaleStatus));
    }
    let statement = snapshot
        .statements()
        .iter()
        .map(auths_model::SignedGrantStatus::statement)
        .find(|statement| statement.grant_id() == grant_id)
        .ok_or(StatusError::Indeterminate(Requirement::MissingGrantStatus))?;
    if statement.observed_at() > evaluation_time
        || evaluation_time.get() - statement.observed_at().get() > max_age.get()
    {
        return Err(StatusError::Indeterminate(Requirement::StaleStatus));
    }
    match statement.state() {
        GrantState::Active => Ok(()),
        GrantState::Revoked | GrantState::Superseded => {
            Err(StatusError::Denied(DenialReason::GrantRevoked))
        }
    }
}
