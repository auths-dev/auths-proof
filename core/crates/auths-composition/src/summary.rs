//! Constant-space state of the complete immediate-child outcome sequence.
use super::{BranchOutcome, ThresholdTruth, evaluate_threshold_counts};
use auths_model::{DenialReason, Requirement};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Summary {
    pub(crate) authorized: usize,
    pub(crate) indeterminate: usize,
    denial: Option<DenialReason>,
    requirement: Option<Requirement>,
}

pub(crate) fn push(state: &mut Summary, outcome: BranchOutcome) {
    match outcome {
        BranchOutcome::Authorized => state.authorized += 1,
        BranchOutcome::Denied(reason) | BranchOutcome::StructurallyInvalid(reason) => {
            match state.denial {
                None => state.denial = Some(reason),
                Some(current) => {
                    if reason.code_precedes(current) {
                        state.denial = Some(reason);
                    }
                }
            }
        }
        BranchOutcome::Indeterminate(requirement) => {
            state.indeterminate += 1;
            match state.requirement {
                None => state.requirement = Some(requirement),
                Some(current) => {
                    if requirement.code_precedes(current) {
                        state.requirement = Some(requirement);
                    }
                }
            }
        }
    }
}

pub(crate) fn all(state: Summary) -> BranchOutcome {
    match state.denial {
        Some(reason) => BranchOutcome::Denied(reason),
        None => match state.requirement {
            Some(requirement) => BranchOutcome::Indeterminate(requirement),
            None => BranchOutcome::Authorized,
        },
    }
}

pub(crate) fn threshold(state: Summary, required: u16) -> BranchOutcome {
    match evaluate_threshold_counts(required, state.authorized, state.indeterminate) {
        ThresholdTruth::Authorized => BranchOutcome::Authorized,
        ThresholdTruth::Indeterminate => match state.requirement {
            Some(requirement) => BranchOutcome::Indeterminate(requirement),
            None => BranchOutcome::Indeterminate(Requirement::ExternalFactUnavailable),
        },
        ThresholdTruth::Denied => match state.denial {
            Some(reason) => BranchOutcome::Denied(reason),
            None => BranchOutcome::Denied(DenialReason::AuthorizationPlanInvalid),
        },
    }
}
