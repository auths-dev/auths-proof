//! The admission order of one gateway submission as a closed step machine.
//!
//! The engine performs I/O only as [`next_step`] directs. Each call takes the
//! machine state and the result of the action the previous decision named,
//! and returns the next state and the next action. The engine therefore has
//! no ordering of its own: a credential lease, a credential read, an action
//! read, a store write, and the provider write each happen only when the
//! machine names them, and the machine names them only in this order:
//!
//! 1. read the clock, verify natively, admit (with the account-scope binding
//!    when declared), and prepare the transport, storing nothing;
//! 2. claim the logical operation; a replay goes to one read-only
//!    re-observation and never to a write;
//! 3. reload the connection record, lease the credential, check the prefix,
//!    the account read, and each denied read;
//! 4. run the pre-entry re-read and the relative-ceiling read, when declared,
//!    and record what they read in one checkpoint;
//! 5. reload the connection record again, refuse entry after the deadline,
//!    and send the one write;
//! 6. record the response or `unknown`, then at most one read-back under a
//!    fresh lease that passes the same credential checks.
//!
//! Every refusal before the claim stores nothing; every refusal after it and
//! before transport entry records `not-entered` with its code. An event the
//! current phase does not expect halts the machine without further I/O.
//!
//! This module is a translated leaf: closed `Copy` enums and structs,
//! `match` dispatch, no loops, and no standard-library call.

use crate::ratio::relative_ceiling_admits;

/// Why a lease is taken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// The lease for the one write.
    Entry,
    /// The lease for the read-back after a recorded response.
    ReadBack,
    /// The lease for a replay's read-only re-observation.
    Reobserve,
}

/// The declarations and verified values the order depends on, fixed before
/// the machine starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent declaration flags translate as plain fields"
)]
pub struct SubmitPlan {
    /// The recipe declares an account-scope header.
    pub account_scope: bool,
    /// The recipe declares the lease-time account read.
    pub account_read: bool,
    /// The number of declared denied reads, at most four.
    pub denied_reads: u8,
    /// The recipe declares a pre-entry re-read.
    pub pre_entry: bool,
    /// The recipe declares a relative ceiling.
    pub relative_ceiling: bool,
    /// The declared basis points; zero when none is declared.
    pub basis_points: u16,
}

/// Where the machine is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Nothing has happened.
    Start,
    /// Awaiting the gateway clock.
    Clock,
    /// Awaiting native verification.
    Verify,
    /// Awaiting admission.
    Admit,
    /// Awaiting the account-scope binding.
    Scope,
    /// Awaiting transport preparation.
    Prepare,
    /// Awaiting the claim.
    Claim,
    /// Awaiting whether a replayed attempt can be re-observed.
    Resume,
    /// Awaiting the connection reload before a lease.
    Reload(Mode),
    /// Awaiting the credential lease.
    Lease(Mode),
    /// Awaiting the prefix guard.
    Prefix(Mode),
    /// Awaiting the account read.
    Account(Mode),
    /// Awaiting the denied read at this index.
    Denied(Mode, u8),
    /// Awaiting the pre-entry re-read.
    PreEntry,
    /// Awaiting the relative-ceiling read.
    Ceiling,
    /// Awaiting the checkpoint of what was read.
    Checkpoint,
    /// Awaiting the connection reload before entry.
    EntryReload,
    /// Awaiting the entry-deadline check.
    Deadline,
    /// Awaiting the provider write.
    Send,
    /// Awaiting the store write of the response.
    RecordResponse,
    /// Awaiting the store write of `unknown`.
    RecordUnknown,
    /// Awaiting the store write of `not-entered`.
    RecordNotEntered,
    /// Awaiting the read-back.
    ReadBack(Mode),
    /// Stopped.
    Done,
}

/// The machine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmitState {
    /// The fixed plan.
    pub plan: SubmitPlan,
    /// The current phase.
    pub phase: Phase,
    /// The verified relative-ceiling argument, set by native verification;
    /// zero before it and when no ceiling is declared.
    pub argument: u64,
}

/// The result of native verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    /// Denied, indeterminate, or unavailable.
    Refused,
    /// Authorized, with the verified relative-ceiling argument (zero when
    /// none is declared).
    Authorized {
        /// The verified argument.
        argument: u64,
    },
}

/// The result of the claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimResult {
    /// This submission stored the claim with every slot.
    Inserted,
    /// The claim step stored the claim as `not-entered`.
    Refused,
    /// The logical operation was already claimed.
    Replay,
    /// Nothing was stored.
    Unavailable,
}

/// The result of the account read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountResult {
    /// The commitments are equal.
    Equal,
    /// A valid account was read and its commitment differs.
    Mismatch,
    /// Anything else.
    Unavailable,
}

/// The result of one denied read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeniedResult {
    /// Refused with a declared status.
    Refused,
    /// Answered with a success status.
    Answered,
    /// Anything else.
    Unavailable,
}

/// The result of the pre-entry re-read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreEntryResult {
    /// Every selected requirement is fresh and satisfied.
    Satisfied,
    /// A fresh observation makes a condition false.
    ConditionFalse,
    /// Anything else.
    Unavailable,
}

/// The result of the relative-ceiling read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeilingRead {
    /// No valid basis was read.
    Unavailable,
    /// A valid basis was read.
    Read {
        /// The basis.
        basis: u64,
        /// Whether every bind pointer equals its verified field.
        binds_equal: bool,
    },
}

/// The result of the provider write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteResult {
    /// Refused before network entry.
    NotEntered,
    /// Transport may have been entered; no complete response.
    Unknown,
    /// A complete bounded response was received.
    Response,
}

/// The result of recording the response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseRecord {
    /// The store write failed.
    Failed,
    /// The response was recorded.
    Recorded {
        /// Whether a read-back request exists for it.
        observable: bool,
    },
}

/// The result of the action the previous decision named.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitEvent {
    /// The machine starts.
    Start,
    /// The clock was read.
    Clock(bool),
    /// The native verification result.
    Verification(Verification),
    /// Admission passed.
    Admission(bool),
    /// Every link's scope lists the verified value.
    Scope(bool),
    /// The transport was prepared.
    Preparation(bool),
    /// The claim result.
    Claim(ClaimResult),
    /// The replayed attempt can be re-observed.
    Resume(bool),
    /// The connection record is unchanged.
    Reload(bool),
    /// The credential was leased.
    Lease(bool),
    /// The leased secret starts with a declared prefix.
    Prefix(bool),
    /// The account read result.
    Account(AccountResult),
    /// The denied read result.
    Denied(DeniedResult),
    /// The pre-entry re-read result.
    PreEntry(PreEntryResult),
    /// The relative-ceiling read result.
    Ceiling(CeilingRead),
    /// A store write succeeded.
    Recorded(bool),
    /// Entry is within the deadline.
    Deadline(bool),
    /// The provider write result.
    Write(WriteResult),
    /// The response record result.
    Response(ResponseRecord),
}

/// Why an entry was refused after the claim; each maps to one recorded code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The connection record changed.
    ConnectionChanged,
    /// The credential could not be leased.
    CredentialUnavailable,
    /// The secret has no declared prefix.
    ModeGuard,
    /// The account read found another account.
    AccountMismatch,
    /// The account read failed.
    AccountUnavailable,
    /// A denied read was answered.
    CapabilityExcess,
    /// A denied read failed.
    CapabilityUnavailable,
    /// The pre-entry re-read made a condition false.
    PreEntryConditionFalse,
    /// The pre-entry re-read failed or was stale.
    PreEntryUnavailable,
    /// The argument is above the relative ceiling.
    CeilingAbove,
    /// A relative-ceiling bind differs.
    CeilingBindingMismatch,
    /// No valid relative-ceiling basis was read.
    CeilingUnavailable,
    /// Entry would be after the deadline.
    EntryDeadline,
    /// The write was refused before network entry.
    TransportNotEntered,
}

/// How the machine stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    /// Refused before the claim; nothing was stored.
    Refused,
    /// The claim could not be stored; nothing was stored.
    StoreUnavailable,
    /// The claim step recorded `not-entered`.
    ClaimRefused,
    /// `not-entered` was recorded after the claim.
    NotEntered,
    /// The stored record is `attempting` or `unknown`.
    Unknown,
    /// The response is recorded and no read-back transition was.
    Response,
    /// A read-back recorded its transition.
    Observed,
    /// A replay recorded nothing.
    ReplayRefused,
    /// An event the phase does not expect.
    Halted,
}

/// The next action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitAction {
    /// Read the gateway clock.
    ReadClock,
    /// Verify natively.
    Verify,
    /// Run admission.
    Admit,
    /// Check the account-scope binding.
    BindScope,
    /// Prepare the pinned transport.
    Prepare,
    /// Claim the logical operation.
    Claim,
    /// Load the replayed attempt and decide whether it can be re-observed.
    Resume,
    /// Reload the connection record before a lease.
    Reload(Mode),
    /// Lease the credential.
    Lease(Mode),
    /// Check the leased secret's prefix.
    CheckPrefix(Mode),
    /// Run the account read.
    ReadAccount(Mode),
    /// Run the denied read at this index.
    DeniedRead(Mode, u8),
    /// Run the pre-entry re-read.
    PreEntryRead,
    /// Run the relative-ceiling read.
    CeilingRead,
    /// Record what was read in one `attempting → attempting`.
    RecordCheckpoint,
    /// Reload the connection record before entry.
    ReloadBeforeEntry,
    /// Check the entry deadline.
    CheckDeadline,
    /// Send the one write.
    Send,
    /// Record the response.
    RecordResponse,
    /// Record `unknown`.
    RecordUnknown,
    /// Record `not-entered` with this refusal.
    RecordNotEntered(Refusal),
    /// Perform one read-only observation and record what it shows.
    ReadBack(Mode),
    /// Stop.
    Stop(Stop),
}

/// The next state and action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmitDecision {
    /// The next state.
    pub state: SubmitState,
    /// The next action.
    pub action: SubmitAction,
}

/// The machine before its first event.
#[must_use]
pub const fn start(plan: SubmitPlan) -> SubmitState {
    SubmitState {
        plan,
        phase: Phase::Start,
        argument: 0,
    }
}

/// Moves to `phase` and names `action`, keeping the plan and argument.
#[must_use]
pub const fn go(state: SubmitState, phase: Phase, action: SubmitAction) -> SubmitDecision {
    SubmitDecision {
        state: SubmitState {
            plan: state.plan,
            phase,
            argument: state.argument,
        },
        action,
    }
}

/// Stops with `stop`.
#[must_use]
pub const fn stop(state: SubmitState, stop: Stop) -> SubmitDecision {
    go(state, Phase::Done, SubmitAction::Stop(stop))
}

/// Halts on an event the phase does not expect.
#[must_use]
pub const fn halt(state: SubmitState) -> SubmitDecision {
    stop(state, Stop::Halted)
}

/// Records `not-entered` with `refusal`.
#[must_use]
pub const fn not_entered(state: SubmitState, refusal: Refusal) -> SubmitDecision {
    go(
        state,
        Phase::RecordNotEntered,
        SubmitAction::RecordNotEntered(refusal),
    )
}

/// A failed lease-time step: an entry records `not-entered`; a read-back or
/// re-observation records nothing.
#[must_use]
pub const fn lease_failed(state: SubmitState, mode: Mode, refusal: Refusal) -> SubmitDecision {
    match mode {
        Mode::Entry => not_entered(state, refusal),
        Mode::ReadBack => stop(state, Stop::Response),
        Mode::Reobserve => stop(state, Stop::ReplayRefused),
    }
}

/// After the relative ceiling, or after the pre-entry re-read when no
/// ceiling is declared: the checkpoint when anything was read, else the
/// reload before entry.
#[must_use]
pub const fn after_reads(state: SubmitState) -> SubmitDecision {
    if state.plan.pre_entry || state.plan.relative_ceiling {
        go(state, Phase::Checkpoint, SubmitAction::RecordCheckpoint)
    } else {
        go(state, Phase::EntryReload, SubmitAction::ReloadBeforeEntry)
    }
}

/// The relative-ceiling read when declared.
#[must_use]
pub const fn ceiling_from(state: SubmitState) -> SubmitDecision {
    if state.plan.relative_ceiling {
        go(state, Phase::Ceiling, SubmitAction::CeilingRead)
    } else {
        after_reads(state)
    }
}

/// The pre-entry re-read when declared.
#[must_use]
pub const fn pre_entry_from(state: SubmitState) -> SubmitDecision {
    if state.plan.pre_entry {
        go(state, Phase::PreEntry, SubmitAction::PreEntryRead)
    } else {
        ceiling_from(state)
    }
}

/// After every credential check passed: the entry's reads, or the one
/// read-back of a read-back or re-observation lease.
#[must_use]
pub const fn after_credentials(state: SubmitState, mode: Mode) -> SubmitDecision {
    match mode {
        Mode::Entry => pre_entry_from(state),
        Mode::ReadBack | Mode::Reobserve => {
            go(state, Phase::ReadBack(mode), SubmitAction::ReadBack(mode))
        }
    }
}

/// The denied read at `index` when one remains.
#[must_use]
pub const fn denied_from(state: SubmitState, mode: Mode, index: u8) -> SubmitDecision {
    if index < state.plan.denied_reads {
        go(
            state,
            Phase::Denied(mode, index),
            SubmitAction::DeniedRead(mode, index),
        )
    } else {
        after_credentials(state, mode)
    }
}

/// After the prefix guard: the account read when declared.
#[must_use]
pub const fn after_prefix(state: SubmitState, mode: Mode) -> SubmitDecision {
    if state.plan.account_read {
        go(state, Phase::Account(mode), SubmitAction::ReadAccount(mode))
    } else {
        denied_from(state, mode, 0)
    }
}

/// After admission: the account-scope binding when declared.
#[must_use]
pub const fn after_admission(state: SubmitState) -> SubmitDecision {
    if state.plan.account_scope {
        go(state, Phase::Scope, SubmitAction::BindScope)
    } else {
        go(state, Phase::Prepare, SubmitAction::Prepare)
    }
}

/// A pre-claim check passed (`next`) or failed (refused, nothing stored).
#[must_use]
pub const fn pre_claim(state: SubmitState, passed: bool, next: SubmitDecision) -> SubmitDecision {
    if passed {
        next
    } else {
        stop(state, Stop::Refused)
    }
}

/// The claim result.
#[must_use]
pub const fn after_claim(state: SubmitState, result: ClaimResult) -> SubmitDecision {
    match result {
        ClaimResult::Inserted => go(
            state,
            Phase::Reload(Mode::Entry),
            SubmitAction::Reload(Mode::Entry),
        ),
        ClaimResult::Refused => stop(state, Stop::ClaimRefused),
        ClaimResult::Replay => go(state, Phase::Resume, SubmitAction::Resume),
        ClaimResult::Unavailable => stop(state, Stop::StoreUnavailable),
    }
}

/// The account read result.
#[must_use]
pub const fn after_account(
    state: SubmitState,
    mode: Mode,
    result: AccountResult,
) -> SubmitDecision {
    match result {
        AccountResult::Equal => denied_from(state, mode, 0),
        AccountResult::Mismatch => lease_failed(state, mode, Refusal::AccountMismatch),
        AccountResult::Unavailable => lease_failed(state, mode, Refusal::AccountUnavailable),
    }
}

/// The result of the denied read at `index`.
#[must_use]
pub const fn after_denied(
    state: SubmitState,
    mode: Mode,
    index: u8,
    result: DeniedResult,
) -> SubmitDecision {
    match result {
        DeniedResult::Refused => {
            if index < state.plan.denied_reads {
                denied_from(state, mode, index + 1)
            } else {
                halt(state)
            }
        }
        DeniedResult::Answered => lease_failed(state, mode, Refusal::CapabilityExcess),
        DeniedResult::Unavailable => lease_failed(state, mode, Refusal::CapabilityUnavailable),
    }
}

/// The pre-entry re-read result.
#[must_use]
pub const fn after_pre_entry(state: SubmitState, result: PreEntryResult) -> SubmitDecision {
    match result {
        PreEntryResult::Satisfied => ceiling_from(state),
        PreEntryResult::ConditionFalse => not_entered(state, Refusal::PreEntryConditionFalse),
        PreEntryResult::Unavailable => not_entered(state, Refusal::PreEntryUnavailable),
    }
}

/// The relative-ceiling read result: a bind mismatch dominates, then the
/// exact ratio comparison on the verified argument.
#[must_use]
pub const fn after_ceiling(state: SubmitState, read: CeilingRead) -> SubmitDecision {
    match read {
        CeilingRead::Unavailable => not_entered(state, Refusal::CeilingUnavailable),
        CeilingRead::Read { basis, binds_equal } => {
            if !binds_equal {
                not_entered(state, Refusal::CeilingBindingMismatch)
            } else if relative_ceiling_admits(state.argument, basis, state.plan.basis_points) {
                after_reads(state)
            } else {
                not_entered(state, Refusal::CeilingAbove)
            }
        }
    }
}

/// The provider write result.
#[must_use]
pub const fn after_write(state: SubmitState, result: WriteResult) -> SubmitDecision {
    match result {
        WriteResult::NotEntered => not_entered(state, Refusal::TransportNotEntered),
        WriteResult::Unknown => go(state, Phase::RecordUnknown, SubmitAction::RecordUnknown),
        WriteResult::Response => go(state, Phase::RecordResponse, SubmitAction::RecordResponse),
    }
}

/// The response record result: at most one read-back, under a fresh lease.
#[must_use]
pub const fn after_response(state: SubmitState, record: ResponseRecord) -> SubmitDecision {
    match record {
        ResponseRecord::Failed => stop(state, Stop::Unknown),
        ResponseRecord::Recorded { observable } => {
            if observable {
                go(
                    state,
                    Phase::Reload(Mode::ReadBack),
                    SubmitAction::Reload(Mode::ReadBack),
                )
            } else {
                stop(state, Stop::Response)
            }
        }
    }
}

/// The read-back result.
#[must_use]
pub const fn after_read_back(state: SubmitState, mode: Mode, recorded: bool) -> SubmitDecision {
    if recorded {
        stop(state, Stop::Observed)
    } else {
        match mode {
            Mode::Entry => halt(state),
            Mode::ReadBack => stop(state, Stop::Response),
            Mode::Reobserve => stop(state, Stop::ReplayRefused),
        }
    }
}

/// The step before the claim: the clock, verification, admission, the
/// account-scope binding, and transport preparation.
#[must_use]
pub const fn pre_claim_step(state: SubmitState, event: SubmitEvent) -> SubmitDecision {
    match state.phase {
        Phase::Start => match event {
            SubmitEvent::Start => go(state, Phase::Clock, SubmitAction::ReadClock),
            _ => halt(state),
        },
        Phase::Clock => match event {
            SubmitEvent::Clock(read) => {
                pre_claim(state, read, go(state, Phase::Verify, SubmitAction::Verify))
            }
            _ => halt(state),
        },
        Phase::Verify => match event {
            SubmitEvent::Verification(verification) => match verification {
                Verification::Refused => stop(state, Stop::Refused),
                Verification::Authorized { argument } => SubmitDecision {
                    state: SubmitState {
                        plan: state.plan,
                        phase: Phase::Admit,
                        argument,
                    },
                    action: SubmitAction::Admit,
                },
            },
            _ => halt(state),
        },
        Phase::Admit => match event {
            SubmitEvent::Admission(admitted) => pre_claim(state, admitted, after_admission(state)),
            _ => halt(state),
        },
        Phase::Scope => match event {
            SubmitEvent::Scope(bound) => pre_claim(
                state,
                bound,
                go(state, Phase::Prepare, SubmitAction::Prepare),
            ),
            _ => halt(state),
        },
        Phase::Prepare => match event {
            SubmitEvent::Preparation(prepared) => pre_claim(
                state,
                prepared,
                go(state, Phase::Claim, SubmitAction::Claim),
            ),
            _ => halt(state),
        },
        Phase::Claim => match event {
            SubmitEvent::Claim(result) => after_claim(state, result),
            _ => halt(state),
        },
        _ => halt(state),
    }
}

/// A lease-time step: the reload, the lease, the prefix guard, the account
/// read, and the denied reads.
#[must_use]
pub const fn lease_step(state: SubmitState, event: SubmitEvent) -> SubmitDecision {
    match state.phase {
        Phase::Resume => match event {
            SubmitEvent::Resume(resumable) => {
                if resumable {
                    go(
                        state,
                        Phase::Reload(Mode::Reobserve),
                        SubmitAction::Reload(Mode::Reobserve),
                    )
                } else {
                    stop(state, Stop::ReplayRefused)
                }
            }
            _ => halt(state),
        },
        Phase::Reload(mode) => match event {
            SubmitEvent::Reload(unchanged) => {
                if unchanged {
                    go(state, Phase::Lease(mode), SubmitAction::Lease(mode))
                } else {
                    lease_failed(state, mode, Refusal::ConnectionChanged)
                }
            }
            _ => halt(state),
        },
        Phase::Lease(mode) => match event {
            SubmitEvent::Lease(leased) => {
                if leased {
                    go(state, Phase::Prefix(mode), SubmitAction::CheckPrefix(mode))
                } else {
                    lease_failed(state, mode, Refusal::CredentialUnavailable)
                }
            }
            _ => halt(state),
        },
        Phase::Prefix(mode) => match event {
            SubmitEvent::Prefix(allowed) => {
                if allowed {
                    after_prefix(state, mode)
                } else {
                    lease_failed(state, mode, Refusal::ModeGuard)
                }
            }
            _ => halt(state),
        },
        Phase::Account(mode) => match event {
            SubmitEvent::Account(result) => after_account(state, mode, result),
            _ => halt(state),
        },
        Phase::Denied(mode, index) => match event {
            SubmitEvent::Denied(result) => after_denied(state, mode, index, result),
            _ => halt(state),
        },
        _ => halt(state),
    }
}

/// A step between the credential checks and the stop: the entry's reads,
/// the checkpoint, the reload and deadline before entry, the write, and the
/// store writes and read-back after it.
#[must_use]
pub const fn entry_step(state: SubmitState, event: SubmitEvent) -> SubmitDecision {
    match state.phase {
        Phase::PreEntry => match event {
            SubmitEvent::PreEntry(result) => after_pre_entry(state, result),
            _ => halt(state),
        },
        Phase::Ceiling => match event {
            SubmitEvent::Ceiling(read) => after_ceiling(state, read),
            _ => halt(state),
        },
        Phase::Checkpoint => match event {
            SubmitEvent::Recorded(recorded) => {
                if recorded {
                    go(state, Phase::EntryReload, SubmitAction::ReloadBeforeEntry)
                } else {
                    stop(state, Stop::Unknown)
                }
            }
            _ => halt(state),
        },
        Phase::EntryReload => match event {
            SubmitEvent::Reload(unchanged) => {
                if unchanged {
                    go(state, Phase::Deadline, SubmitAction::CheckDeadline)
                } else {
                    not_entered(state, Refusal::ConnectionChanged)
                }
            }
            _ => halt(state),
        },
        Phase::Deadline => match event {
            SubmitEvent::Deadline(within) => {
                if within {
                    go(state, Phase::Send, SubmitAction::Send)
                } else {
                    not_entered(state, Refusal::EntryDeadline)
                }
            }
            _ => halt(state),
        },
        Phase::Send => match event {
            SubmitEvent::Write(result) => after_write(state, result),
            _ => halt(state),
        },
        Phase::RecordResponse => match event {
            SubmitEvent::Response(record) => after_response(state, record),
            _ => halt(state),
        },
        Phase::RecordUnknown => match event {
            SubmitEvent::Recorded(_) => stop(state, Stop::Unknown),
            _ => halt(state),
        },
        Phase::RecordNotEntered => match event {
            SubmitEvent::Recorded(recorded) => {
                if recorded {
                    stop(state, Stop::NotEntered)
                } else {
                    stop(state, Stop::Unknown)
                }
            }
            _ => halt(state),
        },
        Phase::ReadBack(mode) => match event {
            SubmitEvent::Recorded(recorded) => after_read_back(state, mode, recorded),
            _ => halt(state),
        },
        _ => halt(state),
    }
}

/// The next state and action for `event`, the result of the action the
/// previous decision named. Total: an event the phase does not expect, and
/// any event after a stop, halts without further I/O.
#[must_use]
pub const fn next_step(state: SubmitState, event: SubmitEvent) -> SubmitDecision {
    match state.phase {
        Phase::Start
        | Phase::Clock
        | Phase::Verify
        | Phase::Admit
        | Phase::Scope
        | Phase::Prepare
        | Phase::Claim => pre_claim_step(state, event),
        Phase::Resume
        | Phase::Reload(_)
        | Phase::Lease(_)
        | Phase::Prefix(_)
        | Phase::Account(_)
        | Phase::Denied(_, _) => lease_step(state, event),
        Phase::PreEntry
        | Phase::Ceiling
        | Phase::Checkpoint
        | Phase::EntryReload
        | Phase::Deadline
        | Phase::Send
        | Phase::RecordResponse
        | Phase::RecordUnknown
        | Phase::RecordNotEntered
        | Phase::ReadBack(_) => entry_step(state, event),
        Phase::Done => halt(state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const STRIPE: SubmitPlan = SubmitPlan {
        account_scope: false,
        account_read: true,
        denied_reads: 2,
        pre_entry: false,
        relative_ceiling: true,
        basis_points: 5_000,
    };

    /// Drives the machine with `events` and returns every action.
    fn run(plan: SubmitPlan, events: &[SubmitEvent]) -> Vec<SubmitAction> {
        let mut state = start(plan);
        let mut actions = Vec::new();
        for event in events {
            let decision = next_step(state, *event);
            actions.push(decision.action);
            state = decision.state;
        }
        actions
    }

    fn admitted() -> Vec<SubmitEvent> {
        alloc::vec![
            SubmitEvent::Start,
            SubmitEvent::Clock(true),
            SubmitEvent::Verification(Verification::Authorized { argument: 500 }),
            SubmitEvent::Admission(true),
            SubmitEvent::Preparation(true),
            SubmitEvent::Claim(ClaimResult::Inserted),
            SubmitEvent::Reload(true),
            SubmitEvent::Lease(true),
            SubmitEvent::Prefix(true),
            SubmitEvent::Account(AccountResult::Equal),
            SubmitEvent::Denied(DeniedResult::Refused),
            SubmitEvent::Denied(DeniedResult::Refused),
        ]
    }

    #[test]
    fn the_full_order_reads_every_check_before_the_one_write() {
        let mut events = admitted();
        events.extend([
            SubmitEvent::Ceiling(CeilingRead::Read {
                basis: 1_001,
                binds_equal: true,
            }),
            SubmitEvent::Recorded(true),
            SubmitEvent::Reload(true),
            SubmitEvent::Deadline(true),
            SubmitEvent::Write(WriteResult::Response),
            SubmitEvent::Response(ResponseRecord::Recorded { observable: true }),
            SubmitEvent::Reload(true),
            SubmitEvent::Lease(true),
            SubmitEvent::Prefix(true),
            SubmitEvent::Account(AccountResult::Equal),
            SubmitEvent::Denied(DeniedResult::Refused),
            SubmitEvent::Denied(DeniedResult::Refused),
            SubmitEvent::Recorded(true),
        ]);
        let entry = Mode::Entry;
        let back = Mode::ReadBack;
        assert_eq!(
            run(STRIPE, &events),
            [
                SubmitAction::ReadClock,
                SubmitAction::Verify,
                SubmitAction::Admit,
                SubmitAction::Prepare,
                SubmitAction::Claim,
                SubmitAction::Reload(entry),
                SubmitAction::Lease(entry),
                SubmitAction::CheckPrefix(entry),
                SubmitAction::ReadAccount(entry),
                SubmitAction::DeniedRead(entry, 0),
                SubmitAction::DeniedRead(entry, 1),
                SubmitAction::CeilingRead,
                SubmitAction::RecordCheckpoint,
                SubmitAction::ReloadBeforeEntry,
                SubmitAction::CheckDeadline,
                SubmitAction::Send,
                SubmitAction::RecordResponse,
                SubmitAction::Reload(back),
                SubmitAction::Lease(back),
                SubmitAction::CheckPrefix(back),
                SubmitAction::ReadAccount(back),
                SubmitAction::DeniedRead(back, 0),
                SubmitAction::DeniedRead(back, 1),
                SubmitAction::ReadBack(back),
                SubmitAction::Stop(Stop::Observed),
            ]
        );
    }

    #[test]
    fn a_failed_check_after_the_claim_records_its_refusal_and_never_sends() {
        let cases = [
            (
                SubmitEvent::Ceiling(CeilingRead::Read {
                    basis: 999,
                    binds_equal: true,
                }),
                Refusal::CeilingAbove,
            ),
            (
                SubmitEvent::Ceiling(CeilingRead::Read {
                    basis: 1_001,
                    binds_equal: false,
                }),
                Refusal::CeilingBindingMismatch,
            ),
            (
                SubmitEvent::Ceiling(CeilingRead::Unavailable),
                Refusal::CeilingUnavailable,
            ),
        ];
        for (event, refusal) in cases {
            let mut events = admitted();
            events.push(event);
            let actions = run(STRIPE, &events);
            assert_eq!(
                actions.last(),
                Some(&SubmitAction::RecordNotEntered(refusal))
            );
            assert!(!actions.contains(&SubmitAction::Send));
        }
        let mut denied = admitted();
        denied.truncate(10);
        denied.push(SubmitEvent::Denied(DeniedResult::Answered));
        assert_eq!(
            run(STRIPE, &denied).last(),
            Some(&SubmitAction::RecordNotEntered(Refusal::CapabilityExcess))
        );
    }

    #[test]
    fn a_replay_never_sends_and_a_pre_claim_refusal_stores_nothing() {
        let replay = [
            SubmitEvent::Start,
            SubmitEvent::Clock(true),
            SubmitEvent::Verification(Verification::Authorized { argument: 500 }),
            SubmitEvent::Admission(true),
            SubmitEvent::Preparation(true),
            SubmitEvent::Claim(ClaimResult::Replay),
            SubmitEvent::Resume(true),
            SubmitEvent::Reload(true),
            SubmitEvent::Lease(true),
            SubmitEvent::Prefix(true),
            SubmitEvent::Account(AccountResult::Mismatch),
        ];
        let actions = run(STRIPE, &replay);
        assert!(!actions.contains(&SubmitAction::Send));
        assert_eq!(
            actions.last(),
            Some(&SubmitAction::Stop(Stop::ReplayRefused))
        );
        let refused = run(
            STRIPE,
            &[
                SubmitEvent::Start,
                SubmitEvent::Clock(true),
                SubmitEvent::Verification(Verification::Authorized { argument: 500 }),
                SubmitEvent::Admission(false),
            ],
        );
        assert_eq!(refused.last(), Some(&SubmitAction::Stop(Stop::Refused)));
        assert!(!refused.contains(&SubmitAction::Claim));
    }

    #[test]
    fn an_unexpected_event_halts_without_io() {
        let decision = next_step(start(STRIPE), SubmitEvent::Write(WriteResult::Response));
        assert_eq!(decision.action, SubmitAction::Stop(Stop::Halted));
        assert_eq!(decision.state.phase, Phase::Done);
        let after = next_step(decision.state, SubmitEvent::Start);
        assert_eq!(after.action, SubmitAction::Stop(Stop::Halted));
    }
}
