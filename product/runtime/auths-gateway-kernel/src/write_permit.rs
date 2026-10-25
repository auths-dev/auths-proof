//! Single-assignment, one-use ownership of a claimed write payload.
//!
//! The runtime arms this slot only after its durable claim succeeds. The slot
//! never verifies authority or invents a store acknowledgement. It freezes that
//! claim's exact request, refuses re-arming and consumes even a refused send.

#[derive(Clone, Copy, Debug)]
enum Phase {
    Empty,
    Armed,
    Spent,
}

/// Private fields prevent consumers from fabricating a phase/payload pairing.
/// This type deliberately implements neither `Clone` nor `Copy`.
#[derive(Debug)]
pub struct WritePermit<T> {
    phase: Phase,
    payload: Option<T>,
}

/// The complete input captured after one acknowledged claim. This container
/// grants no authority: the driver supplies only its already verified command,
/// original evaluation time and selected requirements. It deliberately has no
/// mutable projection, `Clone` or `Copy` implementation.
#[derive(Debug)]
pub struct ClaimedInput<Command, Selection> {
    command: Command,
    evaluated_at: u64,
    selection: Selection,
}

/// Moves the complete verified input into its post-claim lifetime without
/// cloning, normalizing or substituting any payload.
#[must_use]
pub fn capture_input<Command, Selection>(
    command: Command,
    evaluated_at: u64,
    selection: Selection,
) -> ClaimedInput<Command, Selection> {
    ClaimedInput { command, evaluated_at, selection }
}

/// Borrows the command whose claim was acknowledged.
#[must_use]
pub const fn captured_command<Command, Selection>(input: &ClaimedInput<Command, Selection>) -> &Command {
    &input.command
}

/// Returns the evaluation time captured with that same command.
#[must_use]
pub const fn captured_time<Command, Selection>(input: &ClaimedInput<Command, Selection>) -> u64 {
    input.evaluated_at
}

/// Borrows the pre-entry selection captured with that same command.
#[must_use]
pub const fn captured_selection<Command, Selection>(input: &ClaimedInput<Command, Selection>) -> &Selection {
    &input.selection
}

/// A fresh run has no acknowledged claim and no writable request.
#[must_use]
pub const fn empty<T>() -> WritePermit<T> {
    WritePermit { phase: Phase::Empty, payload: None }
}

/// Only an unused empty slot may be armed by a successful claim.
#[must_use]
pub const fn can_arm<T>(permit: &WritePermit<T>) -> bool {
    match permit.phase {
        Phase::Empty => matches!(permit.payload, None),
        Phase::Armed | Phase::Spent => false,
    }
}

/// Whether a send was already attempted, including a pre-transport refusal.
#[must_use]
pub const fn spent<T>(permit: &WritePermit<T>) -> bool {
    match permit.phase {
        Phase::Spent => true,
        Phase::Empty | Phase::Armed => false,
    }
}

/// Captures one payload without overwriting or rearming an existing slot.
#[must_use]
pub fn arm<T>(permit: WritePermit<T>, payload: T) -> WritePermit<T> {
    if can_arm(&permit) {
        WritePermit { phase: Phase::Armed, payload: Some(payload) }
    } else {
        permit
    }
}

/// Consumes the slot before any transport await. A returned value is exactly
/// the stored request. Missing claim/lease, an unarmed slot and repeated calls
/// yield no request; every result leaves a spent slot with no retained payload.
#[must_use]
pub fn consume<T>(
    permit: WritePermit<T>,
    has_claim: bool,
    has_lease: bool,
) -> (WritePermit<T>, Option<T>) {
    let payload = match permit.phase {
        Phase::Armed if has_claim && has_lease => permit.payload,
        Phase::Empty | Phase::Armed | Phase::Spent => None,
    };
    (WritePermit { phase: Phase::Spent, payload: None }, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_assignment_and_consumption_preserve_the_original_payload() {
        let permit = arm(empty(), [1, 2, 3]);
        let permit = arm(permit, [9, 9, 9]);
        let (permit, payload) = consume(permit, true, true);
        assert_eq!(payload, Some([1, 2, 3]));
        assert!(spent(&permit));
        assert!(!can_arm(&permit));
        let permit = arm(permit, [8, 8, 8]);
        let (permit, payload) = consume(permit, true, true);
        assert_eq!(payload, None);
        assert!(spent(&permit));
    }

    #[test]
    fn all_missing_resource_cases_fail_closed_and_cannot_be_rearmed() {
        for has_claim in [false, true] {
            for has_lease in [false, true] {
                let (permit, payload) = consume(arm(empty(), 7), has_claim, has_lease);
                assert_eq!(payload, (has_claim && has_lease).then_some(7));
                let (permit, repeated) = consume(arm(permit, 8), true, true);
                assert_eq!(repeated, None);
                assert!(spent(&permit));
                let (permit, unarmed) = consume(empty::<u8>(), has_claim, has_lease);
                assert_eq!(unarmed, None);
                assert!(!can_arm(&permit));
            }
        }
    }

    #[test]
    fn forged_internal_phase_payload_combinations_do_not_mint_values() {
        for phase in [Phase::Empty, Phase::Armed, Phase::Spent] {
            for payload in [None, Some(17)] {
                let permit = WritePermit { phase, payload };
                let (after, returned) = consume(permit, true, true);
                assert_eq!(returned, if matches!(phase, Phase::Armed) { payload } else { None });
                assert!(spent(&after));
                assert!(!can_arm(&after));
            }
        }
    }
}
