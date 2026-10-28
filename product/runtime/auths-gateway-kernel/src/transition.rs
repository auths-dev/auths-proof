//! The closed stage-transition rule of the gateway attempt record.
//!
//! The gateway store projects each stored record onto an [`AttemptView`]:
//! the canonical bytes of the fields no transition may change (identity,
//! evaluation time, reserved counters, and the observation plan), the stage,
//! and the canonical bytes or presence of every field a transition may add.
//! [`valid_transition`] decides whether one view may replace another. Every
//! transition keeps the unchangeable bytes, and a field, once set, is never
//! changed.
//!
//! This module is a translated leaf: closed enums dispatched by `match`, one
//! index loop in its own helper, byte comparisons, and no standard-library
//! call beyond slice length and indexing.

use alloc::vec::Vec;

/// The stage of an attempt record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Capacity is reserved, but external entry is forbidden.
    Reserved,
    /// A unique durable grant exists; external entry may have occurred.
    EntryGranted,
    /// Transport entry was excluded; terminal.
    NotEntered,
    /// Transport may have been entered and no complete response exists.
    Unknown,
    /// A complete bounded response was recorded.
    ResponseRecorded,
    /// A read-back compared state; terminal.
    Observed,
    /// A read-back found this action's token and value; terminal.
    ObservedByProvider,
}

/// The read-back comparison recorded with an `observed` stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reading {
    /// No comparison is recorded.
    None,
    /// The value matched.
    Match,
    /// The value differed.
    Mismatch,
    /// The echo field held another token.
    EchoMismatch,
}

/// The provider link of the stored observation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Link {
    /// No echo is declared, or no observation.
    None,
    /// The echo is read back at a locator built from verified fields.
    Verified,
    /// The echo is read back at a locator from the recorded response.
    AfterResponse,
}

/// The fields of one stored attempt record the transition rule inspects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptView {
    /// Canonical bytes of the fields no transition may change.
    pub fixed: Vec<u8>,
    /// Immutable canonical grant/audit bytes; empty before entry.
    pub entry: Vec<u8>,
    /// The stage.
    pub stage: Stage,
    /// Whether a refusal code is recorded.
    pub refusal: bool,
    /// Canonical bytes of the pre-entry record; empty when absent.
    pub pre_entry: Vec<u8>,
    /// Canonical bytes of the response status and digest; empty when absent.
    pub response: Vec<u8>,
    /// Canonical bytes of the response locator; empty when absent.
    pub locator: Vec<u8>,
    /// The recorded comparison.
    pub reading: Reading,
    /// Whether provider evidence is recorded.
    pub evidence: bool,
    /// Whether the stored plan has an observation.
    pub observation: bool,
    /// The stored plan's provider link.
    pub link: Link,
}

/// Whether `bytes` is empty.
#[must_use]
#[allow(
    clippy::len_zero,
    reason = "slice length translates without a model of `is_empty`"
)]
pub const fn absent(bytes: &[u8]) -> bool {
    bytes.len() == 0
}

/// Whether `left` and `right`, of equal length, hold the same bytes.
#[must_use]
pub fn same_bytes_from(left: &[u8], right: &[u8]) -> bool {
    let mut index = 0;
    while index < left.len() && index < right.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether `left` and `right` hold the same bytes.
#[must_use]
pub fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() == right.len() {
        same_bytes_from(left, right)
    } else {
        false
    }
}

/// Whether a link lets an `entry-granted` or `unknown` record reach
/// `observed-by-provider`: only a verified-locator link.
#[must_use]
pub const fn resolves_unknown(link: Link) -> bool {
    match link {
        Link::Verified => true,
        Link::None | Link::AfterResponse => false,
    }
}

/// Whether a link declares an echo at all.
#[must_use]
pub const fn has_link(link: Link) -> bool {
    match link {
        Link::None => false,
        Link::Verified | Link::AfterResponse => true,
    }
}

/// Whether a stage carries a refusal code: exactly `not-entered`.
#[must_use]
pub const fn refusal_stage(stage: Stage) -> bool {
    match stage {
        Stage::NotEntered => true,
        Stage::Reserved
        | Stage::EntryGranted
        | Stage::Unknown
        | Stage::ResponseRecorded
        | Stage::Observed
        | Stage::ObservedByProvider => false,
    }
}

/// Whether a stage requires a recorded response.
#[must_use]
pub const fn requires_response(stage: Stage) -> bool {
    match stage {
        Stage::ResponseRecorded | Stage::Observed => true,
        Stage::Reserved
        | Stage::EntryGranted
        | Stage::NotEntered
        | Stage::Unknown
        | Stage::ObservedByProvider => false,
    }
}

/// Whether a stage may carry a recorded response.
#[must_use]
pub const fn permits_response(stage: Stage) -> bool {
    match stage {
        Stage::ResponseRecorded | Stage::Observed | Stage::ObservedByProvider => true,
        Stage::Reserved | Stage::EntryGranted | Stage::NotEntered | Stage::Unknown => false,
    }
}

/// Whether a stage is `observed`.
#[must_use]
pub const fn observed_stage(stage: Stage) -> bool {
    match stage {
        Stage::Observed => true,
        Stage::Reserved
        | Stage::EntryGranted
        | Stage::NotEntered
        | Stage::Unknown
        | Stage::ResponseRecorded
        | Stage::ObservedByProvider => false,
    }
}

/// Whether a stage is `observed-by-provider`.
#[must_use]
pub const fn provider_stage(stage: Stage) -> bool {
    match stage {
        Stage::ObservedByProvider => true,
        Stage::Reserved
        | Stage::EntryGranted
        | Stage::NotEntered
        | Stage::Unknown
        | Stage::ResponseRecorded
        | Stage::Observed => false,
    }
}

/// Whether a stage has no outgoing transition.
#[must_use]
pub const fn terminal_stage(stage: Stage) -> bool {
    match stage {
        Stage::NotEntered | Stage::Observed | Stage::ObservedByProvider => true,
        Stage::Reserved | Stage::EntryGranted | Stage::Unknown | Stage::ResponseRecorded => false,
    }
}

/// Whether a comparison is recorded.
#[must_use]
pub const fn has_reading(reading: Reading) -> bool {
    match reading {
        Reading::None => false,
        Reading::Match | Reading::Mismatch | Reading::EchoMismatch => true,
    }
}

/// Whether a view's fields agree with its stage: a refusal exactly when
/// `not-entered`; a response whenever `response-recorded` or `observed` and
/// never before a response could exist; a locator only with a response; a
/// comparison exactly when `observed`, and only with an observation plan;
/// provider evidence exactly when `observed-by-provider`, only with a
/// declared link, and without a response only for a verified-locator link.
#[must_use]
pub fn consistent(view: &AttemptView) -> bool {
    let has_response = !absent(&view.response);
    requires_entry(view.stage) == !absent(&view.entry)
        && refusal_stage(view.stage) == view.refusal
        && (!requires_response(view.stage) || has_response)
        && (!has_response || permits_response(view.stage))
        && (absent(&view.locator) || has_response)
        && observed_stage(view.stage) == has_reading(view.reading)
        && (!has_reading(view.reading) || view.observation)
        && provider_stage(view.stage) == view.evidence
        && (!view.evidence || has_link(view.link))
        && (!view.evidence || has_response || resolves_unknown(view.link))
}

/// Whether the state requires an immutable entry grant.
#[must_use]
pub const fn requires_entry(stage: Stage) -> bool {
    match stage {
        Stage::Reserved | Stage::NotEntered => false,
        Stage::EntryGranted
        | Stage::Unknown
        | Stage::ResponseRecorded
        | Stage::Observed
        | Stage::ObservedByProvider => true,
    }
}

/// The one transition table: a reservation cannot acquire response evidence
/// or become unknown until it has received a durable entry grant.
#[must_use]
pub const fn stage_transition_allowed(from: Stage, to: Stage, link: Link) -> bool {
    match from {
        Stage::Reserved => matches!(
            to,
            Stage::Reserved | Stage::NotEntered | Stage::EntryGranted
        ),
        Stage::EntryGranted => match to {
            Stage::Unknown | Stage::ResponseRecorded => true,
            Stage::ObservedByProvider => resolves_unknown(link),
            _ => false,
        },
        Stage::Unknown => match to {
            Stage::ResponseRecorded => true,
            Stage::ObservedByProvider => resolves_unknown(link),
            _ => false,
        },
        Stage::ResponseRecorded => matches!(to, Stage::Observed | Stage::ObservedByProvider),
        Stage::NotEntered | Stage::Observed | Stage::ObservedByProvider => false,
    }
}

/// Only a reservation may add pre-entry observations.
#[must_use]
pub const fn adds_pre_entry(from: Stage, to: Stage) -> bool {
    matches!(from, Stage::Reserved) && matches!(to, Stage::Reserved | Stage::NotEntered)
}

/// Only an existing grant may acquire a late or immediate response.
#[must_use]
pub const fn adds_response(from: Stage, to: Stage) -> bool {
    matches!(from, Stage::EntryGranted | Stage::Unknown) && matches!(to, Stage::ResponseRecorded)
}

/// A reservation checkpoint adds its pre-entry record exactly once.
#[must_use]
pub fn checkpoint_valid(old: &AttemptView, new: &AttemptView) -> bool {
    if matches!(old.stage, Stage::Reserved) && matches!(new.stage, Stage::Reserved) {
        absent(&old.pre_entry) && !absent(&new.pre_entry)
    } else {
        true
    }
}

/// Grant bytes are added only at the single reservation-to-entry transition.
#[must_use]
pub fn entry_kept(old: &AttemptView, new: &AttemptView) -> bool {
    if matches!(old.stage, Stage::Reserved) && matches!(new.stage, Stage::EntryGranted) {
        absent(&old.entry) && !absent(&new.entry)
    } else {
        same_bytes(&old.entry, &new.entry)
    }
}

/// Whether the pre-entry record is kept, or added only where a transition
/// may add it.
#[must_use]
pub fn pre_entry_kept(old: &AttemptView, new: &AttemptView) -> bool {
    if absent(&old.pre_entry) {
        absent(&new.pre_entry) || adds_pre_entry(old.stage, new.stage)
    } else {
        same_bytes(&old.pre_entry, &new.pre_entry)
    }
}

/// Whether the response and locator are kept, or added only by the
/// transition that records the response.
#[must_use]
pub fn response_kept(old: &AttemptView, new: &AttemptView) -> bool {
    adds_response(old.stage, new.stage)
        || (same_bytes(&old.response, &new.response) && same_bytes(&old.locator, &new.locator))
}

/// Whether the stored plan's summary is unchanged.
#[must_use]
pub const fn plan_kept(old: &AttemptView, new: &AttemptView) -> bool {
    old.observation == new.observation && link_equal(old.link, new.link)
}

/// Whether two links are the same.
#[must_use]
pub const fn link_equal(left: Link, right: Link) -> bool {
    match left {
        Link::None => match right {
            Link::None => true,
            Link::Verified | Link::AfterResponse => false,
        },
        Link::Verified => match right {
            Link::Verified => true,
            Link::None | Link::AfterResponse => false,
        },
        Link::AfterResponse => match right {
            Link::AfterResponse => true,
            Link::None | Link::Verified => false,
        },
    }
}

/// Whether `new` may replace `old`: the unchangeable bytes and plan are
/// kept, the stage change is in the closed table, pre-entry evidence is
/// added at most once and only before transport entry, the response is
/// added only with `response-recorded` and then kept, and `new` is
/// consistent with its stage.
#[must_use]
pub fn valid_transition(old: &AttemptView, new: &AttemptView) -> bool {
    consistent(old)
        && entry_kept(old, new)
        && same_bytes(&old.fixed, &new.fixed)
        && plan_kept(old, new)
        && stage_transition_allowed(old.stage, new.stage, old.link)
        && checkpoint_valid(old, new)
        && pre_entry_kept(old, new)
        && response_kept(old, new)
        && consistent(new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const STAGES: [Stage; 7] = [
        Stage::Reserved,
        Stage::EntryGranted,
        Stage::NotEntered,
        Stage::Unknown,
        Stage::ResponseRecorded,
        Stage::Observed,
        Stage::ObservedByProvider,
    ];

    fn view(stage: Stage, link: Link) -> AttemptView {
        let response = if requires_response(stage) {
            vec![1]
        } else {
            Vec::new()
        };
        AttemptView {
            entry: if requires_entry(stage) {
                alloc::vec![7]
            } else {
                Vec::new()
            },
            fixed: vec![7; 4],
            stage,
            refusal: refusal_stage(stage),
            pre_entry: Vec::new(),
            response,
            locator: Vec::new(),
            reading: if observed_stage(stage) {
                Reading::Match
            } else {
                Reading::None
            },
            evidence: provider_stage(stage),
            observation: true,
            link,
        }
    }

    #[test]
    fn terminal_stages_have_no_outgoing_transition() {
        for link in [Link::None, Link::Verified, Link::AfterResponse] {
            for from in STAGES {
                for to in STAGES {
                    if terminal_stage(from) {
                        assert!(!stage_transition_allowed(from, to, link));
                        assert!(!valid_transition(&view(from, link), &view(to, link)));
                    }
                }
            }
        }
    }

    #[test]
    fn unknown_resolves_only_for_a_verified_link_with_evidence() {
        for link in [Link::None, Link::Verified, Link::AfterResponse] {
            for to in STAGES {
                let allowed = valid_transition(&view(Stage::Unknown, link), &view(to, link));
                assert_eq!(
                    allowed,
                    to == Stage::ResponseRecorded
                        || (to == Stage::ObservedByProvider && link == Link::Verified),
                    "{link:?} {to:?}"
                );
            }
        }
    }

    #[test]
    fn checkpoint_adds_pre_entry_once_and_changes_nothing_else() {
        let old = view(Stage::Reserved, Link::Verified);
        let mut checkpoint = old.clone();
        checkpoint.pre_entry = vec![9];
        assert!(valid_transition(&old, &checkpoint));
        assert!(!valid_transition(&checkpoint, &checkpoint));
        assert!(
            !valid_transition(&old, &old),
            "a checkpoint must add evidence"
        );
        let mut refused = view(Stage::NotEntered, Link::Verified);
        refused.pre_entry = vec![9];
        assert!(valid_transition(&old, &refused));
        assert!(valid_transition(&checkpoint, &refused));
        refused.pre_entry = vec![8];
        assert!(!valid_transition(&checkpoint, &refused), "kept once set");
        let mut responded = view(Stage::ResponseRecorded, Link::Verified);
        responded.pre_entry = vec![9];
        assert!(
            !valid_transition(&old, &responded),
            "added only before entry"
        );
        assert!(!valid_transition(&checkpoint, &responded));
        let mut grant = view(Stage::EntryGranted, Link::Verified);
        grant.pre_entry = checkpoint.pre_entry.clone();
        assert!(valid_transition(&checkpoint, &grant));
        assert!(valid_transition(&grant, &responded));
        assert!(!valid_transition(&grant, &refused));
        assert!(!valid_transition(&grant, &grant), "no second grant");
        let mut changed = responded.clone();
        changed.entry = vec![8];
        assert!(!valid_transition(&grant, &changed), "grant is immutable");
    }

    #[test]
    fn fixed_bytes_and_the_response_are_kept() {
        let old = view(Stage::ResponseRecorded, Link::AfterResponse);
        let mut moved = view(Stage::ObservedByProvider, Link::AfterResponse);
        moved.response = vec![1];
        assert!(valid_transition(&old, &moved));
        moved.fixed = vec![7; 5];
        assert!(!valid_transition(&old, &moved));
        let mut changed = view(Stage::Observed, Link::AfterResponse);
        changed.response = vec![2];
        assert!(!valid_transition(&old, &changed));
        let attempting = view(Stage::EntryGranted, Link::AfterResponse);
        assert!(!valid_transition(
            &attempting,
            &view(Stage::ObservedByProvider, Link::AfterResponse)
        ));
        let mut located = view(Stage::ResponseRecorded, Link::AfterResponse);
        located.locator = vec![3];
        assert!(valid_transition(&attempting, &located));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use alloc::vec::Vec;

    fn any_stage() -> Stage {
        match kani::any::<u8>() % 7 {
            0 => Stage::EntryGranted,
            1 => Stage::NotEntered,
            2 => Stage::Unknown,
            3 => Stage::ResponseRecorded,
            4 => Stage::Observed,
            5 => Stage::Reserved,
            _ => Stage::ObservedByProvider,
        }
    }

    fn any_link() -> Link {
        match kani::any::<u8>() % 3 {
            0 => Link::None,
            1 => Link::Verified,
            _ => Link::AfterResponse,
        }
    }

    fn any_reading() -> Reading {
        match kani::any::<u8>() % 4 {
            0 => Reading::None,
            1 => Reading::Match,
            2 => Reading::Mismatch,
            _ => Reading::EchoMismatch,
        }
    }

    /// Absent, or one byte of two possible values: enough to tell "kept",
    /// "added", and "changed" apart.
    fn any_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        if kani::any() {
            bytes.push(u8::from(kani::any::<bool>()));
        }
        bytes
    }

    fn any_view() -> AttemptView {
        AttemptView {
            entry: any_bytes(),
            fixed: any_bytes(),
            stage: any_stage(),
            refusal: kani::any(),
            pre_entry: any_bytes(),
            response: any_bytes(),
            locator: any_bytes(),
            reading: any_reading(),
            evidence: kani::any(),
            observation: kani::any(),
            link: any_link(),
        }
    }

    /// The attempt record's stage table, row by row.
    fn table(from: Stage, to: Stage, link: Link) -> bool {
        matches!(
            (from, to),
            (
                Stage::EntryGranted,
                Stage::Unknown | Stage::ResponseRecorded
            ) | (
                Stage::Reserved,
                Stage::Reserved | Stage::NotEntered | Stage::EntryGranted
            ) | (Stage::Unknown, Stage::ResponseRecorded)
                | (
                    Stage::ResponseRecorded,
                    Stage::Observed | Stage::ObservedByProvider
                )
        ) || (matches!(
            (from, to),
            (
                Stage::EntryGranted | Stage::Unknown,
                Stage::ObservedByProvider
            )
        ) && link == Link::Verified)
    }

    /// Which fields each stage's record holds.
    fn fields_match_stage(view: &AttemptView) -> bool {
        let response = !view.response.is_empty();
        let reading = view.reading != Reading::None;
        let shape = match view.stage {
            Stage::NotEntered => view.refusal && !response && !reading && !view.evidence,
            Stage::Reserved | Stage::EntryGranted | Stage::Unknown => {
                !view.refusal && !response && !reading && !view.evidence
            }
            Stage::ResponseRecorded => !view.refusal && response && !reading && !view.evidence,
            Stage::Observed => {
                !view.refusal && response && reading && view.observation && !view.evidence
            }
            Stage::ObservedByProvider => {
                !view.refusal
                    && !reading
                    && view.evidence
                    && view.link != Link::None
                    && (response || view.link == Link::Verified)
            }
        };
        shape
            && (view.locator.is_empty() || response)
            && (matches!(view.stage, Stage::Reserved | Stage::NotEntered) == view.entry.is_empty())
    }

    /// Exhaustive over every stage, link, and reading pair: the closed stage
    /// table.
    #[kani::proof]
    fn stage_transition_allowed_is_the_closed_table() {
        let from = any_stage();
        let to = any_stage();
        let link = any_link();
        assert_eq!(
            stage_transition_allowed(from, to, link),
            table(from, to, link)
        );
        if terminal_stage(from) {
            assert!(!stage_transition_allowed(from, to, link));
        }
    }

    /// Exhaustive over every pair of bounded records (each byte field absent
    /// or one of two values): `valid_transition` holds exactly when the
    /// fixed bytes and plan are kept, the stage change is in the table, the
    /// checkpoint adds pre-entry evidence once, pre-entry evidence is added
    /// only before entry and then kept, the response and locator are added
    /// only with `response-recorded` and then kept, and the new record's
    /// fields match its stage.
    #[kani::proof]
    #[kani::unwind(3)]
    fn valid_transition_agrees_with_the_record_table() {
        let old = any_view();
        let new = any_view();
        let pre_entry = match (old.stage, new.stage) {
            (Stage::Reserved, Stage::Reserved) => {
                old.pre_entry.is_empty() && !new.pre_entry.is_empty()
            }
            (Stage::Reserved, Stage::NotEntered) => {
                old.pre_entry.is_empty() || old.pre_entry == new.pre_entry
            }
            _ => old.pre_entry == new.pre_entry,
        };
        let response = matches!(
            (old.stage, new.stage),
            (
                Stage::EntryGranted | Stage::Unknown,
                Stage::ResponseRecorded
            )
        ) || (old.response == new.response && old.locator == new.locator);
        let entry = if old.stage == Stage::Reserved && new.stage == Stage::EntryGranted {
            old.entry.is_empty() && !new.entry.is_empty()
        } else {
            old.entry == new.entry
        };
        let expected = old.fixed == new.fixed
            && entry
            && fields_match_stage(&old)
            && old.observation == new.observation
            && old.link == new.link
            && table(old.stage, new.stage, old.link)
            && pre_entry
            && response
            && fields_match_stage(&new);
        assert_eq!(valid_transition(&old, &new), expected);
    }
}
