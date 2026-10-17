//! The connection record's generation arithmetic and the credential lease
//! rule, as pure leaves.
//!
//! A record carries two generations. `generation` advances on every change.
//! `credential_generation` names the generation at which the current secret
//! was installed or rotated in: install and rotation set both to the new
//! generation, and a state or authorization change advances only
//! `generation`. A local credential store keys each secret by the generation
//! at which it was stored, so a process may lease for a record only the
//! secret stored at exactly `credential_generation`, found as the newest
//! stored generation not after `generation`.
//!
//! These translated leaves use closed structs/enums, scalar decisions and
//! bounded byte/generation loops. They perform no credential or provider I/O.

/// The two generations of one connection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Generations {
    /// Advances on every change of the record.
    pub generation: u64,
    /// The generation of the last install or rotation; never above
    /// `generation`.
    pub credential_generation: u64,
}

/// The generation after `generation`, or `None` when it would overflow.
#[must_use]
pub const fn next_generation(generation: u64) -> Option<u64> {
    generation.checked_add(1)
}

/// A state or authorization change: `generation` advances and the credential
/// generation is kept, because no secret is stored.
#[must_use]
pub const fn state_change(current: Generations) -> Option<Generations> {
    match next_generation(current.generation) {
        Some(generation) => Some(Generations {
            generation,
            credential_generation: current.credential_generation,
        }),
        None => None,
    }
}

/// A rotation: both generations advance to the next generation, at which the
/// new secret is stored.
#[must_use]
pub const fn rotation(current: Generations) -> Option<Generations> {
    match next_generation(current.generation) {
        Some(generation) => Some(Generations {
            generation,
            credential_generation: generation,
        }),
        None => None,
    }
}

/// The newest of `stored` not after `record_generation`: the stored
/// generation whose secret serves a record at `record_generation`.
#[must_use]
pub fn retained_generation(record_generation: u64, stored: &[u64]) -> Option<u64> {
    let mut found = false;
    let mut best = 0;
    let mut index = 0;
    while index < stored.len() {
        let candidate = stored[index];
        if candidate <= record_generation && (!found || candidate > best) {
            found = true;
            best = candidate;
        }
        index += 1;
    }
    if found { Some(best) } else { None }
}

/// The stored generation a lease for a record may use: the retained
/// generation, only when it is the record's credential generation. A process
/// that stores nothing at the credential generation, or that holds a newer
/// unpublished generation, leases nothing.
#[must_use]
#[allow(
    clippy::manual_filter,
    reason = "a translated leaf dispatches with `match`, not a closure"
)]
pub fn lease_generation(
    record_generation: u64,
    credential_generation: u64,
    stored: &[u64],
) -> Option<u64> {
    match retained_generation(record_generation, stored) {
        Some(retained) => {
            if retained == credential_generation {
                Some(retained)
            } else {
                None
            }
        }
        None => None,
    }
}

#[allow(
    clippy::manual_range_contains,
    reason = "explicit scalar comparisons keep this mechanically translated boundary free of RangeInclusive interfaces"
)]
fn lower_tail_valid(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z') || (byte >= b'0' && byte <= b'9') || byte == b'-'
}
/// Whether bytes form a nonempty bounded `[a-z][a-z0-9-]*` token.
/// Oversized buffers refuse before scanning; no string allocation is performed.
#[must_use]
#[allow(
    clippy::manual_range_contains,
    reason = "explicit scalar comparisons keep this mechanically translated boundary free of RangeInclusive interfaces"
)]
pub fn lower_token_valid(value: &[u8], maximum: usize) -> bool {
    if value.is_empty() || value.len() > maximum {
        return false;
    }
    let first = value[0];
    if first < b'a' || first > b'z' {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if !lower_tail_valid(byte) {
            return false;
        }
        index += 1;
    }
    true
}
/// Whether bytes are nonempty, bounded and entirely printable ASCII.
/// NUL, whitespace, control bytes and UTF-8 multibyte sequences refuse.
#[must_use]
#[allow(
    clippy::manual_range_contains,
    reason = "explicit scalar comparisons keep this mechanically translated boundary free of RangeInclusive interfaces"
)]
pub fn ascii_graphic_valid(value: &[u8], maximum: usize) -> bool {
    if value.is_empty() || value.len() > maximum {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if byte < 0x21 || byte > 0x7e {
            return false;
        }
        index += 1;
    }
    true
}

#[allow(
    clippy::manual_range_contains,
    reason = "explicit scalar comparisons keep this mechanically translated boundary free of RangeInclusive interfaces"
)]
fn semantic_head_valid(byte: u8) -> bool {
    (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'0' && byte <= b'9')
}
fn semantic_tail_valid(byte: u8) -> bool {
    semantic_head_valid(byte)
        || byte == b'.'
        || byte == b'_'
        || byte == b':'
        || byte == b'/'
        || byte == b'-'
}
/// Whether bytes form a nonempty bounded `[A-Za-z0-9][A-Za-z0-9._:/-]*` identifier.
/// Oversized input refuses before scanning; no allocation is performed.
#[must_use]
pub fn semantic_id_valid(value: &[u8], maximum: usize) -> bool {
    if value.is_empty() || value.len() > maximum {
        return false;
    }
    if !semantic_head_valid(value[0]) {
        return false;
    }
    let mut index = 0;
    while index < value.len() {
        if !semantic_tail_valid(value[index]) {
            return false;
        }
        index += 1;
    }
    true
}

use crate::model::{ConnectionRecordError, ConnectionState};
/// Authorizes recovery at a positive generation no newer than the record.
/// Revocation takes precedence and always refuses. Zero raw generations refuse
/// even though the typed shipping caller already excludes them.
///
/// # Errors
/// Returns `Revoked` for a tombstone and `InvalidGeneration` for invalid bounds.
pub fn recovery_lease(
    state: ConnectionState,
    record_generation: u64,
    requested_generation: u64,
) -> Result<(), ConnectionRecordError> {
    match state {
        ConnectionState::Revoked => Err(ConnectionRecordError::Revoked),
        ConnectionState::Active | ConnectionState::Disabled => {
            if record_generation == 0
                || requested_generation == 0
                || requested_generation > record_generation
            {
                Err(ConnectionRecordError::InvalidGeneration)
            } else {
                Ok(())
            }
        }
    }
}

/// Which credential commitment a recovery binding must authenticate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryBindingRequirement {
    /// The generation tuple is malformed or inconsistent.
    Refuse,
    /// The operation predates the current credential; use its authenticated record.
    RecordedCommitment,
    /// The operation uses the current credential; compare the current commitment.
    CurrentCommitment,
}

/// Selects which authenticated credential commitment recovery must check.
/// Invalid tuples refuse. An operation before the current credential generation
/// uses its recorded pair; later operations must name the exact current one.
#[must_use]
pub fn recovery_binding_requirement(
    current_credential_generation: u64,
    operation_generation: u64,
    operation_credential_generation: u64,
) -> RecoveryBindingRequirement {
    if current_credential_generation == 0
        || operation_generation == 0
        || operation_credential_generation == 0
        || operation_credential_generation > operation_generation
    {
        return RecoveryBindingRequirement::Refuse;
    }
    if operation_generation >= current_credential_generation {
        if operation_credential_generation == current_credential_generation {
            RecoveryBindingRequirement::CurrentCommitment
        } else {
            RecoveryBindingRequirement::Refuse
        }
    } else {
        RecoveryBindingRequirement::RecordedCommitment
    }
}

/// Allows only a changed administrative state from a non-revoked record at a
/// nondecreasing timestamp. Revocation is a terminal state.
#[must_use]
pub fn state_transition_allows(
    current: ConnectionState,
    next: ConnectionState,
    previous_time: u64,
    proposed_time: u64,
) -> bool {
    if proposed_time < previous_time {
        return false;
    }
    matches!(
        (current, next),
        (
            ConnectionState::Active,
            ConnectionState::Disabled | ConnectionState::Revoked
        ) | (
            ConnectionState::Disabled,
            ConnectionState::Active | ConnectionState::Revoked
        )
    )
}

/// Allows administrative data changes only from a non-revoked record at a
/// nondecreasing timestamp. Rotation and authorization replacement share this rule.
#[must_use]
pub fn record_change_allows(
    state: ConnectionState,
    previous_time: u64,
    proposed_time: u64,
) -> bool {
    match state {
        ConnectionState::Revoked => false,
        ConnectionState::Active | ConnectionState::Disabled => proposed_time >= previous_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original(value: &[u8], maximum: usize) -> bool {
        (1..=maximum).contains(&value.len())
            && value.is_ascii()
            && value.iter().copied().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
            })
    }
    #[test]
    fn original_semantic_grammar_for_all_byte_pairs_and_length_boundaries() {
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let pair = [first, second];
                for length in 0..=2 {
                    for maximum in [0, 1, 2, 128, usize::MAX] {
                        assert_eq!(
                            semantic_id_valid(&pair[..length], maximum),
                            original(&pair[..length], maximum)
                        );
                    }
                }
            }
        }
        for length in [127, 128, 129] {
            let mut value = vec![b'a'; length];
            for index in 0..length {
                for byte in 0..=u8::MAX {
                    value[index] = byte;
                    assert_eq!(semantic_id_valid(&value, 128), original(&value, 128));
                }
                value[index] = b'a';
            }
        }
    }

    fn oracle_lower(value: &[u8], maximum: usize) -> bool {
        (1..=maximum).contains(&value.len())
            && value.is_ascii()
            && value.iter().copied().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase() || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
            })
    }
    #[test]
    fn all_byte_pairs_preserve_the_original_ascii_predicates() {
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let bytes = [first, second];
                for length in 0..=2 {
                    for maximum in [0, 1, 2, 64, usize::MAX] {
                        let value = &bytes[..length];
                        assert_eq!(
                            lower_token_valid(value, maximum),
                            oracle_lower(value, maximum)
                        );
                        let expected = (1..=maximum).contains(&value.len())
                            && value.iter().all(u8::is_ascii_graphic);
                        assert_eq!(ascii_graphic_valid(value, maximum), expected);
                    }
                }
            }
        }
    }
    #[test]
    fn state_changes_keep_and_rotations_set_the_credential_generation() {
        let installed = Generations {
            generation: 1,
            credential_generation: 1,
        };
        let disabled = state_change(installed).expect("disable");
        let enabled = state_change(disabled).expect("enable");
        assert_eq!(
            enabled,
            Generations {
                generation: 3,
                credential_generation: 1
            }
        );
        assert_eq!(
            rotation(enabled),
            Some(Generations {
                generation: 4,
                credential_generation: 4
            })
        );
        let last = Generations {
            generation: u64::MAX,
            credential_generation: 7,
        };
        assert_eq!(state_change(last), None);
        assert_eq!(rotation(last), None);
    }

    #[test]
    fn the_lease_uses_exactly_the_credential_generation() {
        assert_eq!(retained_generation(5, &[]), None);
        assert_eq!(retained_generation(5, &[1, 4, 6]), Some(4));
        assert_eq!(retained_generation(5, &[6, 4, 1]), Some(4));
        assert_eq!(lease_generation(3, 1, &[1]), Some(1));
        assert_eq!(lease_generation(6, 4, &[1, 4]), Some(4));
        assert_eq!(lease_generation(6, 4, &[1]), None, "a stale host");
        assert_eq!(
            lease_generation(6, 4, &[4, 5]),
            None,
            "an unpublished successor"
        );
        assert_eq!(lease_generation(3, 4, &[4]), None);
        assert_eq!(lease_generation(6, 4, &[4, 7]), Some(4));
    }
}
