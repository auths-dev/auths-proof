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
//! This module is a translated leaf: closed `Copy` structs, `match`
//! dispatch, one index loop over a slice, and no standard-library call
//! beyond checked addition.

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

#[cfg(test)]
mod tests {
    use super::*;

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
