//! Exact workload and profile membership for a connection entry. Inputs are
//! explicit public record fields; reloads, credential leases and transport
//! entry remain in the runtime.
use crate::construct::{field_index, field_name_equal};
use alloc::vec::Vec;

/// Administrative state projected from the loaded connection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryState {
    /// New entries may pass the workload and profile checks.
    Active,
    /// New entries are disabled.
    Disabled,
    /// The connection has been revoked.
    Revoked,
}

/// The exact profile identifier and version projected from a connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryProfile {
    /// Public profile identifier bytes, without case folding or normalization.
    pub id: Vec<u8>,
    /// Exact profile version; validity of the record is a caller boundary.
    pub version: u16,
}

/// Whether a complete profile identifier and version occur in the list.
/// Empty lists refuse; callers bound collections through record validation.
#[must_use]
pub fn profile_allowed(allowed: &[EntryProfile], requested: &EntryProfile) -> bool {
    let mut index = 0;
    while index < allowed.len() {
        let profile = &allowed[index];
        if profile.version == requested.version && field_name_equal(&profile.id, &requested.id) {
            return true;
        }
        index += 1;
    }
    false
}

/// Allows only active records listing the exact workload and profile/version.
/// This is a necessary entry check, not an execution handle or a lease.
#[must_use]
pub fn entry_allows(
    state: EntryState,
    workloads: &[Vec<u8>],
    profiles: &[EntryProfile],
    workload: &[u8],
    profile: &EntryProfile,
) -> bool {
    match state {
        EntryState::Disabled | EntryState::Revoked => return false,
        EntryState::Active => {}
    }
    match field_index(workloads, workload) {
        None => false,
        Some(_) => profile_allowed(profiles, profile),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entry_projection_matches_complete_membership_for_all_states() {
        let names = [
            b"".to_vec(),
            b"worker".to_vec(),
            b"Worker".to_vec(),
            "worker-é".as_bytes().to_vec(),
        ];
        let profiles: Vec<_> = names
            .iter()
            .flat_map(|id| {
                [0, 1, u16::MAX].map(|version| EntryProfile {
                    id: id.clone(),
                    version,
                })
            })
            .collect();
        for state in [
            EntryState::Active,
            EntryState::Disabled,
            EntryState::Revoked,
        ] {
            for name in &names {
                for requested in &profiles {
                    for workload_count in 0..=names.len() {
                        for profile_count in 0..=profiles.len() {
                            let expected = state == EntryState::Active
                                && names[..workload_count].contains(name)
                                && profiles[..profile_count].contains(requested);
                            assert_eq!(
                                entry_allows(
                                    state,
                                    &names[..workload_count],
                                    &profiles[..profile_count],
                                    name,
                                    requested
                                ),
                                expected
                            );
                        }
                    }
                }
            }
        }
    }
}
