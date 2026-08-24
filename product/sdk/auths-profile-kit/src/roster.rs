// This canonical roster surface exposes one fail-closed validation error; the
// validator, rather than each accessor, owns the exact rejection reason.
#![allow(clippy::missing_errors_doc)]

use crate::QualificationTarget;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Immutable build-time roster of statically linked domain packages and
/// profile-and-target qualification facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRoster {
    schema: String,
    packages: Vec<ProfileRosterEntry>,
}

/// One statically linked domain package.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileRosterEntry {
    domain: String,
    rust_package: String,
    manifest_path: String,
    profiles: Vec<ProfileRosterProfile>,
}

/// One exact profile's closed launch state and trusted target records.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileRosterProfile {
    profile: String,
    state: ProfileQualification,
    testkit_available: bool,
    targets: Vec<QualificationTarget>,
    qualification_ids: Vec<String>,
}

/// Build-time promotion state for one exact profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileQualification {
    /// Package code may be linked and generated, but no effect route is exposed.
    Unqualified,
    /// Trusted live evidence exists for every listed target.
    Qualified,
}

impl ProfileRoster {
    /// Parses and validates canonical `auths.profile-roster/2` JSON.
    ///
    /// Roster v1 is intentionally unsupported: Auths is prelaunch and cuts
    /// directly to the profile-and-target qualification model.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProfileRosterError> {
        if bytes.is_empty() || bytes.len() > 131_072 {
            return Err(ProfileRosterError::Limit);
        }
        let roster: Self =
            serde_json::from_slice(bytes).map_err(|_| ProfileRosterError::Malformed)?;
        roster.validate()?;
        Ok(roster)
    }

    /// Validates package and profile bounds, paths, ordering, and launch-state
    /// invariants.
    pub fn validate(&self) -> Result<(), ProfileRosterError> {
        if self.schema != "auths.profile-roster/2"
            || self.packages.is_empty()
            || self.packages.len() > 64
        {
            return Err(ProfileRosterError::Unsupported);
        }
        let mut domains = BTreeSet::new();
        let mut packages = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut profiles = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for entry in &self.packages {
            if !lower_token(&entry.domain)
                || entry.rust_package != format!("auths-{}", entry.domain)
                || !safe_relative_path(&entry.manifest_path)
                || entry.profiles.is_empty()
                || entry.profiles.len() > 32
                || previous.is_some_and(|value| value >= entry.domain.as_str())
                || !domains.insert(entry.domain.as_str())
                || !packages.insert(entry.rust_package.as_str())
                || !paths.insert(entry.manifest_path.as_str())
            {
                return Err(ProfileRosterError::InvalidEntry);
            }
            let mut previous_profile: Option<&str> = None;
            for profile in &entry.profiles {
                profile.validate(&entry.domain)?;
                if previous_profile.is_some_and(|value| value >= profile.profile.as_str())
                    || !profiles.insert(profile.profile.as_str())
                {
                    return Err(ProfileRosterError::InvalidProfile);
                }
                previous_profile = Some(&profile.profile);
            }
            let family = &entry.profiles[0];
            if entry.profiles[1..].iter().any(|profile| {
                profile.state != family.state
                    || profile.targets != family.targets
                    || profile.qualification_ids != family.qualification_ids
            }) {
                return Err(ProfileRosterError::InvalidQualification);
            }
            previous = Some(&entry.domain);
        }
        Ok(())
    }

    /// Returns the byte-sorted domain entries.
    #[must_use]
    pub fn packages(&self) -> &[ProfileRosterEntry] {
        &self.packages
    }
}

impl ProfileRosterEntry {
    /// Returns the domain package identifier.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the statically linked Rust package.
    #[must_use]
    pub fn rust_package(&self) -> &str {
        &self.rust_package
    }

    /// Returns the safe repository-relative manifest path.
    #[must_use]
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    /// Returns the exact manifest profile roster.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileRosterProfile] {
        &self.profiles
    }

    /// Finds an exact profile semantic subject.
    #[must_use]
    pub fn profile(&self, semantic_subject: &str) -> Option<&ProfileRosterProfile> {
        self.profiles
            .binary_search_by(|candidate| candidate.profile.as_str().cmp(semantic_subject))
            .ok()
            .map(|index| &self.profiles[index])
    }
}

impl ProfileRosterProfile {
    fn validate(&self, domain: &str) -> Result<(), ProfileRosterError> {
        if !profile_subject(&self.profile, domain) {
            return Err(ProfileRosterError::InvalidProfile);
        }
        match self.state {
            ProfileQualification::Qualified => {
                if self.targets.is_empty()
                    || self.targets.len() > 4
                    || self.targets.len() != self.qualification_ids.len()
                {
                    return Err(ProfileRosterError::InvalidQualification);
                }
                let mut previous_target: Option<QualificationTarget> = None;
                let mut ids = BTreeSet::new();
                for (target, qualification_id) in self.targets.iter().zip(&self.qualification_ids) {
                    if previous_target.is_some_and(|value| value >= *target)
                        || !qualification_id_value(qualification_id)
                        || !ids.insert(qualification_id.as_str())
                    {
                        return Err(ProfileRosterError::InvalidQualification);
                    }
                    previous_target = Some(*target);
                }
            }
            ProfileQualification::Unqualified => {
                if !self.targets.is_empty() || !self.qualification_ids.is_empty() {
                    return Err(ProfileRosterError::InvalidQualification);
                }
            }
        }
        Ok(())
    }

    /// Returns the exact `id/version` semantic subject.
    #[must_use]
    pub fn profile_ref(&self) -> &str {
        &self.profile
    }

    /// Returns the build-time launch state.
    #[must_use]
    pub const fn qualification(&self) -> ProfileQualification {
        self.state
    }

    /// Whether the separate disposable testkit build exposes this profile.
    #[must_use]
    pub const fn testkit_available(&self) -> bool {
        self.testkit_available
    }

    /// Returns the byte-sorted qualified targets.
    #[must_use]
    pub fn targets(&self) -> &[QualificationTarget] {
        &self.targets
    }

    /// Returns qualification IDs parallel to [`Self::targets`].
    #[must_use]
    pub fn qualification_ids(&self) -> &[String] {
        &self.qualification_ids
    }

    /// Returns the qualification ID for an exact target when qualified.
    #[must_use]
    pub fn qualification_id(&self, target: QualificationTarget) -> Option<&str> {
        self.targets
            .binary_search(&target)
            .ok()
            .map(|index| self.qualification_ids[index].as_str())
    }
}

fn lower_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn safe_relative_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\0')
        || value.contains('\\')
    {
        return false;
    }
    value
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn profile_subject(value: &str, domain: &str) -> bool {
    let Some((id, version)) = value.rsplit_once('/') else {
        return false;
    };
    let prefix = format!("auths.{domain}.");
    id.starts_with(&prefix)
        && id.len() <= 128
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        && version
            .parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed.to_string() == version)
}

fn qualification_id_value(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("qlf_") else {
        return false;
    };
    let mut bytes = [0_u8; 32];
    Base64UrlUnpadded::decode(encoded, &mut bytes).is_ok_and(|decoded| {
        decoded.len() == 32 && Base64UrlUnpadded::encode_string(decoded) == encoded
    })
}

/// Closed roster validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProfileRosterError {
    /// Input is empty or exceeds the hard byte limit.
    #[error("profile roster input exceeds its bound")]
    Limit,
    /// JSON cannot be decoded into the closed roster-v2 schema.
    #[error("profile roster JSON is malformed")]
    Malformed,
    /// The only accepted semantic identity is `auths.profile-roster/2`.
    #[error("profile roster semantic identity is unsupported")]
    Unsupported,
    /// A package identity, path, ordering, or uniqueness invariant failed.
    #[error("profile roster package is invalid, duplicate, or unsorted")]
    InvalidEntry,
    /// A profile identity, ordering, or uniqueness invariant failed.
    #[error("profile roster profile is invalid, duplicate, or unsorted")]
    InvalidProfile,
    /// Qualification state does not match its exact targets and evidence IDs.
    #[error("profile roster qualification is invalid")]
    InvalidQualification,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_v2_requires_exact_per_profile_state() {
        let roster = ProfileRoster::from_json(
            br#"{"schema":"auths.profile-roster/2","packages":[{"domain":"postgresql","rustPackage":"auths-postgresql","manifestPath":"product/integrations/auths-postgresql/profile-package.json","profiles":[{"profile":"auths.postgresql.bounded-update/1","state":"unqualified","testkitAvailable":false,"targets":[],"qualificationIds":[]},{"profile":"auths.postgresql.update-preflight/1","state":"unqualified","testkitAvailable":false,"targets":[],"qualificationIds":[]}]},{"domain":"stripe","rustPackage":"auths-stripe","manifestPath":"product/integrations/auths-stripe/profile-package.json","profiles":[{"profile":"auths.stripe.refund/1","state":"unqualified","testkitAvailable":true,"targets":[],"qualificationIds":[]}]}]}"#,
        )
        .unwrap();
        assert_eq!(roster.packages().len(), 2);
        assert_eq!(
            roster.packages()[1].profiles()[0].qualification(),
            ProfileQualification::Unqualified
        );
        assert!(roster.packages()[1].profiles()[0].testkit_available());
    }

    #[test]
    fn roster_v1_is_rejected_without_compatibility_reader() {
        let error =
            ProfileRoster::from_json(br#"{"schema":"auths.profile-roster/1","packages":[]}"#)
                .unwrap_err();
        assert_eq!(error, ProfileRosterError::Unsupported);
    }

    #[test]
    fn unqualified_profile_cannot_carry_attestation_state() {
        let bytes = br#"{"schema":"auths.profile-roster/2","packages":[{"domain":"stripe","rustPackage":"auths-stripe","manifestPath":"product/integrations/auths-stripe/profile-package.json","profiles":[{"profile":"auths.stripe.refund/1","state":"unqualified","testkitAvailable":true,"targets":["linux-x86_64"],"qualificationIds":["qlf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]}]}]}"#;
        assert_eq!(
            ProfileRoster::from_json(bytes),
            Err(ProfileRosterError::InvalidQualification)
        );
    }

    #[test]
    fn atomic_family_cannot_mix_production_qualification_state() {
        let bytes = br#"{"schema":"auths.profile-roster/2","packages":[{"domain":"postgresql","rustPackage":"auths-postgresql","manifestPath":"product/integrations/auths-postgresql/profile-package.json","profiles":[{"profile":"auths.postgresql.bounded-update/1","state":"qualified","testkitAvailable":false,"targets":["linux-x86_64"],"qualificationIds":["qlf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]},{"profile":"auths.postgresql.update-preflight/1","state":"unqualified","testkitAvailable":false,"targets":[],"qualificationIds":[]}]}]}"#;
        assert_eq!(
            ProfileRoster::from_json(bytes),
            Err(ProfileRosterError::InvalidQualification)
        );
    }
}
