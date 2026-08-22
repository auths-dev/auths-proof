//! Structured generated launch-state projection for built-in profiles.
//!
//! Generated Rust routes are invariant across qualification import. Only this
//! bounded canonical data projection changes, and release tooling normalizes
//! its launch fields when recomputing the attested semantic closure.

use crate::local_agent::LocalAgentFailure;
use auths_production_client::ProfileQualificationAdvertisement;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::OnceLock};

const PROJECTION: &[u8] = include_bytes!("generated/profile_launch_projection.json");
const SCHEMA: &str = "auths.profile-launch-projection/1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchProjection {
    schema: String,
    profiles: Vec<LaunchProfile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LaunchProfile {
    profile: String,
    state: LaunchState,
    testkit_available: bool,
    targets: Vec<String>,
    qualification_ids: Vec<String>,
    semantic_closure_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchFlavor {
    Production,
    #[cfg(feature = "qualification-failpoints")]
    Qualification,
    #[cfg(any(test, feature = "testkit-agent"))]
    Testkit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum LaunchState {
    Qualified,
    Unqualified,
}

impl LaunchProfile {
    pub(crate) fn available_for(&self, flavor: LaunchFlavor) -> bool {
        match flavor {
            LaunchFlavor::Production if self.state == LaunchState::Qualified => current_target()
                .is_some_and(|target| self.targets.iter().any(|value| value == target)),
            #[cfg(feature = "qualification-failpoints")]
            LaunchFlavor::Qualification => true,
            #[cfg(any(test, feature = "testkit-agent"))]
            LaunchFlavor::Testkit => self.testkit_available,
            _ => false,
        }
    }

    pub(crate) fn qualification_for(
        &self,
        flavor: LaunchFlavor,
    ) -> Result<Option<ProfileQualificationAdvertisement>, LocalAgentFailure> {
        if flavor != LaunchFlavor::Production
            || !self.available_for(flavor)
            || self.state != LaunchState::Qualified
        {
            return Ok(None);
        }
        let target = current_target().ok_or(LocalAgentFailure::InvalidConfiguration)?;
        let index = self
            .targets
            .iter()
            .position(|value| value == target)
            .ok_or(LocalAgentFailure::InvalidConfiguration)?;
        let closure: [u8; 32] = hex::decode(
            self.semantic_closure_sha256
                .as_deref()
                .ok_or(LocalAgentFailure::InvalidConfiguration)?,
        )
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?
        .try_into()
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
        ProfileQualificationAdvertisement::new(
            self.qualification_ids[index].clone(),
            target,
            closure,
        )
        .map(Some)
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)
    }
}

pub(crate) fn launch_profile(profile: &str) -> Result<&'static LaunchProfile, LocalAgentFailure> {
    let projection = projection()?;
    projection
        .profiles
        .binary_search_by(|entry| entry.profile.as_str().cmp(profile))
        .map(|index| &projection.profiles[index])
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)
}

pub(crate) fn validate_exact_profiles(expected: &[&str]) -> Result<(), LocalAgentFailure> {
    let projection = projection()?;
    if projection.profiles.len() == expected.len()
        && projection
            .profiles
            .iter()
            .map(|entry| entry.profile.as_str())
            .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(LocalAgentFailure::InvalidConfiguration)
    }
}

fn projection() -> Result<&'static LaunchProjection, LocalAgentFailure> {
    static VALUE: OnceLock<Result<LaunchProjection, ()>> = OnceLock::new();
    VALUE
        .get_or_init(|| parse_projection().map_err(|_| ()))
        .as_ref()
        .map_err(|()| LocalAgentFailure::InvalidConfiguration)
}

fn parse_projection() -> Result<LaunchProjection, LocalAgentFailure> {
    parse_projection_bytes(PROJECTION)
}

fn parse_projection_bytes(bytes: &[u8]) -> Result<LaunchProjection, LocalAgentFailure> {
    let value: LaunchProjection =
        serde_json::from_slice(bytes).map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| LocalAgentFailure::InvalidConfiguration)?;
    if bytes != [canonical.as_slice(), b"\n"].concat()
        || value.schema != SCHEMA
        || value.profiles.is_empty()
        || value.profiles.len() > 64
        || !value
            .profiles
            .windows(2)
            .all(|pair| pair[0].profile < pair[1].profile)
        || value.profiles.iter().any(|entry| !entry.valid())
    {
        return Err(LocalAgentFailure::InvalidConfiguration);
    }
    Ok(value)
}

impl LaunchProfile {
    fn valid(&self) -> bool {
        let targets_valid = self.targets.len() <= 4
            && self.targets.len() == self.qualification_ids.len()
            && self.targets.windows(2).all(|pair| pair[0] < pair[1])
            && self.targets.iter().all(|target| {
                matches!(
                    target.as_str(),
                    "linux-x86_64" | "linux-aarch64" | "macos-x86_64" | "macos-aarch64"
                )
            })
            && self.qualification_ids.iter().collect::<BTreeSet<_>>().len()
                == self.qualification_ids.len();
        let qualified = !self.targets.is_empty()
            && self.semantic_closure_sha256.as_deref().is_some_and(digest)
            && self
                .qualification_ids
                .iter()
                .all(|value| qualification_id(value));
        semantic_subject(&self.profile)
            && targets_valid
            && match self.state {
                LaunchState::Qualified => qualified,
                LaunchState::Unqualified => {
                    self.targets.is_empty()
                        && self.qualification_ids.is_empty()
                        && self.semantic_closure_sha256.is_none()
                }
            }
    }
}

fn semantic_subject(value: &str) -> bool {
    if value.len() > 134 || !value.is_ascii() {
        return false;
    }
    let Some((id, version)) = value.rsplit_once('/') else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index != 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
        && version.len() <= 5
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && !version.starts_with('0')
}

fn qualification_id(value: &str) -> bool {
    value.len() == 47
        && value.starts_with("qlf_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

const fn current_target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux-x86_64")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("linux-aarch64")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("macos-x86_64")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("macos-aarch64")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_line(value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = serde_json_canonicalizer::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn profile(profile: &str) -> serde_json::Value {
        serde_json::json!({
            "profile": profile,
            "qualificationIds": [],
            "semanticClosureSha256": null,
            "state": "unqualified",
            "targets": [],
            "testkitAvailable": false,
        })
    }

    fn fixture(profiles: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({"profiles": profiles, "schema": SCHEMA})
    }

    #[test]
    fn checked_projection_is_canonical_exact_and_flavor_separated() {
        validate_exact_profiles(&[
            "auths.opentofu.plan-preflight/1",
            "auths.opentofu.saved-plan-apply/1",
            "auths.postgresql.bounded-update/1",
            "auths.postgresql.update-preflight/1",
            "auths.stripe.refund/1",
        ])
        .unwrap();
        let stripe = launch_profile("auths.stripe.refund/1").unwrap();
        assert!(!stripe.available_for(LaunchFlavor::Production));
        #[cfg(feature = "qualification-failpoints")]
        assert!(stripe.available_for(LaunchFlavor::Qualification));
        assert!(stripe.available_for(LaunchFlavor::Testkit));
        assert!(launch_profile("auths.unknown.effect/1").is_err());
        assert!(validate_exact_profiles(&["auths.stripe.refund/1"]).is_err());

        let testkit = fixture(vec![serde_json::json!({
            "profile": "auths.example.effect/1",
            "qualificationIds": [],
            "semanticClosureSha256": null,
            "state": "unqualified",
            "targets": [],
            "testkitAvailable": true,
        })]);
        let parsed = parse_projection_bytes(&canonical_line(&testkit)).unwrap();
        assert!(!parsed.profiles[0].available_for(LaunchFlavor::Production));
        assert!(parsed.profiles[0].available_for(LaunchFlavor::Testkit));

        let qualified_testkit = fixture(vec![serde_json::json!({
            "profile": "auths.example.effect/1",
            "qualificationIds": [format!("qlf_{}", "A".repeat(43))],
            "semanticClosureSha256": "a".repeat(64),
            "state": "qualified",
            "targets": [current_target().unwrap_or("linux-x86_64")],
            "testkitAvailable": true,
        })]);
        let parsed = parse_projection_bytes(&canonical_line(&qualified_testkit)).unwrap();
        assert!(
            parsed.profiles[0]
                .qualification_for(LaunchFlavor::Testkit)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn projection_parser_rejects_hostile_shape_and_order() {
        let valid = fixture(vec![profile("auths.example.effect/1")]);
        assert!(parse_projection_bytes(&canonical_line(&valid)).is_ok());

        let mut noncanonical = canonical_line(&valid);
        noncanonical.insert(0, b' ');
        assert!(parse_projection_bytes(&noncanonical).is_err());

        let mut unknown = valid.clone();
        unknown["profiles"][0]["unknown"] = serde_json::json!(true);
        assert!(parse_projection_bytes(&canonical_line(&unknown)).is_err());

        let reordered = fixture(vec![
            profile("auths.example.second/1"),
            profile("auths.example.first/1"),
        ]);
        assert!(parse_projection_bytes(&canonical_line(&reordered)).is_err());

        let maximum = (0..64)
            .map(|index| profile(&format!("auths.example.effect{index:02}/1")))
            .collect::<Vec<_>>();
        assert!(parse_projection_bytes(&canonical_line(&fixture(maximum.clone()))).is_ok());
        let mut too_many = maximum;
        too_many.push(profile("auths.example.effect64/1"));
        assert!(parse_projection_bytes(&canonical_line(&fixture(too_many))).is_err());

        let mut duplicate_id = serde_json::json!({
            "profile": "auths.example.effect/1",
            "qualificationIds": [format!("qlf_{}", "A".repeat(43)), format!("qlf_{}", "A".repeat(43))],
            "semanticClosureSha256": "a".repeat(64),
            "state": "qualified",
            "targets": ["linux-aarch64", "linux-x86_64"],
            "testkitAvailable": false,
        });
        assert!(
            parse_projection_bytes(&canonical_line(&fixture(vec![duplicate_id.clone()]))).is_err()
        );
        duplicate_id.as_object_mut().unwrap().remove("state");
        assert!(parse_projection_bytes(&canonical_line(&fixture(vec![duplicate_id]))).is_err());
    }
}
