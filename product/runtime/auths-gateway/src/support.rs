//! The redacted archive an operator sends when asking for help.
//!
//! The archive is built from [`SupportFacts`], which has no member that can
//! carry text from a request, a provider, or an operator: every member is a
//! digest, a closed state, a stable code, a count, or a bounded integer. A
//! proof, grant, action, request or response body, credential, credential
//! location, key-manager resource name, provider account or resource
//! identifier, or raw header therefore has no member to arrive through. An
//! attempt appears as the digest that keys it and its stage.

use crate::{GatewayAttemptStage, QualificationStatus};
use serde::Serialize;
use std::collections::BTreeMap;

/// The schema of the archive.
pub const SUPPORT_BUNDLE_SCHEMA: &str = "auths.gateway-support-bundle/1";
/// The most attempts one archive lists.
pub const MAX_SUPPORT_ATTEMPTS: usize = 256;

/// The closed state of the shared connection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportConnectionState {
    /// Entries may start.
    Active,
    /// The operator disabled new entries.
    Disabled,
    /// The connection is revoked.
    Revoked,
}

/// What a serving gateway reported about its connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportConnection {
    /// The record's state.
    pub state: SupportConnectionState,
    /// The record's generation.
    pub generation: u64,
    /// The credential generation the record seals.
    pub credential_generation: u64,
    /// Whether the process holds the secret the record commits to.
    pub credential_held: bool,
    /// The process's in-flight entries.
    pub in_flight: u64,
}

/// Everything an archive is built from. No member holds free text.
#[derive(Clone, Debug)]
pub struct SupportFacts {
    /// SHA-256 of the running executable.
    pub build_sha256: [u8; 32],
    /// The compiled recipe's digest.
    pub recipe_sha256: [u8; 32],
    /// SHA-256 of the installed profile lock.
    pub profile_lock_sha256: [u8; 32],
    /// SHA-256 of the installed trusted context.
    pub trusted_context_sha256: [u8; 32],
    /// Whether the installation is a production deployment.
    pub production: bool,
    /// The credential store in use.
    pub credential_store_kind: auths_connections::CredentialStoreKind,
    /// The qualification gate's state.
    pub qualification: QualificationStatus,
    /// The connection, when a serving gateway answered.
    pub connection: Option<SupportConnection>,
    /// Stored attempts as key digest and stage, at most
    /// [`MAX_SUPPORT_ATTEMPTS`]; `None` when the store could not be read.
    pub attempts: Option<Vec<([u8; 32], GatewayAttemptStage)>>,
    /// Whether the store holds more attempts than were listed.
    pub attempts_truncated: bool,
}

const fn stage_token(stage: GatewayAttemptStage) -> &'static str {
    match stage {
        GatewayAttemptStage::NotEntered => "not-entered",
        GatewayAttemptStage::Attempting => "attempting",
        GatewayAttemptStage::ResponseRecorded => "response-recorded",
        GatewayAttemptStage::Unknown => "unknown",
        GatewayAttemptStage::Observed => "observed",
        GatewayAttemptStage::ObservedByProvider => "observed-by-provider",
    }
}

#[derive(Serialize)]
struct Qualification {
    policy: &'static str,
    state: &'static str,
    code: Option<&'static str>,
}

#[derive(Serialize)]
struct Connection {
    state: &'static str,
    generation: u64,
    credential_generation: u64,
    credential_held: bool,
    in_flight: u64,
}

#[derive(Serialize)]
struct Attempt {
    key_sha256: String,
    stage: &'static str,
}

#[derive(Serialize)]
struct Attempts {
    listed: usize,
    truncated: bool,
    by_stage: BTreeMap<&'static str, u64>,
    identifiers: Vec<Attempt>,
}

#[derive(Serialize)]
struct Archive {
    schema: &'static str,
    gateway_package: &'static str,
    gateway_version: &'static str,
    semantic_closure_sha256: &'static str,
    build_sha256: String,
    recipe_sha256: String,
    profile_lock_sha256: String,
    trusted_context_sha256: String,
    deployment: &'static str,
    credential_store_kind: &'static str,
    qualification: Qualification,
    connection: Option<Connection>,
    attempts: Option<Attempts>,
    codes: Vec<&'static str>,
}

/// Builds the archive: canonical JSON of bounded size.
///
/// # Errors
///
/// Returns `gateway.support.unavailable` when the archive cannot be encoded.
pub fn support_bundle(facts: &SupportFacts) -> Result<Vec<u8>, &'static str> {
    let attempts = facts.attempts.as_ref().map(|listed| {
        let listed = &listed[..listed.len().min(MAX_SUPPORT_ATTEMPTS)];
        let mut by_stage = BTreeMap::new();
        for (_, stage) in listed {
            *by_stage.entry(stage_token(*stage)).or_insert(0_u64) += 1;
        }
        Attempts {
            listed: listed.len(),
            truncated: facts.attempts_truncated,
            by_stage,
            identifiers: listed
                .iter()
                .map(|(key, stage)| Attempt {
                    key_sha256: hex::encode(key),
                    stage: stage_token(*stage),
                })
                .collect(),
        }
    });
    let mut codes: Vec<&'static str> = facts.qualification.code.into_iter().collect();
    if facts.attempts.is_none() {
        codes.push("gateway.support.attempts-unavailable");
    }
    if facts.connection.is_none() {
        codes.push("gateway.support.gateway-not-serving");
    }
    let archive = Archive {
        schema: SUPPORT_BUNDLE_SCHEMA,
        gateway_package: env!("CARGO_PKG_NAME"),
        gateway_version: env!("CARGO_PKG_VERSION"),
        semantic_closure_sha256: crate::GATEWAY_SEMANTIC_CLOSURE_SHA256,
        build_sha256: hex::encode(facts.build_sha256),
        recipe_sha256: hex::encode(facts.recipe_sha256),
        profile_lock_sha256: hex::encode(facts.profile_lock_sha256),
        trusted_context_sha256: hex::encode(facts.trusted_context_sha256),
        deployment: if facts.production {
            "production"
        } else {
            "development"
        },
        credential_store_kind: facts.credential_store_kind.as_str(),
        qualification: Qualification {
            policy: facts.qualification.policy.as_str(),
            state: facts.qualification.state.as_str(),
            code: facts.qualification.code,
        },
        connection: facts.connection.map(|connection| Connection {
            state: match connection.state {
                SupportConnectionState::Active => "active",
                SupportConnectionState::Disabled => "disabled",
                SupportConnectionState::Revoked => "revoked",
            },
            generation: connection.generation,
            credential_generation: connection.credential_generation,
            credential_held: connection.credential_held,
            in_flight: connection.in_flight,
        }),
        attempts,
        codes,
    };
    serde_json_canonicalizer::to_vec(&archive).map_err(|_| "gateway.support.unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QualificationPolicy, QualificationStatus};
    use auths_recipe_qualification::RecipeQualificationState;

    fn facts() -> SupportFacts {
        SupportFacts {
            build_sha256: [1; 32],
            recipe_sha256: [2; 32],
            profile_lock_sha256: [3; 32],
            trusted_context_sha256: [4; 32],
            production: true,
            credential_store_kind: auths_connections::CredentialStoreKind::AwsSecretsManagerV1,
            qualification: QualificationStatus {
                policy: QualificationPolicy::Required,
                state: RecipeQualificationState::Stale,
                code: Some("gateway.qualification.revocation-stale"),
            },
            connection: Some(SupportConnection {
                state: SupportConnectionState::Disabled,
                generation: 7,
                credential_generation: 3,
                credential_held: true,
                in_flight: 0,
            }),
            attempts: Some(vec![
                ([9; 32], GatewayAttemptStage::Unknown),
                ([8; 32], GatewayAttemptStage::ObservedByProvider),
                ([7; 32], GatewayAttemptStage::Unknown),
            ]),
            attempts_truncated: false,
        }
    }

    #[test]
    fn an_archive_holds_digests_closed_states_codes_and_counts() {
        let archive: serde_json::Value =
            serde_json::from_slice(&support_bundle(&facts()).expect("archive")).expect("JSON");
        assert_eq!(archive["schema"], SUPPORT_BUNDLE_SCHEMA);
        assert_eq!(archive["deployment"], "production");
        assert_eq!(archive["credential_store_kind"], "aws-secrets-manager-v1");
        assert_eq!(archive["qualification"]["state"], "stale");
        assert_eq!(archive["connection"]["state"], "disabled");
        assert_eq!(archive["attempts"]["by_stage"]["unknown"], 2);
        assert_eq!(
            archive["attempts"]["identifiers"][1]["key_sha256"],
            "08".repeat(32)
        );
        assert_eq!(
            archive["codes"],
            serde_json::json!(["gateway.qualification.revocation-stale"])
        );
    }

    #[test]
    fn what_could_not_be_read_is_stated_and_the_listing_is_bounded() {
        let mut absent = facts();
        absent.connection = None;
        absent.attempts = None;
        let archive: serde_json::Value =
            serde_json::from_slice(&support_bundle(&absent).expect("archive")).expect("JSON");
        assert!(archive["connection"].is_null() && archive["attempts"].is_null());
        assert_eq!(
            archive["codes"],
            serde_json::json!([
                "gateway.qualification.revocation-stale",
                "gateway.support.attempts-unavailable",
                "gateway.support.gateway-not-serving"
            ])
        );
        let mut many = facts();
        many.attempts = Some(vec![([5; 32], GatewayAttemptStage::NotEntered); 400]);
        many.attempts_truncated = true;
        let bytes = support_bundle(&many).expect("archive");
        let archive: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(archive["attempts"]["listed"], MAX_SUPPORT_ATTEMPTS);
        assert_eq!(archive["attempts"]["truncated"], true);
        assert!(bytes.len() < 64 * 1024, "the archive is bounded");
    }

    /// The facts an archive is built from have no member that holds text,
    /// so nothing a request, provider, or operator wrote can enter one.
    #[test]
    fn the_facts_have_no_free_text_member() {
        let source = include_str!("support.rs");
        let facts = source
            .split("pub struct SupportFacts {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("the facts");
        for forbidden in ["String", "&str", "Vec<u8>", "PathBuf", "Value"] {
            assert!(!facts.contains(forbidden), "the facts hold a {forbidden}");
        }
    }
}
