//! Production custody and qualification: the codes the production gateway
//! adds, and hostile vectors for provider-secret custody, rotation, and
//! redaction.
//!
//! Two fixtures are generated here. `production-codes.json` lists every
//! code the production work adds and every existing code its vectors
//! expect, each with its owner, stage, status, implementing epic, and a
//! producing case. `custody-hostile.json` holds the vectors.
//!
//! Vectors that today's types already decide are driven here: the closed
//! credential-store kind, the secret bound, recipes and submission frames
//! that try to select custody or declare qualification, the fixed
//! retirement delay, and redacted debug forms. The qualification codes are
//! implemented by the gate, whose tests drive every verification vector.
//! The support bundle exists and its own test scans it for every canary of
//! the `redaction` section. Readiness checks and restore floors are implemented
//! and exercised in readiness and engine tests. The secret-name and version
//! vectors are generated here from the stated derivation and driven by the
//! Secrets Manager store's own tests, so the two agree or one of them fails. Those assertions are expected to fail when the implementing work
//! lands, wherever it lands, and that work replaces each with the
//! conformance test that drives its vectors.

#![allow(clippy::too_many_lines, reason = "case tables read top to bottom")]

use super::{apply_mutation, crate_defines_code, crate_sources, load, recipes, require_current};
use crate::{CompiledRecipe, CredentialRetirementDelay};
use auths_connections::{CredentialStoreKind, SecretBytes};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(super) const CODES_FILE: &str = "production-codes.json";
pub(super) const CUSTODY_FILE: &str = "custody-hostile.json";
const CODES_SCHEMA: &str = "auths.gateway-production-codes/1";
const CUSTODY_SCHEMA: &str = "auths.gateway-custody-vectors/1";
const VERIFICATION_FILE: &str = "../qualification/verification-vectors.json";
const SCHEMA_VECTORS_FILE: &str = "../qualification/schema-vectors.json";

const ADAPTER_UNSUPPORTED: &str = "gateway.credential.adapter-unsupported";
const PLAINTEXT_REFUSED: &str = "gateway.credential.production-plaintext-refused";
const CREDENTIAL_UNAVAILABLE: &str = "gateway.credential.unavailable";
const GENERATION_MISSING: &str = "gateway.connection.credential-generation-missing";
const SECRET_NAME_DOMAIN: &str = "auths.gateway-secret-name/1";
const SECRET_VERSION_DOMAIN: &str = "auths.gateway-secret-version/1";

/// One row per code: code, owner, stage, status, epic (`-` for an existing
/// code), and the producing case. A status is `existing` for a code that
/// predates this work, `implemented` for one this work added and a test
/// here drives, and `new` for one still pending.
///
/// Columns: code, owner, stage, status, epic, and the producing case as `<fixture letter>:<case id>` (`-` when
/// no vector can produce it). C is the custody vectors and V the
/// qualification verification vectors.
const ROWS: &[&str] = &[
    "gateway.credential.adapter-unsupported credential-store install-and-serve implemented 2 C:store-kind-vault",
    "gateway.credential.production-plaintext-refused credential-store install-and-serve implemented 2 C:store-kind-local-file",
    "gateway.qualification.missing qualification before-lease implemented 3 V:nothing-attested",
    "gateway.qualification.expired qualification before-lease implemented 3 V:attestation-expired",
    "gateway.qualification.revoked qualification before-lease implemented 3 V:qualification-revoked",
    "gateway.qualification.digest-mismatch qualification before-lease implemented 3 V:wrong-recipe",
    "gateway.qualification.target-mismatch qualification before-lease implemented 3 V:wrong-target-os",
    "gateway.qualification.unavailable qualification before-lease implemented 3 V:index-signature-forged",
    "gateway.qualification.revocation-stale qualification before-lease implemented 3 V:revocation-list-past-next-update",
    "gateway.qualification.clock-untrusted qualification before-lease implemented 3 V:clock-untrusted",
    "gateway.commissioning.unavailable commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.revoked commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.revocation-rollback commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.clock-untrusted commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.revocation-stale commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.expired commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.binding-mismatch commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.store-unavailable commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.registration-missing commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.state-corrupt commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.restore-rollback commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.exhausted commissioning-budget before-custody implemented 5 -",
    "gateway.commissioning.contention commissioning-budget before-custody implemented 5 -",
    "gateway.readiness.connection-disabled readiness doctor implemented 4 -",
    "gateway.readiness.trust-unavailable readiness doctor implemented 4 -",
    "gateway.readiness.store-unavailable readiness doctor implemented 4 -",
    "gateway.readiness.recipe-drift readiness doctor implemented 4 -",
    "gateway.readiness.transport-unavailable readiness doctor implemented 4 -",
    "gateway.readiness.observer-unavailable readiness doctor implemented 4 -",
    "gateway.connection.restore-rollback connection before-lease implemented 4 -",
    "gateway.admin.credential-journal-unavailable operator before-custody implemented 4 -",
    "gateway.support.unavailable support support-bundle implemented 4 -",
    "gateway.support.attempts-unavailable support support-bundle implemented 4 -",
    "gateway.support.connection-unavailable support support-bundle implemented 4 -",
    "gateway.attempt.replay engine recorded existing - C:lease-never-precedes-claim",
    "gateway.connection.credential-generation-missing engine before-claim existing - C:lease-generation-not-held",
    "gateway.credential.unavailable engine recorded existing - C:lease-commitment-mismatch",
    "gateway.install.credential-store-unavailable install install existing - -",
    "gateway.serve.credential-store-unavailable serve serve existing - -",
];

/// Code families the production work introduces whole and that are still
/// pending. Until their epics land, the gateway defines no code under them.
/// The qualification family is implemented: the gate's own tests drive
/// every verification vector through it.
const NEW_FAMILIES: &[&str] = &[];

/// Every hostile class the production work must have a vector for.
const REQUIRED_CLASSES: &[&str] = &[
    "selection",
    "mutable-alias",
    "reference-traversal",
    "unicode-confusion",
    "oversize",
    "extra-field",
    "unknown-enum-member",
    "non-canonical",
    "commitment-mismatch",
    "adapter-timeout",
    "partial-response",
    "expired-lease",
    "debug-serialization",
    "rotation-race",
    "crash-stage",
    "forged",
    "expired",
    "wrong-target",
    "wrong-contract",
    "wrong-credential-store",
    "wrong-signer-kind",
    "wrong-store",
    "wrong-recipe",
    "revoked",
    "signer-signed-root-artifact",
    "future-issued-at",
    "elapsed-next-update",
    "untrusted-clock",
    "widened-time-bound",
    "self-declared-qualification",
    "contract-drift",
    "response-without-read-back",
    "support-bundle-canary",
    "telemetry-canary",
];

fn fixture(letter: &str) -> &'static str {
    match letter {
        "C" => CUSTODY_FILE,
        "V" => VERIFICATION_FILE,
        _ => panic!("unknown fixture letter {letter}"),
    }
}

fn row(text: &str) -> Value {
    let fields: Vec<&str> = text.split(' ').collect();
    let [code, owner, stage, status, epic, case] = fields[..] else {
        panic!("malformed row {text}");
    };
    let epic = (epic != "-").then(|| epic.parse::<u8>().expect("epic"));
    let case = case
        .split_once(':')
        .map(|(letter, id)| json!({"fixture": fixture(letter), "id": id}));
    json!({"code": code, "owner": owner, "stage": stage, "status": status, "epic": epic, "case": case})
}

fn codes_document() -> Value {
    let mut rows: Vec<&str> = ROWS.to_vec();
    rows.sort_unstable();
    json!({"schema": CODES_SCHEMA, "codes": rows.into_iter().map(row).collect::<Vec<_>>()})
}

fn store_kind_cases() -> Vec<Value> {
    let kind = |id: &str,
                class: &str,
                token: &str,
                kind: Option<&str>,
                production: Option<&str>| {
        let development = kind.is_none().then_some(ADAPTER_UNSUPPORTED);
        json!({
            "id": id,
            "class": class,
            "token": token,
            "kind": kind,
            "expect": {"development": {"code": development}, "production": {"code": production}},
        })
    };
    let unknown = |id: &str, class: &str, token: &str| {
        kind(id, class, token, None, Some(ADAPTER_UNSUPPORTED))
    };
    vec![
        kind(
            "store-kind-aws",
            "valid",
            "aws-secrets-manager-v1",
            Some("aws-secrets-manager-v1"),
            None,
        ),
        kind(
            "store-kind-local-file",
            "production-plaintext",
            "local-file-v1",
            Some("local-file-v1"),
            Some(PLAINTEXT_REFUSED),
        ),
        unknown("store-kind-empty", "unknown-enum-member", ""),
        unknown("store-kind-environment", "production-plaintext", "env"),
        unknown("store-kind-dotenv", "production-plaintext", ".env"),
        unknown("store-kind-latest", "mutable-alias", "latest"),
        unknown(
            "store-kind-unversioned",
            "mutable-alias",
            "aws-secrets-manager",
        ),
        unknown(
            "store-kind-later-version",
            "unknown-enum-member",
            "aws-secrets-manager-v2",
        ),
        unknown(
            "store-kind-uppercase",
            "non-canonical",
            "AWS-SECRETS-MANAGER-V1",
        ),
        unknown(
            "store-kind-trailing-space",
            "non-canonical",
            "aws-secrets-manager-v1 ",
        ),
        unknown(
            "store-kind-unicode-hyphen",
            "unicode-confusion",
            "local\u{2010}file\u{2010}v1",
        ),
        unknown("store-kind-vault", "unknown-enum-member", "vault-v1"),
        unknown(
            "store-kind-gcp",
            "unknown-enum-member",
            "gcp-secret-manager-v1",
        ),
        unknown(
            "store-kind-azure",
            "unknown-enum-member",
            "azure-key-vault-v1",
        ),
        unknown(
            "store-kind-testkit",
            "unknown-enum-member",
            "testkit-memory-v1",
        ),
        unknown("store-kind-plugin", "selection", "plugin:./adapter.so"),
        unknown(
            "store-kind-executable",
            "selection",
            "exec:/usr/local/bin/fetch-secret",
        ),
        unknown(
            "store-kind-address",
            "selection",
            "https://secrets.example/v1",
        ),
        unknown(
            "store-kind-traversal",
            "reference-traversal",
            "../credentials.cbor",
        ),
    ]
}

/// `accepted` is whether a credential store takes the secret; `injectable`
/// is whether the transport will put it in a header. A stored secret above
/// the injection bound is never sent.
fn secret_bound_cases() -> Vec<Value> {
    [
        ("secret-empty", 0, false, false),
        ("secret-one-byte", 1, true, true),
        ("secret-at-injection-limit", 4_096, true, true),
        ("secret-over-injection-limit", 4_097, true, false),
        ("secret-at-store-limit", 65_536, true, false),
        ("secret-over-store-limit", 65_537, false, false),
    ]
    .into_iter()
    .map(|(id, bytes, accepted, injectable)| {
        json!({
            "id": id,
            "class": "oversize",
            "bytes": bytes,
            "accepted": accepted,
            "injectable": injectable,
        })
    })
    .collect()
}

fn recipe_selection_cases() -> Vec<Value> {
    let set = |id: &str, class: &str, pointer: &str, value: Value, code: &str| {
        let mut mutation = json!({"op": "set", "pointer": pointer});
        mutation["value"] = value;
        json!({"id": id, "class": class, "mutations": [mutation], "code": code})
    };
    let source = "gateway.recipe.invalid-source";
    vec![
        set(
            "recipe-names-credential-generation",
            "selection",
            "/credential/generation",
            json!(7),
            source,
        ),
        set(
            "recipe-names-credential-store",
            "selection",
            "/credential/store",
            json!("aws-secrets-manager-v1"),
            source,
        ),
        set(
            "recipe-names-secret-location",
            "selection",
            "/credential/secret_location",
            json!("auths-gateway/another-connection"),
            source,
        ),
        set(
            "recipe-names-secret-version",
            "mutable-alias",
            "/credential/version",
            json!("latest"),
            source,
        ),
        set(
            "recipe-names-secret-path",
            "reference-traversal",
            "/credential/path",
            json!("../../another-connection/credentials.cbor"),
            source,
        ),
        set(
            "recipe-bearer-carries-header-member",
            "extra-field",
            "/credential/header",
            json!("X-Credential"),
            source,
        ),
        set(
            "recipe-names-store-at-root",
            "selection",
            "/credential_store",
            json!("local-file-v1"),
            source,
        ),
        set(
            "recipe-names-generation-at-root",
            "selection",
            "/credential_generation",
            json!(1),
            source,
        ),
        set(
            "recipe-injects-authorization-header",
            "selection",
            "/provider_headers/Authorization",
            json!("Bearer injected"),
            "gateway.recipe.invalid-provider-header",
        ),
        set(
            "recipe-declares-qualified",
            "self-declared-qualification",
            "/qualification",
            json!("qualified"),
            source,
        ),
        set(
            "recipe-declares-qualification-state",
            "self-declared-qualification",
            "/qualification_state",
            json!("qualified"),
            source,
        ),
        set(
            "recipe-names-qualification",
            "self-declared-qualification",
            "/qualification_id",
            json!("qlf_00000000000000000000000000000001"),
            source,
        ),
        set(
            "recipe-relaxes-qualification-policy",
            "self-declared-qualification",
            "/qualification_policy",
            json!("optional"),
            source,
        ),
    ]
}

fn frame_selection_cases() -> Vec<Value> {
    [
        (
            "frame-names-credential-generation",
            "credential_generation",
            json!(2),
        ),
        (
            "frame-names-credential-store",
            "credential_store",
            json!("local-file-v1"),
        ),
        (
            "frame-names-secret-location",
            "secret_location",
            json!("auths-gateway/another"),
        ),
        (
            "frame-names-credential-header",
            "credential_header",
            json!("X-Credential"),
        ),
        (
            "frame-names-connection",
            "connection",
            json!("another-connection"),
        ),
        (
            "frame-declares-qualification",
            "qualification_state",
            json!("qualified"),
        ),
        ("frame-supplies-clock", "clock", json!("trusted")),
    ]
    .into_iter()
    .map(|(id, member, value)| {
        let mut case = json!({"id": id, "class": "selection", "member": member, "accepted": false});
        case["value"] = value;
        case
    })
    .collect()
}

/// The internal object name of one credential generation: a fixed prefix
/// and the digest of the deployment namespace, connection, and generation.
fn secret_name(namespace: &str, connection: &str, generation: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(SECRET_NAME_DOMAIN.as_bytes());
    hash.update([0]);
    hash.update(namespace.as_bytes());
    hash.update([0]);
    hash.update(connection.as_bytes());
    hash.update([0]);
    hash.update(generation.to_be_bytes());
    format!("auths-gateway/{}", hex::encode(hash.finalize()))
}

/// The exact external version of one credential generation, bound to the
/// reference commitment the connection record seals.
fn secret_version(connection: &str, generation: u64, commitment: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(SECRET_VERSION_DOMAIN.as_bytes());
    hash.update([0]);
    hash.update(connection.as_bytes());
    hash.update([0]);
    hash.update(generation.to_be_bytes());
    hash.update(commitment);
    hex::encode(hash.finalize())
}

fn secret_name_cases() -> Vec<Value> {
    let first = "conn_AAAAAAAAAAAAAAAAAAAAAA";
    let second = "conn_BBBBBBBBBBBBBBBBBBBBBA";
    [
        (
            "secret-name-first-generation",
            "production-eu-1",
            first,
            1_u64,
            [0x5a_u8; 32],
        ),
        (
            "secret-name-next-generation",
            "production-eu-1",
            first,
            2,
            [0x5b; 32],
        ),
        (
            "secret-name-another-connection",
            "production-eu-1",
            second,
            1,
            [0x5a; 32],
        ),
        (
            "secret-name-another-namespace",
            "staging-eu-1",
            first,
            1,
            [0x5a; 32],
        ),
        (
            "secret-name-another-commitment",
            "production-eu-1",
            first,
            1,
            [0x5c; 32],
        ),
    ]
    .into_iter()
    .map(|(id, namespace, connection, generation, commitment)| {
        json!({
            "id": id,
            "class": "valid",
            "namespace": namespace,
            "connection_id": connection,
            "credential_generation": generation,
            "reference_commitment": hex::encode(commitment),
            "name": secret_name(namespace, connection, generation),
            "version_id": secret_version(connection, generation, &commitment),
        })
    })
    .collect()
}

fn version_reference_cases() -> Vec<Value> {
    let exact = secret_version("conn_AAAAAAAAAAAAAAAAAAAAAA", 1, &[0x5a; 32]);
    let reference = |id: &str, class: &str, reference: &str, accepted: bool| json!({"id": id, "class": class, "reference": reference, "accepted": accepted});
    vec![
        reference("version-exact", "valid", &exact, true),
        reference(
            "version-current-stage",
            "mutable-alias",
            "AWSCURRENT",
            false,
        ),
        reference(
            "version-pending-stage",
            "mutable-alias",
            "AWSPENDING",
            false,
        ),
        reference(
            "version-previous-stage",
            "mutable-alias",
            "AWSPREVIOUS",
            false,
        ),
        reference("version-latest", "mutable-alias", "latest", false),
        reference("version-empty", "mutable-alias", "", false),
        reference(
            "version-uppercase",
            "non-canonical",
            &exact.to_uppercase(),
            false,
        ),
        reference("version-truncated", "non-canonical", &exact[..63], false),
        reference("version-extended", "oversize", &format!("{exact}0"), false),
        reference(
            "version-traversal",
            "reference-traversal",
            &format!("../{}", &exact[..61]),
            false,
        ),
        reference(
            "version-fullwidth-digit",
            "unicode-confusion",
            &format!("\u{ff10}{}", &exact[..63]),
            false,
        ),
    ]
}

fn scenario(id: &str, class: &str, given: &[&str], expect: Value) -> Value {
    let mut case = json!({"id": id, "class": class, "given": given});
    case["expect"] = expect;
    case
}

/// An attempt that was claimed and recorded without entering the provider.
fn not_entered(code: &str) -> Value {
    json!({
        "stage": "not-entered",
        "code": code,
        "provider_entries": 0,
        "fallback_used": false,
        "retried_with_another_generation": false,
    })
}

fn lease_cases() -> Vec<Value> {
    let unavailable = || not_entered(CREDENTIAL_UNAVAILABLE);
    vec![
        scenario(
            "lease-commitment-mismatch",
            "commitment-mismatch",
            &["the stored material differs from the sealed reference commitment"],
            unavailable(),
        ),
        scenario(
            "lease-version-drift",
            "mutable-alias",
            &["the store answers with a version other than the exact one requested"],
            unavailable(),
        ),
        scenario(
            "lease-adapter-timeout",
            "adapter-timeout",
            &["the store does not answer before the lease deadline"],
            unavailable(),
        ),
        scenario(
            "lease-partial-response",
            "partial-response",
            &["the store's response ends before its declared length"],
            unavailable(),
        ),
        scenario(
            "lease-oversize-response",
            "oversize",
            &["the store's response exceeds the response limit"],
            unavailable(),
        ),
        scenario(
            "lease-oversize-secret",
            "oversize",
            &["the stored secret exceeds 65,536 bytes"],
            unavailable(),
        ),
        scenario(
            "lease-expired",
            "expired-lease",
            &["the lease deadline passes before any request byte exists"],
            unavailable(),
        ),
        scenario(
            "lease-store-unreachable-with-local-file",
            "selection",
            &[
                "the production store is unreachable",
                "a local credential file holds a secret for the same connection",
            ],
            unavailable(),
        ),
        scenario(
            "lease-store-unreachable-with-environment-secret",
            "selection",
            &[
                "the production store is unreachable",
                "the process environment holds a provider token",
            ],
            unavailable(),
        ),
        scenario(
            "lease-sealed-generation-revoked-with-successor",
            "selection",
            &[
                "the sealed credential generation is revoked after the claim and before the lease",
                "a newer generation of the same connection is stored",
            ],
            unavailable(),
        ),
        scenario(
            "lease-generation-not-held",
            "commitment-mismatch",
            &[
                "no secret is stored at the sealed credential generation when the attempt is admitted",
            ],
            json!({
                "stage": "refused-before-claim",
                "code": GENERATION_MISSING,
                "leases": 0,
                "provider_entries": 0,
            }),
        ),
        scenario(
            "lease-never-precedes-claim",
            "selection",
            &["the logical operation was already claimed"],
            json!({
                "stage": "not-entered",
                "code": "gateway.attempt.replay",
                "leases": 0,
                "provider_entries": 0,
            }),
        ),
    ]
}

fn rotation_cases() -> Vec<Value> {
    let whole = |generation: &str, stage: &str| {
        json!({
            "stage": stage,
            "generation_used": generation,
            "mixed_generation": false,
            "unauthorized_provider_entries": 0,
        })
    };
    let crashed = |record: &str, serves: &str| {
        json!({
            "record_generation": record,
            "serves": serves,
            "mixed_generation": false,
            "unauthorized_provider_entries": 0,
        })
    };
    vec![
        scenario(
            "rotation-commit-between-reload-and-lease",
            "rotation-race",
            &[
                "an attempt reloads the record at the old generation",
                "the rotation commits before the attempt leases",
            ],
            whole("old", "entered"),
        ),
        scenario(
            "rotation-attempt-after-commit",
            "rotation-race",
            &["the rotation commits", "a new attempt reloads the record"],
            whole("new", "entered"),
        ),
        scenario(
            "rotation-two-instances",
            "rotation-race",
            &[
                "instance A admits an attempt before the commit",
                "instance B admits an attempt after the commit",
            ],
            json!({
                "instance_a": "old",
                "instance_b": "new",
                "mixed_generation": false,
                "unauthorized_provider_entries": 0,
            }),
        ),
        scenario(
            "rotation-old-revoked-before-entry",
            "rotation-race",
            &[
                "the operator revokes the old generation before the retirement delay",
                "an attempt admitted under the old generation has not entered",
            ],
            not_entered(CREDENTIAL_UNAVAILABLE),
        ),
        scenario(
            "rotation-old-revoked-after-entry",
            "rotation-race",
            &[
                "an attempt under the old generation has handed its request to transport",
                "the operator revokes the old generation",
            ],
            whole("old", "entered"),
        ),
        scenario(
            "crash-after-prepare",
            "crash-stage",
            &[
                "the new version is written",
                "the process stops before the commit",
            ],
            crashed("old", "old"),
        ),
        scenario(
            "crash-after-commit",
            "crash-stage",
            &[
                "the shared record commits the new generation",
                "the process stops before retirement",
            ],
            crashed("new", "new"),
        ),
        scenario(
            "crash-during-retirement",
            "crash-stage",
            &[
                "the retirement delay has passed",
                "the process stops while revoking the old version",
            ],
            crashed("new", "new"),
        ),
        scenario(
            "crash-after-install-write",
            "crash-stage",
            &[
                "the first version is written",
                "the process stops before the record is inserted",
            ],
            crashed("none", "none"),
        ),
        scenario(
            "crash-after-revoke",
            "crash-stage",
            &[
                "the operator revokes the connection",
                "the process stops before the store deletes",
            ],
            crashed("revoked", "none"),
        ),
    ]
}

fn retirement_cases() -> Vec<Value> {
    [0_u64, 15, 19, 20, 21]
        .into_iter()
        .map(|elapsed| {
            json!({
                "id": format!("retire-after-{elapsed}-seconds"),
                "class": "rotation-race",
                "seconds_after_commit": elapsed,
                "may_revoke": elapsed >= 20,
            })
        })
        .collect()
}

fn redaction() -> Value {
    let canary = |source: &str| json!({"source": source, "canary": format!("auths-canary-{source}-not-a-secret")});
    let debug =
        |id: &str, text: &str| json!({"id": id, "class": "debug-serialization", "debug": text});
    json!({
        "debug": [
            debug("debug-secret-bytes", "SecretBytes([REDACTED])"),
            debug("debug-stored-secret-lease", "StoredSecretLease([REDACTED])"),
            debug("debug-reference-commitment", "CredentialReferenceCommitment([REDACTED])"),
        ],
        "canaries": {
            "classes": ["support-bundle-canary", "telemetry-canary"],
            "surfaces": ["logs", "traces", "metrics", "support-bundle", "evidence-artifacts"],
            "sources": [
                canary("proof"),
                canary("grant"),
                canary("action"),
                canary("request-body"),
                canary("response-body"),
                canary("credential"),
                canary("external-credential-location"),
                canary("key-manager-resource-name"),
                canary("provider-account-id"),
                canary("provider-resource-id"),
                canary("raw-header"),
            ],
        },
    })
}

fn custody_document() -> Value {
    json!({
        "schema": CUSTODY_SCHEMA,
        "store_kinds": store_kind_cases(),
        "secret_bounds": secret_bound_cases(),
        "recipe_selection": {"base": "stripe", "cases": recipe_selection_cases()},
        "frame_selection": frame_selection_cases(),
        "secret_names": {
            "name_domain": SECRET_NAME_DOMAIN,
            "version_domain": SECRET_VERSION_DOMAIN,
            "cases": secret_name_cases(),
        },
        "version_references": version_reference_cases(),
        "lease": lease_cases(),
        "rotation": rotation_cases(),
        "retirement": {"delay_seconds": 20, "transport_seconds": 15, "cases": retirement_cases()},
        "redaction": redaction(),
    })
}

#[test]
fn production_code_inventory_is_current() {
    require_current(CODES_FILE, &codes_document());
}

#[test]
fn custody_vectors_are_current() {
    require_current(CUSTODY_FILE, &custody_document());
}

#[test]
fn store_kind_vectors_match_the_closed_kind() {
    let corpus = load(CUSTODY_FILE);
    for case in corpus["store_kinds"].as_array().expect("store kinds") {
        let id = case["id"].as_str().expect("id");
        let token = case["token"].as_str().expect("token");
        let parsed = CredentialStoreKind::parse(token).ok();
        assert_eq!(
            json!(parsed.map(CredentialStoreKind::as_str)),
            case["kind"],
            "case {id}"
        );
        // The policy the gateway applies at install and at serve.
        for (policy, production) in [("development", false), ("production", true)] {
            let decided = crate::credential_store_policy(token, production);
            assert_eq!(
                json!(decided.err()),
                case["expect"][policy]["code"],
                "case {id} under {policy} policy"
            );
            assert_eq!(
                decided.ok(),
                parsed.filter(|_| decided.is_ok()),
                "case {id}"
            );
        }
    }
}

#[test]
fn secret_bound_vectors_match_the_secret_type() {
    let corpus = load(CUSTODY_FILE);
    for case in corpus["secret_bounds"].as_array().expect("bounds") {
        let length = usize::try_from(case["bytes"].as_u64().expect("bytes")).expect("length");
        assert_eq!(
            json!(SecretBytes::new(vec![b'x'; length]).is_ok()),
            case["accepted"],
            "case {}",
            case["id"]
        );
        assert_eq!(
            json!((1..=crate::transport::MAX_SECRET_BYTES).contains(&length)),
            case["injectable"],
            "case {}",
            case["id"]
        );
    }
}

/// A recipe cannot name a credential generation, store, location, or
/// version, cannot add `Authorization` as a provider header, and cannot
/// declare itself qualified. Which header carries the credential is the
/// recipe's own committed declaration; the recipe corpus holds the cases
/// that refuse a reserved header there.
#[test]
fn recipes_cannot_select_custody_or_declare_qualification() {
    let corpus = load(CUSTODY_FILE);
    let selection = &corpus["recipe_selection"];
    let base = &load(recipes::FILE)["bases"][selection["base"].as_str().expect("base")];
    for case in selection["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        let mut recipe = base["recipe"].clone();
        for mutation in case["mutations"].as_array().expect("mutations") {
            apply_mutation(&mut recipe, mutation);
        }
        let refused = CompiledRecipe::compile(
            &serde_json::to_vec(&recipe).expect("recipe"),
            &serde_json::to_vec(&base["lock"]).expect("lock"),
        )
        .expect_err(id);
        assert_eq!(refused.code(), case["code"], "case {id}");
    }
}

/// A submission frame carries a proof and an action and nothing else.
#[cfg(unix)]
#[test]
fn submission_frames_cannot_select_custody() {
    use crate::app::{APP_REQUEST_SCHEMA, AppSubmission};
    let corpus = load(CUSTODY_FILE);
    let base = json!({"schema": APP_REQUEST_SCHEMA, "proof_b64": "AA", "action_b64": "AA"});
    assert!(serde_json::from_value::<AppSubmission>(base.clone()).is_ok());
    for case in corpus["frame_selection"].as_array().expect("frames") {
        let mut frame = base.clone();
        frame[case["member"].as_str().expect("member")] = case["value"].clone();
        assert_eq!(
            json!(serde_json::from_value::<AppSubmission>(frame).is_ok()),
            case["accepted"],
            "case {}",
            case["id"]
        );
    }
}

#[test]
fn retirement_vectors_match_the_fixed_delay() {
    let corpus = load(CUSTODY_FILE);
    let retirement = &corpus["retirement"];
    let delay = CredentialRetirementDelay::FIXED.as_duration().as_secs();
    assert_eq!(retirement["delay_seconds"], delay);
    assert_eq!(
        retirement["transport_seconds"],
        crate::MAX_TRANSPORT_DURATION.as_secs()
    );
    let committed_at = 1_790_000_000_u64;
    let earliest = CredentialRetirementDelay::FIXED
        .earliest_revocation(committed_at)
        .expect("representable");
    for case in retirement["cases"].as_array().expect("cases") {
        let elapsed = case["seconds_after_commit"].as_u64().expect("elapsed");
        assert_eq!(
            json!(committed_at + elapsed >= earliest),
            case["may_revoke"],
            "case {}",
            case["id"]
        );
    }
}

/// The debug form of every secret-bearing type is the fixed redacted text.
#[tokio::test]
async fn secret_debug_forms_are_redacted() {
    use auths_connections::{
        ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionProfile,
        ConnectionRecord, ConnectionState, InMemoryCredentialStore, ProviderKind, SemanticId,
    };
    use std::num::NonZeroU64;
    use std::time::{Duration, Instant};

    let canary = b"auths-canary-credential-not-a-secret";
    let store = InMemoryCredentialStore::new(1, 1_024).expect("store");
    let connection_id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
    let generation = NonZeroU64::MIN;
    let commitment = store
        .install(
            &connection_id,
            generation,
            SecretBytes::new(canary.to_vec()).expect("secret"),
        )
        .await
        .expect("install");
    let profile =
        ConnectionProfile::new(SemanticId::parse("auths.mcp").expect("id"), 2).expect("profile");
    let record = ConnectionRecord::new(
        ProviderKind::parse("example").expect("provider"),
        ConnectionAlias::parse("default").expect("alias"),
        connection_id,
        SemanticId::parse("auths.gateway-operation/1").expect("contract"),
        SemanticId::parse("auths.gateway-connection-descriptor/1").expect("schema"),
        b"descriptor".to_vec(),
        [2; 32],
        *commitment.as_bytes(),
        generation,
        ConnectionState::Active,
        vec!["gateway".to_owned()],
        vec![profile],
        10,
        10,
        None,
    )
    .expect("record");
    let binding = record
        .binding_for_recovery(generation, generation, commitment)
        .expect("binding");
    let lease = store
        .lease_secret(
            &binding.credential(),
            Instant::now() + Duration::from_secs(30),
        )
        .await
        .expect("lease");
    let forms = [
        format!("{:?}", SecretBytes::new(canary.to_vec()).expect("secret")),
        format!("{lease:?}"),
        format!("{commitment:?}"),
    ];
    let corpus = load(CUSTODY_FILE);
    let expected = corpus["redaction"]["debug"].as_array().expect("debug");
    assert_eq!(forms.len(), expected.len());
    for (form, case) in forms.iter().zip(expected) {
        assert_eq!(
            form,
            case["debug"].as_str().expect("debug"),
            "case {}",
            case["id"]
        );
        assert!(!form.contains("canary"), "case {}", case["id"]);
    }
}

/// Every string under a `code` key anywhere in `value`.
fn expected_codes(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, member) in object {
                if let ("code", Value::String(code)) = (key.as_str(), member) {
                    found.insert(code.clone());
                }
                expected_codes(member, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| expected_codes(item, found)),
        _ => {}
    }
}

/// The first object anywhere in `value` whose `id` is `id`.
fn find_case<'value>(value: &'value Value, id: &str) -> Option<&'value Value> {
    match value {
        Value::Object(object) if object.get("id").and_then(Value::as_str) == Some(id) => {
            Some(value)
        }
        Value::Object(object) => object.values().find_map(|member| find_case(member, id)),
        Value::Array(items) => items.iter().find_map(|item| find_case(item, id)),
        _ => None,
    }
}

/// Every string under a `class` key, and every member of a `classes` list,
/// anywhere in `value`.
fn classes(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, member) in object {
                match (key.as_str(), member) {
                    ("class", Value::String(class)) => {
                        found.insert(class.clone());
                    }
                    ("classes", Value::Array(listed)) => {
                        found.extend(listed.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                    _ => classes(member, found),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| classes(item, found)),
        _ => {}
    }
}

/// Every Rust source file of every product crate, outside test-vector
/// modules. The adapter, the verifier, and the operator commands may land in
/// any product crate, so the shortfall is asserted over all of them.
fn product_sources() -> Vec<(PathBuf, String)> {
    fn walk(directory: &Path, found: &mut Vec<(PathBuf, String)>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("source directory")
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path.file_name().and_then(|name| name.to_str());
            if path.is_dir() {
                if !matches!(name, Some("pending_vectors" | "vectors" | "target")) {
                    walk(&path, found);
                }
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path).expect("source text");
                found.push((path, text));
            }
        }
    }
    let mut found = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
        &mut found,
    );
    found
}

#[test]
fn every_hostile_class_has_a_vector() {
    let mut found = BTreeSet::new();
    for name in [CUSTODY_FILE, VERIFICATION_FILE, SCHEMA_VECTORS_FILE] {
        classes(&load(name), &mut found);
    }
    let missing: Vec<&&str> = REQUIRED_CLASSES
        .iter()
        .filter(|class| !found.contains(**class))
        .collect();
    assert!(
        missing.is_empty(),
        "hostile classes without a vector: {missing:?}"
    );
}

/// The inventory is closed over the vectors, every existing code exists,
/// and the rest of the production work has not landed: no product crate
/// defines a new code or a code under a new family. The secret-name and version vectors
/// are no longer pending: the Secrets Manager store derives them, and its
/// own tests drive `secret_names` and `version_references`.
#[test]
fn production_codes_await_their_epics() {
    let inventory = load(CODES_FILE);
    let gateway = crate_sources();
    let all = product_sources();
    let mut listed = BTreeSet::new();
    for entry in inventory["codes"].as_array().expect("codes") {
        let code = entry["code"].as_str().expect("code");
        assert!(listed.insert(code.to_owned()), "duplicate {code}");
        match entry["status"].as_str().expect("status") {
            "existing" | "implemented" => {
                assert!(crate_defines_code(&gateway, code), "{code} is missing");
            }
            "new" => assert!(
                !crate_defines_code(&all, code),
                "{code} now exists: replace its pending vectors with conformance tests"
            ),
            status => panic!("unknown status {status}"),
        }
        if let Some(case) = entry["case"].as_object() {
            let fixture = load(case["fixture"].as_str().expect("fixture"));
            let id = case["id"].as_str().expect("id");
            let found = find_case(&fixture, id).expect("named case");
            let mut produced = BTreeSet::new();
            expected_codes(found, &mut produced);
            assert!(produced.contains(code), "{code} is not produced by {id}");
        }
    }
    let mut expected = BTreeSet::new();
    for name in [CUSTODY_FILE, VERIFICATION_FILE] {
        expected_codes(&load(name), &mut expected);
    }
    // Recipe compile codes belong to the recipe corpus's own inventory.
    expected.retain(|code| !code.starts_with("gateway.recipe."));
    let missing: Vec<_> = expected.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "codes without an inventory entry: {missing:?}"
    );
    for (path, text) in &all {
        for marker in NEW_FAMILIES {
            assert!(
                !text.contains(&format!("\"{marker}")),
                "{} defines a code under {marker}: drive the pending vectors through it",
                path.display()
            );
        }
    }
}
