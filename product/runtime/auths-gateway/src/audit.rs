//! Offline audit of gateway submissions.
//!
//! An audit bundle carries, for each submitted operation, the exact proof and
//! canonical action the application sent and, when the gateway had a record,
//! the gateway-signed outcome observation. The bundle also carries the
//! installed recipe, profile lock, and trusted context. The auditor pins the
//! trusted context by digest and the observer by principal; nothing in the
//! bundle can replace either pin.
//!
//! Each entry is re-verified with the gateway's own verifier and bounded-
//! policy admission at the time the gateway signed its outcome (or, without
//! an outcome, at the start of the approvals' validity), which derives the
//! count and sum counters of its links in that fixed window. The bounds are
//! then recounted without any order: the gateway gave each entered entry a
//! distinct slot below its capacity, which is possible exactly when, for
//! every capacity value k, at most k entered entries have a capacity of at
//! most k; and it kept a sum within every capacity, which is possible
//! exactly when the arguments of the entered entries with a capacity of at
//! most k sum to at most k. No socket, provider, or gateway state is
//! touched.
//!
//! An entry is `verified` when the auditor admits it and the gateway signed an
//! entered outcome for its exact action commitment; `refused` when the auditor
//! refuses it (with the gateway's stable code) and the gateway recorded no
//! entry; and `inconsistent` when the two disagree or the evidence does not
//! verify. Any inconsistent entry means the bundle was altered or the gateway
//! entered a provider without authority.
//!
//! A bundle may also carry the remote approval responses the application
//! collected, including declines for operations never submitted. They are
//! decoded and listed as recorded, so the report shows who approved and who
//! declined; they never change a verdict. Only the verified proof counts an
//! approval, and a decline's signature carries no authority.

use crate::bounds::BoundAdmission;
use crate::engine::{GatewaySubmitResult, verify_detailed};
use crate::observer::{VerifiedOutcome, operation_subject, verify_outcome};
use crate::{CompiledRecipe, LogicalOperationId};
use auths_model::{PrincipalId, TrustedContext, VerifierLimits};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Schema of an audit bundle.
pub const AUDIT_BUNDLE_SCHEMA: &str = "auths.gateway-audit-bundle/1";
/// Schema of an audit report.
pub const AUDIT_REPORT_SCHEMA: &str = "auths.gateway-audit-report/1";
/// Largest audit bundle, in bytes.
pub const MAX_AUDIT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
/// Largest number of entries one bundle may carry.
pub const MAX_AUDIT_ENTRIES: usize = 4_096;
/// Largest number of approval responses one bundle may carry.
pub const MAX_AUDIT_APPROVAL_RESPONSES: usize = 16 * MAX_AUDIT_ENTRIES;

const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTION_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECIPE_BYTES: usize = 65_536;

/// Out-of-band facts the auditor trusts; the bundle never supplies them.
#[derive(Clone, Debug)]
pub struct AuditPins {
    /// SHA-256 of the installed trusted context, as the operator published it.
    pub trusted_context_sha256: [u8; 32],
    /// The gateway observer principal whose signature outcomes must carry.
    pub observer: PrincipalId,
}

/// Per-entry audit status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditStatus {
    /// Authorized, inside every bound, and entered by the gateway.
    Verified,
    /// Refused with a stable code, and never entered by the gateway.
    Refused,
    /// The evidence does not verify or disagrees with the gateway's record.
    Inconsistent,
}

/// One audited entry.
#[derive(Clone, Debug, Serialize)]
pub struct AuditedEntry {
    /// The logical operation ID the bundle names.
    pub operation_id: String,
    /// The audit status.
    pub status: AuditStatus,
    /// `audit.verified`, a gateway refusal code, or an `audit.*` finding.
    pub code: String,
    /// Actors of the authorized branches when the proof verified.
    pub approvals: Vec<String>,
    /// Verified action arguments when the proof verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Map<String, Value>>,
    /// The stage the gateway signed, when a verified outcome is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_stage: Option<String>,
    /// The gateway clock time the entry was evaluated at.
    pub evaluated_at: u64,
}

/// One recorded approval response, as decoded from the bundle.
#[derive(Clone, Debug, Serialize)]
pub struct AuditedApprovalResponse {
    /// The logical operation ID the bundle names for the response.
    pub operation_id: String,
    /// The answering approver.
    pub approver: String,
    /// `approve` or `decline`.
    pub decision: &'static str,
    /// The decision time a decline records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<u64>,
}

/// A complete offline audit.
#[derive(Clone, Debug, Serialize)]
pub struct AuditReport {
    /// [`AUDIT_REPORT_SCHEMA`].
    pub schema: &'static str,
    /// The pinned trusted-context digest, lowercase hexadecimal.
    pub trusted_context_sha256: String,
    /// The installed recipe digest the bundle carries.
    pub recipe_digest: String,
    /// The pinned observer principal.
    pub observer: String,
    /// Entries in bundle order.
    pub entries: Vec<AuditedEntry>,
    /// Recorded approval responses in bundle order; they never change a verdict.
    pub approval_responses: Vec<AuditedApprovalResponse>,
    /// Number of verified entries.
    pub verified: usize,
    /// Number of refused entries.
    pub refused: usize,
    /// Number of inconsistent entries.
    pub inconsistent: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleSource {
    schema: String,
    recipe_b64: String,
    profile_lock_b64: String,
    trusted_context_b64: String,
    entries: Vec<EntrySource>,
    #[serde(default)]
    approval_responses: Vec<ResponseSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseSource {
    operation_id: String,
    response: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntrySource {
    operation_id: String,
    proof_b64: String,
    action_b64: String,
    #[serde(default)]
    outcome_b64: Option<String>,
}

fn decode(text: &str, maximum: usize) -> Option<Vec<u8>> {
    if text.len() > maximum.div_ceil(3) * 4 {
        return None;
    }
    Base64UrlUnpadded::decode_vec(text)
        .ok()
        .filter(|bytes| !bytes.is_empty() && bytes.len() <= maximum)
}

fn refusal_code(result: GatewaySubmitResult) -> String {
    match result {
        GatewaySubmitResult::Denied { code }
        | GatewaySubmitResult::Indeterminate { code }
        | GatewaySubmitResult::NotEntered { code } => code,
        GatewaySubmitResult::Unknown
        | GatewaySubmitResult::ResponseRecorded { .. }
        | GatewaySubmitResult::Observed { .. }
        | GatewaySubmitResult::ObservedByProvider { .. } => "audit.unexpected-result".to_owned(),
    }
}

/// Start of the approvals' validity, the evaluation time of an entry the
/// gateway never recorded.
fn validity_start(proof: &[u8]) -> u64 {
    auths_codec::decode_bundle(proof, &VerifierLimits::default())
        .ok()
        .and_then(|bundle| {
            bundle
                .actions()
                .iter()
                .map(|action| action.envelope().validity().not_before().get())
                .max()
        })
        .unwrap_or(0)
}

struct Pending {
    entry: AuditedEntry,
    outcome: Option<VerifiedOutcome>,
    bound: Option<BoundAdmission>,
    commitment: Option<String>,
}

fn finding(operation_id: &str, code: &str, evaluated_at: u64) -> Pending {
    Pending {
        entry: AuditedEntry {
            operation_id: operation_id.to_owned(),
            status: AuditStatus::Inconsistent,
            code: code.to_owned(),
            approvals: Vec::new(),
            arguments: None,
            gateway_stage: None,
            evaluated_at,
        },
        outcome: None,
        bound: None,
        commitment: None,
    }
}

/// Audits one bundle offline.
///
/// # Errors
/// Refuses the whole bundle with a stable code when it is oversized,
/// malformed, carries a trusted context other than the pinned one, or a
/// recipe that does not compile. Per-entry problems are reported in the
/// returned report, never as an error.
pub fn audit_bundle(bytes: &[u8], pins: &AuditPins) -> Result<AuditReport, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_AUDIT_BUNDLE_BYTES {
        return Err("audit.bundle-invalid-size");
    }
    let source: BundleSource =
        serde_json::from_slice(bytes).map_err(|_| "audit.bundle-malformed")?;
    if source.schema != AUDIT_BUNDLE_SCHEMA
        || source.entries.len() > MAX_AUDIT_ENTRIES
        || source.approval_responses.len() > MAX_AUDIT_APPROVAL_RESPONSES
    {
        return Err("audit.bundle-malformed");
    }
    let approval_responses = source
        .approval_responses
        .iter()
        .map(recorded_response)
        .collect::<Option<Vec<_>>>()
        .ok_or("audit.bundle-malformed")?;
    let trust =
        decode(&source.trusted_context_b64, MAX_CONTEXT_BYTES).ok_or("audit.bundle-malformed")?;
    let digest: [u8; 32] = Sha256::digest(&trust).into();
    if digest != pins.trusted_context_sha256 {
        return Err("audit.trust-pin-mismatch");
    }
    let context: TrustedContext =
        auths_codec::decode_verifier_context(&trust).map_err(|_| "audit.trust-invalid")?;
    let recipe = CompiledRecipe::compile(
        &decode(&source.recipe_b64, MAX_RECIPE_BYTES).ok_or("audit.bundle-malformed")?,
        &decode(&source.profile_lock_b64, MAX_RECIPE_BYTES).ok_or("audit.bundle-malformed")?,
    )
    .map_err(|_| "audit.recipe-invalid")?;

    let mut seen = BTreeSet::new();
    let mut pending = Vec::with_capacity(source.entries.len());
    for entry in &source.entries {
        pending.push(audit_entry(&recipe, &context, pins, entry, &mut seen));
    }

    recount(&mut pending);

    let entries: Vec<AuditedEntry> = pending.into_iter().map(reconcile).collect();
    let count = |status| entries.iter().filter(|item| item.status == status).count();
    Ok(AuditReport {
        schema: AUDIT_REPORT_SCHEMA,
        trusted_context_sha256: hex::encode(digest),
        recipe_digest: recipe.digest_hex(),
        observer: pins.observer.as_str().to_owned(),
        verified: count(AuditStatus::Verified),
        refused: count(AuditStatus::Refused),
        inconsistent: count(AuditStatus::Inconsistent),
        entries,
        approval_responses,
    })
}

/// The entries, by index, that break the order-free count bound: every
/// entry whose capacity is at most the smallest capacity value `k` that more
/// than `k` entries have a capacity of at most. Each charge is an entry
/// index and its capacity for one counter. Empty when some arrival order
/// gives every entry a distinct slot below its capacity.
pub(crate) fn count_bound_violations(charges: &[(usize, u64)]) -> Vec<usize> {
    let mut capacities: Vec<u64> = charges.iter().map(|(_, capacity)| *capacity).collect();
    capacities.sort_unstable();
    capacities.dedup();
    for capacity in capacities {
        let within = charges
            .iter()
            .filter(|(_, other)| *other <= capacity)
            .count();
        if u64::try_from(within).unwrap_or(u64::MAX) > capacity {
            return charges
                .iter()
                .filter(|(_, other)| *other <= capacity)
                .map(|(entry, _)| *entry)
                .collect();
        }
    }
    Vec::new()
}

/// The entries, by index, that break the order-free sum bound: every entry
/// whose capacity is at most the smallest capacity value `k` at which the
/// arguments of the entries with a capacity of at most `k` sum above `k`.
/// Each charge is an entry index, its capacity for one sum counter, and its
/// argument. Empty when some arrival order keeps every running sum within
/// every capacity; admitting by capacity is optimal, as for deadlines.
pub(crate) fn sum_bound_violations(charges: &[(usize, u64, u64)]) -> Vec<usize> {
    let mut capacities: Vec<u64> = charges.iter().map(|(_, capacity, _)| *capacity).collect();
    capacities.sort_unstable();
    capacities.dedup();
    for capacity in capacities {
        let total: u128 = charges
            .iter()
            .filter(|(_, other, _)| *other <= capacity)
            .map(|(_, _, argument)| u128::from(*argument))
            .sum();
        if total > u128::from(capacity) {
            return charges
                .iter()
                .filter(|(_, other, _)| *other <= capacity)
                .map(|(entry, _, _)| *entry)
                .collect();
        }
    }
    Vec::new()
}

/// Recounts every count and sum counter across the bundle's entered entries
/// without any order, and names the bound a refused entry met when the
/// bundle shows it: a verified entry the gateway did not enter is refused
/// with `gateway.policy.window-exhausted` or `gateway.policy.sum-exhausted`
/// when the entered entries on one of its counters leave it no room. A bundle
/// may be incomplete, so an entry whose exhaustion the bundle does not show
/// keeps `audit.gateway-not-entered`.
fn recount(pending: &mut [Pending]) {
    let entered = |item: &Pending| {
        item.entry.status == AuditStatus::Verified
            && item
                .outcome
                .as_ref()
                .is_some_and(|outcome| outcome.stage != "not-entered")
    };
    let mut counts: BTreeMap<[u8; 32], Vec<(usize, u64)>> = BTreeMap::new();
    let mut sums: BTreeMap<[u8; 32], Vec<(usize, u64, u64)>> = BTreeMap::new();
    for (index, item) in pending.iter().enumerate() {
        let Some(bound) = item.bound.as_ref().filter(|_| entered(item)) else {
            continue;
        };
        for counter in &bound.counts {
            counts
                .entry(counter.key)
                .or_default()
                .push((index, counter.capacity));
        }
        for counter in &bound.sums {
            sums.entry(counter.key)
                .or_default()
                .push((index, counter.capacity, bound.argument));
        }
    }
    let mut flagged: BTreeMap<usize, &'static str> = BTreeMap::new();
    for charges in counts.values() {
        for index in count_bound_violations(charges) {
            flagged.entry(index).or_insert("audit.bound-exceeded");
        }
    }
    for charges in sums.values() {
        for index in sum_bound_violations(charges) {
            flagged.entry(index).or_insert("audit.sum-exceeded");
        }
    }
    for (index, item) in pending.iter_mut().enumerate() {
        if let Some(code) = flagged.get(&index) {
            item.entry.status = AuditStatus::Inconsistent;
            (*code).clone_into(&mut item.entry.code);
            continue;
        }
        let refused_by_gateway = item.entry.status == AuditStatus::Verified
            && item
                .outcome
                .as_ref()
                .is_some_and(|outcome| outcome.stage == "not-entered");
        let Some(bound) = item.bound.as_ref().filter(|_| refused_by_gateway) else {
            continue;
        };
        let count_full = bound.counts.iter().any(|counter| {
            let used = counts.get(&counter.key).map_or(0, Vec::len);
            u64::try_from(used).unwrap_or(u64::MAX) >= counter.capacity
        });
        let sum_full = bound.sums.iter().any(|counter| {
            let used: u128 = sums.get(&counter.key).map_or(0, |charges| {
                charges
                    .iter()
                    .map(|(_, _, argument)| u128::from(*argument))
                    .sum()
            });
            used + u128::from(bound.argument) > u128::from(counter.capacity)
        });
        let code = if count_full {
            "gateway.policy.window-exhausted"
        } else if sum_full {
            "gateway.policy.sum-exhausted"
        } else {
            continue;
        };
        item.entry.status = AuditStatus::Refused;
        code.clone_into(&mut item.entry.code);
    }
}

fn recorded_response(source: &ResponseSource) -> Option<AuditedApprovalResponse> {
    LogicalOperationId::parse(&source.operation_id).ok()?;
    let response = auths_approval_quorum::decode_response(source.response.as_bytes()).ok()?;
    let (decision, decided_at) = match response.body() {
        auths_approval_quorum::ResponseBody::Approve(_) => ("approve", None),
        auths_approval_quorum::ResponseBody::Decline(decline) => {
            ("decline", Some(decline.decided_at()))
        }
    };
    Some(AuditedApprovalResponse {
        operation_id: source.operation_id.clone(),
        approver: response.approver().as_str().to_owned(),
        decision,
        decided_at,
    })
}

fn audit_entry(
    recipe: &CompiledRecipe,
    context: &TrustedContext,
    pins: &AuditPins,
    source: &EntrySource,
    seen: &mut BTreeSet<String>,
) -> Pending {
    let operation = &source.operation_id;
    let Ok(operation_id) = LogicalOperationId::parse(operation) else {
        return finding(operation, "audit.entry-malformed", 0);
    };
    if !seen.insert(operation.clone()) {
        return finding(operation, "audit.duplicate-operation", 0);
    }
    let (Some(proof), Some(action)) = (
        decode(&source.proof_b64, MAX_PROOF_BYTES),
        decode(&source.action_b64, MAX_ACTION_BYTES),
    ) else {
        return finding(operation, "audit.entry-malformed", 0);
    };
    let outcome = match &source.outcome_b64 {
        None => None,
        Some(text) => {
            let verified = decode(text, auths_model::MAX_OBSERVATION_BYTES)
                .ok_or("audit.outcome-invalid")
                .and_then(|bytes| verify_outcome(&bytes, &pins.observer));
            match verified {
                Ok(value)
                    if value.subject == operation_subject(recipe.namespace(), &operation_id) =>
                {
                    Some(value)
                }
                Ok(_) | Err(_) => return finding(operation, "audit.outcome-invalid", 0),
            }
        }
    };
    let evaluated_at = outcome
        .as_ref()
        .map_or_else(|| validity_start(&proof), |value| value.observed_at);
    let mut item = Pending {
        entry: AuditedEntry {
            operation_id: operation.clone(),
            status: AuditStatus::Refused,
            code: String::new(),
            approvals: Vec::new(),
            arguments: None,
            gateway_stage: outcome.as_ref().map(|value| value.stage.clone()),
            evaluated_at,
        },
        outcome,
        bound: None,
        commitment: None,
    };
    match verify_detailed(recipe, context, evaluated_at, &proof, &action) {
        Ok(verified) => {
            if verified.request.operation_id() != &operation_id {
                return finding(operation, "audit.operation-mismatch", evaluated_at);
            }
            item.entry.status = AuditStatus::Verified;
            "audit.verified".clone_into(&mut item.entry.code);
            item.entry.approvals = verified
                .actors
                .iter()
                .map(|actor| actor.as_str().to_owned())
                .collect();
            item.entry.arguments = Some(verified.arguments);
            item.bound = verified.bound;
            item.commitment = Some(hex::encode(verified.request.action_commitment()));
        }
        Err(result) => {
            item.entry.code = refusal_code(result);
            item.commitment = Some(
                auths_codec::domain_commitment("auths.canonical-action.v1", &action)
                    .map(|commitment| hex::encode(commitment.as_bytes()))
                    .unwrap_or_default(),
            );
        }
    }
    item
}

/// Reconciles the auditor's verdict with the gateway-signed outcome.
fn reconcile(item: Pending) -> AuditedEntry {
    let Pending {
        mut entry,
        outcome,
        commitment,
        ..
    } = item;
    if entry.status == AuditStatus::Inconsistent {
        return entry;
    }
    let inconsistent = |mut entry: AuditedEntry, code: &str| {
        entry.status = AuditStatus::Inconsistent;
        code.clone_into(&mut entry.code);
        entry
    };
    let Some(outcome) = outcome else {
        return if entry.status == AuditStatus::Verified {
            AuditedEntry {
                status: AuditStatus::Refused,
                code: "audit.outcome-missing".to_owned(),
                ..entry
            }
        } else {
            entry
        };
    };
    if commitment.as_deref() != Some(outcome.commitment.as_str()) {
        return inconsistent(entry, "audit.outcome-commitment-mismatch");
    }
    let entered = outcome.stage != "not-entered";
    match (entry.status, entered) {
        (AuditStatus::Verified, true)
        | (AuditStatus::Refused, false)
        | (AuditStatus::Inconsistent, _) => entry,
        (AuditStatus::Verified, false) => {
            entry.status = AuditStatus::Refused;
            "audit.gateway-not-entered".clone_into(&mut entry.code);
            entry
        }
        (AuditStatus::Refused, true) => inconsistent(entry, "audit.entered-without-authority"),
    }
}
