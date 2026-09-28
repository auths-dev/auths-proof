//! Offline audit of gateway submissions.
//!
//! An audit bundle carries, for each submitted operation, the exact proof and
//! canonical action the application sent and, when the gateway had a record,
//! the gateway-signed outcome observation and any signed pre-entry
//! observations. The bundle also carries the installed recipe, profile lock,
//! and trusted context. The auditor pins the trusted context by digest and
//! the observer by principal; nothing in the bundle can replace either pin.
//!
//! Each entry is re-verified with the gateway's own verifier and bounded-
//! policy admission at the outcome's `evaluated-at` (or, without an outcome,
//! at the start of the approvals' validity), which derives the count and sum
//! counters of its links in that fixed window. For an entered entry those
//! counters must digest to the outcome's `counters-digest`. The bounds are
//! then recounted without any order: the gateway gave each entered entry a
//! distinct slot below its capacity, which is possible exactly when, for
//! every capacity value k, at most k entered entries have a capacity of at
//! most k; and it kept a sum within every capacity, which is possible
//! exactly when the arguments of the entered entries with a capacity of at
//! most k sum to at most k. For a recipe with a relative ceiling, every
//! entered entry's outcome must carry the basis the gateway read, and the
//! re-derived argument must be within the recipe's ratio of it; for a
//! recipe with a pre-entry re-read, the entry's signed observations must
//! digest to the outcome's `pre-entry-digest` and satisfy the selected
//! requirements. No socket, provider, or gateway state is touched.
//!
//! An entry is `verified` when the auditor admits it and the gateway signed an
//! entered outcome for its exact action commitment; `refused` when the auditor
//! refuses it (with the gateway's stable code) or the gateway recorded a
//! refusal (with the outcome's `refusal`); and `inconsistent` when the two
//! disagree or the evidence does not verify. Any inconsistent entry means the
//! bundle was altered or the gateway entered a provider without authority.
//!
//! `verified` means authorized and entered, never accepted by the provider:
//! the provider's result is reported beside it in `provider_result`, so a
//! refund the provider rejected is `verified` with its `http_status` of 400.
//! One verdict covering both authorization and acceptance is what the
//! boundary plan's UX contract forbids.
//!
//! A bundle may also carry the remote approval responses the application
//! collected, including declines for operations never submitted. They are
//! decoded and listed as recorded, so the report shows who approved and who
//! declined; they never change a verdict. Only the verified proof counts an
//! approval, and a decline's signature carries no authority.

use crate::bounds::BoundAdmission;
use crate::engine::{GatewaySubmitResult, VerifiedCommand, verify_detailed};
use crate::observer::{
    READ_BACK_SCHEMA, VerifiedOutcome, counter_set_digest, operation_subject, verify_outcome,
    verify_signed,
};
use crate::pre_entry::{self, PreEntryObservation};
use crate::recipe::ENTRY_DEADLINE_SECONDS;
use crate::{CompiledRecipe, LogicalOperationId, pre_entry_digest};
use auths_gateway_kernel::order::PreEntryResult;
use auths_gateway_kernel::ratio::relative_ceiling_admits;
use auths_model::{PrincipalId, ResourceId, TrustedContext, VerifierLimits};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Schema of an audit bundle.
pub const AUDIT_BUNDLE_SCHEMA: &str = "auths.gateway-audit-bundle/2";
/// Schema of an audit report.
pub const AUDIT_REPORT_SCHEMA: &str = "auths.gateway-audit-report/2";
/// Largest audit bundle, in bytes.
pub const MAX_AUDIT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
/// Largest number of entries one bundle may carry.
pub const MAX_AUDIT_ENTRIES: usize = 4_096;
/// Largest number of approval responses one bundle may carry.
pub const MAX_AUDIT_APPROVAL_RESPONSES: usize = 16 * MAX_AUDIT_ENTRIES;
/// Largest number of pre-entry observations one entry may carry, one per
/// declared pointer.
pub const MAX_AUDIT_PRE_ENTRY_OBSERVATIONS: usize = 4;

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

/// What the pre-entry observations of one entry show.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AuditedPreEntry {
    /// The number of signed observations the bundle carries for the entry.
    pub observations: usize,
    /// Whether they digest to the outcome's `pre-entry-digest`, verify under
    /// the pinned observer, name the recipe's subjects, fall inside the entry
    /// window, and satisfy the selected requirements.
    pub verified: bool,
}

/// The provider result the gateway signed for one entry, reported beside
/// the verdict and never folded into it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderResult {
    /// The stage the gateway signed.
    pub stage: &'static str,
    /// The provider's HTTP status, when a complete response was recorded.
    pub http_status: Option<u16>,
    /// Lowercase hex SHA-256 of that response.
    pub response_digest: Option<String>,
    /// `match`, `mismatch`, or `echo-mismatch` for an `observed` stage.
    pub observation: Option<&'static str>,
    /// Lowercase hex SHA-256 of provider-held evidence.
    pub evidence_digest: Option<String>,
    /// The gateway's stable refusal code, for `not-entered`.
    pub refusal: Option<String>,
    /// What the entry's pre-entry observations show, when the outcome
    /// records a pre-entry digest.
    pub pre_entry: Option<AuditedPreEntry>,
    /// The relative-ceiling basis the gateway read, under observer trust.
    pub relative_basis: Option<u64>,
    /// `not-shown-by-bundle` for an exhaustion refusal the bundle's own
    /// entries do not account for, because a bundle may be incomplete.
    pub recount: Option<&'static str>,
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
    /// The gateway clock time the entry was evaluated at.
    pub evaluated_at: u64,
    /// The provider result the gateway signed, when a verified outcome is
    /// present.
    pub provider_result: Option<ProviderResult>,
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
    /// The recipe's derived recovery capability.
    pub recovery: Value,
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
    #[serde(default)]
    pre_entry_b64: Option<Vec<String>>,
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
    /// The first finding of the entered-entry checks: the counter set, the
    /// pre-entry observations, and the relative ceiling.
    finding: Option<&'static str>,
    pre_entry: Option<AuditedPreEntry>,
    recount: Option<&'static str>,
}

impl Pending {
    fn entered(&self) -> bool {
        self.entry.status == AuditStatus::Verified
            && self.outcome.as_ref().is_some_and(VerifiedOutcome::entered)
    }

    fn refused_by_gateway(&self) -> bool {
        self.entry.status == AuditStatus::Verified
            && self
                .outcome
                .as_ref()
                .is_some_and(|outcome| !outcome.entered())
    }
}

fn finding(operation_id: &str, code: &str, evaluated_at: u64) -> Pending {
    Pending {
        entry: AuditedEntry {
            operation_id: operation_id.to_owned(),
            status: AuditStatus::Inconsistent,
            code: code.to_owned(),
            approvals: Vec::new(),
            arguments: None,
            evaluated_at,
            provider_result: None,
        },
        outcome: None,
        bound: None,
        commitment: None,
        finding: None,
        pre_entry: None,
        recount: None,
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

    let flagged = recount(&mut pending);

    let entries: Vec<AuditedEntry> = pending
        .into_iter()
        .enumerate()
        .map(|(index, item)| reconcile(item, flagged.get(&index).copied()))
        .collect();
    let count = |status| entries.iter().filter(|item| item.status == status).count();
    Ok(AuditReport {
        schema: AUDIT_REPORT_SCHEMA,
        trusted_context_sha256: hex::encode(digest),
        recipe_digest: recipe.digest_hex(),
        recovery: crate::recipe::recovery_document(&recipe.recovery()),
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
/// without any order and returns the entries, by index, that break a bound.
/// An entry the gateway refused as exhausted keeps the outcome's code; when
/// the bundle's entered entries leave room on every counter it charges, its
/// `recount` is `not-shown-by-bundle`, because a bundle may be incomplete.
fn recount(pending: &mut [Pending]) -> BTreeMap<usize, &'static str> {
    let mut counts: BTreeMap<[u8; 32], Vec<(usize, u64)>> = BTreeMap::new();
    let mut sums: BTreeMap<[u8; 32], Vec<(usize, u64, u64)>> = BTreeMap::new();
    for (index, item) in pending.iter().enumerate() {
        let Some(bound) = item.bound.as_ref().filter(|_| item.entered()) else {
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
    for item in pending.iter_mut() {
        if !item.refused_by_gateway() {
            continue;
        }
        let refusal = item
            .outcome
            .as_ref()
            .and_then(|outcome| outcome.record.refusal.as_deref());
        let (Some(bound), Some(refusal)) = (item.bound.as_ref(), refusal) else {
            continue;
        };
        let shown = match refusal {
            "gateway.policy.window-exhausted" => bound.counts.iter().any(|counter| {
                let used = counts.get(&counter.key).map_or(0, Vec::len);
                u64::try_from(used).unwrap_or(u64::MAX) >= counter.capacity
            }),
            "gateway.policy.sum-exhausted" => bound.sums.iter().any(|counter| {
                let used: u128 = sums.get(&counter.key).map_or(0, |charges| {
                    charges
                        .iter()
                        .map(|(_, _, argument)| u128::from(*argument))
                        .sum()
                });
                used + u128::from(bound.argument) > u128::from(counter.capacity)
            }),
            _ => continue,
        };
        if !shown {
            item.recount = Some("not-shown-by-bundle");
        }
    }
    flagged
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

/// The entry's pre-entry observations, at most one per declared pointer.
fn decode_pre_entry(items: Option<&[String]>) -> Result<Option<Vec<Vec<u8>>>, ()> {
    match items {
        None => Ok(None),
        Some(items) if items.len() <= MAX_AUDIT_PRE_ENTRY_OBSERVATIONS => items
            .iter()
            .map(|text| decode(text, auths_model::MAX_OBSERVATION_BYTES).ok_or(()))
            .collect::<Result<Vec<_>, ()>>()
            .map(Some),
        Some(_) => Err(()),
    }
}

/// The entry's verified outcome, which must name this installation's
/// subject for the operation.
fn entry_outcome(
    recipe: &CompiledRecipe,
    pins: &AuditPins,
    operation_id: &LogicalOperationId,
    text: Option<&str>,
) -> Result<Option<VerifiedOutcome>, ()> {
    let Some(text) = text else {
        return Ok(None);
    };
    decode(text, auths_model::MAX_OBSERVATION_BYTES)
        .and_then(|bytes| verify_outcome(&bytes, &pins.observer).ok())
        .filter(|value| value.subject == operation_subject(recipe.namespace(), operation_id))
        .map(Some)
        .ok_or(())
}

impl Pending {
    /// An entry that starts refused with an empty code until verification runs.
    fn refused(operation: &str, evaluated_at: u64, outcome: Option<VerifiedOutcome>) -> Self {
        Self {
            entry: AuditedEntry {
                operation_id: operation.to_owned(),
                status: AuditStatus::Refused,
                code: String::new(),
                approvals: Vec::new(),
                arguments: None,
                evaluated_at,
                provider_result: None,
            },
            outcome,
            bound: None,
            commitment: None,
            finding: None,
            pre_entry: None,
            recount: None,
        }
    }
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
    let Ok(pre_entry_bytes) = decode_pre_entry(source.pre_entry_b64.as_deref()) else {
        return finding(operation, "audit.entry-malformed", 0);
    };
    let Ok(outcome) = entry_outcome(recipe, pins, &operation_id, source.outcome_b64.as_deref())
    else {
        return finding(operation, "audit.outcome-invalid", 0);
    };
    let evaluated_at = outcome
        .as_ref()
        .map_or_else(|| validity_start(&proof), |value| value.record.evaluated_at);
    let mut item = Pending::refused(operation, evaluated_at, outcome);
    // The auditor applies the per-proof observer check the gateway admits
    // with; it does not re-run the retention rule or pre-entry selection
    // here, and checks the pre-entry evidence of entered entries below.
    let verification =
        verify_detailed(recipe, context, evaluated_at, &proof, &action).and_then(|verified| {
            match verified.observer_refusal {
                Some(code) => Err(crate::engine::not_entered(code)),
                None => Ok(verified),
            }
        });
    match verification {
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
            item.commitment = Some(hex::encode(verified.request.action_commitment()));
            if item.entered() {
                let checks = EnteredChecks {
                    recipe,
                    context,
                    pins,
                    verified: &verified,
                    outcome: item.outcome.as_ref(),
                    evaluated_at,
                };
                item.finding = checks
                    .counters()
                    .err()
                    .or_else(|| {
                        checks
                            .pre_entry(pre_entry_bytes.as_deref(), &mut item.pre_entry)
                            .err()
                    })
                    .or_else(|| checks.relative_ceiling().err());
            } else if item
                .outcome
                .as_ref()
                .is_some_and(|outcome| outcome.record.pre_entry_digest.is_some())
            {
                item.pre_entry = Some(AuditedPreEntry {
                    observations: pre_entry_bytes.as_ref().map_or(0, Vec::len),
                    verified: false,
                });
            }
            item.entry.arguments = Some(verified.arguments);
            item.bound = verified.bound;
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

/// The checks an entered entry must pass beyond authorization.
struct EnteredChecks<'a> {
    recipe: &'a CompiledRecipe,
    context: &'a TrustedContext,
    pins: &'a AuditPins,
    verified: &'a VerifiedCommand,
    outcome: Option<&'a VerifiedOutcome>,
    evaluated_at: u64,
}

impl EnteredChecks<'_> {
    /// The counters re-derived at `evaluated-at` digest to the outcome's
    /// `counters-digest`, both absent when nothing was reserved.
    fn counters(&self) -> Result<(), &'static str> {
        let derived = self.verified.bound.as_ref().and_then(|bound| {
            counter_set_digest(
                bound
                    .counts
                    .iter()
                    .map(|counter| counter.key)
                    .chain(bound.sums.iter().map(|counter| counter.key)),
            )
        });
        let signed = self
            .outcome
            .and_then(|outcome| outcome.record.counters_digest);
        if derived == signed {
            Ok(())
        } else {
            Err("audit.counters-mismatch")
        }
    }

    /// For a pre-entry recipe: the observations digest to the outcome's
    /// `pre-entry-digest`, each verifies under the pinned observer, names a
    /// recipe subject built from the verified arguments, was taken within
    /// the entry window, and together they satisfy the selected
    /// requirements through the shipping predicates.
    fn pre_entry(
        &self,
        observations: Option<&[Vec<u8>]>,
        summary: &mut Option<AuditedPreEntry>,
    ) -> Result<(), &'static str> {
        let (Some(pointers), Some(read)) = (
            self.recipe.pre_entry_pointers(),
            self.verified.request.pre_entry_read(),
        ) else {
            return Ok(());
        };
        let signed_digest = self
            .outcome
            .and_then(|outcome| outcome.record.pre_entry_digest);
        let (Some(signed_digest), Some(observations)) = (signed_digest, observations) else {
            *summary = Some(AuditedPreEntry {
                observations: observations.map_or(0, <[Vec<u8>]>::len),
                verified: false,
            });
            return Err("audit.pre-entry-missing");
        };
        *summary = Some(AuditedPreEntry {
            observations: observations.len(),
            verified: false,
        });
        if pre_entry_digest(observations) != Some(signed_digest) {
            return Err("audit.pre-entry-invalid");
        }
        let subjects: Vec<String> = pointers
            .iter()
            .map(|pointer| read.subject(pointer))
            .collect();
        let latest = self.evaluated_at.saturating_add(ENTRY_DEADLINE_SECONDS);
        let mut read_back = Vec::with_capacity(observations.len());
        for bytes in observations {
            let signed = verify_signed(bytes, &self.pins.observer, READ_BACK_SCHEMA)
                .ok_or("audit.pre-entry-invalid")?;
            let statement = signed.statement();
            let subject = statement.subject().as_str().to_owned();
            let observed_at = statement.observed_at().get();
            if !subjects.contains(&subject) || !(self.evaluated_at..=latest).contains(&observed_at)
            {
                return Err("audit.pre-entry-invalid");
            }
            read_back.push(PreEntryObservation {
                subject,
                observed_at,
                facts: statement.facts().clone(),
                bytes: bytes.clone(),
            });
        }
        let covers = |namespace: &ResourceId, subject: &ResourceId| {
            crate::engine::resource_covers(self.context, namespace, subject)
        };
        let selected = pre_entry::select(
            &self.verified.requirements,
            &self.verified.canonical_action,
            self.context,
            Some(&self.pins.observer),
            read,
            pointers,
            covers,
        )
        .map_err(|_| "audit.pre-entry-unsatisfied")?;
        let now = read_back
            .iter()
            .map(|observation| observation.observed_at)
            .max()
            .unwrap_or(self.evaluated_at);
        if pre_entry::evaluate(&selected, &read_back, now) != PreEntryResult::Satisfied {
            return Err("audit.pre-entry-unsatisfied");
        }
        *summary = Some(AuditedPreEntry {
            observations: observations.len(),
            verified: true,
        });
        Ok(())
    }

    /// For a relative-ceiling recipe: the outcome carries the basis the
    /// gateway read, and the re-derived argument is within the recipe's
    /// basis points of it. The basis is the gateway's assertion under
    /// observer trust.
    fn relative_ceiling(&self) -> Result<(), &'static str> {
        let Some(ceiling) = self.recipe.ceiling_check() else {
            return Ok(());
        };
        let basis = self
            .outcome
            .and_then(|outcome| outcome.record.relative_basis)
            .ok_or("audit.relative-ceiling-missing")?;
        let argument = self
            .verified
            .arguments
            .get(&ceiling.argument)
            .and_then(Value::as_u64)
            .ok_or("audit.relative-ceiling-exceeded")?;
        if relative_ceiling_admits(argument, basis, ceiling.basis_points) {
            Ok(())
        } else {
            Err("audit.relative-ceiling-exceeded")
        }
    }
}

fn provider_result(item: &Pending) -> Option<ProviderResult> {
    let outcome = item.outcome.as_ref()?;
    let record = &outcome.record;
    Some(ProviderResult {
        stage: outcome.stage(),
        http_status: record.http_status,
        response_digest: record.response_digest.map(hex::encode),
        observation: record.observation,
        evidence_digest: record.evidence_digest.map(hex::encode),
        refusal: record.refusal.clone(),
        pre_entry: item.pre_entry,
        relative_basis: record.relative_basis,
        recount: item.recount,
    })
}

/// Reconciles the auditor's verdict with the gateway-signed outcome, then
/// applies the entered-entry findings and the recount's.
fn reconcile(item: Pending, recounted: Option<&'static str>) -> AuditedEntry {
    let result = provider_result(&item);
    let Pending {
        mut entry,
        outcome,
        commitment,
        finding,
        ..
    } = item;
    entry.provider_result = result;
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
    if commitment.as_deref() != Some(outcome.commitment()) {
        return inconsistent(entry, "audit.outcome-commitment-mismatch");
    }
    match (entry.status, outcome.entered()) {
        (AuditStatus::Refused, false) | (AuditStatus::Inconsistent, _) => entry,
        (AuditStatus::Verified, false) => {
            entry.status = AuditStatus::Refused;
            outcome
                .record
                .refusal
                .as_deref()
                .unwrap_or("audit.gateway-not-entered")
                .clone_into(&mut entry.code);
            entry
        }
        (AuditStatus::Refused, true) => inconsistent(entry, "audit.entered-without-authority"),
        (AuditStatus::Verified, true) => match finding.or(recounted) {
            Some(code) => inconsistent(entry, code),
            None => entry,
        },
    }
}
