//! Protected common qualification ledger sealer.
//!
//! This executable intentionally links no provider/domain adapter. It receives
//! the ledger signing seed only over its dedicated stdin pipe, after every
//! independently sourced event signature has been verified.

#![forbid(unsafe_code)]

use auths_config::{AgentConfig, AgentPlatform, ReceiptSigningRole};
use auths_profile_kit::{
    QualificationAttemptKind, QualificationCandidateCollectionV1,
    QualificationCommonOperationEvidence, QualificationCommonOperationInstanceEvidence,
    QualificationCommonPhaseEvidence, QualificationCommonReceiptClaims, QualificationCounters,
    QualificationEffect, QualificationEvidenceEvent, QualificationEvidenceEventKind,
    QualificationEvidenceEventPayload, QualificationEvidenceLedger,
    QualificationEvidenceLedgerPlanV1, QualificationEvidenceLedgerRecord,
    QualificationEvidenceLedgerTrustRegistry, QualificationEvidencePhaseCommitment,
    QualificationEvidenceSource, QualificationEvidenceSourceTrustRegistry,
    QualificationOutcomeKind, QualificationReceiptState, QualificationRedactedAttempt,
    qualification_common_phase_matches_ledger, qualification_evidence_event_chain_valid,
    qualification_pre_admission_attempt_count,
};
#[cfg(target_os = "linux")]
use auths_qualification_evidence_source::{
    QualificationSourceSessionPeer, read_source_session_frame_before,
    write_source_session_frame_before,
};
use auths_receipts::{
    ReceiptTrustAnchor, ReceiptTrustAnchorRole, ReceiptTrustAnchors, decode_receipt_trust_anchors,
    encode_receipt_trust_anchors,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
#[cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, mkdirat, open, openat,
    renameat_with, unlinkat,
};
#[cfg(target_os = "linux")]
use rustix::fs::{FileType, chown, fchown, statat};
#[cfg(target_os = "linux")]
use rustix::process::{Gid, Uid};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::File,
    io::{Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::{fs::PermissionsExt as _, net::UnixListener},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_RECORD_BYTES: u64 = 16_777_216;
const MAX_SOURCE_TRUST_BYTES: u64 = 262_144;
const MAX_LEDGER_TRUST_BYTES: u64 = 262_144;
const MAX_SEED_BYTES: u64 = 128;
const MAX_EVENT_INDEX_BYTES: u64 = 1_048_576;
const MAX_EVENT_BYTES: u64 = 65_536;
const MAX_PHASE_BYTES: u64 = 1_048_576;
const MAX_COLLECTION_BYTES: u64 = 16_777_216;
const MAX_AGENT_CONFIG_BYTES: u64 = 4_194_304;

struct LedgerLock {
    file: File,
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationLedgerEventIndexV1 {
    schema: String,
    events: Vec<QualificationLedgerEventIndexRowV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationLedgerEventIndexRowV1 {
    sequence: u32,
    source: QualificationEvidenceSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationLedgerFinalizationV1 {
    schema: String,
    plan_sha256: String,
    source_context_sha256: String,
    event_count: u32,
    last_event_sequence: u32,
    last_event_sha256: String,
    event_index_sha256: String,
    completed_at_unix_seconds: u64,
}

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qualification supervisor failed closed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    reject_secret_environment()?;
    match arguments.first().map(String::as_str) {
        Some("initialize-ledger") => initialize_ledger(arguments),
        Some("prepare-row-runtime") => prepare_row_runtime(arguments),
        Some("cleanup-row-runtime") => cleanup_row_runtime(arguments),
        Some("cleanup-protected-install") => cleanup_protected_install(arguments),
        Some("materialize-agent-signing-key") => materialize_agent_signing_key(arguments),
        Some("serve-append-session") => serve_append_session(arguments),
        Some("stage-common-phases") => stage_common_phases(arguments),
        Some("build-event-index") => build_event_index(arguments),
        Some("assemble-ledger") => assemble_ledger(arguments),
        Some("seal-ledger") => seal_ledger(arguments),
        Some("export-receipt-anchors") => export_receipt_anchors(arguments),
        _ => Err(usage()),
    }
}

fn export_receipt_anchors(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        config_flag,
        config_output,
        anchors_flag,
        anchors_output,
        digest_flag,
        expected_sha256,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "export-receipt-anchors"
        || config_flag != "--config-output"
        || anchors_flag != "--anchors-output"
        || digest_flag != "--expected-sha256"
        || !lower_hex_64(expected_sha256)
    {
        return Err(usage());
    }
    let mut encoded = Zeroizing::new(String::new());
    std::io::stdin()
        .take(MAX_AGENT_CONFIG_BYTES + 1)
        .read_to_string(&mut encoded)
        .map_err(string_error)?;
    if u64::try_from(encoded.len()).map_err(string_error)? > MAX_AGENT_CONFIG_BYTES {
        return Err("protected agent configuration exceeds its hard bound".into());
    }
    let mut config_bytes = vec![0_u8; encoded.len().saturating_mul(3) / 4 + 3];
    let decoded = Base64UrlUnpadded::decode(encoded.trim(), &mut config_bytes)
        .map_err(|_| "protected agent configuration is not base64url".to_owned())?;
    let config_bytes = decoded.to_vec();
    if config_bytes.is_empty()
        || u64::try_from(config_bytes.len()).map_err(string_error)? > MAX_AGENT_CONFIG_BYTES
    {
        return Err("protected agent configuration is empty or oversized".into());
    }
    let source = std::str::from_utf8(&config_bytes).map_err(string_error)?;
    let config = AgentConfig::from_toml(source, AgentPlatform::Linux).map_err(string_error)?;
    let mut anchors = Vec::with_capacity(config.receipt_signing().prior().len() + 2);
    for value in config.receipt_signing().prior() {
        let mut public_key = [0_u8; 32];
        Base64UrlUnpadded::decode(value.public_key_base64url(), &mut public_key)
            .map_err(string_error)?;
        anchors.push(
            ReceiptTrustAnchor::new(
                match value.role() {
                    ReceiptSigningRole::Decision => ReceiptTrustAnchorRole::Decision,
                    ReceiptSigningRole::Execution => ReceiptTrustAnchorRole::Execution,
                },
                value.key_id(),
                value.verification_method(),
                public_key,
                value.not_before_unix_seconds(),
                value.not_after_unix_seconds(),
            )
            .map_err(string_error)?,
        );
    }
    for (role, value) in [
        (
            ReceiptTrustAnchorRole::Decision,
            config.receipt_signing().decision(),
        ),
        (
            ReceiptTrustAnchorRole::Execution,
            config.receipt_signing().execution(),
        ),
    ] {
        let mut public_key = [0_u8; 32];
        Base64UrlUnpadded::decode(value.public_key_base64url(), &mut public_key)
            .map_err(string_error)?;
        anchors.push(
            ReceiptTrustAnchor::new(
                role,
                value.key_id(),
                value.verification_method(),
                public_key,
                value.not_before_unix_seconds(),
                value.not_after_unix_seconds(),
            )
            .map_err(string_error)?,
        );
    }
    anchors.sort_by(|left, right| {
        (left.role(), left.key_id().as_bytes()).cmp(&(right.role(), right.key_id().as_bytes()))
    });
    let anchors = ReceiptTrustAnchors::new(anchors).map_err(string_error)?;
    let anchor_bytes = encode_receipt_trust_anchors(&anchors).map_err(string_error)?;
    if hex::encode(Sha256::digest(&anchor_bytes)) != *expected_sha256 {
        return Err("protected agent receipt anchors differ from environment policy".into());
    }
    write_new(Path::new(config_output), &config_bytes)?;
    write_new(Path::new(anchors_output), &anchor_bytes)
}

fn initialize_ledger(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        plan_flag,
        plan_path,
        common_flag,
        common_root,
        source_trust_flag,
        source_trust_path,
        ledger_trust_flag,
        ledger_trust_path,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "initialize-ledger"
        || plan_flag != "--plan"
        || common_flag != "--common-root"
        || source_trust_flag != "--source-trust"
        || ledger_trust_flag != "--ledger-trust"
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let source_trust_bytes =
        read_bounded(Path::new(source_trust_path), MAX_SOURCE_TRUST_BYTES, false)?;
    let source_trust = QualificationEvidenceSourceTrustRegistry::from_json(&source_trust_bytes)
        .map_err(string_error)?;
    if source_trust.uses_process_uid(plan.supervisor_controller_uid)
        || source_trust.uses_process_uid(plan.agent_uid)
    {
        return Err(
            "ledger controller or agent UID collides with a protected source process".into(),
        );
    }
    let ledger_trust_bytes =
        read_bounded(Path::new(ledger_trust_path), MAX_LEDGER_TRUST_BYTES, false)?;
    let _ledger_trust = QualificationEvidenceLedgerTrustRegistry::from_json(&ledger_trust_bytes)
        .map_err(string_error)?;

    let common_root = open_private_directory(Path::new(common_root))?;
    let ledger = ensure_private_child_directory(&common_root, "ledger")?;
    let provider = ensure_private_child_directory(&ledger, &plan.provider_run_id)?;
    let _ledger_lock = acquire_ledger_lock(&provider)?;
    if read_private_file_at(&provider, "ledger-plan.json", 262_144)? != plan_bytes {
        return Err("ledger initializer received a different provider-row plan".into());
    }
    write_atomic_new_at_or_verify(
        &provider,
        "evidence-source-trust.json",
        &source_trust_bytes,
        MAX_SOURCE_TRUST_BYTES,
    )?;
    write_atomic_new_at_or_verify(
        &provider,
        "evidence-ledger-trust.json",
        &ledger_trust_bytes,
        MAX_LEDGER_TRUST_BYTES,
    )?;
    ensure_private_child_directory(&provider, "event-markers")?;
    let source_records = ensure_private_child_directory(&provider, "source-records")?;
    for source in [
        QualificationEvidenceSource::Supervisor,
        QualificationEvidenceSource::ClientProxy,
        QualificationEvidenceSource::JournalReader,
        QualificationEvidenceSource::CredentialBroker,
        QualificationEvidenceSource::ProfileStateReader,
        QualificationEvidenceSource::ProviderProxy,
        QualificationEvidenceSource::ReceiptVerifier,
        QualificationEvidenceSource::ProviderObserver,
    ] {
        ensure_private_child_directory(&source_records, source_token(source))?;
    }
    for name in [
        "supervisor-contexts",
        "decision-snapshots",
        "durable-acks",
        "crash-action-contexts",
    ] {
        ensure_private_child_directory(&provider, name)?;
    }
    let scenarios = ensure_private_child_directory(&common_root, "scenarios")?;
    ensure_private_child_directory(&common_root, "receipts")?;
    ensure_private_child_directory(&common_root, "receipt-inspection")?;
    for phase in &plan.phases {
        let scenario = ensure_private_child_directory(&scenarios, &phase.scenario_id)?;
        ensure_private_child_directory(&scenario, &plan.provider_run_id)?;
    }
    common_root.sync_all().map_err(string_error)
}

fn stage_common_phases(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        plan_flag,
        plan_path,
        collection_flag,
        collection_path,
        common_flag,
        common_root,
        source_trust_flag,
        source_trust_path,
        receipt_trust_flag,
        receipt_trust_path,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "stage-common-phases"
        || plan_flag != "--plan"
        || collection_flag != "--candidate-collection"
        || common_flag != "--common-root"
        || source_trust_flag != "--source-trust"
        || receipt_trust_flag != "--receipt-trust"
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let collection_bytes = read_bounded(Path::new(collection_path), MAX_COLLECTION_BYTES, false)?;
    let collection: QualificationCandidateCollectionV1 =
        serde_json::from_slice(&collection_bytes).map_err(string_error)?;
    collection.validate().map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&collection).map_err(string_error)? != collection_bytes {
        return Err("candidate collection is not exact canonical JSON".into());
    }
    let reference = &collection.run_reference;
    if reference.repository_id != plan.repository_id
        || reference.candidate_revision != plan.candidate_revision
        || reference.run_id != plan.run_id
        || reference.run_attempt != plan.run_attempt
        || reference.domain != plan.domain
        || reference.target != plan.target
        || reference.provider_run_id != plan.provider_run_id
    {
        return Err("candidate collection differs from the immutable ledger plan".into());
    }
    let source_trust_bytes =
        read_bounded(Path::new(source_trust_path), MAX_SOURCE_TRUST_BYTES, false)?;
    let source_trust = QualificationEvidenceSourceTrustRegistry::from_json(&source_trust_bytes)
        .map_err(string_error)?;
    let receipt_trust_bytes = read_bounded(Path::new(receipt_trust_path), 262_144, false)?;
    let _receipt_trust =
        decode_receipt_trust_anchors(&receipt_trust_bytes).map_err(string_error)?;

    let common_root = open_private_directory(Path::new(common_root))?;
    let ledger_directory = open_private_child_directory(&common_root, "ledger")?;
    let provider_ledger = open_private_child_directory(&ledger_directory, &plan.provider_run_id)?;
    let _ledger_lock = acquire_ledger_lock(&provider_ledger)?;
    if read_private_file_at(&provider_ledger, "ledger-plan.json", 262_144)? != plan_bytes
        || read_private_file_optional(&provider_ledger, "finalization.json", MAX_EVENT_BYTES)?
            .is_some()
    {
        return Err("common phases can only be staged for the exact open ledger plan".into());
    }
    let marker_directory = open_private_child_directory(&provider_ledger, "event-markers")?;
    let rows = read_event_markers(&marker_directory)?;
    let source_records = open_private_child_directory(&provider_ledger, "source-records")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let events = read_indexed_events(
        &rows,
        &source_records,
        &plan.source_context_sha256().map_err(string_error)?,
        &source_trust,
        &plan,
        now,
    )?;
    validate_phase_prefix(&plan, &events, true)?;

    let collection_scenarios = collection
        .scenarios
        .iter()
        .map(|scenario| (scenario.scenario_id.as_str(), scenario))
        .collect::<BTreeMap<_, _>>();
    let planned_scenarios = plan
        .phases
        .iter()
        .map(|phase| phase.scenario_id.as_str())
        .collect::<BTreeSet<_>>();
    if collection_scenarios
        .keys()
        .copied()
        .ne(planned_scenarios.iter().copied())
    {
        return Err(
            "candidate collection does not exactly cover the planned scenario roster".into(),
        );
    }
    let scenarios_root = open_private_child_directory(&common_root, "scenarios")?;
    for phase in &plan.phases {
        let scenario = collection_scenarios
            .get(phase.scenario_id.as_str())
            .ok_or_else(|| "candidate collection omits a planned scenario".to_owned())?;
        let phase_position = usize::from(phase.phase_index)
            .checked_sub(1)
            .ok_or_else(|| "planned phase index is zero".to_owned())?;
        let operation = scenario
            .operations
            .get(phase_position)
            .ok_or_else(|| "candidate collection omits a planned phase".to_owned())?;
        if operation.role != phase.role
            || operation.profile != phase.profile
            || scenario.operations.len()
                != plan
                    .phases
                    .iter()
                    .filter(|candidate| candidate.scenario_id == phase.scenario_id)
                    .count()
        {
            return Err("candidate operation roster differs from the immutable phase plan".into());
        }
        let phase_events = events
            .iter()
            .filter(|event| {
                event.scenario_id == phase.scenario_id && event.phase_index == phase.phase_index
            })
            .collect::<Vec<_>>();
        let first_event = phase_events
            .first()
            .ok_or_else(|| "planned phase has no authenticated source events".to_owned())?;
        let last_event = phase_events
            .last()
            .ok_or_else(|| "planned phase has no authenticated source events".to_owned())?;
        let supervisor_generation = first_event.supervisor_generation;
        if phase_events.iter().any(|event| {
            event.supervisor_generation != supervisor_generation
                || event.role != phase.role
                || event.profile != phase.profile
                || event.failpoint != phase.failpoint
        }) {
            return Err("authenticated phase events differ from the immutable phase".into());
        }
        let operation_ids = phase_events
            .iter()
            .filter(|event| event.kind == QualificationEvidenceEventKind::DecisionDurable)
            .map(|event| {
                event
                    .operation_id
                    .clone()
                    .ok_or_else(|| "protected decision omits its operation identity".to_owned())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let pre_admission_attempts = qualification_pre_admission_attempt_count(&phase.scenario_id);
        let pre_admission_rejection = pre_admission_attempts.is_some();
        if operation_ids.len() > 8 || operation_ids.is_empty() != pre_admission_rejection {
            return Err("protected phase has an invalid durable operation roster".into());
        }
        let projections = operation_ids
            .iter()
            .map(|operation_id| {
                protected_common_projection(operation_id, &phase_events)
                    .map(|projection| (operation_id.clone(), projection))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let attempts = protected_attempts(&phase_events, &projections)?;
        if pre_admission_rejection {
            let expected_attempts =
                pre_admission_attempts.expect("a pre-admission phase has one closed attempt count");
            if attempts.len() != expected_attempts
                || attempts.iter().any(|attempt| {
                    attempt.operation_id.is_some()
                        || attempt.outcome != QualificationOutcomeKind::Unavailable
                        || attempt.completion.is_some()
                        || attempt.configuration_sha256.is_some()
                        || !attempt.receipt_ids.is_empty()
                })
                || phase_events.iter().any(|event| {
                    !matches!(
                        event.kind,
                        QualificationEvidenceEventKind::ScenarioStarted
                            | QualificationEvidenceEventKind::RequestReceived
                            | QualificationEvidenceEventKind::ResponseProjected
                            | QualificationEvidenceEventKind::ScenarioCompleted
                    )
                })
            {
                return Err(
                    "protected pre-admission rejection has an invalid source transcript".into(),
                );
            }
        }
        let instances = projections
            .into_iter()
            .map(|(operation_id, projection)| {
                let receipt_claims = attempts
                    .iter()
                    .filter(|attempt| {
                        attempt.operation_id.as_deref() == Some(operation_id.as_str())
                    })
                    .enumerate()
                    .map(|(index, attempt)| {
                        protected_receipt_claim(
                            u8::try_from(index + 1).map_err(string_error)?,
                            attempt,
                            &operation.profile,
                            &projection,
                            &phase_events,
                        )
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok(QualificationCommonOperationEvidence {
                    projection,
                    receipt_claims,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let projection = QualificationCommonPhaseEvidence {
            schema: "auths.profile-qualification-common-phase-evidence/1".into(),
            repository_id: plan.repository_id.clone(),
            workflow_run_id: plan.run_id.clone(),
            workflow_run_attempt: plan.run_attempt,
            candidate_revision: plan.candidate_revision.clone(),
            domain: plan.domain.clone(),
            target: plan.target,
            protected_environment: plan.protected_environment.clone(),
            provider_run_id: plan.provider_run_id.clone(),
            scenario_id: phase.scenario_id.clone(),
            phase_index: phase.phase_index,
            role: phase.role,
            profile: phase.profile.clone(),
            failpoint: phase.failpoint,
            operation_plan_sha256: phase.operation_plan_sha256.clone(),
            ledger_id: plan.ledger_id.clone(),
            session_nonce_sha256: plan.session_nonce_sha256.clone(),
            supervisor_generation,
            first_event_sequence: first_event.sequence,
            last_event_sequence: last_event.sequence,
            instances,
            attempts,
        };
        let bytes = serde_json_canonicalizer::to_vec(&projection).map_err(string_error)?;
        let scenario_directory = open_private_child_directory(&scenarios_root, &phase.scenario_id)?;
        let provider_directory =
            open_private_child_directory(&scenario_directory, &plan.provider_run_id)?;
        write_atomic_new_at_or_verify(
            &provider_directory,
            &format!("{}.json", phase.phase_index),
            &bytes,
            MAX_PHASE_BYTES,
        )?;
    }
    require_exact_phase_roster(&scenarios_root, &plan)
}

fn protected_attempts(
    phase_events: &[&QualificationEvidenceEvent],
    projections: &BTreeMap<String, QualificationCommonOperationInstanceEvidence>,
) -> Result<Vec<QualificationRedactedAttempt>, String> {
    use QualificationEvidenceEventKind as Kind;
    use QualificationEvidenceEventPayload as Payload;

    phase_events
        .iter()
        .copied()
        .filter(|event| {
            matches!(
                event.kind,
                Kind::ResponseProjected | Kind::CancellationObserved
            )
        })
        .enumerate()
        .map(|(index, event)| {
            let request_id = event
                .request_id
                .as_deref()
                .ok_or_else(|| "protected client result omits its request identity".to_owned())?;
            let ingress = phase_events
                .iter()
                .copied()
                .filter(|candidate| {
                    candidate.kind == Kind::RequestReceived
                        && candidate.request_id.as_deref() == Some(request_id)
                })
                .collect::<Vec<_>>();
            let [ingress] = ingress.as_slice() else {
                return Err("protected client result does not bind one ingress request".into());
            };
            let Payload::Request {
                request_input_sha256,
                principal_sha256,
                idempotency_sha256,
                preparation_input_sha256,
            } = &ingress.payload
            else {
                return Err("protected ingress has the wrong payload".into());
            };
            let Payload::ClientResult {
                result_sha256,
                journal_projection_kinds,
                outcome,
                completion,
                recovery_id,
                error_code,
                issue_metadata_sha256,
                receipt_ids,
            } = &event.payload
            else {
                return Err("protected client result has the wrong payload".into());
            };
            let operation_id = event.operation_id.clone();
            let projection = operation_id
                .as_ref()
                .and_then(|operation_id| projections.get(operation_id));
            if operation_id.is_some() != projection.is_some() {
                return Err("protected client result names an unknown durable operation".into());
            }
            let kind = if event.kind == Kind::CancellationObserved {
                QualificationAttemptKind::CancelAfterWrite
            } else if *outcome == QualificationOutcomeKind::Conflict {
                QualificationAttemptKind::Conflict
            } else if preparation_input_sha256.is_some() {
                if journal_projection_kinds.contains(&Kind::ReplayObserved) {
                    QualificationAttemptKind::Replay
                } else {
                    QualificationAttemptKind::Execute
                }
            } else if journal_projection_kinds.contains(&Kind::RecoveryObserved) {
                QualificationAttemptKind::Recover
            } else if journal_projection_kinds.contains(&Kind::StatusObserved) {
                QualificationAttemptKind::Status
            } else {
                return Err(
                    "protected non-preparation result has no status or recovery route".into(),
                );
            };
            let preparation = matches!(
                kind,
                QualificationAttemptKind::Execute
                    | QualificationAttemptKind::Replay
                    | QualificationAttemptKind::Conflict
                    | QualificationAttemptKind::CancelAfterWrite
            );
            let value = QualificationRedactedAttempt {
                sequence: u8::try_from(index + 1).map_err(string_error)?,
                kind,
                request_id: request_id.to_owned(),
                operation_id,
                recovery_id: recovery_id.clone(),
                outcome: *outcome,
                completion: *completion,
                idempotency_sha256: idempotency_sha256.clone(),
                request_input_sha256: request_input_sha256.clone(),
                preparation_input_sha256: preparation_input_sha256.clone(),
                principal_sha256: principal_sha256.clone(),
                connection_alias_sha256: preparation
                    .then(|| projection.and_then(|value| value.connection_alias_sha256.clone()))
                    .flatten(),
                connection_generation: preparation
                    .then(|| projection.map(|value| value.connection_generation.clone()))
                    .flatten(),
                requested_scope_sha256: preparation
                    .then(|| projection.and_then(|value| value.credential_scope_sha256.clone()))
                    .flatten(),
                configuration_sha256: projection.map(|value| value.configuration_sha256.clone()),
                sealed_command_sha256: projection
                    .and_then(|value| value.sealed_command_sha256.clone()),
                error_code: error_code.clone(),
                issue_metadata_sha256: issue_metadata_sha256.clone(),
                result_sha256: result_sha256.clone(),
                receipt_ids: receipt_ids.clone(),
            };
            value.validate().map_err(string_error)?;
            Ok(value)
        })
        .collect()
}

fn protected_common_projection(
    operation_id: &str,
    phase_events: &[&QualificationEvidenceEvent],
) -> Result<QualificationCommonOperationInstanceEvidence, String> {
    use QualificationEvidenceEventKind as Kind;
    use QualificationEvidenceEventPayload as Payload;

    let operation_events = phase_events
        .iter()
        .copied()
        .filter(|event| event.operation_id.as_deref() == Some(operation_id))
        .collect::<Vec<_>>();
    let decisions = operation_events
        .iter()
        .copied()
        .filter(|event| event.kind == Kind::DecisionDurable)
        .collect::<Vec<_>>();
    let [decision] = decisions.as_slice() else {
        return Err("protected operation does not have exactly one durable decision".into());
    };
    let request_id = decision
        .request_id
        .as_deref()
        .ok_or_else(|| "protected decision omits its request identity".to_owned())?;
    let requests = phase_events
        .iter()
        .copied()
        .filter(|event| {
            event.kind == Kind::RequestReceived && event.request_id.as_deref() == Some(request_id)
        })
        .collect::<Vec<_>>();
    let [request] = requests.as_slice() else {
        return Err("protected decision does not bind exactly one ingress request".into());
    };
    let Payload::Request {
        principal_sha256, ..
    } = &request.payload
    else {
        return Err("protected request has the wrong source payload".into());
    };
    let Payload::Decision {
        canonical_input_sha256,
        idempotency_sha256,
        canonical_action_sha256,
        receipt_action_sha256,
        receipt_context_sha256,
        authority_sha256,
        configuration_sha256,
        runtime_contract_sha256,
        preparation_sha256,
        decision_class,
        ..
    } = &decision.payload
    else {
        return Err("protected decision has the wrong source payload".into());
    };
    let connection_generation = decision
        .connection_generation
        .clone()
        .ok_or_else(|| "protected decision omits its connection generation".to_owned())?;
    if operation_events
        .iter()
        .any(|event| event.connection_generation.as_deref() != Some(connection_generation.as_str()))
    {
        return Err("protected operation mixes connection generations".into());
    }

    let connections = operation_events
        .iter()
        .filter_map(|event| match &event.payload {
            Payload::Connection {
                connection_id_sha256,
                connection_alias_sha256,
                descriptor_sha256,
                account_sha256,
            } if event.kind == Kind::ConnectionReread => Some((
                connection_id_sha256,
                connection_alias_sha256,
                descriptor_sha256,
                account_sha256,
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    if connections.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err("protected connection rereads disagree".into());
    }
    let connection = connections.first().copied();

    let credential_scopes = operation_events
        .iter()
        .filter_map(|event| match &event.payload {
            Payload::Credential {
                requested_scope_sha256,
                effective_scope_sha256,
                ..
            } if matches!(
                event.kind,
                Kind::CredentialLeaseAttempted
                    | Kind::CredentialLeaseSucceeded
                    | Kind::CredentialLeaseClosed
            ) =>
            {
                Some((requested_scope_sha256, effective_scope_sha256))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if credential_scopes
        .iter()
        .any(|(requested, effective)| requested != effective)
        || credential_scopes.windows(2).any(|pair| pair[0] != pair[1])
    {
        return Err("protected credential scopes disagree".into());
    }

    let unique_digest = |kind: Kind,
                         select: fn(&QualificationEvidenceEventPayload) -> Option<&String>|
     -> Result<Option<String>, String> {
        let values = operation_events
            .iter()
            .filter(|event| event.kind == kind)
            .map(|event| {
                select(&event.payload)
                    .cloned()
                    .ok_or_else(|| "protected event has the wrong payload".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() > 1 && values.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err("protected durable payloads disagree".into());
        }
        Ok(values.into_iter().next())
    };
    let sealed_command_sha256 = unique_digest(Kind::CommandDurable, |payload| match payload {
        Payload::Command {
            sealed_command_sha256,
        } => Some(sealed_command_sha256),
        _ => None,
    })?;
    let provider_result_sha256 =
        unique_digest(Kind::ProviderResultDurable, |payload| match payload {
            Payload::ProviderResult {
                provider_result_sha256,
            } => Some(provider_result_sha256),
            _ => None,
        })?;
    let execution_receipts = operation_events
        .iter()
        .filter(|event| event.kind == Kind::ExecutionReceiptDurable)
        .map(|event| match &event.payload {
            Payload::ExecutionReceipt {
                execution_result_sha256,
                ..
            } => Ok(execution_result_sha256.clone()),
            _ => Err("protected execution receipt has the wrong payload".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if execution_receipts.len() > 1 && execution_receipts.windows(2).any(|pair| pair[0] != pair[1])
    {
        return Err("protected execution receipt payloads disagree".into());
    }
    let execution_result_sha256 = execution_receipts.into_iter().next().flatten();

    let terminals = operation_events
        .iter()
        .filter(|event| event.kind == Kind::TerminalDurable)
        .collect::<Vec<_>>();
    if terminals.len() > 1 {
        return Err("protected operation has multiple terminal boundaries".into());
    }
    let (effect, reconciled) = match terminals.first().map(|event| &event.payload) {
        Some(Payload::Terminal {
            effect, completion, ..
        }) => (
            *effect,
            matches!(
                completion,
                Some(auths_profile_kit::QualificationCompletion::Reconciled)
            ),
        ),
        Some(_) => return Err("protected terminal has the wrong payload".into()),
        None if operation_events
            .iter()
            .any(|event| event.kind == Kind::RecoveryRequiredDurable) =>
        {
            (QualificationEffect::Possible, false)
        }
        None => (QualificationEffect::NotApplied, false),
    };
    let count = |kind| {
        u32::try_from(
            operation_events
                .iter()
                .filter(|event| event.kind == kind)
                .count(),
        )
        .unwrap_or(u32::MAX)
    };
    let projection = QualificationCommonOperationInstanceEvidence {
        operation_id: operation_id.to_owned(),
        connection_generation,
        principal_sha256: principal_sha256.clone(),
        connection_alias_sha256: connection.and_then(|value| value.1.clone()),
        connection_id_sha256: connection.and_then(|value| value.0.clone()),
        connection_descriptor_sha256: connection.and_then(|value| value.2.clone()),
        connection_account_sha256: connection.and_then(|value| value.3.clone()),
        credential_scope_sha256: credential_scopes
            .first()
            .map(|(requested, _)| (*requested).clone()),
        canonical_input_sha256: canonical_input_sha256.clone(),
        idempotency_sha256: idempotency_sha256.clone(),
        canonical_action_sha256: canonical_action_sha256.clone(),
        receipt_action_sha256: receipt_action_sha256.clone(),
        receipt_context_sha256: receipt_context_sha256.clone(),
        authority_sha256: authority_sha256.clone(),
        configuration_sha256: configuration_sha256.clone(),
        runtime_contract_sha256: runtime_contract_sha256.clone(),
        preparation_sha256: preparation_sha256.clone(),
        decision_class: *decision_class,
        reconciled,
        effect,
        counters: QualificationCounters {
            reservation_writes: count(Kind::ReservationDurable),
            reservation_releases: count(Kind::ReservationReleased),
            reservation_consumptions: count(Kind::ReservationConsumed),
            reservation_retentions: count(Kind::ReservationRetained),
            connection_rereads: count(Kind::ConnectionReread),
            credential_lease_attempts: count(Kind::CredentialLeaseAttempted),
            credential_leases: count(Kind::CredentialLeaseSucceeded),
            credential_lease_closes: count(Kind::CredentialLeaseClosed),
            provider_entry_markers: count(Kind::ProviderEntryDurable),
            provider_calls: count(Kind::ProviderRequestWritten),
            provider_request_writes: count(Kind::ProviderRequestWritten),
            provider_responses: count(Kind::ProviderResponseObserved),
            durable_provider_results: count(Kind::ProviderResultDurable),
            observations: count(Kind::ObservationDurable),
            receipt_writes: count(Kind::DecisionDurable)
                .checked_add(count(Kind::ExecutionReceiptDurable))
                .ok_or_else(|| "protected receipt count overflow".to_owned())?,
        },
        sealed_command_sha256,
        provider_result_sha256,
        execution_result_sha256,
    };
    projection.validate().map_err(string_error)?;
    Ok(projection)
}

fn protected_receipt_claim(
    sequence: u8,
    attempt: &QualificationRedactedAttempt,
    profile: &str,
    projection: &QualificationCommonOperationInstanceEvidence,
    phase_events: &[&QualificationEvidenceEvent],
) -> Result<QualificationCommonReceiptClaims, String> {
    use QualificationEvidenceEventKind as Kind;
    use QualificationEvidenceEventPayload as Payload;

    if attempt.receipt_ids.len() > 2
        || attempt.operation_id.as_deref() != Some(projection.operation_id.as_str())
    {
        return Err("protected attempt has an invalid receipt roster".into());
    }
    let decisions = phase_events
        .iter()
        .copied()
        .filter(|event| {
            event.kind == Kind::DecisionDurable
                && event.operation_id.as_deref() == Some(projection.operation_id.as_str())
        })
        .collect::<Vec<_>>();
    let [decision] = decisions.as_slice() else {
        return Err("protected receipt claim has no unique durable decision".into());
    };
    let Payload::Decision {
        receipt_action_sha256,
        receipt_context_sha256,
        decision_class,
        decision_receipt_id,
        decision_receipt_bytes_sha256,
        decoded_claims_sha256: decision_claims_sha256,
        ..
    } = &decision.payload
    else {
        return Err("protected decision has the wrong receipt payload".into());
    };
    let executions = phase_events
        .iter()
        .copied()
        .filter(|event| {
            event.kind == Kind::ExecutionReceiptDurable
                && event.operation_id.as_deref() == Some(projection.operation_id.as_str())
        })
        .collect::<Vec<_>>();
    if executions.len() > 1 {
        return Err("protected operation has multiple execution receipts".into());
    }
    let execution = executions.first().copied();
    let decision_present = attempt.receipt_ids.first() == Some(decision_receipt_id);
    let execution_payload = execution
        .map(|event| match &event.payload {
            Payload::ExecutionReceipt {
                execution_receipt_id,
                receipt_bytes_sha256,
                decoded_claims_sha256,
                execution_result_sha256,
                execution_outcome,
            } => Ok((
                execution_receipt_id,
                receipt_bytes_sha256,
                decoded_claims_sha256,
                execution_result_sha256,
                execution_outcome,
            )),
            _ => Err("protected execution receipt has the wrong payload".to_owned()),
        })
        .transpose()?;
    let execution_present = match (attempt.receipt_ids.get(1), execution_payload) {
        (Some(actual), Some((expected, ..))) if actual == expected => true,
        (None, _) => false,
        _ => return Err("protected attempt receipt IDs differ from durable receipt events".into()),
    };
    if (!attempt.receipt_ids.is_empty() && !decision_present)
        || (attempt.receipt_ids.len() == 2 && !execution_present)
    {
        return Err("protected attempt receipt order is invalid".into());
    }
    let verified_once = |receipt_id: &str, bytes_sha256: &str, claims_sha256: &str| {
        phase_events
            .iter()
            .filter(|event| {
                event.kind == Kind::NativeReceiptVerified
                    && event.operation_id.as_deref() == Some(projection.operation_id.as_str())
                    && event.receipt_id.as_deref() == Some(receipt_id)
                    && matches!(
                        &event.payload,
                        Payload::ReceiptVerification {
                            receipt_bytes_sha256: verified_bytes,
                            decoded_claims_sha256: verified_claims,
                            ..
                        } if verified_bytes == bytes_sha256 && verified_claims == claims_sha256
                    )
            })
            .count()
            == 1
    };
    if decision_present
        && !verified_once(
            decision_receipt_id,
            decision_receipt_bytes_sha256,
            decision_claims_sha256,
        )
        || execution_present
            && !execution_payload
                .is_some_and(|(id, bytes, claims, ..)| verified_once(id, bytes, claims))
    {
        return Err("protected receipt claim lacks exact independent verification".into());
    }
    let value = QualificationCommonReceiptClaims {
        sequence,
        attempt_sequence: attempt.sequence,
        request_id: attempt.request_id.clone(),
        operation_id: projection.operation_id.clone(),
        profile: profile.to_owned(),
        connection_generation: projection.connection_generation.clone(),
        state: match attempt.receipt_ids.len() {
            0 => QualificationReceiptState::None,
            1 => QualificationReceiptState::DecisionOnly,
            2 => QualificationReceiptState::LinkedExecution,
            _ => return Err("protected receipt roster is invalid".into()),
        },
        decision_receipt_id: decision_present.then(|| decision_receipt_id.clone()),
        execution_receipt_id: execution_present.then(|| {
            execution_payload
                .expect("a matched execution receipt payload is present")
                .0
                .clone()
        }),
        decision_action_sha256: decision_present.then(|| receipt_action_sha256.clone()),
        decision_context_sha256: decision_present.then(|| receipt_context_sha256.clone()),
        decision_class: decision_present.then_some(*decision_class),
        execution_command_sha256: execution_present
            .then(|| projection.sealed_command_sha256.clone())
            .flatten(),
        execution_result_sha256: execution_present
            .then(|| execution_payload.and_then(|value| value.3.clone()))
            .flatten(),
        execution_outcome: execution_present
            .then(|| execution_payload.map(|value| *value.4))
            .flatten(),
    };
    value.validate().map_err(string_error)?;
    Ok(value)
}

#[cfg(target_os = "linux")]
fn prepare_row_runtime(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        plan_flag,
        plan_path,
        trust_flag,
        trust_path,
        receipt_flag,
        receipt_path,
        runtime_flag,
        runtime_root,
        cgroup_flag,
        cgroup_root,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "prepare-row-runtime"
        || plan_flag != "--plan"
        || trust_flag != "--source-trust"
        || receipt_flag != "--receipt-trust"
        || runtime_flag != "--runtime-root"
        || cgroup_flag != "--cgroup-root"
        || rustix::process::geteuid().as_raw() != 0
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let trust_bytes = read_bounded(Path::new(trust_path), MAX_SOURCE_TRUST_BYTES, false)?;
    let trust =
        QualificationEvidenceSourceTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    let receipt_bytes = read_bounded(Path::new(receipt_path), MAX_SOURCE_TRUST_BYTES, false)?;
    decode_receipt_trust_anchors(&receipt_bytes).map_err(string_error)?;
    let runtime_root = Path::new(runtime_root);
    let cgroup_root = Path::new(cgroup_root);
    require_new_normalized_directory(runtime_root, false)?;
    require_new_normalized_directory(cgroup_root, true)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    if now < plan.started_at_unix_seconds || now >= plan.deadline_at_unix_seconds {
        return Err("row runtime plan is outside its immutable interval".into());
    }
    let source_uid = |source| {
        trust
            .current_source_process_binding(
                source,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now,
            )
            .map(|(_, _, _, uid)| uid)
            .map_err(string_error)
    };
    let reader_uid = |source| {
        let (_, _, artifact, _) = trust
            .current_source_process_binding(
                source,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now,
            )
            .map_err(string_error)?;
        trust
            .fixed_source_process_binding(
                source,
                artifact,
                &plan.domain,
                plan.started_at_unix_seconds,
                plan.deadline_at_unix_seconds,
                now,
            )
            .map(|(_, _, _, _, _, uid)| uid)
            .map_err(string_error)
    };
    let supervisor_uid = source_uid(QualificationEvidenceSource::Supervisor)?;
    let journal_reader_uid = source_uid(QualificationEvidenceSource::JournalReader)?;
    let client_proxy_source_uid = source_uid(QualificationEvidenceSource::ClientProxy)?;
    let credential_broker_source_uid = source_uid(QualificationEvidenceSource::CredentialBroker)?;
    let profile_state_source_uid = source_uid(QualificationEvidenceSource::ProfileStateReader)?;
    let receipt_verifier_source_uid = source_uid(QualificationEvidenceSource::ReceiptVerifier)?;
    let provider_proxy_source_uid = source_uid(QualificationEvidenceSource::ProviderProxy)?;
    let provider_observer_source_uid = source_uid(QualificationEvidenceSource::ProviderObserver)?;
    let client_proxy_reader_uid = reader_uid(QualificationEvidenceSource::ClientProxy)?;
    let credential_broker_reader_uid = reader_uid(QualificationEvidenceSource::CredentialBroker)?;
    let profile_state_reader_uid = reader_uid(QualificationEvidenceSource::ProfileStateReader)?;
    let receipt_verifier_reader_uid = reader_uid(QualificationEvidenceSource::ReceiptVerifier)?;
    let provider_proxy_reader_uid = reader_uid(QualificationEvidenceSource::ProviderProxy)?;
    let provider_observer_reader_uid = reader_uid(QualificationEvidenceSource::ProviderObserver)?;

    create_owned_directory(
        runtime_root,
        plan.supervisor_controller_uid,
        plan.agent_gid,
        0o710,
    )?;
    create_owned_file(
        &runtime_root.join("ledger-plan.json"),
        &plan_bytes,
        plan.supervisor_controller_uid,
        plan.agent_gid,
    )?;
    create_owned_file(
        &runtime_root.join("source-trust.json"),
        &trust_bytes,
        plan.supervisor_controller_uid,
        plan.agent_gid,
    )?;
    create_owned_file(
        &runtime_root.join("receipt-trust.json"),
        &receipt_bytes,
        plan.supervisor_controller_uid,
        plan.agent_gid,
    )?;
    let role_directories = [
        ("supervisor", supervisor_uid),
        ("client-proxy-signer", client_proxy_source_uid),
        ("client-proxy-reader", client_proxy_reader_uid),
        ("journal-reader", journal_reader_uid),
        ("credential-broker-signer", credential_broker_source_uid),
        ("credential-broker-reader", credential_broker_reader_uid),
        ("credential-broker-store", credential_broker_reader_uid),
        ("profile-state-signer", profile_state_source_uid),
        ("profile-state-reader", profile_state_reader_uid),
        ("receipt-verifier-signer", receipt_verifier_source_uid),
        ("receipt-verifier-reader", receipt_verifier_reader_uid),
        ("provider-proxy-signer", provider_proxy_source_uid),
        ("provider-proxy-reader", provider_proxy_reader_uid),
        ("provider-observer-signer", provider_observer_source_uid),
        ("provider-observer-reader", provider_observer_reader_uid),
    ];
    for (name, uid) in role_directories {
        create_owned_directory(
            &runtime_root.join(name),
            uid,
            plan.agent_gid,
            if name == "credential-broker-store" {
                0o700
            } else {
                0o710
            },
        )?;
        create_owned_file(
            &runtime_root.join(name).join("ledger-plan.json"),
            &plan_bytes,
            uid,
            plan.agent_gid,
        )?;
        create_owned_file(
            &runtime_root.join(name).join("source-trust.json"),
            &trust_bytes,
            uid,
            plan.agent_gid,
        )?;
        if matches!(name, "journal-reader" | "receipt-verifier-reader") {
            create_owned_file(
                &runtime_root.join(name).join("receipt-trust.json"),
                &receipt_bytes,
                uid,
                plan.agent_gid,
            )?;
        }
    }
    create_owned_directory(
        &runtime_root.join("provider-proxy-reader").join("transport"),
        provider_proxy_reader_uid,
        plan.agent_gid,
        0o700,
    )?;
    create_owned_directory(
        &runtime_root
            .join("provider-observer-reader")
            .join("observe"),
        provider_observer_reader_uid,
        plan.agent_gid,
        0o700,
    )?;
    let mut scenario_ids = BTreeSet::new();
    for phase in &plan.phases {
        if !scenario_ids.insert(phase.scenario_id.clone()) {
            continue;
        }
        let scenario_root = runtime_root.join(&phase.scenario_id);
        create_owned_directory(
            &scenario_root,
            plan.supervisor_controller_uid,
            plan.agent_gid,
            0o711,
        )?;
        create_owned_directory(
            &scenario_root.join("state"),
            plan.agent_uid,
            plan.agent_gid,
            0o700,
        )?;
        create_owned_directory(
            &runtime_root
                .join("provider-proxy-reader")
                .join("transport")
                .join(&phase.scenario_id),
            provider_proxy_reader_uid,
            plan.agent_gid,
            0o700,
        )?;
        create_owned_directory(
            &runtime_root
                .join("provider-observer-reader")
                .join("observe")
                .join(&phase.scenario_id),
            provider_observer_reader_uid,
            plan.agent_gid,
            0o700,
        )?;
    }
    for phase in &plan.phases {
        let phase_root = runtime_root
            .join(&phase.scenario_id)
            .join(format!("phase-{}", phase.phase_index));
        create_owned_directory(
            &phase_root,
            plan.supervisor_controller_uid,
            plan.agent_gid,
            0o711,
        )?;
        for (name, uid) in [
            ("agent", plan.agent_uid),
            ("journal-reader", journal_reader_uid),
            ("client-proxy", client_proxy_reader_uid),
            ("credential-broker", credential_broker_reader_uid),
            ("profile-state-reader", profile_state_reader_uid),
            ("receipt-verifier", receipt_verifier_reader_uid),
            ("provider-proxy", provider_proxy_reader_uid),
            ("provider-observer", provider_observer_reader_uid),
        ] {
            create_owned_directory(&phase_root.join(name), uid, plan.agent_gid, 0o710)?;
        }
    }
    create_owned_directory(
        cgroup_root,
        plan.supervisor_controller_uid,
        plan.agent_gid,
        0o700,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_row_runtime(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        plan_flag,
        plan_path,
        runtime_flag,
        runtime_root,
        policy_flag,
        policy_root,
        cgroup_flag,
        cgroup_root,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "cleanup-row-runtime"
        || plan_flag != "--plan"
        || runtime_flag != "--runtime-root"
        || policy_flag != "--policy-root"
        || cgroup_flag != "--cgroup-root"
        || rustix::process::geteuid().as_raw() != 0
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let runtime_root = Path::new(runtime_root);
    let policy_root = Path::new(policy_root);
    let cgroup_root = Path::new(cgroup_root);
    if runtime_root == policy_root
        || !cgroup_root.starts_with("/sys/fs/cgroup")
        || cgroup_root == Path::new("/sys/fs/cgroup")
    {
        return Err("row cleanup roots are not distinct protected targets".into());
    }

    let (runtime_parent, runtime_name, runtime) = open_exact_cleanup_root(
        runtime_root,
        plan.supervisor_controller_uid,
        plan.agent_gid,
        0o710,
    )?;
    if read_owned_file_at(
        &runtime,
        "ledger-plan.json",
        262_144,
        plan.supervisor_controller_uid,
        plan.agent_gid,
        0o600,
    )? != plan_bytes
    {
        return Err("row runtime contains a different immutable ledger plan".into());
    }
    let (policy_parent, policy_name, policy) = open_exact_cleanup_root(policy_root, 0, 0, 0o700)?;
    if read_owned_file_at(&policy, "ledger-plan.json", 262_144, 0, 0, 0o600)? != plan_bytes {
        return Err("row policy contains a different immutable ledger plan".into());
    }

    cleanup_exact_cgroup(cgroup_root, plan.supervisor_controller_uid, plan.agent_gid)?;

    let mut remaining = 65_536_usize;
    let runtime_identity = runtime.metadata().map_err(string_error)?;
    remove_bounded_tree_contents(&runtime, runtime_identity.dev(), 0, &mut remaining)?;
    verify_cleanup_root_name(&runtime_parent, &runtime_name, &runtime)?;
    drop(runtime);
    unlinkat(&runtime_parent, runtime_name.as_str(), AtFlags::REMOVEDIR).map_err(string_error)?;
    runtime_parent.sync_all().map_err(string_error)?;

    let mut remaining = 4_096_usize;
    let policy_identity = policy.metadata().map_err(string_error)?;
    remove_bounded_tree_contents(&policy, policy_identity.dev(), 0, &mut remaining)?;
    verify_cleanup_root_name(&policy_parent, &policy_name, &policy)?;
    drop(policy);
    unlinkat(&policy_parent, policy_name.as_str(), AtFlags::REMOVEDIR).map_err(string_error)?;
    policy_parent.sync_all().map_err(string_error)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_protected_install(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        root_flag,
        root,
        agent_flag,
        agent_sha256,
        launcher_flag,
        launcher_sha256,
        config_flag,
        config_sha256,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "cleanup-protected-install"
        || root_flag != "--root"
        || agent_flag != "--agent-sha256"
        || launcher_flag != "--launcher-sha256"
        || config_flag != "--config-sha256"
        || rustix::process::geteuid().as_raw() != 0
        || ![agent_sha256, launcher_sha256, config_sha256]
            .iter()
            .all(|value| lower_hex_64(value))
    {
        return Err(usage());
    }
    let (parent, name, directory) = open_exact_cleanup_root(Path::new(root), 0, 0, 0o755)?;
    if directory_names(&directory, 4)?
        != [
            "agent.toml".to_owned(),
            "auths-qualification-agent".to_owned(),
            "qualification-agent-launcher".to_owned(),
        ]
    {
        return Err("protected install contains an unexpected member".into());
    }
    for (member, mode, expected) in [
        ("agent.toml", 0o644, config_sha256.as_str()),
        ("auths-qualification-agent", 0o755, agent_sha256.as_str()),
        (
            "qualification-agent-launcher",
            0o4755,
            launcher_sha256.as_str(),
        ),
    ] {
        let bytes = read_cleanup_install_member(&directory, member, mode)?;
        if hex::encode(Sha256::digest(bytes)) != expected {
            return Err("protected install member differs from its reviewed digest".into());
        }
    }
    for member in [
        "agent.toml",
        "auths-qualification-agent",
        "qualification-agent-launcher",
    ] {
        unlinkat(&directory, member, AtFlags::empty()).map_err(string_error)?;
    }
    directory.sync_all().map_err(string_error)?;
    verify_cleanup_root_name(&parent, &name, &directory)?;
    drop(directory);
    unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR).map_err(string_error)?;
    parent.sync_all().map_err(string_error)
}

#[cfg(target_os = "linux")]
fn read_cleanup_install_member(
    directory: &File,
    name: &str,
    expected_mode: u32,
) -> Result<Vec<u8>, String> {
    let mut file = File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let before = file.metadata().map_err(string_error)?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != expected_mode
        || before.len() == 0
        || before.len() > 268_435_456
    {
        return Err("protected install member identity is invalid".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(string_error)?);
    std::io::Read::by_ref(&mut file)
        .take(268_435_457)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after = file.metadata().map_err(string_error)?;
    let named = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(string_error)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
        || named.st_dev != after.dev()
        || named.st_ino != after.ino()
        || named.st_nlink != 1
    {
        return Err("protected install member changed while pinned".into());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn open_exact_cleanup_root(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(File, String, File), String> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("row cleanup root is not one normalized absolute child".into());
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| "row cleanup root has no parent".to_owned())?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| "row cleanup root name is invalid".to_owned())?
        .to_owned();
    let parent = open_directory_componentwise(parent_path)?;
    let directory = File::from(
        openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let metadata = directory.metadata().map_err(string_error)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != mode
    {
        return Err("row cleanup root differs from protected policy".into());
    }
    verify_cleanup_root_name(&parent, &name, &directory)?;
    Ok((parent, name, directory))
}

#[cfg(target_os = "linux")]
fn verify_cleanup_root_name(parent: &File, name: &str, directory: &File) -> Result<(), String> {
    let expected = directory.metadata().map_err(string_error)?;
    let actual = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(string_error)?;
    if FileType::from_raw_mode(actual.st_mode) != FileType::Directory
        || actual.st_dev != expected.dev()
        || actual.st_ino != expected.ino()
        || actual.st_uid != expected.uid()
        || actual.st_gid != expected.gid()
        || u32::from(actual.st_mode) & 0o777 != expected.mode() & 0o777
    {
        return Err("row cleanup root name changed while pinned".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_bounded_tree_contents(
    directory: &File,
    root_device: u64,
    depth: u8,
    remaining: &mut usize,
) -> Result<(), String> {
    if depth > 16 {
        return Err("row cleanup tree exceeds its depth bound".into());
    }
    for name in directory_names(directory, *remaining)? {
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| "row cleanup tree exceeds its member bound".to_owned())?;
        let before =
            statat(directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(string_error)?;
        match FileType::from_raw_mode(before.st_mode) {
            FileType::Directory => {
                let child = File::from(
                    openat(
                        directory,
                        name.as_str(),
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(string_error)?,
                );
                let identity = child.metadata().map_err(string_error)?;
                if identity.dev() != root_device
                    || identity.dev() != before.st_dev
                    || identity.ino() != before.st_ino
                {
                    return Err("row cleanup refuses a substituted or mounted directory".into());
                }
                remove_bounded_tree_contents(&child, root_device, depth + 1, remaining)?;
                let after = statat(directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(string_error)?;
                if FileType::from_raw_mode(after.st_mode) != FileType::Directory
                    || after.st_dev != before.st_dev
                    || after.st_ino != before.st_ino
                {
                    return Err("row cleanup directory changed while pinned".into());
                }
                drop(child);
                unlinkat(directory, name.as_str(), AtFlags::REMOVEDIR).map_err(string_error)?;
            }
            FileType::RegularFile | FileType::Socket | FileType::Fifo => {
                if before.st_nlink != 1 {
                    return Err("row cleanup refuses a multiply linked member".into());
                }
                unlinkat(directory, name.as_str(), AtFlags::empty()).map_err(string_error)?;
            }
            FileType::Symlink
            | FileType::CharacterDevice
            | FileType::BlockDevice
            | FileType::Unknown => {
                return Err("row cleanup refuses an unsafe filesystem member".into());
            }
        }
    }
    directory.sync_all().map_err(string_error)
}

#[cfg(target_os = "linux")]
fn cleanup_exact_cgroup(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let (parent, name, directory) = open_exact_cleanup_root(path, uid, gid, 0o700)?;
    match openat(
        &directory,
        "cgroup.kill",
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(descriptor) => File::from(descriptor)
            .write_all(b"1")
            .map_err(string_error)?,
        Err(error) if error == rustix::io::Errno::NOENT => {
            return Err("row cleanup requires cgroup v2 kill support".into());
        }
        Err(error) => return Err(string_error(error)),
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let events = read_small_virtual_file_at(&directory, "cgroup.events")?;
        let processes = read_small_virtual_file_at(&directory, "cgroup.procs")?;
        if events.lines().any(|line| line == "populated 0") && processes.trim().is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            return Err("row cgroup remained populated during exact cleanup".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut reader = rustix::fs::Dir::read_from(&directory).map_err(string_error)?;
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(string_error)?;
        let member = entry.file_name().to_str().map_err(string_error)?;
        if matches!(member, "." | "..") {
            continue;
        }
        let stat = statat(&directory, member, AtFlags::SYMLINK_NOFOLLOW).map_err(string_error)?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            return Err("row cgroup retains an unexpected child cgroup".into());
        }
    }
    drop(reader);
    verify_cleanup_root_name(&parent, &name, &directory)?;
    drop(directory);
    unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR).map_err(string_error)
}

#[cfg(target_os = "linux")]
fn read_small_virtual_file_at(directory: &File, name: &str) -> Result<String, String> {
    let mut file = File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    if bytes.len() > 4096 {
        return Err("row cgroup control file exceeds its bound".into());
    }
    String::from_utf8(bytes).map_err(string_error)
}

#[cfg(target_os = "linux")]
fn materialize_agent_signing_key(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        role_flag,
        role,
        plan_flag,
        plan_path,
        config_flag,
        config_path,
        runtime_flag,
        runtime_root,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "materialize-agent-signing-key"
        || role_flag != "--role"
        || plan_flag != "--plan"
        || config_flag != "--config"
        || runtime_flag != "--runtime-root"
        || rustix::process::geteuid().as_raw() != 0
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let config_bytes = read_bounded(Path::new(config_path), MAX_AGENT_CONFIG_BYTES, false)?;
    let config = AgentConfig::from_toml(
        std::str::from_utf8(&config_bytes).map_err(string_error)?,
        AgentPlatform::Linux,
    )
    .map_err(string_error)?;
    let (name, expected_public_key) = match role.as_str() {
        "decision" => (
            "qualification-decision.key",
            config.receipt_signing().decision().public_key_base64url(),
        ),
        "execution" => (
            "qualification-execution.key",
            config.receipt_signing().execution().public_key_base64url(),
        ),
        "recovery" => (
            "qualification-recovery.key",
            plan.recovery_public_key_base64url.as_str(),
        ),
        _ => return Err(usage()),
    };

    let runtime_root = Path::new(runtime_root);
    let runtime = open_directory_componentwise(runtime_root)?;
    let runtime_metadata = runtime.metadata().map_err(string_error)?;
    if !runtime_metadata.file_type().is_dir()
        || runtime_metadata.uid() != plan.supervisor_controller_uid
        || runtime_metadata.gid() != plan.agent_gid
        || runtime_metadata.mode() & 0o777 != 0o710
    {
        return Err("agent signing runtime root differs from the ledger plan".into());
    }
    if read_owned_file_at(
        &runtime,
        "ledger-plan.json",
        262_144,
        plan.supervisor_controller_uid,
        plan.agent_gid,
        0o600,
    )? != plan_bytes
    {
        return Err("agent signing runtime root contains a different ledger plan".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    if now < plan.started_at_unix_seconds || now >= plan.deadline_at_unix_seconds {
        return Err("agent signing plan is outside its immutable run interval".into());
    }
    let mut encoded = Zeroizing::new(String::new());
    std::io::stdin()
        .take(MAX_SEED_BYTES + 1)
        .read_to_string(&mut encoded)
        .map_err(string_error)?;
    while encoded.ends_with(['\r', '\n']) {
        encoded.pop();
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    let decoded = Base64UrlUnpadded::decode(&encoded, seed.as_mut())
        .map_err(|_| "agent signing seed is not canonical base64url".to_owned())?;
    if decoded.len() != seed.len()
        || Base64UrlUnpadded::encode_string(seed.as_ref()) != *encoded
        || seed.as_ref() == &[0_u8; 32]
    {
        return Err("agent signing seed is not one nonzero Ed25519 seed".into());
    }
    let actual_public_key =
        Base64UrlUnpadded::encode_string(SigningKey::from_bytes(&seed).verifying_key().as_bytes());
    if actual_public_key != expected_public_key {
        return Err("agent signing seed differs from its reviewed public key".into());
    }
    let scenarios = plan
        .phases
        .iter()
        .map(|phase| phase.scenario_id.as_str())
        .collect::<BTreeSet<_>>();
    if scenarios.is_empty() {
        return Err("agent signing plan has no scenario state directories".into());
    }
    for scenario in scenarios {
        let scenario_directory = File::from(
            openat(
                &runtime,
                scenario,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let state_directory = File::from(
            openat(
                &scenario_directory,
                "state",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
        let state_metadata = state_directory.metadata().map_err(string_error)?;
        if !state_metadata.file_type().is_dir()
            || state_metadata.uid() != plan.agent_uid
            || state_metadata.gid() != plan.agent_gid
            || state_metadata.mode() & 0o777 != 0o700
        {
            return Err("agent signing state directory differs from the ledger plan".into());
        }
        create_owned_seed_at_or_verify(
            &state_directory,
            name,
            &seed,
            plan.agent_uid,
            plan.agent_gid,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_owned_seed_at_or_verify(
    parent: &File,
    name: &str,
    expected: &[u8; 32],
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    if verify_owned_seed_at(parent, name, expected, uid, gid)? {
        remove_seed_stage_after_exact_publish(parent, name, expected, uid, gid)?;
        return Ok(());
    }

    let stage_name = format!(".{name}.installing");
    let mut stage = match openat(
        parent,
        stage_name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(descriptor) => File::from(descriptor),
        Err(error) if error == rustix::io::Errno::EXIST => {
            let mut stage = File::from(
                openat(
                    parent,
                    stage_name.as_str(),
                    OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(string_error)?,
            );
            let metadata = stage.metadata().map_err(string_error)?;
            let owner_is_staging = metadata.uid() == 0 && metadata.gid() == 0;
            let owner_is_published = metadata.uid() == uid && metadata.gid() == gid;
            let mut bytes = Zeroizing::new(Vec::with_capacity(33));
            std::io::Read::by_ref(&mut stage)
                .take(33)
                .read_to_end(&mut bytes)
                .map_err(string_error)?;
            if !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.mode() & 0o777 != 0o600
                || (!owner_is_staging && !owner_is_published)
                || bytes.len() > expected.len()
                || expected[..bytes.len()] != bytes[..]
                || (owner_is_published && bytes.len() != expected.len())
            {
                return Err("staged agent signing seed differs from protected policy".into());
            }
            verify_named_file_identity(parent, stage_name.as_str(), &stage)?;
            if bytes.len() == expected.len() {
                stage
            } else {
                unlinkat(parent, stage_name.as_str(), AtFlags::empty()).map_err(string_error)?;
                parent.sync_all().map_err(string_error)?;
                File::from(
                    openat(
                        parent,
                        stage_name.as_str(),
                        OFlags::RDWR
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::CLOEXEC
                            | OFlags::NOFOLLOW,
                        Mode::RUSR | Mode::WUSR,
                    )
                    .map_err(string_error)?,
                )
            }
        }
        Err(error) => return Err(string_error(error)),
    };
    let before = stage.metadata().map_err(string_error)?;
    if before.len() == 0 {
        stage.write_all(expected).map_err(string_error)?;
        stage.sync_all().map_err(string_error)?;
    }
    fchown(&stage, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(string_error)?;
    stage.sync_all().map_err(string_error)?;
    let installed = stage.metadata().map_err(string_error)?;
    if !installed.file_type().is_file()
        || installed.nlink() != 1
        || installed.uid() != uid
        || installed.gid() != gid
        || installed.mode() & 0o777 != 0o600
        || installed.len() != 32
    {
        return Err("staged agent signing seed differs from protected policy".into());
    }
    verify_named_file_identity(parent, stage_name.as_str(), &stage)?;
    match renameat_with(
        parent,
        stage_name.as_str(),
        parent,
        name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            parent.sync_all().map_err(string_error)?;
            if !verify_owned_seed_at(parent, name, expected, uid, gid)? {
                return Err("published agent signing seed is absent".into());
            }
            Ok(())
        }
        Err(error) if error == rustix::io::Errno::EXIST => {
            if !verify_owned_seed_at(parent, name, expected, uid, gid)? {
                return Err("existing agent signing seed differs from protected policy".into());
            }
            verify_named_file_identity(parent, stage_name.as_str(), &stage)?;
            unlinkat(parent, stage_name.as_str(), AtFlags::empty()).map_err(string_error)?;
            parent.sync_all().map_err(string_error)
        }
        Err(error) => Err(string_error(error)),
    }
}

#[cfg(target_os = "linux")]
fn verify_owned_seed_at(
    parent: &File,
    name: &str,
    expected: &[u8; 32],
    uid: u32,
    gid: u32,
) -> Result<bool, String> {
    match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => {
            let mut file = File::from(descriptor);
            let before = file.metadata().map_err(string_error)?;
            let mut actual = Zeroizing::new([0_u8; 32]);
            let mut trailing = [0_u8; 1];
            if !before.file_type().is_file()
                || before.nlink() != 1
                || before.uid() != uid
                || before.gid() != gid
                || before.mode() & 0o777 != 0o600
                || before.len() != 32
                || file.read_exact(actual.as_mut()).is_err()
                || file.read(&mut trailing).map_err(string_error)? != 0
                || actual.as_ref() != expected
            {
                return Err("existing agent signing seed differs from protected policy".into());
            }
            let after = file.metadata().map_err(string_error)?;
            let reopened = File::from(
                openat(
                    parent,
                    name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(string_error)?,
            );
            let named = reopened.metadata().map_err(string_error)?;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.len() != after.len()
                || before.uid() != after.uid()
                || before.gid() != after.gid()
                || before.mode() != after.mode()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
                || after.dev() != named.dev()
                || after.ino() != named.ino()
                || after.len() != named.len()
                || after.uid() != named.uid()
                || after.gid() != named.gid()
                || after.mode() != named.mode()
            {
                return Err("existing agent signing seed changed while pinned".into());
            }
            Ok(true)
        }
        Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
        Err(error) => Err(string_error(error)),
    }
}

#[cfg(target_os = "linux")]
fn verify_named_file_identity(parent: &File, name: &str, file: &File) -> Result<(), String> {
    let expected = file.metadata().map_err(string_error)?;
    let named = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let actual = named.metadata().map_err(string_error)?;
    if expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
        || expected.file_type() != actual.file_type()
        || expected.nlink() != actual.nlink()
        || expected.uid() != actual.uid()
        || expected.gid() != actual.gid()
        || expected.mode() != actual.mode()
        || expected.len() != actual.len()
        || expected.mtime() != actual.mtime()
        || expected.mtime_nsec() != actual.mtime_nsec()
        || expected.ctime() != actual.ctime()
        || expected.ctime_nsec() != actual.ctime_nsec()
    {
        return Err("agent signing seed name changed while pinned".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_seed_stage_after_exact_publish(
    parent: &File,
    name: &str,
    expected: &[u8; 32],
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let stage_name = format!(".{name}.installing");
    let mut stage = match openat(
        parent,
        stage_name.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => File::from(descriptor),
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
        Err(error) => return Err(string_error(error)),
    };
    let metadata = stage.metadata().map_err(string_error)?;
    let owner_is_staging = metadata.uid() == 0 && metadata.gid() == 0;
    let owner_is_published = metadata.uid() == uid && metadata.gid() == gid;
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    std::io::Read::by_ref(&mut stage)
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || (!owner_is_staging && !owner_is_published)
        || bytes.len() > expected.len()
        || expected[..bytes.len()] != bytes[..]
    {
        return Err("leftover agent signing stage differs from protected policy".into());
    }
    verify_named_file_identity(parent, stage_name.as_str(), &stage)?;
    unlinkat(parent, stage_name.as_str(), AtFlags::empty()).map_err(string_error)?;
    parent.sync_all().map_err(string_error)
}

#[cfg(target_os = "linux")]
fn read_owned_file_at(
    parent: &File,
    name: &str,
    maximum: u64,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<Vec<u8>, String> {
    let mut file = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let before = file.metadata().map_err(string_error)?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != uid
        || before.gid() != gid
        || before.mode() & 0o777 != mode
        || before.len() == 0
        || before.len() > maximum
    {
        return Err("protected row policy file identity is invalid".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(string_error)?);
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after = file.metadata().map_err(string_error)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
    {
        return Err("protected row policy file changed while read".into());
    }
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn materialize_agent_signing_key(_arguments: &[String]) -> Result<(), String> {
    Err("agent signing-key materialization requires Linux ownership".into())
}

#[cfg(target_os = "linux")]
fn require_new_normalized_directory(path: &Path, cgroup: bool) -> Result<(), String> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || path.exists()
        || (cgroup && (!path.starts_with("/sys/fs/cgroup") || path == Path::new("/sys/fs/cgroup")))
    {
        return Err("row runtime target is not one new normalized directory".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "row runtime target has no parent".to_owned())?;
    let parent = open_directory_componentwise(parent)?;
    let metadata = parent.metadata().map_err(string_error)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o002 != 0 {
        return Err("row runtime parent is not a protected directory".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_owned_directory(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    if uid == 0 || uid == u32::MAX || gid == 0 || gid == u32::MAX {
        return Err("row runtime directory identity is invalid".into());
    }
    fs::create_dir(path).map_err(string_error)?;
    chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(string_error)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(string_error)?;
    let metadata = fs::symlink_metadata(path).map_err(string_error)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != mode
    {
        return Err("row runtime directory differs from its requested identity".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_owned_file(path: &Path, bytes: &[u8], uid: u32, gid: u32) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > 4_194_304 || uid == 0 || gid == 0 {
        return Err("row runtime policy file identity or size is invalid".into());
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| "row runtime policy file has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "row runtime policy file has no name".to_owned())?;
    let parent = open_directory_componentwise(parent_path)?;
    let mut file = File::from(
        openat(
            &parent,
            Path::new(name),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(string_error)?,
    );
    fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(string_error)?;
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)?;
    parent.sync_all().map_err(string_error)?;
    let metadata = file.metadata().map_err(string_error)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != u64::try_from(bytes.len()).map_err(string_error)?
    {
        return Err("row runtime policy file differs from its requested identity".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn prepare_row_runtime(_arguments: &[String]) -> Result<(), String> {
    Err("protected row runtime preparation requires Linux ownership".into())
}

#[cfg(not(target_os = "linux"))]
fn cleanup_row_runtime(_arguments: &[String]) -> Result<(), String> {
    Err("protected row runtime cleanup requires Linux ownership".into())
}

#[cfg(not(target_os = "linux"))]
fn cleanup_protected_install(_arguments: &[String]) -> Result<(), String> {
    Err("protected qualification-install cleanup requires Linux ownership".into())
}

#[cfg(target_os = "linux")]
fn serve_append_session(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        plan_flag,
        plan_path,
        common_flag,
        common_root,
        trust_flag,
        trust_path,
        socket_flag,
        socket_path,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "serve-append-session"
        || plan_flag != "--plan"
        || common_flag != "--common-root"
        || trust_flag != "--source-trust"
        || socket_flag != "--socket"
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let source_context_sha256 = plan.source_context_sha256().map_err(string_error)?;
    let trust_bytes = read_bounded(Path::new(trust_path), MAX_SOURCE_TRUST_BYTES, false)?;
    let trust =
        QualificationEvidenceSourceTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    if rustix::process::geteuid().as_raw() != plan.supervisor_controller_uid {
        return Err("append sequencer used the wrong protected controller UID".into());
    }
    let provider_ledger = open_provider_ledger(Path::new(common_root), &plan)?;
    if read_private_file_at(&provider_ledger, "ledger-plan.json", 262_144)? != plan_bytes {
        return Err("append sequencer received a different provider-row plan".into());
    }

    let socket = Path::new(socket_path);
    validate_shared_socket_path(socket)?;
    let listener = UnixListener::bind(socket).map_err(string_error)?;
    let _socket_guard = SocketPathGuard(socket.to_owned());
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660)).map_err(string_error)?;
    listener.set_nonblocking(true).map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let remaining = plan
        .deadline_at_unix_seconds
        .checked_sub(now)
        .filter(|seconds| *seconds != 0)
        .ok_or_else(|| "append sequencer started outside the protected run interval".to_owned())?;
    let session_deadline = Instant::now() + Duration::from_secs(remaining);

    loop {
        let (mut stream, _) = loop {
            if Instant::now() >= session_deadline {
                return Err("append sequencer exceeded the protected run deadline".into());
            }
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        };
        stream.set_nonblocking(true).map_err(string_error)?;
        let peer = QualificationSourceSessionPeer::observe(&stream)?;
        let transaction_deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .map_or(session_deadline, |deadline| deadline.min(session_deadline));
        let policy_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(string_error)?
            .as_secs();
        let expected_source = if peer.uid() == plan.supervisor_controller_uid
            && peer.executable_sha256() == plan.supervisor_controller_artifact_sha256
        {
            QualificationEvidenceSource::Supervisor
        } else {
            trust
                .source_for_append_process(
                    peer.uid(),
                    peer.executable_sha256(),
                    &plan.domain,
                    plan.started_at_unix_seconds,
                    plan.deadline_at_unix_seconds,
                    policy_now,
                )
                .map_err(string_error)?
        };

        let transaction = read_source_session_frame_before(&mut stream, transaction_deadline)?
            .ok_or_else(|| "source reader closed before sending its append intent".to_owned())?;
        if transaction.len() != 33 || !matches!(transaction[0], 0 | 1) {
            return Err("source reader append mode and intent are malformed".into());
        }
        let retry = transaction[0] == 1;
        let intent = &transaction[1..];
        peer.verify_unchanged()?;

        let ledger_lock = acquire_ledger_lock(&provider_ledger)?;
        if read_private_file_optional(&provider_ledger, "finalization.json", MAX_EVENT_BYTES)?
            .is_some()
        {
            return Err("append sequencer cannot extend a finalized ledger".into());
        }
        let source_records = open_private_child_directory(&provider_ledger, "source-records")?;
        let index_root = open_private_child_directory(&provider_ledger, "event-markers")?;
        let rows = read_event_markers(&index_root)?;
        let retry_event = if retry {
            let events = read_indexed_events(
                &rows,
                &source_records,
                &source_context_sha256,
                &trust,
                &plan,
                policy_now,
            )?;
            validate_phase_prefix(&plan, &events, false)?;
            let complete = validate_phase_prefix(&plan, &events, true).is_ok();
            let mut matching = None;
            for (row, event) in rows.iter().zip(&events).rev() {
                if row.source != expected_source
                    || hex::decode(event.intent_sha256().map_err(string_error)?)
                        .map_err(string_error)?
                        != intent
                {
                    continue;
                }
                if matching.is_some() {
                    return Err("append retry intent matches multiple durable events".into());
                }
                let previous_sha256 =
                    hex::decode(&event.previous_event_sha256).map_err(string_error)?;
                if previous_sha256.len() != 32 {
                    return Err("durable retry event has a malformed previous hash".into());
                }
                let role =
                    open_private_child_directory(&source_records, source_token(expected_source))?;
                let previous_bytes = read_private_file_at(
                    &role,
                    &format!("{}.json", row.sequence),
                    MAX_EVENT_BYTES,
                )?;
                matching = Some((row.sequence, previous_sha256, previous_bytes, complete));
            }
            Some(matching.ok_or_else(|| "append retry has no matching durable event".to_owned())?)
        } else {
            None
        };
        let (sequence, previous_sha256) = if let Some((sequence, previous, _, _)) = &retry_event {
            (*sequence, previous.clone())
        } else {
            let sequence = u32::try_from(rows.len() + 1).map_err(string_error)?;
            let previous_sha256 = if let Some(previous) = rows.last() {
                let role =
                    open_private_child_directory(&source_records, source_token(previous.source))?;
                let bytes = read_private_file_at(
                    &role,
                    &format!("{}.json", previous.sequence),
                    MAX_EVENT_BYTES,
                )?;
                Sha256::digest(bytes).to_vec()
            } else {
                vec![0_u8; 32]
            };
            (sequence, previous_sha256)
        };
        let mut ordering = Vec::with_capacity(36);
        ordering.extend_from_slice(&sequence.to_be_bytes());
        ordering.extend_from_slice(&previous_sha256);
        write_source_session_frame_before(&mut stream, &ordering, transaction_deadline)?;
        if let Some((_, _, previous_bytes, complete)) = retry_event {
            write_source_session_frame_before(&mut stream, &previous_bytes, transaction_deadline)?;
            let marker_sha256 = Sha256::digest(
                serde_json_canonicalizer::to_vec(&QualificationLedgerEventIndexRowV1 {
                    sequence,
                    source: expected_source,
                })
                .map_err(string_error)?,
            );
            write_source_session_frame_before(
                &mut stream,
                marker_sha256.as_slice(),
                transaction_deadline,
            )?;
            drop(ledger_lock);
            if complete {
                return Ok(());
            }
            continue;
        }
        let event_bytes = read_source_session_frame_before(&mut stream, transaction_deadline)?
            .ok_or_else(|| "source reader closed before returning its signed event".to_owned())?;
        peer.verify_unchanged()?;
        let verification_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(string_error)?
            .as_secs();
        let unsigned_event: QualificationEvidenceEvent =
            serde_json::from_slice(&event_bytes).map_err(string_error)?;
        let event = QualificationEvidenceEvent::verify_json(
            &event_bytes,
            expected_source,
            &source_context_sha256,
            &trust,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            verification_now,
        )
        .map_err(string_error)?;
        if event.sequence != sequence
            || event.previous_event_sha256 != hex::encode(&previous_sha256)
            || event.source != unsigned_event.source
            || hex::decode(event.intent_sha256().map_err(string_error)?).map_err(string_error)?
                != intent
        {
            return Err(
                "source reader returned an event outside its locked append position".into(),
            );
        }
        let complete = append_verified_event_locked(
            &provider_ledger,
            &plan_bytes,
            &plan,
            &trust,
            &event_bytes,
            event,
            verification_now,
        )?;
        let marker_sha256 = Sha256::digest(
            serde_json_canonicalizer::to_vec(&QualificationLedgerEventIndexRowV1 {
                sequence,
                source: expected_source,
            })
            .map_err(string_error)?,
        );
        write_source_session_frame_before(
            &mut stream,
            marker_sha256.as_slice(),
            transaction_deadline,
        )?;
        drop(ledger_lock);
        if complete {
            return Ok(());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn serve_append_session(_arguments: &[String]) -> Result<(), String> {
    Err("authenticated append sequencing is supported only on Linux".into())
}

#[cfg(target_os = "linux")]
struct SocketPathGuard(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn validate_shared_socket_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("append sequencer socket path is not normalized and absolute".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "append sequencer socket has no parent".to_owned())?;
    let directory = open_directory_componentwise(parent)?;
    let metadata = directory.metadata().map_err(string_error)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.mode() & 0o777 != 0o710
    {
        return Err("append sequencer socket parent is not exact protected shared state".into());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(string_error(error)),
        Ok(_) => Err("append sequencer socket path already exists".into()),
    }
}

#[cfg(target_os = "linux")]
fn open_provider_ledger(
    common_root: &Path,
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<File, String> {
    let common_root = open_private_directory(common_root)?;
    let ledger_directory = ensure_private_child_directory(&common_root, "ledger")?;
    ensure_private_child_directory(&ledger_directory, &plan.provider_run_id)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn append_verified_event_locked(
    provider_ledger: &File,
    plan_bytes: &[u8],
    plan: &QualificationEvidenceLedgerPlanV1,
    trust: &QualificationEvidenceSourceTrustRegistry,
    event_bytes: &[u8],
    event: QualificationEvidenceEvent,
    now: u64,
) -> Result<bool, String> {
    let source_context_sha256 = plan.source_context_sha256().map_err(string_error)?;
    if read_private_file_at(&provider_ledger, "ledger-plan.json", 262_144)? != plan_bytes {
        return Err("ledger plan differs from the fixed provider-run plan".into());
    }
    if read_private_file_optional(&provider_ledger, "finalization.json", MAX_EVENT_BYTES)?.is_some()
    {
        return Err("signed source ledger is already durably finalized".into());
    }
    let source_records = ensure_private_child_directory(&provider_ledger, "source-records")?;
    let role_directory =
        ensure_private_child_directory(&source_records, source_token(event.source))?;
    let index_root = ensure_private_child_directory(&provider_ledger, "event-markers")?;
    let rows = read_event_markers(&index_root)?;
    let expected_sequence = u32::try_from(rows.len() + 1).map_err(string_error)?;
    if event.sequence != expected_sequence {
        if event.sequence == u32::try_from(rows.len()).map_err(string_error)?
            && rows
                .last()
                .is_some_and(|row| row.sequence == event.sequence && row.source == event.source)
            && read_private_file_at(
                &role_directory,
                &format!("{}.json", event.sequence),
                MAX_EVENT_BYTES,
            )? == event_bytes
        {
            let events = read_indexed_events(
                &rows,
                &source_records,
                &source_context_sha256,
                trust,
                plan,
                now,
            )?;
            return Ok(validate_phase_prefix(plan, &events, true).is_ok());
        }
        return Err("signed source event is not the exact next immutable sequence".into());
    }
    if let Some(previous) = rows.last() {
        let previous_role =
            open_private_child_directory(&source_records, source_token(previous.source))?;
        let previous_bytes = read_private_file_at(
            &previous_role,
            &format!("{}.json", previous.sequence),
            MAX_EVENT_BYTES,
        )?;
        let previous_event = QualificationEvidenceEvent::verify_json(
            &previous_bytes,
            previous.source,
            &source_context_sha256,
            trust,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
        if previous_event.sequence != previous.sequence
            || event.previous_event_sha256 != hex::encode(Sha256::digest(&previous_bytes))
            || (
                previous_event.scenario_id.as_str(),
                previous_event.phase_index,
            ) > (event.scenario_id.as_str(), event.phase_index)
        {
            return Err("signed source event does not extend the exact authenticated chain".into());
        }
    } else if event.previous_event_sha256 != "0".repeat(64) {
        return Err("first signed source event does not start the zero hash chain".into());
    }
    let mut prefix = read_indexed_events(
        &rows,
        &source_records,
        &source_context_sha256,
        trust,
        plan,
        now,
    )?;
    prefix.push(event.clone());
    validate_phase_prefix(plan, &prefix, false)?;
    let complete = validate_phase_prefix(plan, &prefix, true).is_ok();
    require_append_source_record_roster(
        &source_records,
        &rows,
        event.source,
        event.sequence,
        event_bytes,
    )?;

    write_atomic_new_at_or_verify(
        &role_directory,
        &format!("{}.json", event.sequence),
        event_bytes,
        MAX_EVENT_BYTES,
    )?;
    let marker = QualificationLedgerEventIndexRowV1 {
        sequence: event.sequence,
        source: event.source,
    };
    let marker_bytes = serde_json_canonicalizer::to_vec(&marker).map_err(string_error)?;
    if event.durable_ack_sha256 != hex::encode(Sha256::digest(&marker_bytes)) {
        return Err("signed source event does not commit its exact durable marker".into());
    }
    write_atomic_new_at_or_verify(
        &index_root,
        &format!("{}.json", marker.sequence),
        &marker_bytes,
        MAX_EVENT_BYTES,
    )?;
    Ok(complete)
}

fn build_event_index(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        plan_flag,
        plan_path,
        common_flag,
        common_root,
        trust_flag,
        trust_path,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "build-event-index"
        || plan_flag != "--plan"
        || common_flag != "--common-root"
        || trust_flag != "--source-trust"
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let source_context_sha256 = plan.source_context_sha256().map_err(string_error)?;
    let trust_bytes = read_bounded(Path::new(trust_path), MAX_SOURCE_TRUST_BYTES, false)?;
    let trust =
        QualificationEvidenceSourceTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    let common_root = open_private_directory(Path::new(common_root))?;
    let ledger_directory = open_private_child_directory(&common_root, "ledger")?;
    let provider_ledger = open_private_child_directory(&ledger_directory, &plan.provider_run_id)?;
    let _ledger_lock = acquire_ledger_lock(&provider_ledger)?;
    if read_private_file_at(&provider_ledger, "ledger-plan.json", 262_144)? != plan_bytes {
        return Err("ledger plan differs from the fixed provider-run plan".into());
    }
    let existing_finalization =
        if read_private_file_optional(&provider_ledger, "finalization.json", MAX_EVENT_BYTES)?
            .is_some()
        {
            Some(verify_existing_finalization(
                &provider_ledger,
                &plan_bytes,
                &plan,
            )?)
        } else {
            None
        };
    let index_root = open_private_child_directory(&provider_ledger, "event-markers")?;
    let events = read_event_markers(&index_root)?;
    if events.is_empty() {
        return Err("ledger event index cannot be empty".into());
    }
    let source_records = open_private_child_directory(&provider_ledger, "source-records")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let verification_time = existing_finalization
        .as_ref()
        .map_or(now, |finalization| finalization.completed_at_unix_seconds);
    let signed_events = read_indexed_events(
        &events,
        &source_records,
        &source_context_sha256,
        &trust,
        &plan,
        verification_time,
    )?;
    validate_phase_prefix(&plan, &signed_events, true)?;
    require_exact_source_record_roster(
        &source_records,
        &QualificationLedgerEventIndexV1 {
            schema: "auths.profile-qualification-evidence-event-index/1".into(),
            events: events.clone(),
        },
    )?;
    let index = QualificationLedgerEventIndexV1 {
        schema: "auths.profile-qualification-evidence-event-index/1".into(),
        events,
    };
    let bytes = serde_json_canonicalizer::to_vec(&index).map_err(string_error)?;
    let last = signed_events
        .last()
        .ok_or_else(|| "ledger event index cannot be empty".to_owned())?;
    let last_source_directory =
        open_private_child_directory(&source_records, source_token(last.source))?;
    let last_bytes = read_private_file_at(
        &last_source_directory,
        &format!("{}.json", last.sequence),
        MAX_EVENT_BYTES,
    )?;
    let completed_at_unix_seconds = if let Some(finalization) = existing_finalization {
        finalization.completed_at_unix_seconds
    } else {
        if now <= plan.started_at_unix_seconds || now > plan.deadline_at_unix_seconds {
            return Err("ledger finalization time is outside the protected run interval".into());
        }
        now
    };
    write_atomic_new_at_or_verify(
        &provider_ledger,
        "event-index.json",
        &bytes,
        MAX_EVENT_INDEX_BYTES,
    )?;
    let finalization = QualificationLedgerFinalizationV1 {
        schema: "auths.profile-qualification-evidence-ledger-finalization/1".into(),
        plan_sha256: hex::encode(Sha256::digest(&plan_bytes)),
        source_context_sha256,
        event_count: u32::try_from(signed_events.len()).map_err(string_error)?,
        last_event_sequence: last.sequence,
        last_event_sha256: hex::encode(Sha256::digest(last_bytes)),
        event_index_sha256: hex::encode(Sha256::digest(&bytes)),
        completed_at_unix_seconds,
    };
    let finalization_bytes =
        serde_json_canonicalizer::to_vec(&finalization).map_err(string_error)?;
    write_atomic_new_at_or_verify(
        &provider_ledger,
        "finalization.json",
        &finalization_bytes,
        MAX_EVENT_BYTES,
    )
}

fn seal_ledger(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        record_flag,
        record,
        trust_flag,
        trust,
        ledger_trust_flag,
        ledger_trust,
        output_flag,
        output,
        key_flag,
        key_id,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "seal-ledger"
        || record_flag != "--record"
        || trust_flag != "--source-trust"
        || ledger_trust_flag != "--ledger-trust"
        || output_flag != "--output"
        || key_flag != "--key-id"
    {
        return Err(usage());
    }
    let record_bytes = read_bounded(Path::new(record), MAX_RECORD_BYTES, true)?;
    let value: QualificationEvidenceLedgerRecord =
        serde_json::from_slice(&record_bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != record_bytes {
        return Err("ledger record is not exact canonical JSON".into());
    }
    value.validate().map_err(string_error)?;
    let trust_bytes = read_bounded(Path::new(trust), MAX_SOURCE_TRUST_BYTES, false)?;
    let source_trust =
        QualificationEvidenceSourceTrustRegistry::from_json(&trust_bytes).map_err(string_error)?;
    let ledger_trust_bytes = read_bounded(Path::new(ledger_trust), MAX_LEDGER_TRUST_BYTES, false)?;
    let ledger_trust = QualificationEvidenceLedgerTrustRegistry::from_json(&ledger_trust_bytes)
        .map_err(string_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    QualificationEvidenceLedger::validate_for_signing(
        &value,
        key_id,
        &source_trust,
        &ledger_trust,
        now,
    )
    .map_err(string_error)?;
    let mut seed = Zeroizing::new(String::new());
    std::io::stdin()
        .take(MAX_SEED_BYTES + 1)
        .read_to_string(&mut seed)
        .map_err(string_error)?;
    if u64::try_from(seed.len()).map_err(string_error)? > MAX_SEED_BYTES {
        return Err("ledger signing seed exceeds its hard bound".into());
    }
    let seed = seed.trim_end_matches(['\r', '\n']);
    let ledger = QualificationEvidenceLedger::sign_json(
        value,
        key_id,
        seed,
        &source_trust,
        &ledger_trust,
        now,
    )
    .map_err(string_error)?;
    write_new(Path::new(output), &ledger)
}

fn assemble_ledger(arguments: &[String]) -> Result<(), String> {
    let [
        command,
        plan_flag,
        plan_path,
        event_index_flag,
        event_index_path,
        common_flag,
        common_root,
        trust_flag,
        trust_path,
        output_flag,
        output_path,
    ] = arguments
    else {
        return Err(usage());
    };
    if command != "assemble-ledger"
        || plan_flag != "--plan"
        || event_index_flag != "--event-index"
        || common_flag != "--common-root"
        || trust_flag != "--source-trust"
        || output_flag != "--output"
    {
        return Err(usage());
    }
    let plan_bytes = read_bounded(Path::new(plan_path), 262_144, true)?;
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
    let source_context_sha256 = plan.source_context_sha256().map_err(string_error)?;
    let source_trust_bytes = read_bounded(Path::new(trust_path), MAX_SOURCE_TRUST_BYTES, false)?;
    let source_trust = QualificationEvidenceSourceTrustRegistry::from_json(&source_trust_bytes)
        .map_err(string_error)?;
    let index_bytes = read_bounded(Path::new(event_index_path), MAX_EVENT_INDEX_BYTES, true)?;
    let index: QualificationLedgerEventIndexV1 =
        serde_json::from_slice(&index_bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&index).map_err(string_error)? != index_bytes
        || index.schema != "auths.profile-qualification-evidence-event-index/1"
        || index.events.is_empty()
        || index.events.len() > 16_384
        || index
            .events
            .iter()
            .enumerate()
            .any(|(position, row)| row.sequence != u32::try_from(position + 1).unwrap_or(u32::MAX))
    {
        return Err("ledger event index is not exact canonical sequence order".into());
    }
    let common_root = open_private_directory(Path::new(common_root))?;
    let ledger_directory = open_private_child_directory(&common_root, "ledger")?;
    let provider_ledger = open_private_child_directory(&ledger_directory, &plan.provider_run_id)?;
    let _ledger_lock = acquire_ledger_lock(&provider_ledger)?;
    if read_private_file_at(&provider_ledger, "ledger-plan.json", 262_144)? != plan_bytes
        || read_private_file_at(&provider_ledger, "event-index.json", MAX_EVENT_INDEX_BYTES)?
            != index_bytes
    {
        return Err("ledger assembly inputs differ from the fixed finalized run".into());
    }
    let finalization = verify_existing_finalization(&provider_ledger, &plan_bytes, &plan)?;
    let source_records = open_private_child_directory(&provider_ledger, "source-records")?;
    let scenarios = open_private_child_directory(&common_root, "scenarios")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let mut events = Vec::with_capacity(index.events.len());
    for row in &index.events {
        let role_directory =
            open_private_child_directory(&source_records, source_token(row.source))?;
        let bytes = read_private_file_at(
            &role_directory,
            &format!("{}.json", row.sequence),
            MAX_EVENT_BYTES,
        )?;
        let event = QualificationEvidenceEvent::verify_json(
            &bytes,
            row.source,
            &source_context_sha256,
            &source_trust,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
        if event.sequence != row.sequence {
            return Err("signed source record differs from its indexed sequence".into());
        }
        events.push(event);
    }
    require_exact_source_record_roster(&source_records, &index)?;

    let mut phase_commitments = Vec::with_capacity(plan.phases.len());
    let mut phase_projections = Vec::with_capacity(plan.phases.len());
    let mut next = 0_usize;
    for phase in &plan.phases {
        let first = next;
        while let Some(event) = events.get(next) {
            if event.scenario_id != phase.scenario_id || event.phase_index != phase.phase_index {
                break;
            }
            if event.role != phase.role
                || event.profile != phase.profile
                || event.failpoint != phase.failpoint
            {
                return Err("signed event differs from its immutable phase plan".into());
            }
            next += 1;
        }
        if next == first {
            return Err("immutable phase plan has no signed source events".into());
        }
        let first_sequence = u32::try_from(first + 1).map_err(string_error)?;
        let last_sequence = u32::try_from(next).map_err(string_error)?;
        let scenario_directory = open_private_child_directory(&scenarios, &phase.scenario_id)?;
        let provider_directory =
            open_private_child_directory(&scenario_directory, &plan.provider_run_id)?;
        let phase_bytes = read_private_file_at(
            &provider_directory,
            &format!("{}.json", phase.phase_index),
            MAX_PHASE_BYTES,
        )?;
        let projection: QualificationCommonPhaseEvidence =
            serde_json::from_slice(&phase_bytes).map_err(string_error)?;
        if serde_json_canonicalizer::to_vec(&projection).map_err(string_error)? != phase_bytes
            || projection.schema != "auths.profile-qualification-common-phase-evidence/1"
            || projection.repository_id != plan.repository_id
            || projection.workflow_run_id != plan.run_id
            || projection.workflow_run_attempt != plan.run_attempt
            || projection.candidate_revision != plan.candidate_revision
            || projection.domain != plan.domain
            || projection.target != plan.target
            || projection.protected_environment != plan.protected_environment
            || projection.provider_run_id != plan.provider_run_id
            || projection.scenario_id != phase.scenario_id
            || projection.phase_index != phase.phase_index
            || projection.role != phase.role
            || projection.profile != phase.profile
            || projection.failpoint != phase.failpoint
            || projection.operation_plan_sha256 != phase.operation_plan_sha256
            || projection.ledger_id != plan.ledger_id
            || projection.session_nonce_sha256 != plan.session_nonce_sha256
            || projection.first_event_sequence != first_sequence
            || projection.last_event_sequence != last_sequence
            || projection.attempts.is_empty()
            || projection.instances.iter().any(|instance| {
                instance.projection.validate().is_err()
                    || instance
                        .receipt_claims
                        .iter()
                        .any(|claim| claim.validate().is_err())
            })
            || projection
                .attempts
                .iter()
                .any(|attempt| attempt.validate().is_err())
        {
            return Err("protected common phase projection differs from its signed phase".into());
        }
        phase_commitments.push(QualificationEvidencePhaseCommitment {
            scenario_id: phase.scenario_id.clone(),
            phase_index: phase.phase_index,
            role: phase.role,
            profile: phase.profile.clone(),
            failpoint: phase.failpoint,
            operation_plan_sha256: phase.operation_plan_sha256.clone(),
            credential_requirement: phase.credential_requirement.clone(),
            common_phase_evidence_sha256: hex::encode(Sha256::digest(&phase_bytes)),
            first_event_sequence: first_sequence,
            last_event_sequence: last_sequence,
        });
        phase_projections.push(projection);
    }
    if next != events.len() {
        return Err("signed source event roster has an unplanned phase".into());
    }
    require_exact_phase_roster(&scenarios, &plan)?;
    let record = QualificationEvidenceLedgerRecord {
        schema: "auths.profile-qualification-evidence-ledger-record/1".into(),
        repository_id: plan.repository_id,
        workflow_path: plan.workflow_path,
        workflow_revision: plan.workflow_revision,
        candidate_revision: plan.candidate_revision,
        attester_revision: plan.attester_revision,
        run_id: plan.run_id,
        run_attempt: plan.run_attempt,
        domain: plan.domain,
        target: plan.target,
        protected_environment: plan.protected_environment,
        provider_run_id: plan.provider_run_id,
        ledger_id: plan.ledger_id,
        session_nonce_sha256: plan.session_nonce_sha256,
        supervisor_controller_uid: plan.supervisor_controller_uid,
        supervisor_controller_artifact_sha256: plan.supervisor_controller_artifact_sha256,
        ledger_appender_artifact_sha256: plan.ledger_appender_artifact_sha256,
        agent_uid: plan.agent_uid,
        agent_gid: plan.agent_gid,
        agent_executable_sha256: plan.agent_executable_sha256,
        recovery_key_id: plan.recovery_key_id,
        recovery_public_key_base64url: plan.recovery_public_key_base64url,
        phase_commitments,
        events,
        started_at_unix_seconds: plan.started_at_unix_seconds,
        deadline_at_unix_seconds: plan.deadline_at_unix_seconds,
        completed_at_unix_seconds: finalization.completed_at_unix_seconds,
    };
    record.validate().map_err(string_error)?;
    for (commitment, projection) in record.phase_commitments.iter().zip(&phase_projections) {
        if !qualification_common_phase_matches_ledger(&record, commitment, projection)
            .map_err(string_error)?
        {
            return Err("common phase projection differs from authenticated source events".into());
        }
    }
    if record.source_context_sha256().map_err(string_error)? != source_context_sha256 {
        return Err("assembled ledger changed the immutable source context".into());
    }
    let bytes = serde_json_canonicalizer::to_vec(&record).map_err(string_error)?;
    write_new(Path::new(output_path), &bytes)
}

fn open_private_directory(path: &Path) -> Result<File, String> {
    let directory = open_directory_componentwise(path)?;
    let metadata = directory.metadata().map_err(string_error)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err("ledger assembly root is not an owner-only directory".into());
    }
    Ok(directory)
}

fn open_directory_componentwise(path: &Path) -> Result<File, String> {
    let mut directory = File::from(
        open(
            if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            },
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            _ => return Err("qualification supervisor path has an unsafe component".into()),
        };
        directory = File::from(
            openat(
                &directory,
                Path::new(name),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(string_error)?,
        );
    }
    Ok(directory)
}

fn open_private_child_directory(parent: &File, name: &str) -> Result<File, String> {
    if name.is_empty()
        || name.len() > 128
        || name.contains(['/', '\\'])
        || matches!(name, "." | "..")
    {
        return Err("ledger assembly directory name is invalid".into());
    }
    let directory = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let metadata = directory.metadata().map_err(string_error)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err("ledger assembly child is not an owner-only directory".into());
    }
    Ok(directory)
}

fn ensure_private_child_directory(parent: &File, name: &str) -> Result<File, String> {
    if name.is_empty()
        || name.len() > 128
        || name.contains(['/', '\\'])
        || matches!(name, "." | "..")
    {
        return Err("ledger assembly directory name is invalid".into());
    }
    match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => parent.sync_all().map_err(string_error)?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.to_string()),
    }
    open_private_child_directory(parent, name)
}

fn read_private_file_at(directory: &File, name: &str, maximum: u64) -> Result<Vec<u8>, String> {
    if name.is_empty()
        || name.len() > 128
        || name.contains(['/', '\\'])
        || matches!(name, "." | "..")
    {
        return Err("ledger assembly file name is invalid".into());
    }
    let mut file = File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let before = file.metadata().map_err(string_error)?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o077 != 0
        || before.len() > maximum
    {
        return Err("ledger assembly member is not one bounded owner-only file".into());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after = file.metadata().map_err(string_error)?;
    if u64::try_from(bytes.len()).map_err(string_error)? > maximum
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || after.len() != u64::try_from(bytes.len()).map_err(string_error)?
    {
        return Err("ledger assembly member changed while it was read".into());
    }
    Ok(bytes)
}

fn read_private_file_optional(
    directory: &File,
    name: &str,
    maximum: u64,
) -> Result<Option<Vec<u8>>, String> {
    match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => {
            drop(File::from(file));
            read_private_file_at(directory, name, maximum).map(Some)
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn acquire_ledger_lock(provider_ledger: &File) -> Result<LedgerLock, String> {
    let file = File::from(
        openat(
            provider_ledger,
            ".ledger.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(string_error)?,
    );
    let metadata = file.metadata().map_err(string_error)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 0
    {
        return Err("provider ledger lock is not the exact owner-only lock file".into());
    }
    flock(&file, FlockOperation::LockExclusive).map_err(string_error)?;
    Ok(LedgerLock { file })
}

fn directory_names(directory: &File, maximum: usize) -> Result<Vec<String>, String> {
    let mut reader = rustix::fs::Dir::read_from(directory).map_err(string_error)?;
    let mut names = Vec::new();
    while let Some(entry) = reader.read() {
        let entry = entry.map_err(string_error)?;
        let name = entry.file_name().to_str().map_err(string_error)?;
        if matches!(name, "." | "..") {
            continue;
        }
        if names.len() >= maximum {
            return Err("ledger assembly directory exceeds its entry bound".into());
        }
        names.push(name.to_owned());
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("ledger assembly directory repeats a member".into());
    }
    Ok(names)
}

fn read_event_markers(
    index_root: &File,
) -> Result<Vec<QualificationLedgerEventIndexRowV1>, String> {
    let names = directory_names(index_root, 16_384)?;
    let mut numbered = names
        .into_iter()
        .map(|name| {
            let token = name
                .strip_suffix(".json")
                .ok_or_else(|| "event-index marker name is invalid".to_owned())?;
            if token.is_empty()
                || token.len() > 5
                || !token.bytes().all(|byte| byte.is_ascii_digit())
                || token.starts_with('0')
            {
                return Err("event-index marker name is invalid".into());
            }
            let sequence = token.parse::<u32>().map_err(string_error)?;
            Ok((sequence, name))
        })
        .collect::<Result<Vec<_>, String>>()?;
    numbered.sort_by_key(|(sequence, _)| *sequence);
    let mut rows = Vec::with_capacity(numbered.len());
    for (position, (sequence, name)) in numbered.into_iter().enumerate() {
        if sequence != u32::try_from(position + 1).map_err(string_error)? {
            return Err("event-index marker sequence is not contiguous".into());
        }
        let bytes = read_private_file_at(index_root, &name, MAX_EVENT_BYTES)?;
        let row: QualificationLedgerEventIndexRowV1 =
            serde_json::from_slice(&bytes).map_err(string_error)?;
        if serde_json_canonicalizer::to_vec(&row).map_err(string_error)? != bytes
            || row.sequence != sequence
        {
            return Err("event-index marker is not exact canonical sequence metadata".into());
        }
        rows.push(row);
    }
    Ok(rows)
}

fn write_atomic_new_at_or_verify(
    directory: &File,
    name: &str,
    bytes: &[u8],
    maximum: u64,
) -> Result<(), String> {
    if u64::try_from(bytes.len()).map_err(string_error)? > maximum
        || name.is_empty()
        || name.len() > 128
        || name.contains(['/', '\\'])
        || matches!(name, "." | "..")
    {
        return Err("immutable ledger member name or size is invalid".into());
    }
    if let Some(existing) = read_private_file_optional(directory, name, maximum)? {
        return if existing == bytes {
            Ok(())
        } else {
            Err("immutable ledger member already exists with different bytes".into())
        };
    }
    let temporary_name = format!(".{name}.stage");
    match unlinkat(directory, temporary_name.as_str(), AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.to_string()),
    }
    let mut file = File::from(
        openat(
            directory,
            temporary_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(string_error)?,
    );
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(string_error);
    drop(file);
    if let Err(error) = result {
        let _ = unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
        return Err(error);
    }
    match renameat_with(
        directory,
        temporary_name.as_str(),
        directory,
        name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => directory.sync_all().map_err(string_error),
        Err(rustix::io::Errno::EXIST) => {
            let _ = unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
            if read_private_file_at(directory, name, maximum)? == bytes {
                Ok(())
            } else {
                Err("immutable ledger member already exists with different bytes".into())
            }
        }
        Err(error) => {
            let _ = unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
            Err(error.to_string())
        }
    }
}

fn read_indexed_events(
    rows: &[QualificationLedgerEventIndexRowV1],
    source_records: &File,
    source_context_sha256: &str,
    trust: &QualificationEvidenceSourceTrustRegistry,
    plan: &QualificationEvidenceLedgerPlanV1,
    now: u64,
) -> Result<Vec<QualificationEvidenceEvent>, String> {
    let mut events = Vec::with_capacity(rows.len());
    let mut previous_sha256 = "0".repeat(64);
    for (position, row) in rows.iter().enumerate() {
        if row.sequence != u32::try_from(position + 1).map_err(string_error)? {
            return Err("event index sequence is not contiguous".into());
        }
        let role_directory =
            open_private_child_directory(source_records, source_token(row.source))?;
        let bytes = read_private_file_at(
            &role_directory,
            &format!("{}.json", row.sequence),
            MAX_EVENT_BYTES,
        )?;
        let event = QualificationEvidenceEvent::verify_json(
            &bytes,
            row.source,
            source_context_sha256,
            trust,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
        if event.sequence != row.sequence || event.previous_event_sha256 != previous_sha256 {
            return Err("source event differs from the exact authenticated hash chain".into());
        }
        previous_sha256 = hex::encode(Sha256::digest(&bytes));
        events.push(event);
    }
    Ok(events)
}

fn validate_phase_prefix(
    plan: &QualificationEvidenceLedgerPlanV1,
    events: &[QualificationEvidenceEvent],
    complete: bool,
) -> Result<(), String> {
    if events.is_empty() {
        return Err("source event prefix cannot be empty".into());
    }
    let mut next = 0_usize;
    for phase in &plan.phases {
        if next == events.len() {
            return if complete {
                Err("finalized source events omit a planned phase".into())
            } else {
                Ok(())
            };
        }
        let first = next;
        while let Some(event) = events.get(next) {
            if event.scenario_id != phase.scenario_id || event.phase_index != phase.phase_index {
                break;
            }
            if event.role != phase.role
                || event.profile != phase.profile
                || event.failpoint != phase.failpoint
            {
                return Err("source event differs from its immutable phase plan".into());
            }
            next += 1;
        }
        if next == first
            || events[first].kind != QualificationEvidenceEventKind::ScenarioStarted
            || events[first..next]
                .iter()
                .filter(|event| event.kind == QualificationEvidenceEventKind::ScenarioStarted)
                .count()
                != 1
        {
            return Err("source event phase does not start exactly once".into());
        }
        let completed = events[first..next]
            .iter()
            .filter(|event| event.kind == QualificationEvidenceEventKind::ScenarioCompleted)
            .count();
        if completed > 1
            || completed == 1
                && events[next - 1].kind != QualificationEvidenceEventKind::ScenarioCompleted
        {
            return Err("source event phase has an invalid terminal boundary".into());
        }
        if next < events.len() && completed != 1 {
            return Err(
                "source event entered the next phase before closing the prior phase".into(),
            );
        }
        if completed == 1 {
            qualification_evidence_event_chain_valid(&events[..next]).map_err(string_error)?;
        }
        if next == events.len() {
            return if complete && completed != 1 {
                Err("final source event phase is not durably complete".into())
            } else if complete && phase != plan.phases.last().expect("plan is nonempty") {
                Err("finalized source events omit a planned phase".into())
            } else {
                Ok(())
            };
        }
    }
    Err("source event prefix contains an unplanned phase".into())
}

fn verify_existing_finalization(
    provider_ledger: &File,
    plan_bytes: &[u8],
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<QualificationLedgerFinalizationV1, String> {
    let finalization_bytes =
        read_private_file_at(provider_ledger, "finalization.json", MAX_EVENT_BYTES)?;
    let finalization: QualificationLedgerFinalizationV1 =
        serde_json::from_slice(&finalization_bytes).map_err(string_error)?;
    let index_bytes =
        read_private_file_at(provider_ledger, "event-index.json", MAX_EVENT_INDEX_BYTES)?;
    let index: QualificationLedgerEventIndexV1 =
        serde_json::from_slice(&index_bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&finalization).map_err(string_error)? != finalization_bytes
        || serde_json_canonicalizer::to_vec(&index).map_err(string_error)? != index_bytes
        || finalization.schema != "auths.profile-qualification-evidence-ledger-finalization/1"
        || finalization.plan_sha256 != hex::encode(Sha256::digest(plan_bytes))
        || finalization.source_context_sha256
            != plan.source_context_sha256().map_err(string_error)?
        || finalization.event_index_sha256 != hex::encode(Sha256::digest(&index_bytes))
        || finalization.event_count != u32::try_from(index.events.len()).map_err(string_error)?
        || finalization.completed_at_unix_seconds <= plan.started_at_unix_seconds
        || finalization.completed_at_unix_seconds > plan.deadline_at_unix_seconds
        || index.events.last().map(|row| row.sequence) != Some(finalization.last_event_sequence)
        || index.schema != "auths.profile-qualification-evidence-event-index/1"
        || index.events.is_empty()
        || index
            .events
            .iter()
            .enumerate()
            .any(|(position, row)| row.sequence != u32::try_from(position + 1).unwrap_or(u32::MAX))
    {
        return Err("ledger finalization marker differs from the immutable run".into());
    }
    let last = index.events.last().expect("checked nonempty");
    let source_records = open_private_child_directory(provider_ledger, "source-records")?;
    let role = open_private_child_directory(&source_records, source_token(last.source))?;
    let last_bytes =
        read_private_file_at(&role, &format!("{}.json", last.sequence), MAX_EVENT_BYTES)?;
    if finalization.last_event_sha256 != hex::encode(Sha256::digest(last_bytes)) {
        return Err("ledger finalization last-event commitment differs from retained bytes".into());
    }
    Ok(finalization)
}

fn require_exact_source_record_roster(
    source_records: &File,
    index: &QualificationLedgerEventIndexV1,
) -> Result<(), String> {
    let expected = index
        .events
        .iter()
        .map(|row| {
            (
                source_token(row.source).to_owned(),
                format!("{}.json", row.sequence),
            )
        })
        .collect::<BTreeSet<_>>();
    let expected_roles = expected
        .iter()
        .map(|(role, _)| role.clone())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let role_names = directory_names(source_records, 8)?;
    if role_names.iter().cloned().collect::<BTreeSet<_>>() != expected_roles {
        return Err("source-record role directory set differs from the event index".into());
    }
    for role in role_names {
        if !matches!(
            role.as_str(),
            "supervisor"
                | "client-proxy"
                | "journal-reader"
                | "credential-broker"
                | "profile-state-reader"
                | "provider-proxy"
                | "receipt-verifier"
                | "provider-observer"
        ) {
            return Err("source-record directory names an unknown role".into());
        }
        let directory = open_private_child_directory(source_records, &role)?;
        for name in directory_names(&directory, 16_384)? {
            actual.insert((role.clone(), name));
        }
    }
    if actual != expected {
        return Err("source-record directory differs from the exact signed event index".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_append_source_record_roster(
    source_records: &File,
    rows: &[QualificationLedgerEventIndexRowV1],
    next_source: QualificationEvidenceSource,
    next_sequence: u32,
    next_bytes: &[u8],
) -> Result<(), String> {
    let expected = rows
        .iter()
        .map(|row| {
            (
                source_token(row.source).to_owned(),
                format!("{}.json", row.sequence),
            )
        })
        .collect::<BTreeSet<_>>();
    let next = (
        source_token(next_source).to_owned(),
        format!("{next_sequence}.json"),
    );
    let mut allowed = expected.clone();
    allowed.insert(next.clone());
    let mut actual = BTreeSet::new();
    for role in directory_names(source_records, 8)? {
        if !matches!(
            role.as_str(),
            "supervisor"
                | "client-proxy"
                | "journal-reader"
                | "credential-broker"
                | "profile-state-reader"
                | "provider-proxy"
                | "receipt-verifier"
                | "provider-observer"
        ) {
            return Err("source-record directory names an unknown role".into());
        }
        let directory = open_private_child_directory(source_records, &role)?;
        for name in directory_names(&directory, 16_384)? {
            actual.insert((role.clone(), name));
        }
    }
    if actual != expected && actual != allowed {
        return Err("source-record directory contains an unindexed or conflicting event".into());
    }
    if actual == allowed {
        let role = open_private_child_directory(source_records, &next.0)?;
        if read_private_file_at(&role, &next.1, MAX_EVENT_BYTES)? != next_bytes {
            return Err("partially published source event differs from the retry".into());
        }
    }
    Ok(())
}

fn require_exact_phase_roster(
    scenarios: &File,
    plan: &QualificationEvidenceLedgerPlanV1,
) -> Result<(), String> {
    let expected = plan
        .phases
        .iter()
        .map(|phase| {
            (
                phase.scenario_id.clone(),
                format!("{}.json", phase.phase_index),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for scenario in directory_names(scenarios, 256)? {
        let scenario_directory = open_private_child_directory(scenarios, &scenario)?;
        let children = directory_names(&scenario_directory, 16)?;
        if children.binary_search(&plan.provider_run_id).is_err() {
            continue;
        }
        let provider_directory =
            open_private_child_directory(&scenario_directory, &plan.provider_run_id)?;
        for name in directory_names(&provider_directory, 8)? {
            actual.insert((scenario.clone(), name));
        }
    }
    if actual != expected {
        return Err("phase projection directory differs from the immutable plan".into());
    }
    Ok(())
}

const fn source_token(source: QualificationEvidenceSource) -> &'static str {
    match source {
        QualificationEvidenceSource::Supervisor => "supervisor",
        QualificationEvidenceSource::ClientProxy => "client-proxy",
        QualificationEvidenceSource::JournalReader => "journal-reader",
        QualificationEvidenceSource::CredentialBroker => "credential-broker",
        QualificationEvidenceSource::ProfileStateReader => "profile-state-reader",
        QualificationEvidenceSource::ProviderProxy => "provider-proxy",
        QualificationEvidenceSource::ReceiptVerifier => "receipt-verifier",
        QualificationEvidenceSource::ProviderObserver => "provider-observer",
    }
}

fn reject_secret_environment() -> Result<(), String> {
    if let Some((name, _)) = env::vars_os().next() {
        return Err(format!(
            "ledger sealer requires an empty inherited environment; found {}",
            name.to_string_lossy()
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, owner_only: bool) -> Result<Vec<u8>, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "qualification supervisor input has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "qualification supervisor input has no file name".to_owned())?;
    let parent = open_directory_componentwise(parent)?;
    let mut file = File::from(
        openat(
            &parent,
            Path::new(name),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(string_error)?,
    );
    let before = file.metadata().map_err(string_error)?;
    let permissions_invalid = if owner_only {
        before.mode() & 0o077 != 0
    } else {
        before.mode() & 0o022 != 0
    };
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || permissions_invalid
        || before.len() > maximum
    {
        return Err("qualification supervisor input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    if u64::try_from(bytes.len()).map_err(string_error)? > maximum {
        return Err("qualification supervisor input exceeds its hard bound".into());
    }
    let after = file.metadata().map_err(string_error)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || after.len() != u64::try_from(bytes.len()).map_err(string_error)?
    {
        return Err("qualification supervisor input changed while it was read".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "qualification supervisor output has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "qualification supervisor output has no file name".to_owned())?;
    let name = name
        .to_str()
        .ok_or_else(|| "qualification supervisor output file name is not UTF-8".to_owned())?;
    let parent_directory = open_directory_componentwise(parent)?;
    let parent_metadata = parent_directory.metadata().map_err(string_error)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != rustix::process::geteuid().as_raw()
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err("qualification supervisor output parent is not owner-only".into());
    }
    write_atomic_new_at_or_verify(&parent_directory, name, bytes, MAX_RECORD_BYTES)
}

fn usage() -> String {
    "usage: auths-qualification-supervisor <export-receipt-anchors --config-output <new-config> --anchors-output <new-anchors> --expected-sha256 <digest>|initialize-ledger --plan <canonical-plan> --common-root <owner-only-common-root> --source-trust <registry> --ledger-trust <registry>|prepare-row-runtime --plan <canonical-plan> --source-trust <registry> --receipt-trust <anchors> --runtime-root <new-runtime-root> --cgroup-root <new-delegated-cgroup-root>|cleanup-row-runtime --plan <canonical-plan> --runtime-root <prepared-row-runtime> --policy-root <root-owned-row-policy> --cgroup-root <delegated-cgroup-root>|cleanup-protected-install --root <protected-install-root> --agent-sha256 <digest> --launcher-sha256 <digest> --config-sha256 <digest>|materialize-agent-signing-key --role <decision|execution|recovery> --plan <canonical-plan> --config <public-agent-config> --runtime-root <prepared-row-runtime>|serve-append-session --plan <canonical-plan> --common-root <owner-only-common-root> --source-trust <registry> --socket <new-protected-unix-socket>|stage-common-phases --plan <canonical-plan> --candidate-collection <canonical-collection> --common-root <owner-only-common-root> --source-trust <registry> --receipt-trust <anchors>|build-event-index --plan <canonical-plan> --common-root <owner-only-common-root> --source-trust <registry>|assemble-ledger --plan <canonical-plan> --event-index <canonical-index> --common-root <owner-only-common-root> --source-trust <registry> --output <new-record>|seal-ledger --record <canonical-record> --source-trust <registry> --ledger-trust <registry> --output <new-path> --key-id <id>>; prepare-row-runtime is the root-only exact UID/GID topology and role-policy snapshot materializer and accepts no seed; cleanup-row-runtime removes only the exact plan-bound runtime, policy, and empty delegated cgroup through retained no-follow descriptors; cleanup-protected-install removes only the reviewed root-owned agent, launcher, and public configuration; materialize-agent-signing-key consumes exactly one base64url seed on stdin and writes only its fixed scenario-state handles; serve-append-session is the sole source-event writer and owns the provider-row lock while an authenticated reader obtains each signature; export-receipt-anchors reads one base64url public agent configuration from stdin, and seal-ledger reads its one seed from stdin".into()
}

fn lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_profile_kit::{
        QualificationEvidenceLedgerPlanV1, QualificationEvidencePhasePlanV1,
        QualificationOperationRole, QualificationTarget,
    };
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink},
    };

    #[test]
    fn inputs_are_one_open_nofollow_owner_only_snapshots() {
        let directory = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let input = directory.path().join("record.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&input)
            .unwrap();
        file.write_all(b"{}").unwrap();
        file.sync_all().unwrap();
        assert_eq!(read_bounded(&input, 2, true).unwrap(), b"{}");
        let link = directory.path().join("record-link.json");
        symlink(&input, &link).unwrap();
        assert!(read_bounded(&link, 2, true).is_err());
        assert!(read_bounded(&input, 1, true).is_err());
    }

    #[test]
    fn one_shot_source_append_is_not_a_command() {
        assert!(!usage().contains("append-source-event"));
    }

    #[test]
    fn output_never_clobbers_existing_evidence() {
        let directory = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = directory.path().join("ledger.json");
        write_new(&output, b"first").unwrap();
        assert!(write_new(&output, b"second").is_err());
        assert_eq!(fs::read(output).unwrap(), b"first");
    }

    #[test]
    fn event_markers_are_contiguous_canonical_and_immutable() {
        let directory = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = open_private_directory(directory.path()).unwrap();
        let first = QualificationLedgerEventIndexRowV1 {
            sequence: 1,
            source: QualificationEvidenceSource::ClientProxy,
        };
        let first_bytes = serde_json_canonicalizer::to_vec(&first).unwrap();
        write_atomic_new_at_or_verify(&root, "1.json", &first_bytes, MAX_EVENT_BYTES).unwrap();
        write_atomic_new_at_or_verify(&root, "1.json", &first_bytes, MAX_EVENT_BYTES).unwrap();
        assert_eq!(read_event_markers(&root).unwrap(), vec![first]);

        let wrong = QualificationLedgerEventIndexRowV1 {
            sequence: 2,
            source: QualificationEvidenceSource::ProviderProxy,
        };
        let wrong_bytes = serde_json_canonicalizer::to_vec(&wrong).unwrap();
        assert!(
            write_atomic_new_at_or_verify(&root, "1.json", &wrong_bytes, MAX_EVENT_BYTES).is_err()
        );
        write_atomic_new_at_or_verify(&root, "3.json", &wrong_bytes, MAX_EVENT_BYTES).unwrap();
        assert!(read_event_markers(&root).is_err());
    }

    #[test]
    fn atomic_publication_recovers_only_its_exact_staging_member() {
        let directory = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = open_private_directory(directory.path()).unwrap();
        let stage = directory.path().join(".event.json.stage");
        let mut partial = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)
            .unwrap();
        partial.write_all(b"partial").unwrap();
        partial.sync_all().unwrap();
        drop(partial);

        write_atomic_new_at_or_verify(&root, "event.json", b"complete", MAX_EVENT_BYTES).unwrap();
        assert_eq!(
            fs::read(directory.path().join("event.json")).unwrap(),
            b"complete"
        );
        assert!(!stage.exists());
        write_atomic_new_at_or_verify(&root, "event.json", b"complete", MAX_EVENT_BYTES).unwrap();
        assert!(
            write_atomic_new_at_or_verify(&root, "event.json", b"different", MAX_EVENT_BYTES)
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn agent_signing_seed_publication_is_retry_safe_and_rejects_foreign_names() {
        use rustix::process::{getegid, geteuid};

        let directory = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = open_private_directory(directory.path()).unwrap();
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();
        let expected = [0x5a; 32];
        let name = "qualification-decision.key";
        let stage = directory.path().join(format!(".{name}.installing"));

        let mut interrupted = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stage)
            .unwrap();
        interrupted.write_all(&expected[..13]).unwrap();
        interrupted.sync_all().unwrap();
        drop(interrupted);

        create_owned_seed_at_or_verify(&root, name, &expected, uid, gid).unwrap();
        assert_eq!(fs::read(directory.path().join(name)).unwrap(), expected);
        assert!(!stage.exists());
        create_owned_seed_at_or_verify(&root, name, &expected, uid, gid).unwrap();

        let different = [0xa5; 32];
        assert!(create_owned_seed_at_or_verify(&root, name, &different, uid, gid).is_err());

        let linked_name = "qualification-execution.key";
        fs::hard_link(
            directory.path().join(name),
            directory.path().join(linked_name),
        )
        .unwrap();
        assert!(create_owned_seed_at_or_verify(&root, linked_name, &expected, uid, gid).is_err());
        fs::remove_file(directory.path().join(linked_name)).unwrap();

        let symlink_name = "qualification-recovery.key";
        symlink(
            directory.path().join(name),
            directory.path().join(symlink_name),
        )
        .unwrap();
        assert!(create_owned_seed_at_or_verify(&root, symlink_name, &expected, uid, gid).is_err());
    }

    #[test]
    fn assembly_rosters_reject_orphaned_source_and_phase_members() {
        let root = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for relative in [
            "ledger",
            "ledger/provider-run",
            "ledger/provider-run/source-records",
            "ledger/provider-run/source-records/client-proxy",
            "scenarios",
            "scenarios/happy-path",
            "scenarios/happy-path/provider-run",
        ] {
            let path = root.path().join(relative);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let write_member = |relative: &str| {
            let path = root.path().join(relative);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(b"{}").unwrap();
            file.sync_all().unwrap();
        };
        write_member("ledger/provider-run/source-records/client-proxy/1.json");
        write_member("scenarios/happy-path/provider-run/1.json");
        let root_directory = open_private_directory(root.path()).unwrap();
        let ledger = open_private_child_directory(&root_directory, "ledger").unwrap();
        let provider = open_private_child_directory(&ledger, "provider-run").unwrap();
        let records = open_private_child_directory(&provider, "source-records").unwrap();
        let scenarios = open_private_child_directory(&root_directory, "scenarios").unwrap();
        let index = QualificationLedgerEventIndexV1 {
            schema: "auths.profile-qualification-evidence-event-index/1".into(),
            events: vec![QualificationLedgerEventIndexRowV1 {
                sequence: 1,
                source: QualificationEvidenceSource::ClientProxy,
            }],
        };
        let plan = QualificationEvidenceLedgerPlanV1 {
            schema: "auths.profile-qualification-evidence-ledger-plan/1".into(),
            repository_id: "1".into(),
            workflow_path: ".github/workflows/profile-qualification-stripe.yml".into(),
            workflow_revision: "1".repeat(40),
            candidate_revision: "2".repeat(40),
            attester_revision: "3".repeat(40),
            run_id: "4".into(),
            run_attempt: 1,
            domain: "stripe".into(),
            target: QualificationTarget::LinuxX86_64,
            protected_environment: "stripe-qualification".into(),
            provider_run_id: "provider-run".into(),
            ledger_id: "ledger-run".into(),
            session_nonce_sha256: "4".repeat(64),
            supervisor_controller_uid: 1000,
            supervisor_controller_artifact_sha256: "5".repeat(64),
            ledger_appender_artifact_sha256: "7".repeat(64),
            agent_uid: 1001,
            agent_gid: 1001,
            agent_executable_sha256: "6".repeat(64),
            recovery_key_id: "recovery".into(),
            recovery_public_key_base64url: Base64UrlUnpadded::encode_string(&[9; 32]),
            phases: vec![QualificationEvidencePhasePlanV1 {
                scenario_id: "happy-path".into(),
                phase_index: 1,
                role: QualificationOperationRole::Effect,
                profile: "auths.stripe.refund/1".into(),
                failpoint: None,
                operation_plan_sha256: "5".repeat(64),
                credential_requirement: auths_profile_kit::QualificationCredentialRequirementV1 {
                    workload_id_sha256: "8".repeat(64),
                    provider_kind: "stripe".into(),
                    contract: "auths.stripe.connection/1".into(),
                    descriptor_schema: "auths.stripe.connection-descriptor/1".into(),
                    credential_scope: "stripe.refunds.write/1".into(),
                },
            }],
            started_at_unix_seconds: 10,
            deadline_at_unix_seconds: 20,
        };
        require_exact_source_record_roster(&records, &index).unwrap();
        require_exact_phase_roster(&scenarios, &plan).unwrap();

        write_member("ledger/provider-run/source-records/client-proxy/2.json");
        assert!(require_exact_source_record_roster(&records, &index).is_err());
        write_member("scenarios/happy-path/provider-run/2.json");
        assert!(require_exact_phase_roster(&scenarios, &plan).is_err());
    }

    #[test]
    fn assembly_never_follows_an_intermediate_directory_symlink() {
        let root = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let outside = tempfile::tempdir_in(".").unwrap();
        fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700)).unwrap();
        symlink(outside.path(), root.path().join("ledger")).unwrap();
        let root_directory = open_private_directory(root.path()).unwrap();
        assert!(open_private_child_directory(&root_directory, "ledger").is_err());

        let outside_file = outside.path().join("input.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&outside_file)
            .unwrap();
        file.write_all(b"{}").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(read_bounded(&root.path().join("ledger/input.json"), 2, true).is_err());
        assert!(write_new(&root.path().join("ledger/output.json"), b"{}").is_err());
    }
}
