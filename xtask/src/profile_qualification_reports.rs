use crate::prelude::*;
use auths_profile_kit::{
    QualificationCounters, QualificationEffect, QualificationFailpoint, QualificationOperationRole,
    QualificationReceiptState, QualificationRedactedAttempt,
};

const MAX_REPORT_BYTES: usize = 16_777_216;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReportBinding {
    pub(crate) repository_id: String,
    pub(crate) workflow_run_id: String,
    pub(crate) workflow_run_attempt: u32,
    pub(crate) candidate_revision: String,
    pub(crate) domain: String,
    pub(crate) target: String,
    pub(crate) profiles: Vec<String>,
    pub(crate) provider_run_ids: Vec<String>,
    pub(crate) scenario_ids: Vec<String>,
    pub(crate) failpoints: Vec<QualificationFailpoint>,
    pub(crate) operation_ids: Vec<String>,
    pub(crate) connection_generations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedReportBinding {
    pub(crate) repository_id: String,
    pub(crate) workflow_run_id: String,
    pub(crate) workflow_run_attempt: u32,
    pub(crate) candidate_revision: String,
    pub(crate) domain: String,
    pub(crate) target: String,
    pub(crate) profiles: Vec<String>,
    pub(crate) provider_run_ids: Vec<String>,
    pub(crate) scenario_ids: Vec<String>,
    pub(crate) failpoints: Vec<QualificationFailpoint>,
    pub(crate) operation_ids: Vec<String>,
    pub(crate) connection_generations: Vec<String>,
    pub(crate) scenario_applicability: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CleanupReport {
    schema: String,
    pub(crate) binding: ReportBinding,
    status: String,
    provider_resources_destroyed: bool,
    connection_disabled: bool,
    credentials_revoked: bool,
    residual_resource_count: u32,
    completed_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CountersReport {
    schema: String,
    pub(crate) binding: ReportBinding,
    pub(crate) operations: Vec<CounterOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CounterOperation {
    pub(crate) operation_id: String,
    pub(crate) counters: QualificationCounters,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderTruthReport {
    schema: String,
    pub(crate) binding: ReportBinding,
    pub(crate) operations: Vec<ProviderTruthOperation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderTruthOperation {
    pub(crate) operation_id: String,
    pub(crate) provider_run_id: String,
    pub(crate) provider_version: String,
    pub(crate) provider_artifact_sha256: String,
    pub(crate) effect: QualificationEffect,
    pub(crate) provider_calls: u32,
    pub(crate) commitment_sha256: String,
    pub(crate) domain_facts: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScenarioReport {
    schema: String,
    pub(crate) binding: ReportBinding,
    pub(crate) scenario_id: String,
    pub(crate) assertions: u32,
    pub(crate) executions: Vec<ScenarioExecution>,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScenarioExecution {
    pub(crate) provider_run_id: String,
    pub(crate) operations: Vec<ScenarioOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScenarioOperation {
    pub(crate) role: QualificationOperationRole,
    pub(crate) profile: String,
    pub(crate) instances: Vec<ScenarioOperationInstance>,
    pub(crate) attempts: Vec<QualificationRedactedAttempt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScenarioOperationInstance {
    pub(crate) operation_id: String,
    pub(crate) connection_generation: String,
    pub(crate) principal_sha256: String,
    pub(crate) connection_alias_sha256: Option<String>,
    pub(crate) connection_id_sha256: Option<String>,
    pub(crate) connection_descriptor_sha256: Option<String>,
    pub(crate) connection_account_sha256: Option<String>,
    pub(crate) credential_scope_sha256: Option<String>,
    pub(crate) canonical_input_sha256: String,
    pub(crate) idempotency_sha256: Option<String>,
    pub(crate) canonical_action_sha256: String,
    pub(crate) receipt_action_sha256: String,
    pub(crate) receipt_context_sha256: String,
    pub(crate) authority_sha256: String,
    pub(crate) configuration_sha256: String,
    pub(crate) runtime_contract_sha256: String,
    pub(crate) preparation_sha256: String,
    pub(crate) decision_class: auths_profile_kit::QualificationReceiptDecisionClass,
    pub(crate) reconciled: bool,
    pub(crate) failpoint: Option<QualificationFailpoint>,
    pub(crate) effect: QualificationEffect,
    pub(crate) counters: QualificationCounters,
    pub(crate) provider_truth_sha256: String,
    pub(crate) sealed_command_sha256: Option<String>,
    pub(crate) provider_result_sha256: Option<String>,
    pub(crate) execution_result_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReceiptsReport {
    schema: String,
    pub(crate) binding: ReportBinding,
    pub(crate) language: String,
    portable_receipt_schema: String,
    pub(crate) operations: Vec<ReceiptOperation>,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReceiptOperation {
    pub(crate) operation_id: String,
    pub(crate) state: QualificationReceiptState,
    pub(crate) decision_receipt_id: Option<String>,
    pub(crate) execution_receipt_id: Option<String>,
    pub(crate) decision_verification_method: Option<String>,
    pub(crate) execution_verification_method: Option<String>,
    pub(crate) linked: bool,
    pub(crate) profile_claims_match: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstalledPackagesReport {
    schema: String,
    pub(crate) binding: InstalledReportBinding,
    fixture_set_sha256: String,
    mutation_corpus_sha256: String,
    pub(crate) toolchain: Toolchain,
    packages: Vec<InstalledPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstalledReportBinding {
    pub(crate) candidate_revision: String,
    pub(crate) domain: String,
    pub(crate) target: String,
    pub(crate) profiles: Vec<String>,
    pub(crate) provider_run_ids: Vec<String>,
    pub(crate) scenario_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Toolchain {
    pub(crate) rust: String,
    pub(crate) node: String,
    pub(crate) python: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstalledPackage {
    language: String,
    name: String,
    artifact_sha256: String,
    consumer_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScanReport {
    schema: String,
    pub(crate) binding: ReportBinding,
    scan_kind: String,
    tool: String,
    version: String,
    status: String,
    scanned_file_count: u32,
    finding_count: u32,
    redacted_value_count: u32,
    unredacted_sensitive_value_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProvenanceReport {
    schema: String,
    pub(crate) binding: ReportBinding,
    workflow_path: String,
    workflow_revision: String,
    collector_revision: String,
    observer_revision: String,
    attester_revision: String,
    runner_label: String,
    runner_image_release: String,
    pinned_actions: Vec<NamedRevision>,
    installed_artifacts: Vec<NamedDigest>,
    failpoint_build_sha256: String,
    production_build_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedRevision {
    name: String,
    revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedDigest {
    name: String,
    sha256: String,
}

pub(crate) fn parse_canonical<T>(bytes: &[u8]) -> Result<T, String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_REPORT_BYTES {
        return Err("qualification report exceeds its byte bound".into());
    }
    let value: T = serde_json::from_slice(bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes {
        return Err("qualification report is not canonical JCS".into());
    }
    Ok(value)
}

impl ReportBinding {
    pub(crate) fn require_exact(&self, expected: &ExpectedReportBinding) -> Result<(), String> {
        if self.repository_id != expected.repository_id
            || self.workflow_run_id != expected.workflow_run_id
            || self.workflow_run_attempt != expected.workflow_run_attempt
            || self.candidate_revision != expected.candidate_revision
            || self.domain != expected.domain
            || self.target != expected.target
            || self.profiles != expected.profiles
            || self.provider_run_ids != expected.provider_run_ids
            || self.scenario_ids != expected.scenario_ids
            || self.failpoints != expected.failpoints
            || self.operation_ids != expected.operation_ids
            || self.connection_generations != expected.connection_generations
            || !sorted_unique(&self.profiles)
            || !sorted_unique(&self.provider_run_ids)
            || !sorted_unique(&self.scenario_ids)
            || !sorted_unique(&self.operation_ids)
            || !sorted_unique(&self.connection_generations)
            || !self
                .failpoints
                .windows(2)
                .all(|pair| failpoint_token(pair[0]) < failpoint_token(pair[1]))
        {
            return Err("qualification report binding differs from the protected run".into());
        }
        Ok(())
    }
}

impl CleanupReport {
    pub(crate) fn validate(&self, expected: &ExpectedReportBinding) -> Result<(), String> {
        self.binding.require_exact(expected)?;
        if self.schema != "auths.profile-qualification-cleanup-report/1"
            || self.status != "passed"
            || !self.provider_resources_destroyed
            || !self.connection_disabled
            || !self.credentials_revoked
            || self.residual_resource_count != 0
            || self.completed_at_unix_seconds == 0
        {
            return Err("qualification cleanup report is invalid".into());
        }
        Ok(())
    }

    pub(crate) const fn completed_at_unix_seconds(&self) -> u64 {
        self.completed_at_unix_seconds
    }
}

impl CountersReport {
    pub(crate) fn validate(&self, expected: &ExpectedReportBinding) -> Result<(), String> {
        self.binding.require_exact(expected)?;
        if self.schema != "auths.profile-qualification-counters-report/1"
            || self.operations.len() != expected.operation_ids.len()
            || self
                .operations
                .iter()
                .map(|operation| operation.operation_id.as_str())
                .ne(expected.operation_ids.iter().map(String::as_str))
        {
            return Err("qualification counter report is incomplete or unsorted".into());
        }
        Ok(())
    }
}

impl ProviderTruthReport {
    pub(crate) fn validate(
        &self,
        expected: &ExpectedReportBinding,
        domain: &str,
    ) -> Result<(), String> {
        self.binding.require_exact(expected)?;
        if self.schema != "auths.profile-qualification-provider-truth-report/1"
            || self.operations.len() != expected.operation_ids.len()
            || self
                .operations
                .iter()
                .map(|operation| operation.operation_id.as_str())
                .ne(expected.operation_ids.iter().map(String::as_str))
        {
            return Err("qualification provider-truth report is incomplete or unsorted".into());
        }
        for operation in &self.operations {
            if !expected
                .provider_run_ids
                .contains(&operation.provider_run_id)
                || operation.provider_version.is_empty()
                || operation.provider_version.len() > 128
                || !operation.provider_version.is_ascii()
                || !digest(&operation.provider_artifact_sha256)
                || !digest(&operation.commitment_sha256)
            {
                return Err("qualification provider-truth commitment is malformed".into());
            }
            validate_domain_facts(domain, operation)?;
        }
        Ok(())
    }
}

impl ScenarioReport {
    pub(crate) fn validate(&self, expected: &ExpectedReportBinding) -> Result<(), String> {
        self.binding.require_exact(expected)?;
        if self.schema != "auths.profile-qualification-scenario-report/1"
            || self.status != "passed"
            || !(1..=100_000).contains(&self.assertions)
            || !expected.scenario_ids.contains(&self.scenario_id)
            || self.executions.is_empty()
            || self.executions.len() > 16
            || !self
                .executions
                .windows(2)
                .all(|pair| pair[0].provider_run_id < pair[1].provider_run_id)
            || self.executions.iter().any(|execution| {
                !expected
                    .provider_run_ids
                    .contains(&execution.provider_run_id)
                    || execution.operations.is_empty()
                    || execution.operations.len() > 8
                    || !execution.operations.windows(2).all(|pair| {
                        (pair[0].role, pair[0].profile.as_str())
                            < (pair[1].role, pair[1].profile.as_str())
                    })
                    || execution.operations.iter().any(|operation| {
                        let instance_ids = operation
                            .instances
                            .iter()
                            .map(|instance| instance.operation_id.as_str())
                            .collect::<BTreeSet<_>>();
                        !expected.profiles.contains(&operation.profile)
                            || operation.instances.len() > 8
                            || !operation
                                .instances
                                .windows(2)
                                .all(|pair| pair[0].operation_id < pair[1].operation_id)
                            || operation.instances.iter().any(|instance| {
                                !expected.operation_ids.contains(&instance.operation_id)
                                    || !expected
                                        .connection_generations
                                        .contains(&instance.connection_generation)
                                    || !digest(&instance.principal_sha256)
                                    || instance
                                        .connection_alias_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || instance
                                        .connection_id_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || instance
                                        .connection_descriptor_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || instance
                                        .connection_account_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || instance
                                        .credential_scope_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || !digest(&instance.canonical_input_sha256)
                                    || instance
                                        .idempotency_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || !digest(&instance.canonical_action_sha256)
                                    || !digest(&instance.receipt_action_sha256)
                                    || !digest(&instance.receipt_context_sha256)
                                    || !digest(&instance.authority_sha256)
                                    || !digest(&instance.configuration_sha256)
                                    || !digest(&instance.runtime_contract_sha256)
                                    || !digest(&instance.preparation_sha256)
                                    || !digest(&instance.provider_truth_sha256)
                                    || instance
                                        .sealed_command_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || instance
                                        .provider_result_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || instance
                                        .execution_result_sha256
                                        .as_deref()
                                        .is_some_and(|value| !digest(value))
                                    || !instance.counters.valid_for_instance(
                                        instance.effect,
                                        instance.sealed_command_sha256.is_some(),
                                        instance.provider_result_sha256.is_some(),
                                        instance.reconciled,
                                    )
                            })
                            || operation.attempts.is_empty()
                            || operation.attempts.len() > 8
                            || operation
                                .attempts
                                .iter()
                                .enumerate()
                                .any(|(index, attempt)| {
                                    attempt.sequence != u8::try_from(index + 1).unwrap_or(u8::MAX)
                                        || attempt.validate().is_err()
                                        || attempt
                                            .operation_id
                                            .as_deref()
                                            .is_some_and(|id| !instance_ids.contains(id))
                                })
                            || instance_ids.iter().any(|id| {
                                !operation
                                    .attempts
                                    .iter()
                                    .any(|attempt| attempt.operation_id.as_deref() == Some(*id))
                            })
                    })
            })
        {
            return Err("qualification scenario report is invalid".into());
        }
        Ok(())
    }

    pub(crate) fn provider_run_ids(&self) -> Vec<String> {
        self.executions
            .iter()
            .map(|execution| execution.provider_run_id.clone())
            .collect()
    }
}

impl ReceiptsReport {
    pub(crate) fn validate(
        &self,
        expected: &ExpectedReportBinding,
        language: &str,
    ) -> Result<(), String> {
        self.binding.require_exact(expected)?;
        if self.schema != "auths.profile-qualification-receipts-report/1"
            || self.language != language
            || self.portable_receipt_schema != "auths.portable-receipt/1"
            || self.status != "passed"
            || self.operations.len() != expected.operation_ids.len()
            || self
                .operations
                .iter()
                .map(|operation| operation.operation_id.as_str())
                .ne(expected.operation_ids.iter().map(String::as_str))
            || self.operations.iter().any(|operation| {
                !operation.profile_claims_match
                    || match operation.state {
                        QualificationReceiptState::None => {
                            operation.decision_receipt_id.is_some()
                                || operation.execution_receipt_id.is_some()
                                || operation.decision_verification_method.is_some()
                                || operation.execution_verification_method.is_some()
                                || operation.linked
                        }
                        QualificationReceiptState::DecisionOnly => {
                            !operation
                                .decision_receipt_id
                                .as_deref()
                                .is_some_and(receipt_id)
                                || operation.execution_receipt_id.is_some()
                                || operation.decision_verification_method.is_none()
                                || operation.execution_verification_method.is_some()
                                || operation.linked
                        }
                        QualificationReceiptState::LinkedExecution => {
                            !operation
                                .decision_receipt_id
                                .as_deref()
                                .is_some_and(receipt_id)
                                || !operation
                                    .execution_receipt_id
                                    .as_deref()
                                    .is_some_and(receipt_id)
                                || operation.decision_receipt_id == operation.execution_receipt_id
                                || operation.decision_verification_method.is_none()
                                || operation.execution_verification_method.is_none()
                                || operation.decision_verification_method
                                    == operation.execution_verification_method
                                || !operation.linked
                        }
                    }
            })
        {
            return Err("qualification receipt report is invalid".into());
        }
        Ok(())
    }
}

impl InstalledPackagesReport {
    pub(crate) fn validate(&self, expected: &ExpectedReportBinding) -> Result<(), String> {
        if self.binding.candidate_revision != expected.candidate_revision
            || self.binding.domain != expected.domain
            || self.binding.target != expected.target
            || self.binding.profiles != expected.profiles
            || self.binding.provider_run_ids != expected.provider_run_ids
            || self.binding.scenario_ids != expected.scenario_ids
        {
            return Err(
                "installed-package binding differs from the immutable proposal facts".into(),
            );
        }
        let languages = self
            .packages
            .iter()
            .map(|package| package.language.as_str())
            .collect::<Vec<_>>();
        if self.schema != "auths.profile-qualification-installed-packages-report/1"
            || !digest(&self.fixture_set_sha256)
            || !digest(&self.mutation_corpus_sha256)
            || languages != ["rust", "python", "typescript"]
            || self.packages.iter().any(|package| {
                package.name.is_empty()
                    || package.name.len() > 128
                    || !digest(&package.artifact_sha256)
                    || package.consumer_status != "passed"
            })
            || [
                self.toolchain.rust.as_str(),
                self.toolchain.node.as_str(),
                self.toolchain.python.as_str(),
            ]
            .iter()
            .any(|value| value.is_empty() || value.len() > 128 || !value.is_ascii())
        {
            return Err("installed-package qualification report is invalid".into());
        }
        Ok(())
    }

    pub(crate) fn create(
        binding: InstalledReportBinding,
        fixture_set_sha256: String,
        mutation_corpus_sha256: String,
        toolchain: Toolchain,
        packages: [(String, String); 3],
    ) -> Self {
        Self {
            schema: "auths.profile-qualification-installed-packages-report/1".into(),
            binding,
            fixture_set_sha256,
            mutation_corpus_sha256,
            toolchain,
            packages: ["rust", "python", "typescript"]
                .into_iter()
                .zip(packages)
                .map(|(language, (name, artifact_sha256))| InstalledPackage {
                    language: language.into(),
                    name,
                    artifact_sha256,
                    consumer_status: "passed".into(),
                })
                .collect(),
        }
    }
}

impl ScanReport {
    pub(crate) fn clean(
        binding: ReportBinding,
        kind: &str,
        scanned_file_count: u32,
        redacted_value_count: u32,
    ) -> Result<Self, String> {
        let (tool, version) = match kind {
            "gitleaks" => ("gitleaks", "8.28.0"),
            "typed-forbidden-field" => ("auths-typed-forbidden-field", "1"),
            "redaction" => ("auths-redaction-check", "1"),
            _ => return Err("unknown qualification scan kind".into()),
        };
        Ok(Self {
            schema: "auths.profile-qualification-scan-report/1".into(),
            binding,
            scan_kind: kind.into(),
            tool: tool.into(),
            version: version.into(),
            status: "passed".into(),
            scanned_file_count,
            finding_count: 0,
            redacted_value_count,
            unredacted_sensitive_value_count: 0,
        })
    }

    pub(crate) fn validate(
        &self,
        expected: &ExpectedReportBinding,
        kind: &str,
    ) -> Result<(), String> {
        self.binding.require_exact(expected)?;
        let tool = match kind {
            "gitleaks" => ("gitleaks", "8.28.0"),
            "typed-forbidden-field" => ("auths-typed-forbidden-field", "1"),
            "redaction" => ("auths-redaction-check", "1"),
            _ => return Err("unknown qualification scan kind".into()),
        };
        if self.schema != "auths.profile-qualification-scan-report/1"
            || self.scan_kind != kind
            || self.tool != tool.0
            || self.version != tool.1
            || self.status != "passed"
            || self.scanned_file_count == 0
            || self.scanned_file_count > 4_096
            || self.finding_count != 0
            || self.unredacted_sensitive_value_count != 0
        {
            return Err("qualification scan report is invalid".into());
        }
        Ok(())
    }

    pub(crate) fn require_recomputed_clean_scan(
        &self,
        scanned_file_count: u32,
        redacted_value_count: u32,
    ) -> Result<(), String> {
        if self.scanned_file_count != scanned_file_count
            || self.finding_count != 0
            || self.redacted_value_count != redacted_value_count
            || self.unredacted_sensitive_value_count != 0
        {
            return Err("qualification scan report differs from the independent rerun".into());
        }
        Ok(())
    }
}

impl ProvenanceReport {
    pub(crate) fn validate(&self, expected: &ExpectedReportBinding) -> Result<(), String> {
        self.binding.require_exact(expected)?;
        if self.schema != "auths.profile-qualification-provenance-report/1"
            || self.workflow_path
                != format!(
                    ".github/workflows/profile-qualification-{}.yml",
                    expected.domain
                )
            || !revision(&self.workflow_revision)
            || self.collector_revision != expected.candidate_revision
            || !revision(&self.observer_revision)
            || !revision(&self.attester_revision)
            || self.runner_label.is_empty()
            || self.runner_image_release.is_empty()
            || self.pinned_actions.len() < 3
            || self.installed_artifacts.len() < 3
            || !digest(&self.failpoint_build_sha256)
            || !digest(&self.production_build_sha256)
            || !sorted_unique_by(&self.pinned_actions, |entry| &entry.name)
            || !sorted_unique_by(&self.installed_artifacts, |entry| &entry.name)
            || self
                .pinned_actions
                .iter()
                .any(|entry| entry.name.is_empty() || !revision(&entry.revision))
            || self
                .installed_artifacts
                .iter()
                .any(|entry| entry.name.is_empty() || !digest(&entry.sha256))
        {
            return Err("qualification provenance report is invalid".into());
        }
        Ok(())
    }
}

fn validate_domain_facts(domain: &str, operation: &ProviderTruthOperation) -> Result<(), String> {
    let canonical =
        serde_json_canonicalizer::to_vec(&operation.domain_facts).map_err(string_error)?;
    crate::profile_qualification_adapters::validate_provider_truth_facts(
        domain,
        &canonical,
        operation.effect,
    )?;
    if hex::encode(Sha256::digest(canonical)) != operation.commitment_sha256 {
        return Err("qualification provider truth commitment does not match domain facts".into());
    }
    Ok(())
}

fn sorted_unique(values: &[String]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_unique_by<T, F>(values: &[T], key: F) -> bool
where
    F: Fn(&T) -> &String,
{
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn receipt_id(value: &str) -> bool {
    value.len() == 48
        && value.starts_with("rcpt_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn failpoint_token(value: QualificationFailpoint) -> &'static str {
    match value {
        QualificationFailpoint::BeforeDecision => "before-decision",
        QualificationFailpoint::AfterDecision => "after-decision",
        QualificationFailpoint::AfterReservation => "after-reservation",
        QualificationFailpoint::AfterCommand => "after-command",
        QualificationFailpoint::AfterReread => "after-reread",
        QualificationFailpoint::AfterLease => "after-lease",
        QualificationFailpoint::AfterEntryMarker => "after-entry-marker",
        QualificationFailpoint::AfterRequestWrite => "after-request-write",
        QualificationFailpoint::AfterProviderResult => "after-provider-result",
        QualificationFailpoint::AfterObservation => "after-observation",
        QualificationFailpoint::AfterExecutionReceipt => "after-execution-receipt",
        QualificationFailpoint::AfterTerminal => "after-terminal",
    }
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
