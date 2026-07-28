use std::{
    collections::BTreeMap,
    io::Read as _,
    str,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use auths_kubernetes::{
    AdmissionMode, AllowedChangeProjectionV1, CredentialProvider, ImageDigestRef,
    KubernetesCredential, KubernetesEvidenceV1, KubernetesGateway, KubernetesName,
    KubernetesRolloutResult, KubernetesUid, KubernetesVerifierConfiguration,
    KubernetesVerifierConfigurationInput, KubernetesWorkloadRolloutInput,
    KubernetesWorkloadRolloutV1, PortError, VerifiedRolloutCommand,
    canonical::{canonical_json, sha256},
};
use reqwest::{
    Certificate, Method,
    blocking::{Client, Response},
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde_json::{Value, json};

const APPLY_CONTENT_TYPE: &str = "application/apply-patch+yaml";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const POLL_ATTEMPTS: usize = 45;

/// Inputs shared by a signed demo session.
pub struct PreparedRollout {
    pub configuration: KubernetesVerifierConfiguration,
    pub evidence: KubernetesEvidenceV1,
    pub action: KubernetesWorkloadRolloutV1,
}

/// Live Kubernetes API adapter or deterministic test double.
#[derive(Clone)]
pub enum KubernetesBackend {
    Live(Arc<LiveKubernetes>),
    Fixture(Arc<FixtureKubernetes>),
}

impl KubernetesBackend {
    pub fn live(config: LiveKubernetesConfig) -> Result<Self, BackendError> {
        Ok(Self::Live(Arc::new(LiveKubernetes::new(config)?)))
    }

    #[cfg(test)]
    pub fn fixture() -> Self {
        Self::Fixture(Arc::new(FixtureKubernetes::default()))
    }

    pub fn prepare(&self, now: u64, workflow_id: &str) -> Result<PreparedRollout, BackendError> {
        match self {
            Self::Live(live) => live.prepare(now, workflow_id),
            Self::Fixture(fixture) => fixture.prepare(now, workflow_id),
        }
    }

    pub fn readiness(&self) -> Result<(), BackendError> {
        match self {
            Self::Live(live) => live.readiness(),
            Self::Fixture(_) => Ok(()),
        }
    }

    #[must_use]
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Live(_) => "live-kubernetes",
            Self::Fixture(_) => "deterministic-fixture",
        }
    }
}

impl CredentialProvider for KubernetesBackend {
    fn mutation_credential(
        &self,
        action: &KubernetesWorkloadRolloutV1,
    ) -> Result<KubernetesCredential, PortError> {
        match self {
            Self::Live(live) => live.mutation_credential(action),
            Self::Fixture(fixture) => fixture.mutation_credential(action),
        }
    }
}

impl KubernetesGateway for KubernetesBackend {
    fn apply_and_observe(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        match self {
            Self::Live(live) => live.apply_and_observe(command, credential, now),
            Self::Fixture(fixture) => fixture.apply_and_observe(command, credential, now),
        }
    }

    fn reconcile(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        match self {
            Self::Live(live) => live.reconcile(command, credential, now),
            Self::Fixture(fixture) => fixture.reconcile(command, credential, now),
        }
    }
}

/// Explicit live-cluster configuration.
pub struct LiveKubernetesConfig {
    pub api_server: String,
    pub ca_pem: Vec<u8>,
    pub evidence_token: Vec<u8>,
    pub mutation_token: Vec<u8>,
    pub cluster_audience: String,
    pub namespace: KubernetesName,
    pub deployment: KubernetesName,
    pub container: KubernetesName,
    pub image_a: ImageDigestRef,
    pub image_b: ImageDigestRef,
    pub executor_audience: String,
}

pub struct LiveKubernetes {
    client: Client,
    api_server: String,
    evidence_token: Vec<u8>,
    mutation_token: Vec<u8>,
    cluster_audience: String,
    api_server_identity: String,
    namespace: KubernetesName,
    deployment: KubernetesName,
    container: KubernetesName,
    image_a: ImageDigestRef,
    image_b: ImageDigestRef,
    executor_audience: String,
}

impl Drop for LiveKubernetes {
    fn drop(&mut self) {
        self.evidence_token.fill(0);
        self.mutation_token.fill(0);
    }
}

impl LiveKubernetes {
    fn new(config: LiveKubernetesConfig) -> Result<Self, BackendError> {
        if !config.api_server.starts_with("https://")
            || config.evidence_token.len() < 16
            || config.mutation_token.len() < 16
            || config.cluster_audience.is_empty()
            || config.executor_audience.is_empty()
        {
            return Err(BackendError::InvalidConfiguration);
        }
        let certificate = Certificate::from_pem(&config.ca_pem)
            .map_err(|_| BackendError::InvalidConfiguration)?;
        let client = Client::builder()
            .add_root_certificate(certificate)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| BackendError::InvalidConfiguration)?;
        Ok(Self {
            client,
            api_server: config.api_server.trim_end_matches('/').into(),
            evidence_token: config.evidence_token,
            mutation_token: config.mutation_token,
            cluster_audience: config.cluster_audience,
            api_server_identity: format!("sha256:{}", sha256(&config.ca_pem)),
            namespace: config.namespace,
            deployment: config.deployment,
            container: config.container,
            image_a: config.image_a,
            image_b: config.image_b,
            executor_audience: config.executor_audience,
        })
    }

    fn prepare(&self, now: u64, workflow_id: &str) -> Result<PreparedRollout, BackendError> {
        let namespace = self.get_namespace(&self.evidence_token)?;
        let current = self.get_deployment(&self.evidence_token)?;
        let observed = deployment_observation(&current, &self.container)?;
        let target = if observed.image == self.image_a {
            self.image_b.clone()
        } else {
            self.image_a.clone()
        };
        let patch = rollout_patch(
            &self.namespace,
            &self.deployment,
            &self.container,
            &target,
            observed.replicas,
            workflow_id,
        )?;
        let dry_run = self.apply(&self.evidence_token, &patch, true)?;
        let dry_run_digest = canonical_value_digest(&dry_run.value)?;
        let configuration = verifier_configuration(
            &self.cluster_audience,
            &self.namespace,
            &self.deployment,
            &self.container,
            &self.executor_audience,
            3,
        )?;
        let namespace_uid = object_uid(&namespace)?;
        let evidence = KubernetesEvidenceV1 {
            cluster_audience: self.cluster_audience.clone(),
            api_server_identity: self.api_server_identity.clone(),
            namespace_name: self.namespace.clone(),
            namespace_uid,
            resource_name: self.deployment.clone(),
            resource_uid: observed.uid.clone(),
            resource_version: observed.resource_version.clone(),
            generation: observed.generation,
            deletion_timestamp: current
                .pointer("/metadata/deletionTimestamp")
                .and_then(Value::as_str)
                .map(str::to_owned),
            current_spec_digest: current_spec_digest(&current)?,
            current_image: observed.image.clone(),
            current_replicas: observed.replicas,
            dry_run_response_digest: dry_run_digest.clone(),
            dry_run_warnings: dry_run.warnings,
            managed_field_conflict: false,
            observed_at: now,
        };
        evidence
            .validate()
            .map_err(|_| BackendError::MalformedResponse)?;
        let projection = AllowedChangeProjectionV1 {
            container_name: self.container.clone(),
            previous_image_digest: observed.image,
            requested_image_digest: target,
            previous_replicas: observed.replicas,
            requested_replicas: observed.replicas,
            annotation_changes: BTreeMap::from([("auths.dev/rollout".into(), workflow_id.into())]),
            unchanged_fields_digest: unchanged_fields_digest(&current, &self.container)?,
        };
        let action = KubernetesWorkloadRolloutV1::new(KubernetesWorkloadRolloutInput {
            workflow_id: workflow_id.into(),
            executor_audience: configuration.executor_audience().into(),
            cluster_audience: configuration.cluster_audience().into(),
            api_server_identity: evidence.api_server_identity.clone(),
            namespace_name: evidence.namespace_name.clone(),
            namespace_uid: evidence.namespace_uid.clone(),
            resource_name: evidence.resource_name.clone(),
            resource_uid: evidence.resource_uid.clone(),
            expected_resource_version: evidence.resource_version.clone(),
            current_spec_digest: evidence.current_spec_digest.clone(),
            patch_bytes: patch,
            dry_run_response_digest: dry_run_digest,
            dry_run_observed_at: now,
            allowed_change_projection: projection,
            required_configuration_digest: configuration
                .digest()
                .map_err(|_| BackendError::Canonicalization)?,
            evidence_digest: evidence
                .digest()
                .map_err(|_| BackendError::Canonicalization)?,
            expires_at: now + 300,
            nonce: sha256(format!("{workflow_id}\0{now}").as_bytes()),
        })
        .map_err(|_| BackendError::Canonicalization)?;
        Ok(PreparedRollout {
            configuration,
            evidence,
            action,
        })
    }

    fn readiness(&self) -> Result<(), BackendError> {
        object_uid(&self.get_namespace(&self.evidence_token)?)?;
        deployment_observation(&self.get_deployment(&self.evidence_token)?, &self.container)?;
        Ok(())
    }

    fn get_namespace(&self, token: &[u8]) -> Result<Value, BackendError> {
        self.request_value(
            Method::GET,
            &format!("/api/v1/namespaces/{}", self.namespace),
            token,
            None,
            None,
        )
        .map(|response| response.value)
    }

    fn get_deployment(&self, token: &[u8]) -> Result<Value, BackendError> {
        self.request_value(
            Method::GET,
            &format!(
                "/apis/apps/v1/namespaces/{}/deployments/{}",
                self.namespace, self.deployment
            ),
            token,
            None,
            None,
        )
        .map(|response| response.value)
    }

    fn apply(&self, token: &[u8], patch: &str, dry_run: bool) -> Result<ApiValue, BackendError> {
        let suffix = if dry_run {
            "?fieldManager=auths-workload-rollout&force=false&fieldValidation=Strict&dryRun=All"
        } else {
            "?fieldManager=auths-workload-rollout&force=false&fieldValidation=Strict"
        };
        self.request_value(
            Method::PATCH,
            &format!(
                "/apis/apps/v1/namespaces/{}/deployments/{}{}",
                self.namespace, self.deployment, suffix
            ),
            token,
            Some(APPLY_CONTENT_TYPE),
            Some(patch.as_bytes()),
        )
    }

    fn request_value(
        &self,
        method: Method,
        path: &str,
        token: &[u8],
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<ApiValue, BackendError> {
        let token = str::from_utf8(token).map_err(|_| BackendError::InvalidConfiguration)?;
        let mut request = self
            .client
            .request(method, format!("{}{}", self.api_server, path))
            .header(ACCEPT, "application/json")
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| BackendError::InvalidConfiguration)?,
            );
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        parse_response(request.send().map_err(|_| BackendError::Unavailable)?)
    }

    fn observe_result(
        &self,
        token: &[u8],
        action: &KubernetesWorkloadRolloutV1,
        audit_id: Option<String>,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        for _ in 0..POLL_ATTEMPTS {
            let value = self
                .get_deployment(token)
                .map_err(|_| PortError::Execution)?;
            let observed = deployment_observation(&value, &self.container)
                .map_err(|_| PortError::Malformed)?;
            if observed.uid != *action.resource_uid() {
                return Err(PortError::PersistedStateMismatch);
            }
            let observed_generation = value
                .pointer("/status/observedGeneration")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let updated_replicas = value
                .pointer("/status/updatedReplicas")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(0);
            let available_replicas = value
                .pointer("/status/availableReplicas")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(0);
            let projection = action.projection();
            let persisted_verified = observed.image == projection.requested_image_digest
                && observed.replicas == projection.requested_replicas;
            let converged = persisted_verified
                && observed_generation >= observed.generation
                && updated_replicas == projection.requested_replicas
                && available_replicas == projection.requested_replicas;
            if converged {
                return Ok(KubernetesRolloutResult {
                    resource_uid: observed.uid,
                    resource_version: observed.resource_version,
                    generation: observed.generation,
                    observed_generation,
                    requested_replicas: projection.requested_replicas,
                    updated_replicas,
                    available_replicas,
                    image: observed.image,
                    api_accepted: true,
                    persisted_verified: true,
                    rollout_converged: true,
                    audit_id,
                    observed_at: now,
                });
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(PortError::RolloutFailed)
    }
}

impl CredentialProvider for LiveKubernetes {
    fn mutation_credential(
        &self,
        action: &KubernetesWorkloadRolloutV1,
    ) -> Result<KubernetesCredential, PortError> {
        if action.cluster_audience() != self.cluster_audience
            || action.namespace_name() != &self.namespace
            || action.resource_name() != &self.deployment
        {
            return Err(PortError::InvalidConfiguration);
        }
        KubernetesCredential::new(self.mutation_token.clone())
    }
}

impl KubernetesGateway for LiveKubernetes {
    fn apply_and_observe(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        let response = self
            .apply(
                credential.expose(),
                str::from_utf8(command.action().patch_bytes()).map_err(|_| PortError::Malformed)?,
                false,
            )
            .map_err(|error| match error {
                BackendError::Unavailable => PortError::OutcomeUnknown,
                _ => PortError::Execution,
            })?;
        self.observe_result(
            credential.expose(),
            command.action(),
            response.audit_id,
            now,
        )
    }

    fn reconcile(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        self.observe_result(credential.expose(), command.action(), None, now)
    }
}

struct ApiValue {
    value: Value,
    warnings: Vec<String>,
    audit_id: Option<String>,
}

fn parse_response(mut response: Response) -> Result<ApiValue, BackendError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(BackendError::LimitExceeded);
    }
    let warnings = response
        .headers()
        .get_all("warning")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect();
    let audit_id = response
        .headers()
        .get("audit-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BackendError::Unavailable)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(BackendError::LimitExceeded);
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| BackendError::MalformedResponse)?;
    if !status.is_success() {
        return Err(if status.as_u16() == 409 {
            BackendError::Conflict
        } else {
            BackendError::Rejected
        });
    }
    Ok(ApiValue {
        value,
        warnings,
        audit_id,
    })
}

#[derive(Clone)]
struct DeploymentObservation {
    uid: KubernetesUid,
    resource_version: String,
    generation: u64,
    replicas: u32,
    image: ImageDigestRef,
}

fn deployment_observation(
    value: &Value,
    container: &KubernetesName,
) -> Result<DeploymentObservation, BackendError> {
    let containers = value
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .ok_or(BackendError::MalformedResponse)?;
    let selected = containers
        .iter()
        .find(|entry| entry.get("name").and_then(Value::as_str) == Some(container.as_str()))
        .ok_or(BackendError::MalformedResponse)?;
    let image = selected
        .get("image")
        .and_then(Value::as_str)
        .ok_or(BackendError::MalformedResponse)?;
    Ok(DeploymentObservation {
        uid: object_uid(value)?,
        resource_version: value
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .ok_or(BackendError::MalformedResponse)?
            .into(),
        generation: value
            .pointer("/metadata/generation")
            .and_then(Value::as_u64)
            .ok_or(BackendError::MalformedResponse)?,
        replicas: value
            .pointer("/spec/replicas")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(BackendError::MalformedResponse)?,
        image: ImageDigestRef::parse(image).map_err(|_| BackendError::MalformedResponse)?,
    })
}

fn object_uid(value: &Value) -> Result<KubernetesUid, BackendError> {
    KubernetesUid::parse(
        value
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .ok_or(BackendError::MalformedResponse)?,
    )
    .map_err(|_| BackendError::MalformedResponse)
}

fn canonical_value_digest(value: &Value) -> Result<auths_kubernetes::DigestHex, BackendError> {
    canonical_json(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| BackendError::Canonicalization)
}

fn current_spec_digest(value: &Value) -> Result<auths_kubernetes::DigestHex, BackendError> {
    canonical_value_digest(value.get("spec").ok_or(BackendError::MalformedResponse)?)
}

fn unchanged_fields_digest(
    value: &Value,
    container: &KubernetesName,
) -> Result<auths_kubernetes::DigestHex, BackendError> {
    let mut protected = value
        .get("spec")
        .cloned()
        .ok_or(BackendError::MalformedResponse)?;
    if let Some(object) = protected.as_object_mut() {
        object.remove("replicas");
    }
    let containers = protected
        .pointer_mut("/template/spec/containers")
        .and_then(Value::as_array_mut)
        .ok_or(BackendError::MalformedResponse)?;
    for entry in containers {
        if entry.get("name").and_then(Value::as_str) == Some(container.as_str())
            && let Some(object) = entry.as_object_mut()
        {
            object.remove("image");
        }
    }
    canonical_value_digest(&protected)
}

fn rollout_patch(
    namespace: &KubernetesName,
    deployment: &KubernetesName,
    container: &KubernetesName,
    image: &ImageDigestRef,
    replicas: u32,
    workflow_id: &str,
) -> Result<String, BackendError> {
    let value = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": deployment.as_str(),
            "namespace": namespace.as_str(),
            "annotations": {"auths.dev/rollout": workflow_id}
        },
        "spec": {
            "replicas": replicas,
            "template": {
                "spec": {
                    "containers": [{
                        "name": container.as_str(),
                        "image": image.as_str()
                    }]
                }
            }
        }
    });
    String::from_utf8(canonical_json(&value).map_err(|_| BackendError::Canonicalization)?)
        .map_err(|_| BackendError::Canonicalization)
}

fn verifier_configuration(
    cluster_audience: &str,
    namespace: &KubernetesName,
    deployment: &KubernetesName,
    container: &KubernetesName,
    executor_audience: &str,
    maximum_replicas: u32,
) -> Result<KubernetesVerifierConfiguration, BackendError> {
    KubernetesVerifierConfiguration::new(KubernetesVerifierConfigurationInput {
        cluster_audience: cluster_audience.into(),
        allowed_namespaces: vec![namespace.clone()],
        allowed_deployments: vec![deployment.clone()],
        allowed_container_names: vec![container.clone()],
        minimum_replicas: 1,
        maximum_replicas,
        allowed_annotation_keys: vec!["auths.dev/rollout".into()],
        maximum_evidence_age_seconds: 300,
        maximum_authorization_lifetime_seconds: 300,
        field_manager: "auths-workload-rollout".into(),
        permitted_api_versions: vec!["apps/v1".into()],
        permitted_resource_kinds: vec!["Deployment".into()],
        admission_mode: AdmissionMode::DeterministicDemo,
        receipt_schema_version: "auths.kubernetes.receipt/1".into(),
        executor_audience: executor_audience.into(),
    })
    .map_err(|_| BackendError::InvalidConfiguration)
}

/// Deterministic adapter used only by unit and browser smoke tests.
pub struct FixtureKubernetes {
    executed: Mutex<bool>,
}

impl Default for FixtureKubernetes {
    fn default() -> Self {
        Self {
            executed: Mutex::new(false),
        }
    }
}

impl FixtureKubernetes {
    fn prepare(&self, now: u64, workflow_id: &str) -> Result<PreparedRollout, BackendError> {
        let mut fixture = auths_kubernetes::test_support::fixture();
        fixture.evidence.observed_at = now;
        let evidence_digest = fixture
            .evidence
            .digest()
            .map_err(|_| BackendError::Canonicalization)?;
        let mut action =
            serde_json::to_value(&fixture.action).map_err(|_| BackendError::Canonicalization)?;
        action["workflow_id"] = Value::String(workflow_id.into());
        action["dry_run_observed_at"] = json!(now);
        action["expires_at"] = json!(now + 300);
        action["evidence_digest"] =
            serde_json::to_value(evidence_digest).map_err(|_| BackendError::Canonicalization)?;
        let action: KubernetesWorkloadRolloutV1 =
            serde_json::from_value(action).map_err(|_| BackendError::Canonicalization)?;
        action
            .validate()
            .map_err(|_| BackendError::Canonicalization)?;
        Ok(PreparedRollout {
            configuration: fixture.configuration,
            evidence: fixture.evidence,
            action,
        })
    }
}

impl CredentialProvider for FixtureKubernetes {
    fn mutation_credential(
        &self,
        _: &KubernetesWorkloadRolloutV1,
    ) -> Result<KubernetesCredential, PortError> {
        KubernetesCredential::new("fixture-kubernetes-token")
    }
}

impl KubernetesGateway for FixtureKubernetes {
    fn apply_and_observe(
        &self,
        command: &VerifiedRolloutCommand,
        _: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        *self.executed.lock().map_err(|_| PortError::Persistence)? = true;
        let action = command.action();
        Ok(KubernetesRolloutResult {
            resource_uid: action.resource_uid().clone(),
            resource_version: "43".into(),
            generation: 8,
            observed_generation: 8,
            requested_replicas: action.projection().requested_replicas,
            updated_replicas: action.projection().requested_replicas,
            available_replicas: action.projection().requested_replicas,
            image: action.projection().requested_image_digest.clone(),
            api_accepted: true,
            persisted_verified: true,
            rollout_converged: true,
            audit_id: Some("fixture-audit-id".into()),
            observed_at: now,
        })
    }

    fn reconcile(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        self.apply_and_observe(command, credential, now)
    }
}

/// Closed preparation/configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BackendError {
    #[error("invalid Kubernetes backend configuration")]
    InvalidConfiguration,
    #[error("Kubernetes API is unavailable")]
    Unavailable,
    #[error("Kubernetes API response exceeded a hard limit")]
    LimitExceeded,
    #[error("Kubernetes API returned malformed data")]
    MalformedResponse,
    #[error("Kubernetes request conflicted")]
    Conflict,
    #[error("Kubernetes rejected the request")]
    Rejected,
    #[error("Kubernetes canonicalization failed")]
    Canonicalization,
}
