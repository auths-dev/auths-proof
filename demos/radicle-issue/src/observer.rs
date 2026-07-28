use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use auths_radicle::{
    DigestHex, GitOid, LocalPublication, NodeId, Rid,
    ports::{PortError, PropagationObserver},
    receipts::RadiclePropagationReceipt,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    DeploymentMetadata, NodeRole, RunningNode,
    deployment::{git_output, rad_output, storage_repository},
};

const MAX_OBSERVER_REQUEST_BYTES: usize = 8 * 1024;

pub struct ObserverRuntime {
    node: Arc<RunningNode>,
    authentication_token: Arc<str>,
    release: Arc<str>,
}

impl ObserverRuntime {
    /// Constructs a private observer API around a dedicated non-executor node.
    ///
    /// # Errors
    ///
    /// Rejects the executor role or a weak/malformed authentication token.
    pub fn new(
        node: Arc<RunningNode>,
        authentication_token: String,
        release: String,
    ) -> Result<Self, ObserverError> {
        if node.configuration.role != NodeRole::Observer
            || authentication_token.len() < 32
            || authentication_token.len() > 256
            || !authentication_token.is_ascii()
            || release.is_empty()
            || release.len() > 128
        {
            return Err(ObserverError);
        }
        Ok(Self {
            node,
            authentication_token: authentication_token.into(),
            release: release.into(),
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    rid: Rid,
    executor_node_id: NodeId,
    executor_address: String,
    canonical_base_oid: GitOid,
    issue_id: auths_radicle::CobId,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObserveRequest {
    publication: LocalPublication,
    execution_receipt_digest: DigestHex,
    executor_address: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObserveResponse {
    observer_node_id: NodeId,
    revision_id: GitOid,
    candidate_oid: GitOid,
    observed_at: u64,
}

/// Builds the authenticated read-only observer service.
pub fn observer_app(runtime: ObserverRuntime) -> Router {
    Router::new()
        .route("/healthz", get(observer_health))
        .route("/internal/v1/prepare", post(prepare))
        .route("/internal/v1/observe", post(observe))
        .layer(DefaultBodyLimit::max(MAX_OBSERVER_REQUEST_BYTES))
        .with_state(Arc::new(runtime))
}

async fn observer_health(State(runtime): State<Arc<ObserverRuntime>>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "role": "independent-observer",
        "node_id": runtime.node.node_id,
        "release": &*runtime.release,
    }))
}

async fn prepare(
    State(runtime): State<Arc<ObserverRuntime>>,
    headers: HeaderMap,
    Json(request): Json<PrepareRequest>,
) -> Result<Json<Value>, ObserverApiError> {
    authenticate(&headers, &runtime.authentication_token)?;
    connect_and_fetch(
        &runtime,
        &request.rid,
        &request.executor_node_id,
        &request.executor_address,
    )?;
    let repository = storage_repository(&runtime.node.configuration.rad_home, &request.rid)
        .map_err(|_| ObserverApiError::Unavailable)?;
    let canonical = GitOid::parse(
        git_output(
            &runtime.node.configuration,
            &repository,
            ["rev-parse", "refs/heads/main"],
        )
        .map_err(|_| ObserverApiError::Unavailable)?
        .trim(),
    )
    .map_err(|_| ObserverApiError::Unavailable)?;
    if canonical != request.canonical_base_oid {
        return Err(ObserverApiError::Mismatch);
    }
    let issue_suffix = format!("/refs/cobs/xyz.radicle.issue/{}", request.issue_id);
    let refs = git_output(
        &runtime.node.configuration,
        &repository,
        ["for-each-ref", "--format=%(refname)", "refs/namespaces"],
    )
    .map_err(|_| ObserverApiError::Unavailable)?;
    if !refs
        .lines()
        .any(|reference| reference.ends_with(&issue_suffix))
    {
        return Err(ObserverApiError::Mismatch);
    }
    Ok(Json(json!({
        "status": "prepared",
        "observer_node_id": runtime.node.node_id,
        "rid": request.rid,
        "canonical_base_oid": canonical,
        "issue_id": request.issue_id,
    })))
}

async fn observe(
    State(runtime): State<Arc<ObserverRuntime>>,
    headers: HeaderMap,
    Json(request): Json<ObserveRequest>,
) -> Result<Json<ObserveResponse>, ObserverApiError> {
    authenticate(&headers, &runtime.authentication_token)?;
    connect_and_fetch(
        &runtime,
        &request.publication.rid,
        &request.publication.node_id,
        &request.executor_address,
    )?;
    if request.publication.node_id == runtime.node.node_id {
        return Err(ObserverApiError::Mismatch);
    }
    let repository = storage_repository(
        &runtime.node.configuration.rad_home,
        &request.publication.rid,
    )
    .map_err(|_| ObserverApiError::Unavailable)?;
    let reference = format!(
        "refs/namespaces/{}/refs/heads/patches/{}",
        request.publication.node_id, request.publication.patch_id
    );
    let candidate = GitOid::parse(
        git_output(
            &runtime.node.configuration,
            &repository,
            ["rev-parse", reference.as_str()],
        )
        .map_err(|_| ObserverApiError::Unavailable)?
        .trim(),
    )
    .map_err(|_| ObserverApiError::Unavailable)?;
    if candidate != request.publication.candidate_oid {
        return Err(ObserverApiError::Mismatch);
    }
    let patch = rad_output(
        &runtime.node.configuration,
        [
            "cob",
            "show",
            "--repo",
            request.publication.rid.as_str(),
            "--type",
            "xyz.radicle.patch",
            "--object",
            request.publication.patch_id.as_str(),
            "--format",
            "json",
        ],
    )
    .map_err(|_| ObserverApiError::Unavailable)?;
    let patch: Value = serde_json::from_str(&patch).map_err(|_| ObserverApiError::Unavailable)?;
    let revision_path = format!("/revisions/{}", request.publication.revision_id);
    let exact = patch.pointer("/author/id").and_then(Value::as_str)
        == Some(request.publication.signer_did.as_str())
        && patch
            .pointer(&format!("{revision_path}/oid"))
            .and_then(Value::as_str)
            == Some(request.publication.candidate_oid.as_str())
        && patch
            .pointer(&format!("{revision_path}/author/id"))
            .and_then(Value::as_str)
            == Some(request.publication.signer_did.as_str());
    if !exact {
        return Err(ObserverApiError::Mismatch);
    }
    Ok(Json(ObserveResponse {
        observer_node_id: runtime.node.node_id.clone(),
        revision_id: request.publication.revision_id,
        candidate_oid: candidate,
        observed_at: unix_time().map_err(|_| ObserverApiError::Unavailable)?,
    }))
}

fn connect_and_fetch(
    runtime: &ObserverRuntime,
    rid: &Rid,
    executor_node_id: &NodeId,
    executor_address: &str,
) -> Result<(), ObserverApiError> {
    runtime
        .node
        .connect(executor_node_id, executor_address)
        .map_err(|_| ObserverApiError::Unavailable)?;
    rad_output(
        &runtime.node.configuration,
        [
            "seed",
            rid.as_str(),
            "--from",
            executor_node_id.as_str(),
            "--timeout",
            "15s",
            "--scope",
            "all",
        ],
    )
    .map(|_| ())
    .map_err(|_| ObserverApiError::Unavailable)
}

fn authenticate(headers: &HeaderMap, expected: &str) -> Result<(), ObserverApiError> {
    let supplied = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ObserverApiError::Unauthorized)?;
    let expected_digest = Sha256::digest(expected.as_bytes());
    let supplied_digest = Sha256::digest(supplied.as_bytes());
    if bool::from(expected_digest.ct_eq(&supplied_digest)) {
        Ok(())
    } else {
        Err(ObserverApiError::Unauthorized)
    }
}

fn unix_time() -> Result<u64, ObserverError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ObserverError)
}

#[derive(Clone)]
pub struct HttpPropagationObserver {
    client: reqwest::blocking::Client,
    endpoint: Arc<str>,
    authentication_token: Arc<str>,
    executor_address: Arc<str>,
    expected_observer: NodeId,
}

impl HttpPropagationObserver {
    /// Configures the authenticated observer trust domain.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTP endpoints, malformed tokens, or client construction.
    pub fn new(
        endpoint: String,
        authentication_token: String,
        executor_address: String,
        expected_observer: NodeId,
    ) -> Result<Self, ObserverError> {
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://"))
            || endpoint.ends_with('/')
            || authentication_token.len() < 32
            || executor_address.is_empty()
        {
            return Err(ObserverError);
        }
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|_| ObserverError)?,
            endpoint: endpoint.into(),
            authentication_token: authentication_token.into(),
            executor_address: executor_address.into(),
            expected_observer,
        })
    }

    /// Makes the observer independently fetch and validate the pinned demo
    /// repository before the public coordinator becomes ready.
    ///
    /// # Errors
    ///
    /// Fails closed when the observer cannot materialize the exact canonical
    /// base and issue from the executor node.
    pub fn prepare(
        &self,
        metadata: &DeploymentMetadata,
        executor_node_id: &NodeId,
    ) -> Result<(), ObserverError> {
        let response = self
            .client
            .post(format!("{}/internal/v1/prepare", self.endpoint))
            .bearer_auth(&*self.authentication_token)
            .json(&PrepareRequest {
                rid: metadata.rid.clone(),
                executor_node_id: executor_node_id.clone(),
                executor_address: self.executor_address.to_string(),
                canonical_base_oid: metadata.canonical_base_oid.clone(),
                issue_id: metadata.issue_id.clone(),
            })
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json::<Value>)
            .map_err(|_| ObserverError)?;
        if response.get("observer_node_id").and_then(Value::as_str)
            != Some(self.expected_observer.as_str())
        {
            return Err(ObserverError);
        }
        Ok(())
    }
}

impl PropagationObserver for HttpPropagationObserver {
    fn observe(
        &self,
        publication: &LocalPublication,
        execution_receipt_digest: &DigestHex,
        _: u64,
    ) -> Result<RadiclePropagationReceipt, PortError> {
        let response = self
            .client
            .post(format!("{}/internal/v1/observe", self.endpoint))
            .bearer_auth(&*self.authentication_token)
            .json(&ObserveRequest {
                publication: publication.clone(),
                execution_receipt_digest: execution_receipt_digest.clone(),
                executor_address: self.executor_address.to_string(),
            })
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json::<ObserveResponse>)
            .map_err(|_| PortError::Propagation)?;
        if response.observer_node_id != self.expected_observer
            || response.revision_id != publication.revision_id
            || response.candidate_oid != publication.candidate_oid
        {
            return Err(PortError::Propagation);
        }
        Ok(RadiclePropagationReceipt {
            schema: "auths-radicle-propagation-v1".into(),
            execution_receipt_digest: execution_receipt_digest.clone(),
            observer_node_id: response.observer_node_id,
            revision_id: response.revision_id,
            candidate_oid: response.candidate_oid,
            observed_at: response.observed_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("independent Radicle observer configuration failed closed")]
pub struct ObserverError;

enum ObserverApiError {
    Unauthorized,
    Unavailable,
    Mismatch,
}

impl IntoResponse for ObserverApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "observer-unauthorized"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "observer-unavailable"),
            Self::Mismatch => (StatusCode::CONFLICT, "observer-postcondition-mismatch"),
        };
        (
            status,
            Json(json!({
                "error": {
                    "code": code,
                    "message": "the independent observer failed closed",
                }
            })),
        )
            .into_response()
    }
}
