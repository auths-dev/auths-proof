//! Deterministic profile inputs for tests and higher-layer demos.

#![allow(
    clippy::missing_panics_doc,
    reason = "fixed test constants are asserted during fixture construction and cannot contain hostile input"
)]

use std::collections::BTreeMap;

use crate::{
    canonical::{canonical_json, sha256},
    types::{
        AdmissionMode, AllowedChangeProjectionV1, ImageDigestRef, KubernetesEvidenceV1,
        KubernetesName, KubernetesUid, KubernetesVerifierConfiguration,
        KubernetesVerifierConfigurationInput, KubernetesWorkloadRolloutInput,
        KubernetesWorkloadRolloutV1,
    },
};

pub const NOW: u64 = 1_800_000_000;
pub const OLD_IMAGE: &str =
    "registry.k8s.io/pause@sha256:927d98197ec1141a3685508224df2f2c54c2eafd6a24dc154edb8f7d8adf4d2c";
pub const NEW_IMAGE: &str =
    "registry.k8s.io/pause@sha256:7031c1b283388d2e9c161cbace5a8e1f20e3766a4f3aa5c0d4c6c6d0d8a98c9d";

/// Complete deterministic test fixture.
pub struct Fixture {
    pub now: u64,
    pub configuration: KubernetesVerifierConfiguration,
    pub evidence: KubernetesEvidenceV1,
    pub action: KubernetesWorkloadRolloutV1,
}

impl Fixture {
    #[must_use]
    pub fn configuration_with_maximum_replicas(
        &self,
        maximum_replicas: u32,
    ) -> KubernetesVerifierConfiguration {
        configuration(maximum_replicas)
    }
}

#[must_use]
pub fn configuration(maximum_replicas: u32) -> KubernetesVerifierConfiguration {
    KubernetesVerifierConfiguration::new(KubernetesVerifierConfigurationInput {
        cluster_audience: "fly-fks://auths-kubernetes-demo".into(),
        allowed_namespaces: vec![KubernetesName::parse("auths-demo").unwrap()],
        allowed_deployments: vec![KubernetesName::parse("color-service").unwrap()],
        allowed_container_names: vec![KubernetesName::parse("color-service").unwrap()],
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
        executor_audience: "https://kubernetes-executor.auths.dev".into(),
    })
    .unwrap()
}

#[must_use]
pub fn fixture() -> Fixture {
    let configuration = configuration(3);
    let patch_value = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "color-service",
            "namespace": "auths-demo",
            "annotations": {"auths.dev/rollout": "green"}
        },
        "spec": {
            "replicas": 2,
            "template": {
                "spec": {
                    "containers": [{
                        "name": "color-service",
                        "image": NEW_IMAGE
                    }]
                }
            }
        }
    });
    let patch_bytes = String::from_utf8(canonical_json(&patch_value).unwrap()).unwrap();
    let evidence = KubernetesEvidenceV1 {
        cluster_audience: configuration.cluster_audience().into(),
        api_server_identity: "sha256:fks-demo-ca".into(),
        namespace_name: KubernetesName::parse("auths-demo").unwrap(),
        namespace_uid: KubernetesUid::parse("namespace-demo-uid").unwrap(),
        resource_name: KubernetesName::parse("color-service").unwrap(),
        resource_uid: KubernetesUid::parse("deployment-demo-uid").unwrap(),
        resource_version: "42".into(),
        generation: 7,
        deletion_timestamp: None,
        current_spec_digest: sha256(b"current-spec"),
        current_image: ImageDigestRef::parse(OLD_IMAGE).unwrap(),
        current_replicas: 2,
        dry_run_response_digest: sha256(b"dry-run-response"),
        dry_run_warnings: Vec::new(),
        managed_field_conflict: false,
        observed_at: NOW,
    };
    let projection = AllowedChangeProjectionV1 {
        container_name: KubernetesName::parse("color-service").unwrap(),
        previous_image_digest: ImageDigestRef::parse(OLD_IMAGE).unwrap(),
        requested_image_digest: ImageDigestRef::parse(NEW_IMAGE).unwrap(),
        previous_replicas: 2,
        requested_replicas: 2,
        annotation_changes: BTreeMap::from([("auths.dev/rollout".into(), "green".into())]),
        unchanged_fields_digest: sha256(b"unchanged-fields"),
    };
    let action = KubernetesWorkloadRolloutV1::new(KubernetesWorkloadRolloutInput {
        workflow_id: "kubernetes-fixture-workflow".into(),
        executor_audience: configuration.executor_audience().into(),
        cluster_audience: configuration.cluster_audience().into(),
        api_server_identity: evidence.api_server_identity.clone(),
        namespace_name: evidence.namespace_name.clone(),
        namespace_uid: evidence.namespace_uid.clone(),
        resource_name: evidence.resource_name.clone(),
        resource_uid: evidence.resource_uid.clone(),
        expected_resource_version: evidence.resource_version.clone(),
        current_spec_digest: evidence.current_spec_digest.clone(),
        patch_bytes,
        dry_run_response_digest: evidence.dry_run_response_digest.clone(),
        dry_run_observed_at: NOW,
        allowed_change_projection: projection,
        required_configuration_digest: configuration.digest().unwrap(),
        evidence_digest: evidence.digest().unwrap(),
        expires_at: NOW + 300,
        nonce: sha256(b"kubernetes-nonce"),
    })
    .unwrap();
    Fixture {
        now: NOW,
        configuration,
        evidence,
        action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_is_canonical_and_digest_bound() {
        let fixture = fixture();
        assert_eq!(
            fixture.action.patch_digest(),
            &sha256(fixture.action.patch_bytes())
        );
    }
}
