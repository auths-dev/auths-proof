#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn matrix() -> Result<(), String> {
    let nominal = auths_lab_matrix::nominal_matrix();
    let compatible = auths_lab_matrix::compatible_matrix();
    if nominal.len() != 504 || compatible.len() != 396 {
        return Err(format!(
            "unexpected target matrix shape: {} nominal, {} compatible",
            nominal.len(),
            compatible.len()
        ));
    }
    println!(
        "Auths Lab matrix: {} nominal points, {} baseline-compatible points",
        nominal.len(),
        compatible.len()
    );
    Ok(())
}

pub(crate) fn cross_language_corpus() -> Result<(), String> {
    let manifest = root().join("core/fixtures/v1/manifest.json");
    let go_root = root().join("bindings/independent/go");
    let go_cache = root().join("target/go-build-cache");
    fs::create_dir_all(&go_cache).map_err(|error| format!("could not create Go cache: {error}"))?;
    let typescript_program = root().join("bindings/independent/typescript/auths-corpus-check.ts");
    let go = command_output_in(
        "go",
        &["run", "./cmd/auths-corpus-check", path_text(&manifest)?],
        &go_root,
        Some(("GOCACHE", &go_cache)),
    )?;
    let typescript = command_output_in(
        "node",
        &[
            "--experimental-strip-types",
            path_text(&typescript_program)?,
            path_text(&manifest)?,
        ],
        &root(),
        None,
    )?;
    let go = go.trim();
    let typescript = typescript.trim();
    if go != typescript {
        return Err(format!(
            "independent corpus auditors disagreed: Go={go:?}, TypeScript={typescript:?}"
        ));
    }
    let go_semantic = command_output_in(
        "go",
        &[
            "run",
            "./cmd/auths-corpus-check",
            "--semantic",
            path_text(&manifest)?,
        ],
        &go_root,
        Some(("GOCACHE", &go_cache)),
    )?;
    let typescript_semantic = command_output_in(
        "node",
        &[
            "--experimental-strip-types",
            path_text(&typescript_program)?,
            "--semantic",
            path_text(&manifest)?,
        ],
        &root(),
        None,
    )?;
    let rust_semantic = semantic_digest_value()?;
    let go_semantic = go_semantic.trim();
    let typescript_semantic = typescript_semantic.trim();
    if go_semantic != typescript_semantic || go_semantic != rust_semantic {
        return Err(format!(
            "independent semantic verifiers disagreed: \
             Rust={rust_semantic:?}, Go={go_semantic:?}, TypeScript={typescript_semantic:?}"
        ));
    }
    println!("Rust, Go, and TypeScript corpus verifiers agree: {go_semantic}");
    Ok(())
}

pub(crate) fn product_fixtures(update: bool) -> Result<(), String> {
    let fixture = auths_apps_testkit::demo_fixture_bytes();
    let mut expected = BTreeMap::from([
        (PathBuf::from("mcp-call.json"), fixture.body),
        (PathBuf::from("mcp-call.proof.cbor"), fixture.proof),
        (
            PathBuf::from("root-principal.txt"),
            format!("{}\n", fixture.root_principal).into_bytes(),
        ),
    ]);
    expected.extend(github_product_fixtures()?);
    expected.extend(radicle_product_fixtures()?);
    expected.extend(stripe_product_fixtures()?);
    expected.extend(kubernetes_product_fixtures()?);
    expected.extend(records_api_product_fixtures()?);
    expected.extend(opentofu_product_fixtures()?);
    expected.extend(postgresql_product_fixtures()?);
    expected.extend(bounded_policy_contract_fixtures()?);
    let directory = root().join("product/fixtures/v1");
    if update {
        fs::create_dir_all(&directory)
            .map_err(|error| format!("could not create product fixtures: {error}"))?;
        for (relative, bytes) in expected {
            let path = directory.join(relative);
            let parent = path
                .parent()
                .ok_or_else(|| format!("product fixture {} has no parent", path.display()))?;
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create product fixture directory: {error}"))?;
            fs::write(path, bytes)
                .map_err(|error| format!("could not write product fixture: {error}"))?;
        }
        println!("product fixtures updated");
        return Ok(());
    }
    for (relative, expected) in expected {
        let actual = fs::read(directory.join(&relative)).map_err(|error| {
            format!(
                "could not read product fixture {}: {error}",
                relative.display()
            )
        })?;
        if actual != expected {
            return Err(format!(
                "product fixture {} drifted; run `cargo xtask product-fixtures --update`",
                relative.display()
            ));
        }
    }
    println!("product fixtures are stable");
    Ok(())
}

fn bounded_policy_contract_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    const REGISTRY: &str = r#"schema = "auths.product.closed-evaluator-registry/1"
contract = "auths.product.bounded-policy-contract/1"
migration_status = "reference-only"
domains = ["github", "kubernetes", "opentofu", "postgresql", "radicle", "records-api", "stripe"]

[[semantic_surfaces]]
id = "auths.product.policy-commitment/1"
rust_symbol = "auths_bounded_policy::PolicyCommitmentV1"
lean_artifact = "Auths.Product.PolicyCommitment"

[[semantic_surfaces]]
id = "auths.product.evaluation-commitments/1"
rust_symbol = "auths_bounded_policy::EvaluationCommitmentsV1"
lean_artifact = "Auths.Product.ConfigurationCommitment"

[[semantic_surfaces]]
id = "auths.product.configuration-match/1"
rust_symbol = "auths_bounded_policy::configuration_match"
lean_artifact = "Auths.Product.configurationMatch"

[[semantic_surfaces]]
id = "auths.product.eligibility/1"
rust_symbol = "auths_bounded_policy::EligibilityV1"
lean_artifact = "Auths.Product.Eligibility"

[[semantic_surfaces]]
id = "auths.product.checked-arithmetic/1"
rust_symbol = "auths_bounded_policy::checked_basis_points"
lean_artifact = "Auths.Product.checkedAdd"

[[semantic_surfaces]]
id = "auths.product.bounded-decision-envelope/1"
rust_symbol = "auths_bounded_policy::BoundedDecisionEnvelopeV1"
lean_artifact = "Auths.Product.OutputCommitments"

[[semantic_surfaces]]
id = "auths.product.bounded-policy-compatibility/1"
rust_symbol = "auths_bounded_policy::validate_registry"
lean_artifact = "Auths.Product.ClosedEvaluator"

[[evaluators]]
domain_id = "records-api"
owning_package = "auths-records-api"
layer = "product"
profile_id = "auths.demo.records.create/1"
policy_type_id = "auths.records.create-policy/1"
evaluator_semantic_id = "auths.demo.records.create.evaluate/1"
implementation_id = "auths-records-api/reference-pre-migration"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_records_api::evaluate_create"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_records_api::CreateRecordV1"
policy_schema = "auths_records_api::BoundedRecordApiPolicyV1"
evidence_schema = "none-pre-migration"
state_schema = "none-pre-migration"
result_schema = "auths_records_api::RecordsDecision"
intent_schema = "none-pre-migration"
obligation_schema = "none-pre-migration"
receipt_schema = "auths_records_api::DecisionReceipt"
stable_code_source = "product/integrations/auths-records-api/src/decision.rs"
stable_stage_source = "product/integrations/auths-records-api/src/decision.rs"
hard_limit_source = "product/integrations/auths-records-api/src/policy.rs"
fixture_manifest = "product/fixtures/v1/records-api/manifest.json"
mutation_corpus = "product/fixtures/v1/records-api"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-records-api/src/decision.rs"
reference_evaluator = "auths_records_api::evaluate_create"
migration_status = "reference-only"

[[evaluators]]
domain_id = "records-api"
owning_package = "auths-records-api"
layer = "product"
profile_id = "auths.demo.records.read/1"
policy_type_id = "auths.records.read-policy/1"
evaluator_semantic_id = "auths.demo.records.read.evaluate/1"
implementation_id = "auths-records-api/reference-pre-migration"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_records_api::evaluate_read"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_records_api::ReadRecordV1"
policy_schema = "auths_records_api::BoundedRecordApiPolicyV1"
evidence_schema = "none-pre-migration"
state_schema = "none-pre-migration"
result_schema = "auths_records_api::RecordsDecision"
intent_schema = "none-pre-migration"
obligation_schema = "none-pre-migration"
receipt_schema = "auths_records_api::DecisionReceipt"
stable_code_source = "product/integrations/auths-records-api/src/decision.rs"
stable_stage_source = "product/integrations/auths-records-api/src/decision.rs"
hard_limit_source = "product/integrations/auths-records-api/src/policy.rs"
fixture_manifest = "product/fixtures/v1/records-api/manifest.json"
mutation_corpus = "product/fixtures/v1/records-api"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-records-api/src/decision.rs"
reference_evaluator = "auths_records_api::evaluate_read"
migration_status = "reference-only"

[[evaluators]]
domain_id = "github"
owning_package = "auths-github"
layer = "product"
profile_id = "auths.github.issue-address.branch-publish/1"
policy_type_id = "auths.github.issue-workflow-grant/1"
evaluator_semantic_id = "auths.github.branch-publish.evaluate/1"
implementation_id = "auths-github/shared-lifecycle-production/1"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_github::containment::evaluate"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_github::ExactGitHubAction"
policy_schema = "auths_github::WorkflowGrant"
evidence_schema = "auths_github::GitHubEvidence"
state_schema = "auths.github.branch-ref-snapshot/1"
result_schema = "auths_github::Decision"
intent_schema = "auths.github.branch-ref-exclusive-intent/1"
obligation_schema = "auths_github::VerifiedPublishBranchCommand"
receipt_schema = "auths_github::GitHubDecisionReceipt"
stable_code_source = "product/integrations/auths-github/src/containment.rs"
stable_stage_source = "product/integrations/auths-github/src/containment.rs"
hard_limit_source = "product/integrations/auths-github/src/profile.rs"
fixture_manifest = "product/fixtures/v1/github/manifest.json"
mutation_corpus = "product/fixtures/v1/github"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-github/src/containment.rs"
reference_evaluator = "auths_github::containment::evaluate"
migration_status = "reference-only"

[[evaluators]]
domain_id = "github"
owning_package = "auths-github"
layer = "product"
profile_id = "auths.github.issue-address.pull-request-open-draft/1"
policy_type_id = "auths.github.issue-workflow-grant/1"
evaluator_semantic_id = "auths.github.pull-request-open-draft.evaluate/1"
implementation_id = "auths-github/shared-lifecycle-production/1"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_github::containment::evaluate"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_github::ExactGitHubAction"
policy_schema = "auths_github::WorkflowGrant"
evidence_schema = "auths_github::GitHubEvidence"
state_schema = "auths.github.pull-request-set-snapshot/1"
result_schema = "auths_github::Decision"
intent_schema = "auths.github.pull-request-head-exclusive-intent/1"
obligation_schema = "auths_github::VerifiedOpenDraftPullRequestCommand"
receipt_schema = "auths_github::GitHubDecisionReceipt"
stable_code_source = "product/integrations/auths-github/src/containment.rs"
stable_stage_source = "product/integrations/auths-github/src/containment.rs"
hard_limit_source = "product/integrations/auths-github/src/profile.rs"
fixture_manifest = "product/fixtures/v1/github/manifest.json"
mutation_corpus = "product/fixtures/v1/github"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-github/src/containment.rs"
reference_evaluator = "auths_github::containment::evaluate"
migration_status = "reference-only"

[[evaluators]]
domain_id = "kubernetes"
owning_package = "auths-kubernetes"
layer = "product"
profile_id = "auths.kubernetes.workload-rollout/1"
policy_type_id = "auths.kubernetes.rollout-policy/1"
evaluator_semantic_id = "auths.kubernetes.workload-rollout.evaluate/1"
implementation_id = "auths-kubernetes/reference-pre-migration"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_kubernetes::evaluate"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_kubernetes::KubernetesWorkloadRolloutV1"
policy_schema = "auths_kubernetes::KubernetesVerifierConfiguration"
evidence_schema = "auths_kubernetes::KubernetesEvidenceV1"
state_schema = "auths_kubernetes::KubernetesEvidenceV1"
result_schema = "auths_kubernetes::Decision"
intent_schema = "auths_kubernetes::ClaimRecord"
obligation_schema = "auths_kubernetes::VerifiedRolloutCommand"
receipt_schema = "auths_kubernetes::DecisionReceipt"
stable_code_source = "product/integrations/auths-kubernetes/src/decision.rs"
stable_stage_source = "product/integrations/auths-kubernetes/src/decision.rs"
hard_limit_source = "product/integrations/auths-kubernetes/src/profile.rs"
fixture_manifest = "product/fixtures/v1/kubernetes/manifest.json"
mutation_corpus = "product/fixtures/v1/kubernetes"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-kubernetes/src/decision.rs"
reference_evaluator = "auths_kubernetes::evaluate"
migration_status = "reference-only"

[[evaluators]]
domain_id = "opentofu"
owning_package = "auths-opentofu"
layer = "product"
profile_id = "auths.opentofu.saved-plan-apply/1"
policy_type_id = "auths.opentofu.saved-plan-policy/1"
evaluator_semantic_id = "auths.opentofu.saved-plan-apply.evaluate/1"
implementation_id = "auths-opentofu/reference-pre-migration"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_opentofu::evaluate"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_opentofu::OpenTofuSavedPlanApplyV1"
policy_schema = "auths_opentofu::OpenTofuVerifierConfigurationV1"
evidence_schema = "auths_opentofu::OpenTofuStateEvidenceV1"
state_schema = "auths_opentofu::SavedPlanProjectionV1"
result_schema = "auths_opentofu::Decision"
intent_schema = "auths_opentofu::ClaimRecord"
obligation_schema = "auths_opentofu::VerifiedOpenTofuApply"
receipt_schema = "auths_opentofu::DecisionReceipt"
stable_code_source = "product/integrations/auths-opentofu/src/decision.rs"
stable_stage_source = "product/integrations/auths-opentofu/src/decision.rs"
hard_limit_source = "product/integrations/auths-opentofu/src/profile.rs"
fixture_manifest = "product/fixtures/v1/opentofu/manifest.json"
mutation_corpus = "product/fixtures/v1/opentofu"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-opentofu/src/decision.rs"
reference_evaluator = "auths_opentofu::evaluate"
migration_status = "reference-only"

[[evaluators]]
domain_id = "postgresql"
owning_package = "auths-postgresql"
layer = "product"
profile_id = "auths.postgresql.bounded-update/1"
policy_type_id = "auths.postgresql.bounded-update-policy/1"
evaluator_semantic_id = "auths.postgresql.bounded-update.evaluate/1"
implementation_id = "auths-postgresql/reference-pre-migration"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_postgresql::evaluate"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_postgresql::PostgresBoundedUpdateV1"
policy_schema = "auths_postgresql::PostgresUpdateIntentV1"
evidence_schema = "auths_postgresql::PostgresEvidenceV1"
state_schema = "auths_postgresql::PostgresEvidenceV1"
result_schema = "auths_postgresql::Decision"
intent_schema = "auths_postgresql::ClaimRecord"
obligation_schema = "auths_postgresql::VerifiedPostgresUpdate"
receipt_schema = "auths_postgresql::DecisionReceipt"
stable_code_source = "product/integrations/auths-postgresql/src/decision.rs"
stable_stage_source = "product/integrations/auths-postgresql/src/decision.rs"
hard_limit_source = "product/integrations/auths-postgresql/src/schema.rs"
fixture_manifest = "product/fixtures/v1/postgresql/manifest.json"
mutation_corpus = "product/fixtures/v1/postgresql"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-postgresql/src/decision.rs"
reference_evaluator = "auths_postgresql::evaluate"
migration_status = "reference-only"

[[evaluators]]
domain_id = "radicle"
owning_package = "auths-radicle"
layer = "product"
profile_id = "auths.radicle.issue-address/1"
policy_type_id = "auths.radicle.issue-address-grant/1"
evaluator_semantic_id = "auths.radicle.issue-address.evaluate/1"
implementation_id = "auths-radicle/reference-pre-migration"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_radicle::containment::evaluate"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_radicle::OpenPatchActionV1"
policy_schema = "auths_radicle::IssueAddressGrantV1"
evidence_schema = "auths_radicle::RadicleEvidenceV1"
state_schema = "auths_radicle::CandidateFacts"
result_schema = "auths_radicle::Decision"
intent_schema = "auths_radicle::workflow::ExecutionLease"
obligation_schema = "auths_radicle::VerifiedOpenPatchCommand"
receipt_schema = "auths_radicle::RadicleDecisionReceipt"
stable_code_source = "product/integrations/auths-radicle/src/containment.rs"
stable_stage_source = "product/integrations/auths-radicle/src/containment.rs"
hard_limit_source = "product/integrations/auths-radicle/src/profile.rs"
fixture_manifest = "product/fixtures/v1/radicle/manifest.json"
mutation_corpus = "product/fixtures/v1/radicle"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-radicle/src/containment.rs"
reference_evaluator = "auths_radicle::containment::evaluate"
migration_status = "reference-only"

[[evaluators]]
domain_id = "stripe"
owning_package = "auths-stripe"
layer = "product"
profile_id = "auths.stripe.exact-refund/1"
policy_type_id = "auths.stripe.bounded-refund-policy/1"
evaluator_semantic_id = "auths.stripe.exact-refund.evaluate/1"
implementation_id = "auths-stripe/reference-pre-migration"
canonicalization_id = "rfc8785-sha256-v1"
rust_symbol = "auths_stripe::evaluate_bounded_refund"
lean_artifact = "Auths.Product.fixed_context_tightening"
action_schema = "auths_stripe::ExactRefundActionV1"
policy_schema = "auths_stripe::StripeBoundedRefundPolicyV1"
evidence_schema = "auths_stripe::RefundEvidenceV1"
state_schema = "auths_stripe::AggregateBudgetSnapshot"
result_schema = "auths_stripe::BoundedRefundDecision"
intent_schema = "auths_stripe::RefundReservationRecord"
obligation_schema = "auths_stripe::VerifiedRefundCommand"
receipt_schema = "auths_stripe::BoundedDecisionReceipt"
stable_code_source = "product/integrations/auths-stripe/src/bounded.rs"
stable_stage_source = "product/integrations/auths-stripe/src/bounded.rs"
hard_limit_source = "product/integrations/auths-stripe/src/bounded.rs"
fixture_manifest = "product/fixtures/v1/stripe/manifest.json"
mutation_corpus = "product/fixtures/v1/stripe"
fuzz_target = "product/policy/auths-bounded-policy/fuzz/fuzz_targets/target_bounded_policy.rs"
kani_harnesses = "auths_bounded_policy::kernel::proof_configuration_match_total"
property_tests = "product/integrations/auths-stripe/src/bounded.rs"
reference_evaluator = "auths_stripe::evaluate_bounded_refund"
migration_status = "reference-only"
"#;
    let registry = REGISTRY.as_bytes().to_vec();
    let manifest = serde_json::to_vec(&json!({
        "schema": "auths.product.bounded-policy-conformance-manifest/1",
        "contract": "auths.product.bounded-policy-contract/1",
        "generator": "cargo xtask product-fixtures --update",
        "registry": "registry.toml",
        "registry_bytes": registry.len(),
        "registry_sha256": format!("{:x}", Sha256::digest(&registry)),
        "migration_status": "reference-only",
        "domain_oracles": [
            "github",
            "kubernetes",
            "opentofu",
            "postgresql",
            "radicle",
            "records-api",
            "stripe",
        ],
    }))
    .map_err(|error| format!("could not serialize bounded-policy manifest: {error}"))?;
    Ok(BTreeMap::from([
        (PathBuf::from("bounded-policy/manifest.json"), manifest),
        (PathBuf::from("bounded-policy/registry.toml"), registry),
    ]))
}

pub(crate) fn github_product_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    use auths_github::{
        ExactGitHubAction,
        canonical::canonical_json,
        containment::{EvaluationContext, evaluate},
        derive_publish_branch_action,
        test_support::{NOW, fixture},
    };

    let fixture = fixture();
    let action = ExactGitHubAction::PublishBranch(
        derive_publish_branch_action(&fixture.grant, &fixture.configuration, &fixture.evidence)
            .map_err(|error| format!("could not derive GitHub fixture action: {error}"))?,
    );
    let authorized = evaluate(&EvaluationContext {
        grant: &fixture.grant,
        action: &action,
        candidate: &fixture.candidate,
        evidence: &fixture.evidence,
        required_configuration: &fixture.configuration,
        executed_configuration: &fixture.configuration,
        request_audience: fixture.configuration.executor_audience().as_str(),
        now: NOW,
    });
    let mismatched_configuration =
        auths_github::VerifierConfiguration::new(auths_github::VerifierConfigurationInput {
            candidate_inspector: "git-cli-bounded-v2".into(),
            github_adapter: "github-rest-2022-11-28".into(),
            canonical_reference: "jcs-rfc8785-v1".into(),
            repository_automation_policy_digest: fixture
                .configuration
                .repository_automation_policy_digest()
                .clone(),
            maximum_evidence_age_seconds: 30,
            executor_audience: fixture.configuration.executor_audience().clone(),
            receipt_schema: "auths-github-receipt-v1".into(),
        })
        .map_err(|error| format!("could not build GitHub mismatch configuration: {error}"))?;
    let mismatch = evaluate(&EvaluationContext {
        grant: &fixture.grant,
        action: &action,
        candidate: &fixture.candidate,
        evidence: &fixture.evidence,
        required_configuration: &fixture.configuration,
        executed_configuration: &mismatched_configuration,
        request_audience: fixture.configuration.executor_audience().as_str(),
        now: NOW,
    });
    let mut files = BTreeMap::from([
        (
            PathBuf::from("github/action.json"),
            action
                .canonical_bytes()
                .map_err(|error| format!("could not serialize GitHub action: {error}"))?,
        ),
        (
            PathBuf::from("github/policy.json"),
            fixture
                .grant
                .canonical_bytes()
                .map_err(|error| format!("could not serialize GitHub grant: {error}"))?,
        ),
        (
            PathBuf::from("github/evidence.json"),
            canonical_json(&fixture.evidence)
                .map_err(|error| format!("could not serialize GitHub evidence: {error}"))?,
        ),
        (
            PathBuf::from("github/required-configuration.json"),
            canonical_json(&fixture.configuration)
                .map_err(|error| format!("could not serialize GitHub configuration: {error}"))?,
        ),
        (
            PathBuf::from("github/authorized-decision.json"),
            canonical_json(&authorized)
                .map_err(|error| format!("could not serialize GitHub decision: {error}"))?,
        ),
        (
            PathBuf::from("github/configuration-mismatch-decision.json"),
            canonical_json(&mismatch)
                .map_err(|error| format!("could not serialize GitHub denial: {error}"))?,
        ),
    ]);
    insert_bounded_fixture_manifest(
        "github",
        &[
            "auths.github.issue-address.branch-publish/1",
            "auths.github.issue-address.pull-request-open-draft/1",
        ],
        bounded_scenarios("github"),
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn radicle_product_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    use auths_radicle::{
        canonical::canonical_json,
        containment::{EvaluationContext, evaluate},
        test_support::{NOW, action, candidate, configuration, evidence, grant, submission},
    };

    let required = configuration(30);
    let grant = grant(required.clone());
    let submission = submission();
    let candidate = candidate(&submission);
    let evidence = evidence(&grant, NOW - 5);
    let action = action(&grant, &required, &submission, &candidate, &evidence);
    let authorized = evaluate(&EvaluationContext {
        grant: &grant,
        action: &action,
        submission: &submission,
        candidate: &candidate,
        evidence: &evidence,
        required_configuration: &required,
        executed_configuration: &required,
        request_audience: required.executor_audience().as_str(),
        now: NOW,
    });
    let executed = configuration(29);
    let mismatch = evaluate(&EvaluationContext {
        grant: &grant,
        action: &action,
        submission: &submission,
        candidate: &candidate,
        evidence: &evidence,
        required_configuration: &required,
        executed_configuration: &executed,
        request_audience: required.executor_audience().as_str(),
        now: NOW,
    });
    let mut files = BTreeMap::from([
        (
            PathBuf::from("radicle/action.json"),
            action
                .canonical_bytes()
                .map_err(|error| format!("could not serialize Radicle action: {error}"))?,
        ),
        (
            PathBuf::from("radicle/policy.json"),
            grant
                .canonical_bytes()
                .map_err(|error| format!("could not serialize Radicle grant: {error}"))?,
        ),
        (
            PathBuf::from("radicle/evidence.json"),
            canonical_json(&evidence)
                .map_err(|error| format!("could not serialize Radicle evidence: {error}"))?,
        ),
        (
            PathBuf::from("radicle/required-configuration.json"),
            canonical_json(&required)
                .map_err(|error| format!("could not serialize Radicle configuration: {error}"))?,
        ),
        (
            PathBuf::from("radicle/authorized-decision.json"),
            canonical_json(&authorized)
                .map_err(|error| format!("could not serialize Radicle decision: {error}"))?,
        ),
        (
            PathBuf::from("radicle/configuration-mismatch-decision.json"),
            canonical_json(&mismatch)
                .map_err(|error| format!("could not serialize Radicle denial: {error}"))?,
        ),
    ]);
    insert_bounded_fixture_manifest(
        "radicle",
        &["auths.radicle.issue-address/1"],
        bounded_scenarios("radicle"),
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn stripe_product_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    use auths_stripe::{
        AggregateBudgetSnapshot, BoundedEvaluationContext, RefundDenominator,
        canonical::canonical_json,
        evaluate_bounded_refund,
        test_support::{
            NOW, action as exact_action, bounded_action,
            bounded_configuration as make_bounded_configuration, bounded_policy, configuration,
            evidence,
        },
    };

    let exact_configuration = configuration(2_000);
    let evidence = evidence(10_000, 0);
    let policy = bounded_policy(
        &evidence,
        2_000,
        10_000,
        RefundDenominator::OriginalChargeAmount,
        5_000,
    );
    let bounded_configuration = make_bounded_configuration(&policy);
    let action = bounded_action(
        &exact_configuration,
        &policy,
        &evidence,
        2_000,
        "stripe-bounded-oracle",
    );
    let snapshot = AggregateBudgetSnapshot::default();
    let authorized = evaluate_bounded_refund(&BoundedEvaluationContext {
        policy: &policy,
        action: &action,
        evidence: &evidence,
        aggregate_snapshot: &snapshot,
        required_exact_configuration: &exact_configuration,
        executed_exact_configuration: &exact_configuration,
        required_bounded_configuration: &bounded_configuration,
        executed_bounded_configuration: &bounded_configuration,
        request_audience: exact_configuration.executor_audience(),
        now: NOW,
    });
    let plus_one_action = exact_action(&exact_configuration, &evidence, 2_001);
    let boundary_plus_one = evaluate_bounded_refund(&BoundedEvaluationContext {
        policy: &policy,
        action: &plus_one_action,
        evidence: &evidence,
        aggregate_snapshot: &snapshot,
        required_exact_configuration: &exact_configuration,
        executed_exact_configuration: &exact_configuration,
        required_bounded_configuration: &bounded_configuration,
        executed_bounded_configuration: &bounded_configuration,
        request_audience: exact_configuration.executor_audience(),
        now: NOW,
    });
    let changed_policy = bounded_policy(
        &evidence,
        1_999,
        10_000,
        RefundDenominator::OriginalChargeAmount,
        5_000,
    );
    let executed_bounded_configuration = make_bounded_configuration(&changed_policy);
    let mismatch = evaluate_bounded_refund(&BoundedEvaluationContext {
        policy: &policy,
        action: &action,
        evidence: &evidence,
        aggregate_snapshot: &snapshot,
        required_exact_configuration: &exact_configuration,
        executed_exact_configuration: &exact_configuration,
        required_bounded_configuration: &bounded_configuration,
        executed_bounded_configuration: &executed_bounded_configuration,
        request_audience: exact_configuration.executor_audience(),
        now: NOW,
    });
    let mut files = BTreeMap::from([
        (
            PathBuf::from("stripe/action.json"),
            action
                .canonical_bytes()
                .map_err(|error| format!("could not serialize Stripe action: {error}"))?,
        ),
        (
            PathBuf::from("stripe/policy.json"),
            canonical_json(&policy)
                .map_err(|error| format!("could not serialize Stripe policy: {error}"))?,
        ),
        (
            PathBuf::from("stripe/evidence.json"),
            canonical_json(&evidence)
                .map_err(|error| format!("could not serialize Stripe evidence: {error}"))?,
        ),
        (
            PathBuf::from("stripe/required-configuration.json"),
            canonical_json(&bounded_configuration)
                .map_err(|error| format!("could not serialize Stripe configuration: {error}"))?,
        ),
        (
            PathBuf::from("stripe/authorized-decision.json"),
            canonical_json(&authorized)
                .map_err(|error| format!("could not serialize Stripe decision: {error}"))?,
        ),
        (
            PathBuf::from("stripe/boundary-plus-one-decision.json"),
            canonical_json(&boundary_plus_one)
                .map_err(|error| format!("could not serialize Stripe boundary denial: {error}"))?,
        ),
        (
            PathBuf::from("stripe/configuration-mismatch-decision.json"),
            canonical_json(&mismatch)
                .map_err(|error| format!("could not serialize Stripe mismatch: {error}"))?,
        ),
    ]);
    insert_bounded_fixture_manifest(
        "stripe",
        &["auths.stripe.exact-refund/1"],
        bounded_scenarios("stripe"),
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn kubernetes_product_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    use auths_kubernetes::{
        EvaluationContext,
        canonical::canonical_json,
        evaluate,
        test_support::{configuration, fixture},
    };

    let fixture = fixture();
    let authorized = evaluate(&EvaluationContext {
        action: &fixture.action,
        evidence: &fixture.evidence,
        required_configuration: &fixture.configuration,
        executed_configuration: &fixture.configuration,
        request_audience: fixture.configuration.executor_audience(),
        now: fixture.now,
    });
    let executed = configuration(2);
    let mismatch = evaluate(&EvaluationContext {
        action: &fixture.action,
        evidence: &fixture.evidence,
        required_configuration: &fixture.configuration,
        executed_configuration: &executed,
        request_audience: fixture.configuration.executor_audience(),
        now: fixture.now,
    });
    let mut files = BTreeMap::from([
        (
            PathBuf::from("kubernetes/action.json"),
            fixture
                .action
                .canonical_bytes()
                .map_err(|error| format!("could not serialize Kubernetes action: {error}"))?,
        ),
        (
            PathBuf::from("kubernetes/policy.json"),
            canonical_json(&fixture.configuration)
                .map_err(|error| format!("could not serialize Kubernetes policy: {error}"))?,
        ),
        (
            PathBuf::from("kubernetes/evidence.json"),
            canonical_json(&fixture.evidence)
                .map_err(|error| format!("could not serialize Kubernetes evidence: {error}"))?,
        ),
        (
            PathBuf::from("kubernetes/authorized-decision.json"),
            canonical_json(&authorized)
                .map_err(|error| format!("could not serialize Kubernetes decision: {error}"))?,
        ),
        (
            PathBuf::from("kubernetes/configuration-mismatch-decision.json"),
            canonical_json(&mismatch)
                .map_err(|error| format!("could not serialize Kubernetes mismatch: {error}"))?,
        ),
    ]);
    insert_bounded_fixture_manifest(
        "kubernetes",
        &["auths.kubernetes.workload-rollout/1"],
        bounded_scenarios("kubernetes"),
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn records_api_product_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    use auths_records_api::{
        BoundedRecordApiPolicyV1, CREATE_OPERATION, CreateEvaluation, CreateRecordV1,
        CustomerRecordV1, READ_OPERATION, ReadEvaluation, ReadField, ReadRecordV1,
        RecordIdentifier, canonical::canonical_json, demo_configuration, evaluate_create,
        evaluate_read,
    };

    let now = 200;
    let configuration = demo_configuration("https://records-executor.auths.dev");
    let policy = BoundedRecordApiPolicyV1 {
        policy_type: "auths.demo.bounded-record-api-policy".into(),
        policy_version: 1,
        policy_id: "policy-fixture".into(),
        namespace_id: RecordIdentifier::parse("visitor-fixture")
            .map_err(|error| format!("could not build records namespace: {error}"))?,
        presenter_principal:
            "key:ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        allowed_operations: vec![CREATE_OPERATION.into(), READ_OPERATION.into()],
        allowed_record_ids: Vec::new(),
        allowed_record_id_prefixes: vec!["demo-".into()],
        maximum_value_bytes: 1024,
        maximum_response_bytes: 4096,
        allowed_read_fields: vec![ReadField::Customer, ReadField::RecordId, ReadField::Version],
        maximum_creates: 3,
        maximum_reads: 3,
        maximum_created_bytes: 3072,
        maximum_disclosed_bytes: 12_288,
        fixed_and_rolling_budgets: Vec::new(),
        valid_from: 100,
        expires_at: 1_000,
        maximum_action_lifetime_seconds: 300,
        maximum_presentation_lifetime_seconds: 120,
        maximum_evidence_age_seconds: 60,
        executor_audience: "https://records-executor.auths.dev".into(),
    };
    policy
        .validate()
        .map_err(|error| format!("could not validate records policy: {error}"))?;
    let policy_digest = policy
        .digest()
        .map_err(|error| format!("could not commit records policy: {error}"))?;
    let configuration_digest = configuration
        .digest()
        .map_err(|error| format!("could not commit records configuration: {error}"))?;
    let record_id = RecordIdentifier::parse("demo-bob")
        .map_err(|error| format!("could not build records record ID: {error}"))?;
    let create = CreateRecordV1 {
        profile: "auths.demo.records.create/1".into(),
        namespace_id: policy.namespace_id.clone(),
        record_id: record_id.clone(),
        customer: CustomerRecordV1 {
            age: 25,
            name: "Bob".into(),
            notes: "Deterministic migration oracle".into(),
            occupation: "Sales".into(),
        },
        value_encoding: "auths.demo.customer-record/1".into(),
        expected_absent: true,
        policy_digest: policy_digest.clone(),
        required_evaluator: "auths.records.create-evaluator/1".into(),
        required_configuration_digest: configuration_digest.clone(),
        executor_audience: policy.executor_audience.clone(),
        expires_at: 500,
        nonce: "records-create-0001".into(),
    };
    let read = ReadRecordV1 {
        profile: "auths.demo.records.read/1".into(),
        namespace_id: policy.namespace_id.clone(),
        record_id,
        allowed_fields: vec![ReadField::Customer, ReadField::RecordId, ReadField::Version],
        maximum_response_bytes: 4096,
        expected_record_version: 1,
        policy_digest,
        required_evaluator: "auths.records.read-evaluator/1".into(),
        required_configuration_digest: configuration_digest,
        executor_audience: policy.executor_audience.clone(),
        expires_at: 500,
        nonce: "records-read-000001".into(),
    };
    let create_decision = evaluate_create(&CreateEvaluation {
        action: &create,
        policy: &policy,
        required_configuration: &configuration,
        executed_configuration: &configuration,
        now,
    });
    let read_decision = evaluate_read(&ReadEvaluation {
        action: &read,
        policy: &policy,
        required_configuration: &configuration,
        executed_configuration: &configuration,
        now,
    });
    let mut changed_configuration = configuration.clone();
    changed_configuration.maximum_response_bytes += 1;
    let mismatch = evaluate_create(&CreateEvaluation {
        action: &create,
        policy: &policy,
        required_configuration: &configuration,
        executed_configuration: &changed_configuration,
        now,
    });
    let mut over_disclosure = read.clone();
    over_disclosure.maximum_response_bytes += 1;
    let boundary_plus_one = evaluate_read(&ReadEvaluation {
        action: &over_disclosure,
        policy: &policy,
        required_configuration: &configuration,
        executed_configuration: &configuration,
        now,
    });
    let stale = evaluate_create(&CreateEvaluation {
        action: &create,
        policy: &policy,
        required_configuration: &configuration,
        executed_configuration: &configuration,
        now: 1_001,
    });
    let mut files = BTreeMap::from([
        (
            PathBuf::from("records-api/create-action.json"),
            create
                .canonical_bytes()
                .map_err(|error| format!("could not serialize records create action: {error}"))?,
        ),
        (
            PathBuf::from("records-api/read-action.json"),
            read.canonical_bytes()
                .map_err(|error| format!("could not serialize records read action: {error}"))?,
        ),
        (
            PathBuf::from("records-api/policy.json"),
            canonical_json(&policy)
                .map_err(|error| format!("could not serialize records policy: {error}"))?,
        ),
        (
            PathBuf::from("records-api/configuration.json"),
            canonical_json(&configuration)
                .map_err(|error| format!("could not serialize records configuration: {error}"))?,
        ),
        (
            PathBuf::from("records-api/create-authorized-decision.json"),
            canonical_json(&create_decision)
                .map_err(|error| format!("could not serialize records create decision: {error}"))?,
        ),
        (
            PathBuf::from("records-api/read-authorized-decision.json"),
            canonical_json(&read_decision)
                .map_err(|error| format!("could not serialize records read decision: {error}"))?,
        ),
        (
            PathBuf::from("records-api/boundary-plus-one-decision.json"),
            canonical_json(&boundary_plus_one).map_err(|error| {
                format!("could not serialize records boundary decision: {error}")
            })?,
        ),
        (
            PathBuf::from("records-api/configuration-mismatch-decision.json"),
            canonical_json(&mismatch)
                .map_err(|error| format!("could not serialize records mismatch: {error}"))?,
        ),
        (
            PathBuf::from("records-api/stale-decision.json"),
            canonical_json(&stale)
                .map_err(|error| format!("could not serialize records stale decision: {error}"))?,
        ),
        (
            PathBuf::from("records-api/malformed-17-byte.json"),
            b"{\"profile\":null}\n".to_vec(),
        ),
    ]);
    insert_bounded_fixture_manifest(
        "records-api",
        &["auths.demo.records.create/1", "auths.demo.records.read/1"],
        bounded_scenarios("records-api"),
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn opentofu_product_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    use auths_opentofu::{
        OpenTofuReceipt,
        canonical::canonical_json,
        decision_receipt,
        test_support::{NOW, PLAN_BYTES, configuration_with_maximum_resource_changes, fixture},
    };

    let fixture = fixture();
    let authorized = decision_receipt(
        &fixture.action,
        &fixture.projection,
        &fixture.evidence,
        &fixture.configuration,
        &fixture.configuration,
        fixture.configuration.executor_audience(),
        NOW,
    )
    .map_err(|error| format!("could not build OpenTofu authorized fixture: {error}"))?;
    let narrower_execution = configuration_with_maximum_resource_changes(3);
    let denied = decision_receipt(
        &fixture.action,
        &fixture.projection,
        &fixture.evidence,
        &fixture.configuration,
        &narrower_execution,
        fixture.configuration.executor_audience(),
        NOW,
    )
    .map_err(|error| format!("could not build OpenTofu denied fixture: {error}"))?;

    let mut files = BTreeMap::from([
        (
            PathBuf::from("opentofu/action.json"),
            fixture
                .action
                .canonical_bytes()
                .map_err(|error| format!("could not serialize OpenTofu action: {error}"))?,
        ),
        (
            PathBuf::from("opentofu/plan-projection.json"),
            canonical_json(&fixture.projection)
                .map_err(|error| format!("could not serialize OpenTofu projection: {error}"))?,
        ),
        (
            PathBuf::from("opentofu/state-evidence.json"),
            canonical_json(&fixture.evidence)
                .map_err(|error| format!("could not serialize OpenTofu evidence: {error}"))?,
        ),
        (
            PathBuf::from("opentofu/required-configuration.json"),
            canonical_json(&fixture.configuration)
                .map_err(|error| format!("could not serialize OpenTofu configuration: {error}"))?,
        ),
        (
            PathBuf::from("opentofu/authorized-decision.json"),
            canonical_json(&OpenTofuReceipt::Decision(Box::new(authorized)))
                .map_err(|error| format!("could not serialize OpenTofu receipt: {error}"))?,
        ),
        (
            PathBuf::from("opentofu/configuration-mismatch-decision.json"),
            canonical_json(&OpenTofuReceipt::Decision(Box::new(denied)))
                .map_err(|error| format!("could not serialize OpenTofu denial: {error}"))?,
        ),
        (
            PathBuf::from("opentofu/saved-plan.bin"),
            PLAN_BYTES.to_vec(),
        ),
    ]);
    insert_bounded_fixture_manifest(
        "opentofu",
        &["auths.opentofu.saved-plan-apply/1"],
        bounded_scenarios("opentofu"),
        &mut files,
    )?;
    Ok(files)
}

pub(crate) fn postgresql_product_fixtures() -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    use auths_postgresql::{
        PostgresReceipt,
        canonical::canonical_json,
        compile_statement, decision_receipt,
        test_support::{NOW, configuration_with_maximum_rows, fixture},
    };

    let fixture = fixture();
    let authorized = decision_receipt(
        &fixture.action,
        &fixture.evidence,
        &fixture.configuration,
        &fixture.configuration,
        &fixture.evidence.database_audience,
        NOW,
    )
    .map_err(|error| format!("could not build PostgreSQL authorized fixture: {error}"))?;
    let narrower_execution = configuration_with_maximum_rows(2);
    let denied = decision_receipt(
        &fixture.action,
        &fixture.evidence,
        &fixture.configuration,
        &narrower_execution,
        &fixture.evidence.database_audience,
        NOW,
    )
    .map_err(|error| format!("could not build PostgreSQL denied fixture: {error}"))?;
    let statement = compile_statement(&fixture.intent, &fixture.configuration)
        .map_err(|error| format!("could not compile PostgreSQL fixture statement: {error}"))?;

    let mut files = BTreeMap::from([
        (
            PathBuf::from("postgresql/action.json"),
            fixture
                .action
                .canonical_bytes()
                .map_err(|error| format!("could not serialize PostgreSQL action: {error}"))?,
        ),
        (
            PathBuf::from("postgresql/intent.json"),
            canonical_json(&fixture.intent)
                .map_err(|error| format!("could not serialize PostgreSQL intent: {error}"))?,
        ),
        (
            PathBuf::from("postgresql/evidence.json"),
            canonical_json(&fixture.evidence)
                .map_err(|error| format!("could not serialize PostgreSQL evidence: {error}"))?,
        ),
        (
            PathBuf::from("postgresql/required-configuration.json"),
            canonical_json(&fixture.configuration).map_err(|error| {
                format!("could not serialize PostgreSQL configuration: {error}")
            })?,
        ),
        (
            PathBuf::from("postgresql/compiled-statement.json"),
            canonical_json(&statement)
                .map_err(|error| format!("could not serialize PostgreSQL statement: {error}"))?,
        ),
        (
            PathBuf::from("postgresql/authorized-decision.json"),
            canonical_json(&PostgresReceipt::Decision(Box::new(authorized)))
                .map_err(|error| format!("could not serialize PostgreSQL receipt: {error}"))?,
        ),
        (
            PathBuf::from("postgresql/configuration-mismatch-decision.json"),
            canonical_json(&PostgresReceipt::Decision(Box::new(denied)))
                .map_err(|error| format!("could not serialize PostgreSQL denial: {error}"))?,
        ),
    ]);
    insert_bounded_fixture_manifest(
        "postgresql",
        &["auths.postgresql.bounded-update/1"],
        bounded_scenarios("postgresql"),
        &mut files,
    )?;
    Ok(files)
}

fn insert_bounded_fixture_manifest(
    domain: &str,
    profiles: &[&str],
    scenarios: BTreeMap<String, Value>,
    files: &mut BTreeMap<PathBuf, Vec<u8>>,
) -> Result<(), String> {
    let entries = files
        .iter()
        .map(|(path, bytes)| {
            Ok((
                path.file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| format!("fixture path {} has no file name", path.display()))?
                    .to_owned(),
                format!("{:x}", Sha256::digest(bytes)),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let sizes = files
        .iter()
        .map(|(path, bytes)| {
            Ok((
                path.file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| format!("fixture path {} has no file name", path.display()))?
                    .to_owned(),
                bytes.len(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let prefix = files
        .keys()
        .next()
        .and_then(|path| path.parent())
        .ok_or("fixture corpus has no directory")?
        .to_owned();
    let manifest = serde_json::to_vec(&json!({
        "schema": "auths.bounded-domain-oracle-manifest/1",
        "domain": domain,
        "profiles": profiles,
        "generator": "cargo xtask product-fixtures --update",
        "scenarios": scenarios,
        "bytes": sizes,
        "sha256": entries,
    }))
    .map_err(|error| format!("could not serialize fixture manifest: {error}"))?;
    files.insert(prefix.join("manifest.json"), manifest);
    Ok(())
}

fn bounded_scenarios(domain: &str) -> BTreeMap<String, Value> {
    let names = [
        "authorized",
        "exact-boundary",
        "boundary-plus-one",
        "malformed-input",
        "stale-evidence",
        "configuration-mismatch",
        "concurrent-final-capacity",
        "replay",
        "definite-pre-effect-failure",
        "outcome-unknown",
        "reconciliation",
    ];
    names
        .into_iter()
        .filter(|scenario| {
            !((domain == "radicle" && *scenario == "outcome-unknown")
                || (domain == "records-api"
                    && matches!(*scenario, "outcome-unknown" | "reconciliation")))
        })
        .map(|scenario| {
            (
                scenario.to_owned(),
                json!({
                    "kind": "canonical-fixture-and-executable-evidence",
                    "inventory": "bounded-domains.toml",
                }),
            )
        })
        .collect()
}

pub(crate) fn package_check() -> Result<(), String> {
    let metadata = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not inspect package publication policy: {error}"))?;
    if !metadata.status.success() {
        return Err("cargo metadata failed while selecting publishable packages".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&metadata.stdout)
        .map_err(|error| format!("could not parse package publication policy: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;
    let policy = load_architecture_policy()?;
    let mut private = Vec::new();
    for package in packages {
        let name = package["name"]
            .as_str()
            .ok_or("workspace package has no name")?;
        let publishable = package_is_publishable(package);
        let layer = policy
            .packages
            .get(name)
            .ok_or_else(|| format!("package {name} is not classified"))?;
        if matches!(layer.as_str(), "demos" | "tooling") && publishable {
            return Err(format!(
                "{layer} package {name} must declare publish = false"
            ));
        }
        if !publishable {
            private.push(name.to_owned());
        }
    }
    private.sort();
    let mut arguments = vec!["package".to_owned(), "--workspace".to_owned()];
    for name in private {
        arguments.push("--exclude".to_owned());
        arguments.push(name);
    }
    arguments.extend(["--allow-dirty".to_owned(), "--no-verify".to_owned()]);
    let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    cargo(&argument_refs)
}

pub(crate) fn package_is_publishable(package: &Value) -> bool {
    !package["publish"]
        .as_array()
        .is_some_and(|registries| registries.is_empty())
}

pub(crate) fn spec_sync() -> Result<(), String> {
    use auths_model::{DenialReason as D, Requirement as R};

    let denied = [
        D::MalformedProof,
        D::NonCanonicalProof,
        D::ResourceLimitExceeded,
        D::DigestMismatch,
        D::DuplicateObject,
        D::MissingReference,
        D::ReferenceCycle,
        D::AmbiguousTerminalGrant,
        D::UnusedCriticalEvidence,
        D::InvalidSignature,
        D::PrincipalMethodMismatch,
        D::VerificationMethodMismatch,
        D::SignatureSuiteMismatch,
        D::UntrustedRoot,
        D::BrokenGrantChain,
        D::DelegationExpanded,
        D::PermissionNotGranted,
        D::ActionConstraintMismatch,
        D::BudgetCeilingExceeded,
        D::AuthorizationPlanInvalid,
        D::CompositionRequirementNotMet,
        D::PlanActionMismatch,
        D::ActionBodyMismatch,
        D::AudienceMismatch,
        D::ChallengeMismatch,
        D::ActionOutsideValidity,
        D::PrincipalRevoked,
        D::GrantRevoked,
        D::StatusSequenceRollback,
        D::StatusMethodMismatch,
        D::StatusIssuerUntrusted,
        D::RegistryManifestMismatch,
        D::VerifierConfigurationMismatch,
        D::ResourceNamespaceMismatch,
        D::CriticalExtensionUnknown,
        D::AttachmentMissing,
        D::AttachmentDigestMismatch,
        D::AttachmentLengthMismatch,
        D::DuplicateAttachment,
        D::UnusedCriticalAttachment,
        D::OpaqueAttachmentNotAllowed,
        D::LocalPolicyDenied,
    ];
    let indeterminate = [
        R::UnsupportedProtocol,
        R::UnsupportedPrincipalMethod,
        R::UnsupportedSignatureSuite,
        R::UnsupportedEvidenceType,
        R::UnsupportedStatusMethod,
        R::UnsupportedProfile,
        R::UnsupportedProfilePolicy,
        R::UnsupportedResourceMatcher,
        R::UnsupportedBudgetAlgebra,
        R::UnsupportedCriticalExtension,
        R::UnsupportedAssuranceClaim,
        R::MissingPrincipalEvidence,
        R::MissingPrincipalStatus,
        R::MissingGrantStatus,
        R::StaleStatus,
        R::HistoricalStateUnavailable,
        R::AssuranceRequirementNotMet,
        R::ExternalFactUnavailable,
    ];
    let errors = fs::read_to_string(root().join("core/spec/v1/error-codes.md"))
        .map_err(|error| format!("could not read error registry: {error}"))?;
    for code in denied
        .iter()
        .map(|value| value.code())
        .chain(indeterminate.iter().map(|value| value.code()))
    {
        if !errors.contains(&format!("`{code}`")) {
            return Err(format!(
                "stable result code {code} is absent from error-codes.md"
            ));
        }
    }
    let reserved = BTreeSet::from([
        D::AmbiguousTerminalGrant.code(),
        D::AuthorizationPlanInvalid.code(),
        D::ReferenceCycle.code(),
    ]);
    let manifest_bytes = fs::read(root().join("core/fixtures/v1/manifest.json"))
        .map_err(|error| format!("could not read corpus manifest: {error}"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("could not parse corpus manifest: {error}"))?;
    let fixtures = manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or_else(|| "corpus manifest has no fixtures array".to_owned())?;
    let covered: BTreeSet<&str> = fixtures
        .iter()
        .filter_map(|fixture| fixture.get("expected_code").and_then(Value::as_str))
        .collect();
    for code in denied
        .iter()
        .map(|value| value.code())
        .chain(indeterminate.iter().map(|value| value.code()))
    {
        if reserved.contains(code) {
            if covered.contains(code) {
                return Err(format!(
                    "reserved V1 result code {code} has a corpus vector"
                ));
            }
        } else if !covered.contains(code) {
            return Err(format!(
                "implemented V1 result code {code} has no committed corpus vector"
            ));
        }
    }
    if !covered.contains("authorized") {
        return Err("authorized V1 result has no committed corpus vector".to_owned());
    }
    let registry = fs::read_to_string(root().join("core/spec/v1/registry.md"))
        .map_err(|error| format!("could not read registry specification: {error}"))?;
    for identifier in [
        auths_registries::URI_NAMESPACE_V1,
        auths_registries::EXACT_PROFILE_V1,
        auths_registries::NUMERIC_CEILING_V1,
        auths_registries::EXACT_MARKER_EXTENSION_V1,
    ] {
        if !registry.contains(&format!("`{identifier}`")) {
            return Err(format!(
                "executable registry ID {identifier} is undocumented"
            ));
        }
    }
    let traceability = fs::read_to_string(root().join("docs/TRACEABILITY.md"))
        .map_err(|error| format!("could not read traceability matrix: {error}"))?;
    for family in [
        "Canonical CBOR",
        "Signed fields and domains",
        "Identifier derivation",
        "Graph/reference rules",
        "Attenuation",
        "Required composition",
        "Status",
        "Assurance quantifiers",
        "Evidence consumption",
        "Registry/configuration",
        "Resource limits",
        "Portable normalization",
    ] {
        if !traceability.contains(family) {
            return Err(format!("traceability matrix is missing {family}"));
        }
    }
    let limit_coverage = fs::read_to_string(root().join("docs/LIMIT_COVERAGE.md"))
        .map_err(|error| format!("could not read limit coverage matrix: {error}"))?;
    for limit in [
        "BundleBytes",
        "ActionBytes",
        "ContextBytes",
        "Grants",
        "Actions",
        "PlanLeaves",
        "PlanDepth",
        "PlanBranching",
        "EvidenceObjects",
        "EvidenceBytes",
        "ControlBindings",
        "PrincipalStatusStatements",
        "GrantStatusStatements",
        "Attachments",
        "AttachmentBytes",
        "Signatures",
        "SignatureBytes",
        "Permissions",
        "Audiences",
        "CriticalExtensions",
        "CriticalExtensionBytes",
        "AllowedBodyDigests",
        "BindingEvidence",
        "CanonicalBodyBytes",
        "RegistryEntries",
        "TrustAnchors",
        "work units",
    ] {
        if !limit_coverage.contains(limit) {
            return Err(format!("limit coverage matrix is missing {limit}"));
        }
    }
    println!("specification, registry, and result-code registries are synchronized");
    Ok(())
}
