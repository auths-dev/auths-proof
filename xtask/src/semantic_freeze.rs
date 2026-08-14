#![allow(clippy::too_many_lines)]

use crate::*;

const INVENTORY_PATH: &str = "release/semantic-freeze.json";
const INVENTORY_SCHEMA: &str = "auths.semantic-freeze/1";
const FREEZE_VERSION: u64 = 96;
const PUBLIC_RUST_ROOTS: [&str; 10] = [
    "auths",
    "auths-byte-channel",
    "auths-byte-channel-memory",
    "auths-identity",
    "auths-identity-authority",
    "auths-identity-raw-key",
    "auths-iroh",
    "auths-runtime",
    "auths-sdk",
    "auths-signature-ed25519",
];
const PUBLIC_RUST_CLOSURE: [&str; 41] = [
    "auths",
    "auths-algebra-kernel",
    "auths-assurance",
    "auths-author",
    "auths-authority",
    "auths-bounded-policy",
    "auths-byte-channel",
    "auths-byte-channel-memory",
    "auths-codec",
    "auths-composition",
    "auths-config",
    "auths-custody",
    "auths-did-keri",
    "auths-did-key",
    "auths-errors",
    "auths-identity",
    "auths-identity-authority",
    "auths-identity-raw-key",
    "auths-iroh",
    "auths-kernel-runtime",
    "auths-lifecycle",
    "auths-model",
    "auths-multikey",
    "auths-operations",
    "auths-ports",
    "auths-profile-api",
    "auths-profile-domains",
    "auths-profile-mcp",
    "auths-proof",
    "auths-proof-exchange-model",
    "auths-proof-exchange-port",
    "auths-sdk",
    "auths-raw-key",
    "auths-raw-key-core",
    "auths-receipts",
    "auths-registries",
    "auths-runtime",
    "auths-signature",
    "auths-signature-core",
    "auths-signature-ed25519",
    "auths-verifier",
];

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemanticFreezeInventory {
    schema: String,
    freeze_version: u64,
    public_surface: PublicSurface,
    entries: Vec<FreezeEntry>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicSurface {
    rust_roots: Vec<String>,
    rust_publishable_closure: Vec<String>,
    release_artifact_families: Vec<String>,
    deferred_surface_issue: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FreezeEntry {
    id: String,
    version: u64,
    classification: FreezeClassification,
    categories: Vec<String>,
    owners: Vec<String>,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FreezeClassification {
    FrozenMeaning,
    FrozenBytes,
    ReleaseMetadata,
}

struct RustSurface {
    public: PublicSurface,
    package_manifests: Vec<String>,
}

#[derive(Deserialize)]
struct BoundedDomainRegistry {
    domains: Vec<BoundedDomain>,
}

#[derive(Deserialize)]
struct BoundedDomain {
    package_path: String,
    status: String,
}

pub(crate) fn semantic_freeze(update: bool) -> Result<(), String> {
    let generated = generate_inventory()?;
    validate_inventory(&generated)?;
    let mut bytes = serde_json::to_vec_pretty(&generated)
        .map_err(|error| format!("could not encode semantic freeze: {error}"))?;
    bytes.push(b'\n');
    let path = root().join(INVENTORY_PATH);

    if update {
        if path.is_file() {
            let committed = load_inventory(&path)?;
            validate_evolution(&committed, &generated)?;
        }
        let parent = path
            .parent()
            .ok_or("semantic-freeze inventory has no parent directory")?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        fs::write(&path, bytes)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        println!("semantic freeze inventory updated");
        return Ok(());
    }

    let committed = fs::read(&path).map_err(|error| {
        format!(
            "could not read {}: {error}; run `cargo xtask semantic-freeze --update`",
            path.display()
        )
    })?;
    if committed != bytes {
        return Err(
            "semantic freeze drifted; assign new semantic identities or versions, then run \
             `cargo xtask semantic-freeze --update`"
                .to_owned(),
        );
    }
    println!(
        "semantic freeze passed ({} entries, {} public Rust packages)",
        generated.entries.len(),
        generated.public_surface.rust_publishable_closure.len()
    );
    Ok(())
}

fn generate_inventory() -> Result<SemanticFreezeInventory, String> {
    let rust_surface = rust_surface()?;
    let bounded_domain_sources = bounded_domain_sources()?;

    let mut entries = vec![
        freeze_entry(
            "auths.core.protocol",
            15,
            FreezeClassification::FrozenMeaning,
            &[
                "protocol-versions",
                "canonicalization",
                "authoring-codecs",
                "decision-codes",
                "denial-codes",
                "indeterminate-codes",
            ],
            vec![
                "core/spec/v1".to_owned(),
                "core/crates/auths-model/src".to_owned(),
                "core/crates/auths-codec/src".to_owned(),
                "core/crates/auths-author/src".to_owned(),
                "core/crates/auths-verifier/src".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.identity.protocol",
            25,
            FreezeClassification::FrozenMeaning,
            &[
                "identity-protocol-versions",
                "identity-wire",
                "identity-signing-preimages",
                "identity-method-identifiers",
                "identity-signature-semantics",
                "identity-binding-contracts",
                "identity-transport-labels",
            ],
            vec![
                "core/spec/identity/v1".to_owned(),
                "core/fixtures/identity/v1/vectors.json".to_owned(),
                "core/crates/auths-identity/src".to_owned(),
                "core/crates/auths-raw-key-core/src".to_owned(),
                "core/crates/auths-signature-core/src".to_owned(),
                "core/adapters/auths-identity-raw-key/src".to_owned(),
                "core/adapters/auths-signature-ed25519/src".to_owned(),
                "bindings/wasm/auths-proof-wasm/identity-abi-v1.json".to_owned(),
                "bindings/typescript/api/public-api.txt".to_owned(),
                "compliance.toml".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.modular-components",
            6,
            FreezeClassification::FrozenMeaning,
            &[
                "published-neutral-ports",
                "reference-adapter-contracts",
                "negative-security-claims",
                "adapter-conformance",
                "packaged-consumer-qualification",
            ],
            vec![
                "core/crates/auths-identity/Cargo.toml".to_owned(),
                "core/crates/auths-identity/README.md".to_owned(),
                "core/crates/auths-identity/examples".to_owned(),
                "core/adapters/auths-identity-raw-key/Cargo.toml".to_owned(),
                "core/adapters/auths-identity-raw-key/README.md".to_owned(),
                "core/adapters/auths-identity-authority/Cargo.toml".to_owned(),
                "core/adapters/auths-identity-authority/README.md".to_owned(),
                "core/adapters/auths-signature-ed25519/Cargo.toml".to_owned(),
                "core/adapters/auths-signature-ed25519/README.md".to_owned(),
                "exchange/crates/auths-byte-channel/Cargo.toml".to_owned(),
                "exchange/crates/auths-byte-channel/README.md".to_owned(),
                "exchange/adapters/auths-byte-channel-memory/Cargo.toml".to_owned(),
                "exchange/adapters/auths-byte-channel-memory/README.md".to_owned(),
                "exchange/adapters/auths-iroh/Cargo.toml".to_owned(),
                "exchange/adapters/auths-iroh/README.md".to_owned(),
                "exchange/adapters/auths-iroh/examples".to_owned(),
                "docs/adapter-conformance.md".to_owned(),
                "docs/modular-components.md".to_owned(),
                "xtask/src/fixtures.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.portable-abi-bindings",
            46,
            FreezeClassification::FrozenMeaning,
            &["portable-abi", "authoring-abi", "binding-contracts"],
            vec![
                "bindings/python/native-abi-v2.json".to_owned(),
                "bindings/python/python/auths".to_owned(),
                "core/crates/auths-model/src/lib.rs".to_owned(),
                "core/spec/v1/auths-proof.cddl".to_owned(),
                "bindings/wasm/auths-proof-wasm/authoring-abi-v1.json".to_owned(),
                "bindings/wasm/auths-proof-wasm/src/lib.rs".to_owned(),
                "bindings/typescript/src".to_owned(),
                "bindings/python/src".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.public-sdk-contract",
            35,
            FreezeClassification::FrozenMeaning,
            &[
                "rust-sdk-contract",
                "exact-action-profiles",
                "custody-boundary",
                "runtime-boundary",
            ],
            vec![
                "product/sdk/auths-sdk/src".to_owned(),
                "product/profiles/auths-profile-api/src".to_owned(),
                "product/profiles/auths-profile-domains/src".to_owned(),
                "product/profiles/auths-profile-mcp/src".to_owned(),
                "product/integrations/auths-custody/src".to_owned(),
                "product/runtime/auths-runtime/src".to_owned(),
                "compliance.toml".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.mcp-closed-execution",
            11,
            FreezeClassification::FrozenMeaning,
            &[
                "profile-session",
                "commitment-derived-execution",
                "bounded-handler-contract",
                "authenticated-recovery",
                "receipt-eligibility",
            ],
            vec![
                "product/profiles/auths-profile-mcp/src/session.rs".to_owned(),
                "product/profiles/auths-profile-mcp/profile-v1.json".to_owned(),
                "bindings/typescript/src/generated/mcp-profile.ts".to_owned(),
                "bindings/typescript/src/profiles/mcp/index.ts".to_owned(),
                "bindings/python/python/auths/_mcp_profile.py".to_owned(),
                "bindings/python/python/auths/profiles/_mcp.py".to_owned(),
                "bindings/python/src/mcp.rs".to_owned(),
                "bindings/wasm/auths-proof-wasm/src/lib.rs".to_owned(),
                "xtask/src/mcp_session_contract.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.simplified-waist",
            7,
            FreezeClassification::FrozenMeaning,
            &[
                "product-waist-invariants",
                "cross-language-guardrails",
                "shared-workflow-projection",
                "conformance-runners",
            ],
            vec![
                "core/testkit/auths-testkit/src/product_waist.rs".to_owned(),
                "product/conformance/v1/simplified-product-waist.json".to_owned(),
                "bindings/wasm/auths-proof-wasm/examples/generate-node-vectors.rs".to_owned(),
                "bindings/typescript/src/testkit/product-waist-conformance.ts".to_owned(),
                "bindings/python/python/auths/testkit.py".to_owned(),
                "xtask/src/product_waist.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.facade",
            7,
            FreezeClassification::FrozenMeaning,
            &[
                "create",
                "delegate",
                "execute",
                "resume",
                "opaque-recovery-reference",
            ],
            vec![
                "bindings/typescript/src/product.ts".to_owned(),
                "bindings/python/python/auths/_product.py".to_owned(),
                "bindings/typescript/src/profiles/mcp/index.ts".to_owned(),
                "bindings/python/python/auths/profiles/_mcp.py".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.development-composition",
            7,
            FreezeClassification::FrozenMeaning,
            &[
                "explicit-development-mode",
                "deterministic-local-identity",
                "atomic-development-state",
                "recoverable-single-machine-state",
            ],
            vec![
                "bindings/typescript/src/integrations.ts".to_owned(),
                "bindings/typescript/src/internal/development.ts".to_owned(),
                "bindings/typescript/src/internal/development-store-node.ts".to_owned(),
                "bindings/python/python/auths/integrations.py".to_owned(),
                "bindings/python/python/auths/_development.py".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.mechanism-profile-conformance",
            4,
            FreezeClassification::FrozenMeaning,
            &[
                "contract-inventory",
                "auths-owned-cases",
                "bounded-reports",
                "profile-owned-provider-conformance",
            ],
            vec![
                "core/testkit/auths-testkit/src/mechanism_conformance.rs".to_owned(),
                "product/conformance/v1/mechanism-profile-conformance.json".to_owned(),
                "bindings/typescript/src/testkit/conformance.ts".to_owned(),
                "bindings/python/python/auths/_conformance.py".to_owned(),
                "xtask/src/mechanism_conformance.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.vocabulary",
            6,
            FreezeClassification::FrozenMeaning,
            &[
                "customer-vocabulary",
                "cross-language-naming",
                "beginner-documentation-language",
                "vocabulary-lint",
            ],
            vec![
                "docs/product/sdk-glossary.json".to_owned(),
                "docs/product/GLOSSARY.md".to_owned(),
                "docs/product/recipes".to_owned(),
                "docs/product/vocabulary-review.json".to_owned(),
                "bindings/typescript/README.md".to_owned(),
                "bindings/python/README.md".to_owned(),
                "product/sdk/auths-sdk/Cargo.toml".to_owned(),
                "xtask/src/sdk_vocabulary.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.error-recovery-contract",
            10,
            FreezeClassification::FrozenMeaning,
            &[
                "error-envelope",
                "effect-and-retry-classification",
                "profile-error-registration",
                "bounded-support-evidence",
                "cross-language-error-fixtures",
            ],
            vec![
                "product/errors/auths-errors/src".to_owned(),
                "product/errors/v1".to_owned(),
                "product/fixtures/v1/errors".to_owned(),
                "bindings/typescript/src/product-errors.ts".to_owned(),
                "bindings/typescript/src/generated/error-registry.ts".to_owned(),
                "bindings/python/python/auths/_product_errors.py".to_owned(),
                "bindings/python/python/auths/_error_registry.py".to_owned(),
                "xtask/src/error_registry.rs".to_owned(),
                "docs/reference/error-codes.md".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.bounded-policy",
            2,
            FreezeClassification::FrozenMeaning,
            &[
                "policy-semantic-ids",
                "evaluator-semantic-ids",
                "optimized-evaluator-semantic-ids",
            ],
            vec![
                "product/fixtures/v1/bounded-policy/registry.toml".to_owned(),
                "product/policy/auths-bounded-policy/src".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.bounded-domains",
            5,
            FreezeClassification::FrozenMeaning,
            &[
                "bounded-domain-inventory",
                "exact-action-profiles",
                "domain-evaluators",
                "domain-lifecycle-transitions",
                "domain-credential-scopes",
                "domain-provider-gateways",
                "domain-receipt-meanings",
            ],
            with_paths(["bounded-domains.toml"], &bounded_domain_sources),
        )?,
        freeze_entry(
            "auths.product.lifecycle",
            7,
            FreezeClassification::FrozenMeaning,
            &[
                "reservation-state",
                "claim-state",
                "execution-state",
                "reconciliation-state",
                "lifecycle-codes",
            ],
            vec![
                "product/fixtures/v1/lifecycle/registry.toml".to_owned(),
                "product/runtime/auths-lifecycle/src".to_owned(),
                "product/stores/auths-stores/src/lifecycle.rs".to_owned(),
                "product/stores/auths-stores/migrations/postgres_lifecycle_v3.sql".to_owned(),
                "product/stores/auths-stores/tests/postgres_lifecycle.rs".to_owned(),
                "product/stores/auths-stores/tests/postgres_tls".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.receipts",
            4,
            FreezeClassification::FrozenMeaning,
            &["receipt-schemas", "receipt-commitment-meanings"],
            vec![
                "product/receipts/auths-receipts/src".to_owned(),
                "product/spec/v1/receipts.md".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.configuration-commitments",
            1,
            FreezeClassification::FrozenMeaning,
            &[
                "required-configuration-commitments",
                "executed-configuration-commitments",
            ],
            vec![
                "product/policy/auths-bounded-policy/src/commitment.rs".to_owned(),
                "product/policy/auths-bounded-policy/src/receipt.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.open-production-contract",
            8,
            FreezeClassification::FrozenMeaning,
            &[
                "production-topology",
                "qualified-profiles",
                "sdk-parity",
                "operations-objectives",
                "evidence-requirements",
                "production-exclusions",
            ],
            vec![
                "docs/specs/0038-production-runtime-custody-observability-and-assurance.md"
                    .to_owned(),
                "docs/specs/0038/epic_1.md".to_owned(),
                "product/config/auths-config/src/production.rs".to_owned(),
                "product/spec/v1/open-production-candidate.schema.json".to_owned(),
                "release/open-production-candidate.json".to_owned(),
                "release/open-production-candidate.toml".to_owned(),
                "xtask/src/production_contract.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.external-custody",
            2,
            FreezeClassification::FrozenMeaning,
            &[
                "transaction-bound-signing",
                "central-signature-validation",
                "custody-key-lifecycle",
                "aws-kms-p256",
                "pkcs11-p256",
                "custody-conformance",
            ],
            vec![
                "docs/operations/CUSTODY_LIFECYCLE_RUNBOOK.md".to_owned(),
                "docs/specs/0038/epic_4.md".to_owned(),
                "product/fixtures/v1/custody".to_owned(),
                "product/integrations/auths-custody/src".to_owned(),
                "product/integrations/auths-custody-aws-kms/Cargo.toml".to_owned(),
                "product/integrations/auths-custody-aws-kms/src".to_owned(),
                "product/integrations/auths-custody-pkcs11/Cargo.toml".to_owned(),
                "product/integrations/auths-custody-pkcs11/src".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.product.operations",
            1,
            FreezeClassification::FrozenMeaning,
            &[
                "privacy-safe-events",
                "workflow-status-projection",
                "readiness-contract",
                "otel-export",
                "prometheus-projection",
                "operator-recovery-advice",
            ],
            vec![
                "docs/operations/OPEN_PRODUCTION_INCIDENT_RUNBOOKS.md".to_owned(),
                "docs/specs/0038/epic_5.md".to_owned(),
                "product/operations/auths-operations/src".to_owned(),
                "product/operations/auths-operations-otel/src".to_owned(),
                "product/operations/v2".to_owned(),
                "product/runtime/auths-runtime/src/production.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.release.evolution-contract",
            10,
            FreezeClassification::FrozenMeaning,
            &[
                "version-axes",
                "release-classification",
                "support-windows",
                "retirement-lifecycle",
                "mixed-version-behavior",
                "migration-contract",
                "stable-launch-gate",
            ],
            vec![
                ".github/workflows/ci.yml".to_owned(),
                "bindings/python/api/public-api.txt".to_owned(),
                "bindings/typescript/api/public-api.txt".to_owned(),
                "docs/product/COMPATIBILITY_AND_SUPPORT.md".to_owned(),
                "release/evolution-lifecycle-v1.json".to_owned(),
                "release/evolution-policy-v1.json".to_owned(),
                "release/fixtures/evolution".to_owned(),
                "xtask/src/evolution_policy.rs".to_owned(),
            ],
        )?,
        freeze_entry(
            "auths.release.benchmark-contract",
            1,
            FreezeClassification::FrozenMeaning,
            &["benchmark-definition", "accepted-baseline"],
            vec![
                "demos/benchmarks/profiles/release.toml".to_owned(),
                "demos/benchmarks/auths-bench-model/src".to_owned(),
                "xtask/src/benchmark.rs".to_owned(),
                "xtask/src/bounded_benchmark.rs".to_owned(),
                "docs/research/domains/0004-seven-domain-bounded-authorization-performance-baseline.md"
                    .to_owned(),
            ],
        )?,
    ];

    for (id, path) in frozen_byte_inventories()? {
        let version = match path.as_str() {
            "architecture/dependency-graph.json" => 23,
            "bindings/wasm/auths-proof-wasm/identity-abi-v1.json" => 3,
            "core/fixtures/v1/manifest.json" => 3,
            "product/conformance/v1/simplified-product-waist.json" => 2,
            "formal/assurance-manifest-v1.toml"
            | "formal/qualification/aeneas/qualification.toml" => 3,
            "formal/qualification/aeneas/generated" => 4,
            "formal/qualification/aeneas/source-closure.json" => 11,
            "product/fixtures/v1/errors/manifest.json" => 3,
            "product/fixtures/v1/github/manifest.json"
            | "product/fixtures/v1/opentofu/manifest.json" => 2,
            "product/fixtures/v1/lifecycle/manifest.json" => 2,
            _ => 1,
        };
        entries.push(freeze_entry(
            &id,
            version,
            FreezeClassification::FrozenBytes,
            &["canonical-generated-evidence"],
            vec![path],
        )?);
    }

    let mut release_owners = rust_surface.package_manifests;
    release_owners.extend([
        ".github/workflows/release.yml".to_owned(),
        ".github/workflows/release-builder.yml".to_owned(),
        "Cargo.toml".to_owned(),
        "Cargo.lock".to_owned(),
        "rust-toolchain.toml".to_owned(),
        "bindings/typescript/package.json".to_owned(),
        "bindings/typescript/package-lock.json".to_owned(),
        "bindings/python/pyproject.toml".to_owned(),
        "architecture.toml".to_owned(),
        "docs/plans/PHASE_7_RELEASE_OWNER_DECISIONS.md".to_owned(),
        "release/public-naming.toml".to_owned(),
        "release/evolution-lifecycle-v1.json".to_owned(),
        "release/evolution-policy-v1.json".to_owned(),
        "release/fixtures/evolution".to_owned(),
        "release/README.md".to_owned(),
        "release/RELEASE_CONTROL.md".to_owned(),
        "release/RELEASE_RUNBOOK.md".to_owned(),
        "release/CANDIDATE_CLOSURE.md".to_owned(),
        "release/SLSA_BUILD_LEVEL_3_ASSESSMENT.md".to_owned(),
        "release/slsa-build-level-3-assessment.json".to_owned(),
        "release/RELEASE_CANDIDATE_NOTES.md".to_owned(),
        "release/release-manifest.contract-fixture.json".to_owned(),
        "release/release-manifest.schema.json".to_owned(),
        "release/release-subjects.toml".to_owned(),
        "release/open-production-candidate.json".to_owned(),
        "release/open-production-candidate.toml".to_owned(),
        "product/spec/v1/open-production-candidate.schema.json".to_owned(),
        "release/owner-authorization.schema.json".to_owned(),
        "xtask/src/architecture.rs".to_owned(),
        "xtask/src/checks.rs".to_owned(),
        "xtask/src/evolution_policy.rs".to_owned(),
        "xtask/src/fixtures.rs".to_owned(),
        "xtask/src/main.rs".to_owned(),
        "xtask/src/public_naming.rs".to_owned(),
        "xtask/src/production_contract.rs".to_owned(),
        "xtask/src/release.rs".to_owned(),
        "xtask/src/release_control.rs".to_owned(),
        "xtask/src/semantic_freeze.rs".to_owned(),
    ]);
    entries.push(freeze_entry(
        "auths.release.public-surface",
        96,
        FreezeClassification::ReleaseMetadata,
        &[
            "package-names",
            "package-versions",
            "publishable-closure",
            "binding-names",
            "artifact-names",
            "registry-dispositions",
            "publication-order",
            "toolchains",
        ],
        release_owners,
    )?);

    entries.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(SemanticFreezeInventory {
        schema: INVENTORY_SCHEMA.to_owned(),
        freeze_version: FREEZE_VERSION,
        public_surface: rust_surface.public,
        entries,
    })
}

fn rust_surface() -> Result<RustSurface, String> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
        ])
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not inspect release package closure: {error}"))?;
    if !output.status.success() {
        return Err("cargo metadata failed while freezing release package closure".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid cargo metadata: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata has no packages")?;
    let workspace_ids = metadata["workspace_members"]
        .as_array()
        .ok_or("cargo metadata has no workspace members")?
        .iter()
        .map(|id| {
            id.as_str()
                .ok_or_else(|| "workspace package id is not a string".to_owned())
                .map(str::to_owned)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut names_by_id = BTreeMap::new();
    let mut manifest_by_name = BTreeMap::new();
    let mut publishable = BTreeSet::new();
    for package in packages {
        let id = package["id"].as_str().ok_or("cargo package has no id")?;
        let name = package["name"]
            .as_str()
            .ok_or("cargo package has no name")?;
        names_by_id.insert(id.to_owned(), name.to_owned());
        if workspace_ids.contains(id) {
            let manifest = Path::new(
                package["manifest_path"]
                    .as_str()
                    .ok_or("workspace package has no manifest path")?,
            );
            manifest_by_name.insert(name.to_owned(), repository_relative(manifest)?);
            if package_is_publishable(package) {
                if package["license"] != "MIT OR Apache-2.0"
                    || package["description"]
                        .as_str()
                        .is_none_or(|value| value.trim().is_empty())
                    || package["repository"]
                        .as_str()
                        .is_none_or(|value| value.trim().is_empty())
                    || package["homepage"]
                        .as_str()
                        .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(format!(
                        "public package {name} must freeze its license, description, repository, and homepage"
                    ));
                }
                publishable.insert(name.to_owned());
            }
        }
    }

    let expected = PUBLIC_RUST_CLOSURE
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if publishable != expected {
        return Err(set_drift(
            "publishable Rust package surface",
            &expected,
            &publishable,
        ));
    }

    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata has no resolve nodes")?;
    let node_by_id = nodes
        .iter()
        .filter_map(|node| node["id"].as_str().map(|id| (id, node)))
        .collect::<BTreeMap<_, _>>();
    let roots = PUBLIC_RUST_ROOTS
        .iter()
        .map(|root_name| {
            names_by_id
                .iter()
                .find_map(|(id, name)| (name == root_name).then(|| id.clone()))
                .ok_or_else(|| format!("public Rust root package is absent: {root_name}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut stack = roots;
    let mut visited = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let node = node_by_id
            .get(id.as_str())
            .ok_or_else(|| format!("cargo resolve node is absent for {id}"))?;
        for dependency in node["deps"]
            .as_array()
            .ok_or("cargo resolve dependencies are not an array")?
        {
            let kinds = dependency["dep_kinds"]
                .as_array()
                .ok_or("cargo dependency kinds are not an array")?;
            let is_normal = kinds.is_empty()
                || kinds
                    .iter()
                    .any(|kind| kind["kind"].is_null() || kind["kind"] == "normal");
            if is_normal {
                let dependency_id = dependency["pkg"]
                    .as_str()
                    .ok_or("cargo dependency has no package id")?;
                stack.push(dependency_id.to_owned());
            }
        }
    }
    let actual_closure = visited
        .intersection(&workspace_ids)
        .map(|id| {
            names_by_id
                .get(id)
                .ok_or_else(|| format!("workspace package name is absent for {id}"))
                .cloned()
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual_closure != expected {
        return Err(set_drift(
            "all-features normal dependency closure for public Rust roots",
            &expected,
            &actual_closure,
        ));
    }
    let package_manifests = expected
        .iter()
        .map(|name| {
            manifest_by_name
                .get(name)
                .ok_or_else(|| format!("manifest path is absent for public package {name}"))
                .cloned()
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RustSurface {
        public: PublicSurface {
            rust_roots: PUBLIC_RUST_ROOTS
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            rust_publishable_closure: expected.into_iter().collect(),
            release_artifact_families: vec![
                "source-archive".to_owned(),
                "rust-crates".to_owned(),
                "npm:@auths-dev/sdk".to_owned(),
                "pypi:auths".to_owned(),
                "assurance-bundle".to_owned(),
            ],
            deferred_surface_issue: "https://github.com/auths-dev/auths-proof/issues/51".to_owned(),
        },
        package_manifests,
    })
}

fn bounded_domain_sources() -> Result<Vec<String>, String> {
    let registry_path = root().join("bounded-domains.toml");
    let registry: BoundedDomainRegistry = toml::from_str(
        &fs::read_to_string(&registry_path)
            .map_err(|error| format!("could not read {}: {error}", registry_path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", registry_path.display()))?;
    let mut sources = registry
        .domains
        .into_iter()
        .filter(|domain| domain.status == "implemented")
        .map(|domain| format!("{}/src", domain.package_path.trim_end_matches('/')))
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    if sources.is_empty() {
        return Err("bounded-domain inventory has no implemented source owners".to_owned());
    }
    for source in &sources {
        validate_relative_path(source)?;
        if !root().join(source).is_dir() {
            return Err(format!("bounded-domain source owner is absent: {source}"));
        }
    }
    Ok(sources)
}

fn frozen_byte_inventories() -> Result<Vec<(String, String)>, String> {
    let mut paths = vec![
        "architecture/dependency-graph.json".to_owned(),
        "bounded-domains.toml".to_owned(),
        "core/conformance/v1/manifest.json".to_owned(),
        "product/conformance/v1/simplified-product-waist.json".to_owned(),
        "product/conformance/v1/mechanism-profile-conformance.json".to_owned(),
        "core/explanations/v1/fact-inventory.json".to_owned(),
        "core/fixtures/v1/manifest.json".to_owned(),
        "core/formal-vectors/v1/manifest.json".to_owned(),
        "core/fixtures/identity/v1/vectors.json".to_owned(),
        "bindings/wasm/auths-proof-wasm/identity-abi-v1.json".to_owned(),
        "formal/assurance-manifest-v1.toml".to_owned(),
        "formal/qualification/aeneas/generated".to_owned(),
        "formal/qualification/aeneas/qualification.toml".to_owned(),
        "formal/qualification/aeneas/source-closure.json".to_owned(),
        "demos/benchmarks/profiles/release.toml".to_owned(),
    ];
    paths.extend(selected_files(
        &root().join("product/fixtures/v1"),
        |path| path.file_name().and_then(|name| name.to_str()) == Some("manifest.json"),
    )?);
    paths.extend(selected_files(
        &root().join("product/integrations/auths-stripe/fixtures"),
        |path| path.file_name().and_then(|name| name.to_str()) == Some("manifest.sha256.json"),
    )?);
    paths.sort();
    paths.dedup();
    Ok(paths
        .into_iter()
        .map(|path| (format!("auths.frozen-bytes/{path}"), path))
        .collect())
}

fn selected_files(
    directory: &Path,
    predicate: impl Fn(&Path) -> bool + Copy,
) -> Result<Vec<String>, String> {
    if !directory.is_dir() {
        return Err(format!(
            "semantic source directory is absent: {}",
            directory.display()
        ));
    }
    let mut selected = Vec::new();
    visit_files(directory, &mut |path| {
        if predicate(path) {
            selected.push(repository_relative(path)?);
        }
        Ok(())
    })?;
    selected.sort();
    if selected.is_empty() {
        return Err(format!(
            "semantic source selection is empty: {}",
            directory.display()
        ));
    }
    Ok(selected)
}

fn freeze_entry(
    id: &str,
    version: u64,
    classification: FreezeClassification,
    categories: &[&str],
    mut owners: Vec<String>,
) -> Result<FreezeEntry, String> {
    owners.sort();
    owners.dedup();
    if id.trim().is_empty() || version == 0 || categories.is_empty() || owners.is_empty() {
        return Err("semantic freeze entry is incomplete".to_owned());
    }
    let sha256 = digest_owners(&owners)?;
    Ok(FreezeEntry {
        id: id.to_owned(),
        version,
        classification,
        categories: categories
            .iter()
            .map(|category| (*category).to_owned())
            .collect(),
        owners,
        sha256,
    })
}

fn digest_owners(owners: &[String]) -> Result<String, String> {
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    let mut owner_names = BTreeSet::new();
    for owner in owners {
        validate_relative_path(owner)?;
        if !owner_names.insert(owner) {
            return Err(format!("duplicate semantic owner path: {owner}"));
        }
        let path = root().join(owner);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("semantic owner is absent {owner}: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("semantic owner must not be a symlink: {owner}"));
        }
        if metadata.is_file() {
            files.insert(owner.clone(), read_owned_file(&path)?);
        } else if metadata.is_dir() {
            let before = files.len();
            visit_files(&path, &mut |file| {
                let relative = repository_relative(file)?;
                files.insert(relative, read_owned_file(file)?);
                Ok(())
            })?;
            if files.len() == before {
                return Err(format!("semantic owner directory is empty: {owner}"));
            }
        } else {
            return Err(format!(
                "semantic owner is not a file or directory: {owner}"
            ));
        }
    }
    let mut hasher = Sha256::new();
    for owner in owners {
        hash_field(&mut hasher, owner.as_bytes());
    }
    for (path, bytes) in files {
        hash_field(&mut hasher, path.as_bytes());
        hash_field(&mut hasher, &bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn visit_files(
    directory: &Path,
    visitor: &mut impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("could not enumerate {}: {error}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "semantic owner trees must not contain symlinks: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            if generated_owner_directory(&path) {
                continue;
            }
            visit_files(&path, visitor)?;
        } else if metadata.is_file() {
            if generated_owner_file(&path) {
                continue;
            }
            visitor(&path)?;
        }
    }
    Ok(())
}

fn generated_owner_directory(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            ".git"
                | ".lake"
                | ".mypy_cache"
                | ".pytest_cache"
                | ".ruff_cache"
                | ".venv"
                | "__pycache__"
                | "node_modules"
                | "target"
        )
    )
}

fn generated_owner_file(path: &Path) -> bool {
    if matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".DS_Store" | ".coverage")
    ) {
        return true;
    }
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("dll" | "dylib" | "pyc" | "pyd" | "pyo" | "so")
    )
}

fn read_owned_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn repository_relative(path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root())
        .map_err(|_| format!("path escapes repository: {}", path.display()))?;
    let text = relative.to_string_lossy().replace('\\', "/");
    validate_relative_path(&text)?;
    Ok(text)
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty()
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "semantic owner path is not repository-relative: {path}"
        ));
    }
    Ok(())
}

fn validate_inventory(inventory: &SemanticFreezeInventory) -> Result<(), String> {
    if inventory.schema != INVENTORY_SCHEMA || inventory.freeze_version == 0 {
        return Err("semantic freeze schema or version is invalid".to_owned());
    }
    if inventory.public_surface.rust_roots.is_empty()
        || inventory.public_surface.rust_publishable_closure.is_empty()
    {
        return Err("semantic freeze public Rust surface is empty".to_owned());
    }
    if inventory.public_surface.rust_roots.iter().any(|root| {
        !inventory
            .public_surface
            .rust_publishable_closure
            .contains(root)
    }) {
        return Err(
            "semantic freeze public Rust root is outside its publishable closure".to_owned(),
        );
    }
    let mut identities = BTreeSet::new();
    let mut classifications = BTreeSet::new();
    for entry in &inventory.entries {
        if entry.id.trim().is_empty()
            || entry.version == 0
            || entry.categories.is_empty()
            || entry.owners.is_empty()
            || entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!("semantic freeze entry is invalid: {}", entry.id));
        }
        if !identities.insert((entry.id.as_str(), entry.version)) {
            return Err(format!(
                "duplicate semantic freeze identity: {}@{}",
                entry.id, entry.version
            ));
        }
        classifications.insert(match entry.classification {
            FreezeClassification::FrozenMeaning => "frozen-meaning",
            FreezeClassification::FrozenBytes => "frozen-bytes",
            FreezeClassification::ReleaseMetadata => "release-metadata",
        });
        for owner in &entry.owners {
            validate_relative_path(owner)?;
        }
    }
    if classifications
        != ["frozen-bytes", "frozen-meaning", "release-metadata"]
            .into_iter()
            .collect()
    {
        return Err("semantic freeze must contain all three classifications".to_owned());
    }
    Ok(())
}

fn validate_evolution(
    previous: &SemanticFreezeInventory,
    proposed: &SemanticFreezeInventory,
) -> Result<(), String> {
    validate_inventory(previous)?;
    validate_inventory(proposed)?;
    if proposed.freeze_version < previous.freeze_version {
        return Err("semantic freeze version must not decrease".to_owned());
    }
    if proposed != previous && proposed.freeze_version == previous.freeze_version {
        return Err("semantic freeze changed without a new freezeVersion".to_owned());
    }
    let proposed_entries = proposed
        .entries
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    for old in &previous.entries {
        if let Some(new) = proposed_entries.get(old.id.as_str())
            && (old.sha256 != new.sha256 || old.owners != new.owners)
            && old.version == new.version
        {
            return Err(format!(
                "{} changed under frozen identity version {}; assign a new version",
                old.id, old.version
            ));
        }
    }
    Ok(())
}

fn load_inventory(path: &Path) -> Result<SemanticFreezeInventory, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid semantic freeze {}: {error}", path.display()))
}

fn with_paths<const N: usize>(base: [&str; N], additions: &[String]) -> Vec<String> {
    base.into_iter()
        .map(str::to_owned)
        .chain(additions.iter().cloned())
        .collect()
}

fn set_drift(label: &str, expected: &BTreeSet<String>, actual: &BTreeSet<String>) -> String {
    let missing = expected.difference(actual).cloned().collect::<Vec<_>>();
    let extra = actual.difference(expected).cloned().collect::<Vec<_>>();
    format!("{label} drifted; missing={missing:?}, extra={extra:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn test_inventory(
        freeze_version: u64,
        entry_version: u64,
        sha256: String,
    ) -> SemanticFreezeInventory {
        SemanticFreezeInventory {
            schema: INVENTORY_SCHEMA.to_owned(),
            freeze_version,
            public_surface: PublicSurface {
                rust_roots: PUBLIC_RUST_ROOTS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                rust_publishable_closure: PUBLIC_RUST_CLOSURE
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                release_artifact_families: vec!["source-archive".to_owned()],
                deferred_surface_issue: "https://example.invalid/51".to_owned(),
            },
            entries: vec![
                FreezeEntry {
                    id: "auths.test.meaning".to_owned(),
                    version: entry_version,
                    classification: FreezeClassification::FrozenMeaning,
                    categories: vec!["test".to_owned()],
                    owners: vec!["core/spec/v1/protocol.md".to_owned()],
                    sha256,
                },
                FreezeEntry {
                    id: "auths.test.bytes".to_owned(),
                    version: 1,
                    classification: FreezeClassification::FrozenBytes,
                    categories: vec!["test".to_owned()],
                    owners: vec!["core/fixtures/v1/manifest.json".to_owned()],
                    sha256: digest('b'),
                },
                FreezeEntry {
                    id: "auths.test.metadata".to_owned(),
                    version: 1,
                    classification: FreezeClassification::ReleaseMetadata,
                    categories: vec!["test".to_owned()],
                    owners: vec!["Cargo.toml".to_owned()],
                    sha256: digest('c'),
                },
            ],
        }
    }

    #[test]
    fn same_identity_semantic_drift_is_terminal() {
        let previous = test_inventory(1, 1, digest('a'));
        let proposed = test_inventory(2, 1, digest('d'));
        let error = validate_evolution(&previous, &proposed).expect_err("drift must fail");
        assert!(error.contains("changed under frozen identity version 1"));
    }

    #[test]
    fn same_identity_frozen_byte_drift_is_terminal() {
        let previous = test_inventory(1, 1, digest('a'));
        let mut proposed = test_inventory(2, 1, digest('a'));
        proposed.entries[1].sha256 = digest('d');
        let error = validate_evolution(&previous, &proposed).expect_err("drift must fail");
        assert!(error.contains("auths.test.bytes changed under frozen identity version 1"));
    }

    #[test]
    fn versioned_semantic_change_requires_and_accepts_new_freeze_version() {
        let previous = test_inventory(1, 1, digest('a'));
        let proposed = test_inventory(2, 2, digest('d'));
        validate_evolution(&previous, &proposed).expect("versioned change must pass");
    }

    #[test]
    fn inventory_change_without_freeze_version_is_terminal() {
        let previous = test_inventory(1, 1, digest('a'));
        let proposed = test_inventory(1, 2, digest('d'));
        let error = validate_evolution(&previous, &proposed).expect_err("freeze drift must fail");
        assert!(error.contains("without a new freezeVersion"));
    }

    #[test]
    fn owner_path_escape_is_terminal() {
        assert!(validate_relative_path("../Cargo.toml").is_err());
        assert!(validate_relative_path("/tmp/Cargo.toml").is_err());
        assert!(validate_relative_path("Cargo.toml").is_ok());
    }

    #[test]
    fn missing_owner_is_terminal() {
        let error = digest_owners(&["definitely-not-a-semantic-owner".to_owned()])
            .expect_err("missing owner must fail");
        assert!(error.contains("semantic owner is absent"));
    }

    #[test]
    fn duplicate_identity_is_terminal() {
        let mut inventory = test_inventory(1, 1, digest('a'));
        inventory.entries.push(inventory.entries[0].clone());
        let error = validate_inventory(&inventory).expect_err("duplicate must fail");
        assert!(error.contains("duplicate semantic freeze identity"));
    }

    #[test]
    fn generated_owner_artifacts_are_excluded() {
        assert!(generated_owner_directory(Path::new("auths/__pycache__")));
        assert!(generated_owner_directory(Path::new("auths/node_modules")));
        assert!(generated_owner_file(Path::new("auths/module.pyc")));
        assert!(generated_owner_file(Path::new("auths/_native.abi3.so")));
        assert!(!generated_owner_directory(Path::new("auths/profiles")));
        assert!(!generated_owner_file(Path::new("auths/verify.py")));
    }
}
