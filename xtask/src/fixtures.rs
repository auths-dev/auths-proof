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
    expected.extend(opentofu_product_fixtures()?);
    expected.extend(postgresql_product_fixtures()?);
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
    insert_fixture_manifest("auths.opentofu.fixture-manifest/1", &mut files)?;
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
    insert_fixture_manifest("auths.postgresql.fixture-manifest/1", &mut files)?;
    Ok(files)
}

pub(crate) fn insert_fixture_manifest(
    schema: &str,
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
    let prefix = files
        .keys()
        .next()
        .and_then(|path| path.parent())
        .ok_or("fixture corpus has no directory")?
        .to_owned();
    let manifest = serde_json::to_vec(&json!({
        "schema": schema,
        "sha256": entries,
    }))
    .map_err(|error| format!("could not serialize fixture manifest: {error}"))?;
    files.insert(prefix.join("manifest.json"), manifest);
    Ok(())
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
