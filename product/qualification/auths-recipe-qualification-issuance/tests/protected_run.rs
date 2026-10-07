//! The protected run's workflow, read as text: which jobs can reach a
//! secret or an environment, and when they run. A pull request reaches
//! neither, so it can gather no live evidence and sign nothing.

use std::collections::BTreeMap;
use std::path::Path;

use auths_recipe_qualification::{
    QualificationRevocationList, QualificationSignerCertificate, QualificationTrustRoot,
};

const WORKFLOW: &str = ".github/workflows/recipe-qualification.yml";
const PROTECTED: &str =
    "if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'";

fn repository() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The workflow's jobs, each with the lines of its definition.
fn jobs(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut jobs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = None;
    let mut inside = false;
    for line in text.lines() {
        if line == "jobs:" {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        let name = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' ') && !rest.starts_with('#'))
            .and_then(|rest| rest.strip_suffix(':'));
        if let Some(name) = name {
            current = Some(name.to_owned());
            jobs.entry(name.to_owned()).or_default();
        } else if let Some(job) = &current {
            jobs.entry(job.clone())
                .or_default()
                .push(line.trim().to_owned());
        }
    }
    jobs
}

#[test]
fn shared_custody_jobs_cannot_run_pull_request_source_with_live_identity() {
    let text =
        std::fs::read_to_string(repository().join(".github/workflows/gateway-custody-live.yml"))
            .expect("custody workflow");
    let jobs = jobs(&text);
    assert_eq!(
        jobs.keys().map(String::as_str).collect::<Vec<_>>(),
        ["gateway-journey", "provider-journey", "store-contract"]
    );
    for (name, lines) in jobs {
        assert!(
            lines.iter().any(|line| line == PROTECTED),
            "{name} obtains a live identity only from reviewed main source"
        );
    }
}

#[test]
fn a_pull_request_reaches_no_secret_and_no_signing_job() {
    let text = std::fs::read_to_string(repository().join(WORKFLOW)).expect("workflow");

    // Only a person on the default branch, or a pull request, starts it.
    let triggers: Vec<&str> = text
        .lines()
        .skip_while(|line| *line != "on:")
        .skip(1)
        .take_while(|line| line.starts_with(' ') || line.is_empty())
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .map(str::trim)
        .collect();
    assert_eq!(triggers, ["workflow_dispatch:", "pull_request:"]);
    assert!(
        text.contains("\npermissions:\n  contents: read\n"),
        "the default token is read-only"
    );

    let jobs = jobs(&text);
    let names: Vec<&str> = jobs.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "candidate",
            "commissioner",
            "families",
            "first-sign",
            "live",
            "offline",
            "packet-author",
            "sign",
            "simulation",
            "typescript-consumer",
            "verify"
        ]
    );
    for (name, lines) in &jobs {
        let has = |needle: &str| lines.iter().any(|line| line.contains(needle));
        let privileged = has("secrets.") || has("environment:") || has("id-token");
        assert_eq!(
            privileged,
            matches!(
                name.as_str(),
                "commissioner" | "first-sign" | "live" | "sign"
            ),
            "{name}: only the operator, commissioner and release signers reach protected inputs"
        );
        let protected = lines.iter().any(|line| line == PROTECTED);
        assert_eq!(
            protected,
            matches!(
                name.as_str(),
                "commissioner" | "first-sign" | "live" | "sign" | "verify"
            ),
            "{name}: live evidence and signing run only by hand on the default branch"
        );
        assert_eq!(
            has("QUALIFICATION_RELEASE_SIGNER_KEY"),
            matches!(name.as_str(), "first-sign" | "sign"),
            "{name}: the release signer's key"
        );
        assert_eq!(
            has("qualification/run/sign_release.py"),
            matches!(name.as_str(), "first-sign" | "sign"),
            "{name}: the signing command"
        );
    }
    assert!(!text.contains("pull_request_target"));
}

#[test]
fn signing_builds_are_independent_and_operator_exports_follow_scanning() {
    let text = std::fs::read_to_string(repository().join(WORKFLOW)).expect("workflow");
    let jobs = jobs(&text);
    let sign = &jobs["sign"];
    assert!(
        sign.iter()
            .any(|line| line == "environment: recipe-qualification-signing")
    );
    let signer_source =
        std::fs::read_to_string(repository().join("qualification/run/sign_release.py"))
            .expect("source-owned signer");
    assert!(signer_source.contains("with tempfile.TemporaryDirectory("));
    assert!(signer_source.contains("verify_proposal("));
    assert!(signer_source.contains("commission.signing_seed(os.environ.get("));
    // The key is used only by a tool the signing job built itself, and no
    // signing-path job runs a binary another job produced.
    for name in ["commissioner", "first-sign", "sign", "verify"] {
        let lines = &jobs[name];
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("run: cargo build --locked --release")),
            "{name} builds its own tool"
        );
        assert!(
            !lines.iter().any(|line| line.contains("chmod +x")),
            "{name} runs no downloaded binary"
        );
    }
    // The canaries never leave the job that planted them.
    let live = &jobs["live"];
    let scan = live
        .iter()
        .position(|line| line.contains("--phase prepare"))
        .expect("the retained operator prepares and scans before export");
    let upload = live
        .iter()
        .position(|line| line.contains("upload-artifact"))
        .expect("the live job uploads");
    assert!(scan < upload, "the scan precedes the upload");
    assert!(
        live.iter()
            .any(|line| line.contains("test ! -e") && line.contains("canaries"))
    );
    assert!(
        live.iter()
            .any(|line| line == "environment: gateway-custody-live")
    );
    for phase in [
        "commissioning-permit",
        "first-release",
        "import-first live cleanup final-proposal",
    ] {
        assert!(live.iter().any(|line| line.contains(phase)), "{phase}");
    }
    assert!(!live.iter().any(|line| line.contains("resource-session.sh")));
    assert!(
        jobs["commissioner"]
            .iter()
            .any(|line| line.contains("commission.py"))
    );
    assert!(!text.contains("pull_request_target"));
}

#[test]
fn custody_environment_protection_is_checked_before_provider_credentials() {
    let text = std::fs::read_to_string(repository().join(WORKFLOW)).expect("workflow");
    let jobs = jobs(&text);
    let live = &jobs["live"];
    let policy = live
        .iter()
        .position(|line| line.contains("custody-branches.json"))
        .expect("actual environment branch policy check");
    let credential = live
        .iter()
        .position(|line| line.contains("secrets.STRIPE_QUALIFICATION_SETUP_KEY"))
        .expect("provider credential step");
    assert!(policy < credential);
    for required in [
        "required_reviewers",
        ".total_count == 1",
        ".branch_policies[0].name == \"main\"",
        ".branch_policies[0].type == \"branch\"",
    ] {
        assert!(live.iter().any(|line| line.contains(required)));
    }
    assert!(!live.iter().any(|line| line.contains("--method")));
}

#[test]
fn other_workflows_cannot_reach_qualification_signing() {
    // No other workflow names the signer's key, and nothing in the
    // repository runs on a trigger that gives a pull request's code secrets.
    for entry in std::fs::read_dir(repository().join(".github/workflows")).expect("workflows") {
        let path = entry.expect("entry").path();
        let other = std::fs::read_to_string(&path).expect("workflow text");
        if !path.ends_with("recipe-qualification.yml") {
            assert!(
                !other.contains("QUALIFICATION_RELEASE_SIGNER_KEY")
                    && !other.contains("recipe-qualification-signing"),
                "{} reaches the signing environment",
                path.display()
            );
        }
    }
    assert!(
        !std::fs::read_to_string(repository().join(WORKFLOW))
            .expect("workflow")
            .contains("pull_request_target")
    );
}

/// The trust directory holds public artifacts only.
#[test]
fn the_repository_holds_no_qualification_key() {
    let trust = repository().join("qualification/trust");
    for entry in std::fs::read_dir(trust).expect("trust directory") {
        let entry = entry.expect("entry");
        assert!(entry.file_type().expect("type").is_file());
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(
            matches!(
                name.as_ref(),
                ".gitkeep"
                    | "qualification-trust-root.json"
                    | "signer-certificate.json"
                    | "commissioning-signer-certificate.json"
                    | "revocation-list.json"
                    | "ceremony.json"
            ),
            "{name} is not a public trust artifact"
        );
        let bytes = std::fs::read(entry.path()).expect("public artifact");
        match name.as_ref() {
            "qualification-trust-root.json" => {
                QualificationTrustRoot::from_canonical_json(&bytes).expect("closed public root");
            }
            "signer-certificate.json" | "commissioning-signer-certificate.json" => {
                QualificationSignerCertificate::from_canonical_json(&bytes)
                    .expect("closed public certificate");
            }
            "revocation-list.json" => {
                QualificationRevocationList::from_canonical_json(&bytes)
                    .expect("closed public revocations");
            }
            "ceremony.json" => {
                let ceremony: serde_json::Value = serde_json::from_slice(&bytes).expect("ceremony");
                let mut keys: Vec<&str> = ceremony
                    .as_object()
                    .expect("ceremony object")
                    .keys()
                    .map(String::as_str)
                    .collect();
                keys.sort_unstable();
                assert_eq!(
                    keys,
                    [
                        "assessment",
                        "created_at",
                        "operator",
                        "private_key_retention",
                        "public_artifacts",
                        "qualification_issued",
                        "schema",
                        "scope",
                        "stable_launch_ready"
                    ]
                );
                assert_eq!(ceremony["schema"], "auths.qualification-root-ceremony/1");
                assert_eq!(ceremony["qualification_issued"], false);
                assert_eq!(ceremony["stable_launch_ready"], false);
            }
            ".gitkeep" => assert!(bytes.is_empty()),
            _ => unreachable!("filename checked above"),
        }
    }
}
