//! The protected run's workflow, read as text: which jobs can reach a
//! secret or an environment, and when they run. A pull request reaches
//! neither, so it can gather no live evidence and sign nothing.

use std::collections::BTreeMap;
use std::path::Path;

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
        ["assemble", "families", "live", "offline", "sign", "verify"]
    );
    for (name, lines) in &jobs {
        let has = |needle: &str| lines.iter().any(|line| line.contains(needle));
        let privileged = has("secrets.") || has("environment:") || has("id-token");
        assert_eq!(
            privileged,
            matches!(name.as_str(), "live" | "sign"),
            "{name}: only the live and signing jobs reach a secret or an environment"
        );
        let protected = lines.iter().any(|line| line == PROTECTED);
        assert_eq!(
            protected,
            !matches!(name.as_str(), "families" | "offline"),
            "{name}: everything after offline evidence runs only by hand on the default branch"
        );
        assert_eq!(
            has("QUALIFICATION_RELEASE_SIGNER_KEY"),
            name == "sign",
            "{name}: the signer's key"
        );
        assert_eq!(
            has("\" sign ") || has("${tool}\" sign"),
            name == "sign",
            "{name}: the signing command"
        );
    }
    let sign = &jobs["sign"];
    assert!(
        sign.iter()
            .any(|line| line == "environment: recipe-qualification-signing")
    );
    assert!(
        sign.iter().any(|line| line.contains("rm -f \"${key}\"")),
        "the key file is removed when the job ends"
    );

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
    assert!(!text.contains("pull_request_target"));
}

/// The trust directory holds public artifacts only.
#[test]
fn the_repository_holds_no_qualification_key() {
    let trust = repository().join("qualification/trust");
    for entry in std::fs::read_dir(trust).expect("trust directory") {
        let name = entry.expect("entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            matches!(
                name.as_ref(),
                ".gitkeep"
                    | "qualification-trust-root.json"
                    | "signer-certificate.json"
                    | "revocation-list.json"
            ),
            "{name} is not a public trust artifact"
        );
    }
}
