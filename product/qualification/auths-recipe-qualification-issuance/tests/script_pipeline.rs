//! Execute stage collection, redaction and assembly through the scripts the
//! hosted workflow uses. The family port is a subprocess double; this checks
//! orchestration, not a provider qualification.

#![cfg(unix)]

mod common;

use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn succeed(command: &mut Command) {
    let output = command.output().expect("command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one script pipeline reads top to bottom"
)]
fn stage_reports_flow_through_redaction_and_assembly_and_missing_execution_refuses() {
    let temporary = tempfile::tempdir().expect("directory");
    let root = temporary.path().join("repository");
    let family = root.join("qualification/families/example-refund-v1");
    fs::create_dir_all(&family).expect("family");
    let draft = common::draft_json();
    let record = serde_json::json!({
        "provider_kind": draft["provider_kind"], "validity_days": 30,
        "not_applicable": draft["not_applicable"],
        "custody_descriptor": draft["custody_descriptor"], "store_descriptor": draft["store_descriptor"],
        "residual_assumptions": draft["residual_assumptions"], "excluded_claims": draft["excluded_claims"],
    });
    fs::write(family.join("record.json"), record.to_string()).expect("record");
    succeed(Command::new("git").args(["init", "--quiet"]).arg(&root));
    succeed(Command::new("git").arg("-C").arg(&root).args(["add", "."]));
    succeed(Command::new("git").arg("-C").arg(&root).args([
        "-c",
        "user.name=Qualification test",
        "-c",
        "user.email=qualification@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "test corpus",
    ]));
    let revision = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("revision");
    assert!(revision.status.success());
    let revision = String::from_utf8(revision.stdout)
        .expect("UTF-8")
        .trim()
        .to_owned();
    let work = temporary.path().join("work");
    let harness = common::stage_fixture(&work);
    let tool = env!("CARGO_BIN_EXE_auths-qualification");
    for phase in ["offline", "live"] {
        succeed(
            Command::new(tool)
                .args(["run-stage", "--phase", phase])
                .arg("--corpus")
                .arg(work.join("corpus.json"))
                .arg("--harness")
                .arg(&harness)
                .arg("--tuple")
                .arg(work.join("tuple.json"))
                .arg("--work-dir")
                .arg(&work),
        );
    }
    fs::write(
        work.join("packages.json"),
        draft["installed_packages"].to_string(),
    )
    .expect("packages");
    fs::write(
        work.join("resources.json"),
        draft["provider_resources"].to_string(),
    )
    .expect("resources");
    let facts = serde_json::json!({
        "commit": revision, "source_closure_sha256": draft["source_closure_sha256"],
        "generated_artifacts_sha256": draft["generated_artifacts_sha256"],
        "recipe_decision_record_sha256": draft["recipe_decision_record_sha256"],
        "corpus_manifest_sha256": draft["corpus_manifest_sha256"],
    });
    fs::write(work.join("facts.json"), facts.to_string()).expect("facts");
    fs::write(work.join("canaries"), "synthetic-canary-not-a-credential\n").expect("canaries");
    fs::set_permissions(work.join("canaries"), fs::Permissions::from_mode(0o600))
        .expect("private canaries");
    for kind in ["log", "trace", "metric", "support-bundle"] {
        let directory = work.join("scan").join(kind);
        fs::create_dir_all(&directory).expect("scan directory");
        fs::write(directory.join("test-output"), "closed test states only").expect("output");
    }
    let scripts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../qualification/run");
    for name in [
        "commissioning-effects.json",
        "facts.json",
        "unexpected-public-output",
    ] {
        let path = work.join(name);
        let original = fs::read(&path).ok();
        fs::write(&path, "synthetic-canary-not-a-credential").expect("planted leak");
        let refused = Command::new("bash")
            .arg(scripts.join("redact.sh"))
            .arg(&work)
            .env("AUTHS_QUALIFICATION", tool)
            .current_dir(&root)
            .output()
            .expect("redaction refusal");
        assert!(!refused.status.success(), "unlisted output must be scanned");
        assert!(
            work.join("canaries").exists(),
            "retain private scan inputs on failure"
        );
        assert!(!work.join("cases/redaction.scan.json").exists());
        assert!(
            !String::from_utf8_lossy(&refused.stderr).contains("synthetic-canary-not-a-credential")
        );
        match original {
            Some(bytes) => fs::write(path, bytes).expect("restore public fact"),
            None => fs::remove_file(path).expect("remove leak"),
        }
    }
    succeed(
        Command::new("bash")
            .arg(scripts.join("redact.sh"))
            .arg(&work)
            .env("AUTHS_QUALIFICATION", tool)
            .current_dir(&root),
    );
    assert!(!work.join("canaries").exists());
    let assemble = || {
        Command::new("bash")
            .arg(scripts.join("assemble.sh"))
            .arg("example-refund-v1")
            .arg(&work)
            .args(["test-environment", "test-run"])
            .env("AUTHS_QUALIFICATION", tool)
            .current_dir(&root)
            .output()
            .expect("assemble")
    };
    let assembled = assemble();
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    assert!(work.join("proposal/record.json").is_file());
    // A failed rerun cannot leave its old proposal usable by the signing job.
    fs::copy(
        work.join("cases/recovery.live.json"),
        work.join("cases/recovery.harness.json"),
    )
    .expect("extra harness report");
    fs::remove_file(work.join("cases/recovery.live.json")).expect("remove execution");
    assert!(!assemble().status.success());
    assert!(!work.join("proposal/record.json").exists());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the four resource-session exits and stale phase outputs are checked together"
)]
fn live_script_cleans_up_after_success_setup_failure_and_stage_failure() {
    let temporary = tempfile::tempdir().expect("directory");
    let root = temporary.path().join("repository");
    let family = root.join("qualification/families/example-refund-v1");
    fs::create_dir_all(&family).expect("family");
    succeed(Command::new("git").args(["init", "--quiet"]).arg(&root));
    let work = temporary.path().join("work");
    let harness = common::stage_fixture(&work);
    fs::copy(harness, family.join("harness")).expect("harness");
    fs::copy(
        work.join("corpus.json"),
        family.join("corpus-manifest.json"),
    )
    .expect("corpus");
    let scripts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../qualification/run");
    for mode in ["success", "setup-failed", "failed", "cleanup-failed"] {
        fs::write(work.join("fault"), mode).expect("fault");
        // A prior phase's outputs must also become unusable if the overall
        // resource session fails. These are synthetic orchestration fixtures.
        fs::write(
            work.join("commissioning-effects.json"),
            r#"{"entered":1,"confirmed_by_read_back":1}"#,
        )
        .expect("earlier phase effects");
        fs::write(work.join("cases/live.commissioning.json"), "[]").expect("earlier phase report");
        let output = Command::new("bash")
            .arg(scripts.join("resource-session.sh"))
            .arg("example-refund-v1")
            .arg(&work)
            .arg("bash")
            .arg("-c")
            .arg(
                r#"set -e
test -f "$1/disposable-resource"
bash "$2" "$3" "$1"
test -f "$1/disposable-resource"
bash "$2" "$3" "$1"
test -f "$1/disposable-resource"
"#,
            )
            .arg("protected-journey-test")
            .arg(&work)
            .arg(scripts.join("live.sh"))
            .arg("example-refund-v1")
            .env(
                "AUTHS_QUALIFICATION",
                env!("CARGO_BIN_EXE_auths-qualification"),
            )
            .current_dir(&root)
            .output()
            .expect("live script");
        assert_eq!(output.status.success(), mode == "success", "{mode}");
        assert_eq!(
            work.join("live-effects.json").exists(),
            mode == "success",
            "a failed setup, stage or cleanup leaves no passing live evidence"
        );
        assert_eq!(
            work.join("disposable-resource").exists(),
            mode == "cleanup-failed",
            "teardown runs even after partial setup or a refused stage"
        );
        assert_eq!(
            work.join("cases/live.commissioning.json").exists(),
            mode == "success",
            "a failed resource session invalidates earlier commissioning evidence"
        );
        assert_eq!(
            work.join("commissioning-effects.json").exists(),
            mode == "success"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr)
                .contains("synthetic-canary-must-not-leave-child"),
            "setup and cleanup output must not expose a credential"
        );
    }
    assert_eq!(
        fs::read_to_string(work.join("cleanup-calls"))
            .expect("cleanup calls")
            .lines()
            .count(),
        4
    );
}
