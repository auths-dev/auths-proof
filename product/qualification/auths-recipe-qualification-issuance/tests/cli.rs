//! The release tool end to end: ceremony, evidence, assembly, signing, and
//! the verification a gateway performs.

#![allow(clippy::too_many_lines, reason = "one journey reads top to bottom")]

mod common;

use auths_recipe_qualification::EvidenceMemberKind;
use common::{COMMIT, DAY, HOUR, NOW, draft_json, tuple_json};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn tool(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_auths-qualification"))
        .args(arguments)
        .output()
        .expect("run the tool")
}

fn succeed(arguments: &[&str]) -> String {
    let output = tool(arguments);
    assert!(
        output.status.success(),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8")
}

fn refuse(arguments: &[&str]) -> String {
    let output = tool(arguments);
    assert!(!output.status.success(), "{arguments:?} succeeded");
    String::from_utf8(output.stderr).expect("UTF-8")
}

fn borrowed(owned: &[String]) -> Vec<&str> {
    owned.iter().map(String::as_str).collect()
}

fn path(directory: &Path, name: &str) -> String {
    directory
        .join(name)
        .to_str()
        .expect("UTF-8 path")
        .to_owned()
}

fn member_token(member: EvidenceMemberKind) -> String {
    serde_json::to_value(member)
        .expect("member")
        .as_str()
        .expect("token")
        .to_owned()
}

#[test]
#[cfg(unix)]
fn a_release_is_built_signed_and_verified_and_a_proposal_alone_is_not() {
    let directory = tempfile::tempdir().expect("directory");
    let at = |name: &str| path(directory.path(), name);
    let (now, not_after) = (NOW.to_string(), (NOW + 180 * DAY).to_string());

    // The ceremony: a root, a signer, a certificate, a revocation list.
    succeed(&[
        "root-init",
        "--root-id",
        "test-root",
        "--key-out",
        &at("root.key"),
        "--root-out",
        &at("root.json"),
    ]);
    let public_key = succeed(&["signer-init", "--key-out", &at("signer.key")])
        .trim()
        .strip_prefix("public_key=")
        .expect("public key")
        .to_owned();
    succeed(&[
        "certify",
        "--root-key",
        &at("root.key"),
        "--root",
        &at("root.json"),
        "--signer-id",
        "release-signer",
        "--public-key",
        &public_key,
        "--issued-at",
        &(NOW - DAY).to_string(),
        "--not-before",
        &(NOW - DAY).to_string(),
        "--not-after",
        &not_after,
        "--out",
        &at("certificate.json"),
    ]);
    assert!(
        refuse(&[
            "root-init",
            "--root-id",
            "test-root",
            "--key-out",
            &at("root.key"),
            "--root-out",
            &at("other.json")
        ])
        .starts_with("qualification.key-unwritable"),
        "an existing key file is never replaced"
    );

    // Execute the stages through the real release tool. The provider-specific
    // port is a subprocess double; reports are authored only by the runner.
    fs::write(at("draft.json"), draft_json().to_string()).expect("draft");
    let work = directory.path().join("staged");
    let harness = common::stage_fixture(&work);
    let tuple_file = work.join("tuple.json").display().to_string();
    let corpus_file = work.join("corpus.json").display().to_string();
    let harness_file = harness.display().to_string();
    let work_text = work.display().to_string();
    for phase in ["offline", "live"] {
        succeed(&[
            "run-stage",
            "--phase",
            phase,
            "--corpus",
            &corpus_file,
            "--harness",
            &harness_file,
            "--tuple",
            &tuple_file,
            "--work-dir",
            &work_text,
        ]);
    }
    let trust_cases = work.join("cases/rotation.trust.json").display().to_string();
    succeed(&[
        "stage-trust",
        "--tuple",
        &tuple_file,
        "--now",
        &now,
        "--out",
        &trust_cases,
    ]);
    let canaries = at("canaries");
    let clean = at("clean-output");
    fs::write(&canaries, b"synthetic-canary-not-a-credential\n").expect("canaries");
    fs::write(&clean, b"closed states and digests only").expect("output");
    let redaction_cases = work.join("cases/redaction.scan.json").display().to_string();
    let mut redact = vec![
        "stage-redaction".to_owned(),
        "--canaries".to_owned(),
        canaries,
        "--out".to_owned(),
        redaction_cases,
    ];
    for kind in ["log", "trace", "metric", "support-bundle", "evidence"] {
        redact.extend(["--source".to_owned(), format!("{kind}={clean}")]);
    }
    succeed(&borrowed(&redact));
    for member in EvidenceMemberKind::ALL {
        let token = member_token(member);
        let mut arguments = vec![
            "evidence".to_owned(),
            "--member".to_owned(),
            token.clone(),
            "--commit".to_owned(),
            COMMIT.to_owned(),
            "--tuple".to_owned(),
            tuple_file.clone(),
            "--out".to_owned(),
            at(&format!("evidence/{token}.json")),
        ];
        for entry in fs::read_dir(work.join("cases")).expect("cases") {
            let file = entry.expect("file").path();
            if file
                .file_name()
                .expect("name")
                .to_string_lossy()
                .starts_with(&format!("{token}."))
            {
                arguments.extend(["--cases".to_owned(), file.display().to_string()]);
            }
        }
        if member == EvidenceMemberKind::Live {
            let live: serde_json::Value =
                serde_json::from_slice(&fs::read(work.join("live-effects.json")).expect("effects"))
                    .expect("JSON");
            arguments.extend([
                "--live-entered".to_owned(),
                live["entered"].to_string(),
                "--live-confirmed".to_owned(),
                live["confirmed_by_read_back"].to_string(),
            ]);
        }
        succeed(&borrowed(&arguments));
    }
    fs::write(at("tuple.json"), tuple_json().to_string()).expect("tuple");

    // An unsigned proposal: what a pull request can produce.
    succeed(&[
        "assemble",
        "--draft",
        &at("draft.json"),
        "--evidence-dir",
        &at("evidence"),
        "--out-dir",
        &at("proposal"),
    ]);
    fs::create_dir_all(directory.path().join("unsigned/records")).expect("directory");
    fs::create_dir_all(directory.path().join("unsigned/attestations")).expect("directory");
    fs::copy(
        at("proposal/record.json"),
        at("unsigned/records/record.json"),
    )
    .expect("copy");
    fs::copy(
        at("certificate.json"),
        at("unsigned/signer-certificate.json"),
    )
    .expect("copy");
    succeed(&[
        "revoke",
        "--root-key",
        &at("root.key"),
        "--root",
        &at("root.json"),
        "--sequence",
        "1",
        "--issued-at",
        &(NOW - HOUR).to_string(),
        "--next-update",
        &(NOW + 47 * HOUR).to_string(),
        "--out",
        &at("unsigned/revocation-list.json"),
    ]);
    fs::write(at("unsigned/release-index.json"), "{}").expect("index");
    let verify = |release: &str, at_time: &str| {
        vec![
            "verify".to_owned(),
            "--root".to_owned(),
            at("root.json"),
            "--release-dir".to_owned(),
            at(release),
            "--deployment".to_owned(),
            at("tuple.json"),
            "--now".to_owned(),
            at_time.to_owned(),
        ]
    };
    assert!(
        refuse(&borrowed(&verify("unsigned", &now)))
            .starts_with("qualification.not-qualified state=unqualified code=unavailable"),
        "a record no signer indexed qualifies nothing"
    );

    // Signing re-verifies the closure: a proposal missing evidence is refused.
    fs::create_dir_all(directory.path().join("open/evidence")).expect("directory");
    fs::copy(at("proposal/record.json"), at("open/record.json")).expect("copy");
    fs::copy(at("proposal/evidence/00.json"), at("open/evidence/00.json")).expect("copy");
    let sign = |proposal: &str, key: &str| {
        vec![
            "sign".to_owned(),
            "--proposal-dir".to_owned(),
            at(proposal),
            "--signer-key".to_owned(),
            at(key),
            "--certificate".to_owned(),
            at("certificate.json"),
            "--issued-at".to_owned(),
            now.clone(),
            "--out-dir".to_owned(),
            at("release"),
        ]
    };
    assert!(
        refuse(&borrowed(&sign("open", "signer.key")))
            .starts_with("qualification.evidence-closure")
    );
    assert!(
        refuse(&borrowed(&sign("proposal", "root.key"))).starts_with("qualification.key-mismatch"),
        "the root's key is not the certified signer"
    );
    assert!(
        !directory.path().join("release").exists(),
        "a refused signing writes nothing"
    );

    succeed(&borrowed(&sign("proposal", "signer.key")));
    fs::copy(
        at("unsigned/revocation-list.json"),
        at("release/revocation-list.json"),
    )
    .expect("copy");
    assert_eq!(
        succeed(&borrowed(&verify("release", &now))).trim(),
        "state=qualified code=none lease=true"
    );
    assert!(
        refuse(&borrowed(&verify(
            "release",
            &(NOW + 48 * HOUR).to_string()
        )))
        .starts_with("qualification.not-qualified state=stale code=revocation-stale")
    );

    // The stages that need no provider run on the same candidate.
    succeed(&[
        "stage-freshness",
        "--root",
        &at("root.json"),
        "--release-dir",
        &at("release"),
        "--deployment",
        &at("tuple.json"),
        "--now",
        &now,
        "--out",
        &at("freshness.cases.json"),
    ]);
    succeed(&[
        "stage-trust",
        "--tuple",
        &at("tuple.json"),
        "--now",
        &now,
        "--out",
        &at("trust.cases.json"),
    ]);
    let trust: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(at("trust.cases.json")).expect("cases")).expect("JSON");
    assert_eq!(
        trust.len(),
        11,
        "seven rotation cases and four freshness cases"
    );
    fs::write(at("canaries"), "canary-value-not-a-secret\n").expect("canaries");
    fs::write(at("gateway.log"), "attempt recorded\n").expect("log");
    succeed(&[
        "stage-redaction",
        "--canaries",
        &at("canaries"),
        "--source",
        &format!("log={}", at("gateway.log")),
        "--source",
        &format!("evidence={}", at("proposal/record.json")),
        "--out",
        &at("redaction.cases.json"),
    ]);
    fs::write(
        at("leaky.log"),
        "authorization: canary-value-not-a-secret\n",
    )
    .expect("log");
    assert!(
        refuse(&[
            "stage-redaction",
            "--canaries",
            &at("canaries"),
            "--source",
            &format!("log={}", at("leaky.log")),
            "--out",
            &at("leaky.cases.json")
        ])
        .starts_with("qualification.case-failed cases=1 failed=1")
    );

    // A revoked signer: the same release is refused.
    succeed(&[
        "revoke",
        "--root-key",
        &at("root.key"),
        "--root",
        &at("root.json"),
        "--sequence",
        "2",
        "--issued-at",
        &now,
        "--next-update",
        &(NOW + 47 * HOUR).to_string(),
        "--signer",
        "release-signer",
        "--out",
        &at("release/revocation-list.json"),
    ]);
    assert!(
        refuse(&borrowed(&verify("release", &(NOW + 1).to_string())))
            .starts_with("qualification.not-qualified state=revoked code=revoked")
    );
}

#[cfg(unix)]
#[test]
fn a_key_file_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().expect("directory");
    let at = |name: &str| path(directory.path(), name);
    succeed(&[
        "root-init",
        "--root-id",
        "test-root",
        "--key-out",
        &at("root.key"),
        "--root-out",
        &at("root.json"),
    ]);
    let mode = fs::metadata(at("root.key"))
        .expect("key")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    fs::set_permissions(at("root.key"), fs::Permissions::from_mode(0o644)).expect("mode");
    assert!(
        refuse(&[
            "revoke",
            "--root-key",
            &at("root.key"),
            "--root",
            &at("root.json"),
            "--sequence",
            "1",
            "--next-update",
            "1",
            "--out",
            &at("list.json"),
        ])
        .starts_with("qualification.key-not-private")
    );
}
