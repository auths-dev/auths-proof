//! The release tool end to end: ceremony, evidence, assembly, signing, and
//! the verification a gateway performs.

#![allow(clippy::too_many_lines, reason = "one journey reads top to bottom")]

mod common;

use auths_recipe_qualification::EvidenceMemberKind;
use common::{COMMIT, DAY, HOUR, NOW, cases, draft_json, live_effects, tuple_json};
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

    // Evidence for each member, from reported cases.
    fs::write(at("tuple.json"), tuple_json().to_string()).expect("tuple");
    fs::write(at("draft.json"), draft_json().to_string()).expect("draft");
    for member in EvidenceMemberKind::ALL {
        let token = member_token(member);
        let cases_file = at(&format!("{token}.cases.json"));
        fs::write(
            &cases_file,
            serde_json::to_vec(&cases(member)).expect("cases"),
        )
        .expect("cases");
        let out = at(&format!("evidence/{token}.json"));
        let mut arguments = vec![
            "evidence",
            "--member",
            &token,
            "--commit",
            COMMIT,
            "--tuple",
            "",
            "--cases",
            &cases_file,
            "--out",
            &out,
        ];
        let tuple_file = at("tuple.json");
        arguments[6] = &tuple_file;
        let effects = live_effects(member).map(|effects| {
            (
                effects.entered.to_string(),
                effects.confirmed_by_read_back.to_string(),
            )
        });
        if let Some((entered, confirmed)) = &effects {
            arguments.extend(["--live-entered", entered, "--live-confirmed", confirmed]);
        }
        succeed(&arguments);
    }

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
        "stage-rotation",
        "--proposal-dir",
        &at("proposal"),
        "--now",
        &now,
        "--out",
        &at("rotation.cases.json"),
    ]);
    fs::write(at("canaries"), "canary-value-not-a-secret\n").expect("canaries");
    fs::write(at("gateway.log"), "attempt recorded\n").expect("log");
    succeed(&[
        "stage-redaction",
        "--canaries",
        &at("canaries"),
        "--source",
        &at("gateway.log"),
        "--source",
        &at("proposal/record.json"),
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
            &at("leaky.log"),
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
