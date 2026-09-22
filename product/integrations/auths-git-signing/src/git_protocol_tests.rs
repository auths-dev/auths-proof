//! The envelope and signing-program protocol against real Git.
//!
//! A shell stub stands in for the future signing program. It records exactly
//! what Git passes and replays bytes produced by this crate, so each assertion
//! checks this crate's encoding against Git's behavior rather than against a
//! hand-written expectation.

use crate::envelope::GitSignatureEnvelope;
use crate::program::{
    ProgramRequest, SigningKeyRef, VerifiedSigner, VerifyStatus, parse_arguments,
    sign_created_status,
};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const STUB: &str = r#"#!/bin/sh
set -eu
dir="$(dirname "$0")"
n=$(ls "$dir/calls" | wc -l | tr -d ' ')
call="$dir/calls/$n"
mkdir "$call"
for argument in "$@"; do printf '%s\0' "$argument" >> "$call/argv"; done
cat > "$call/stdin"
if [ "$1" = "--status-fd=1" ]; then
  cp "$3" "$call/signature"
  cat "$dir/verify-stdout"
  exit "$(cat "$dir/verify-exit")"
fi
cat "$dir/sign-stdout"
cat "$dir/sign-stderr" >&2
exit "$(cat "$dir/sign-exit")"
"#;

struct Harness {
    _root: tempfile::TempDir,
    repo: PathBuf,
    stub_dir: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let repo = root.path().join("repo");
        let stub_dir = root.path().join("stub");
        fs::create_dir_all(stub_dir.join("calls")).expect("stub dir");
        let stub = stub_dir.join("auths-git-sign");
        fs::write(&stub, STUB).expect("stub");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).expect("chmod");
        let harness = Self {
            _root: root,
            repo,
            stub_dir,
        };
        harness.git_ok(
            &["init", "-q", harness.repo.to_str().expect("utf-8 path")],
            None,
        );
        for (key, value) in [
            ("gpg.format", "x509"),
            ("gpg.x509.program", stub.to_str().expect("utf-8 path")),
            ("user.signingkey", "auths:probe-agent"),
            ("user.name", "probe"),
            ("user.email", "probe@example.invalid"),
        ] {
            harness.git_ok(&["config", key, value], Some(&harness.repo));
        }
        harness
    }

    fn git(&self, arguments: &[&str], directory: Option<&Path>) -> Output {
        let mut command = Command::new("git");
        command
            .args(arguments)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_DATE", "1790000000 +0000")
            .env("GIT_COMMITTER_DATE", "1790000000 +0000")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE");
        if let Some(directory) = directory {
            command.current_dir(directory);
        }
        command.output().expect("git is installed")
    }

    fn git_ok(&self, arguments: &[&str], directory: Option<&Path>) -> Vec<u8> {
        let output = self.git(arguments, directory);
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn in_repo(&self, arguments: &[&str]) -> Output {
        self.git(arguments, Some(&self.repo))
    }

    fn arm_signer(&self, stdout: &[u8], stderr: &[u8], exit: i32) {
        fs::write(self.stub_dir.join("sign-stdout"), stdout).expect("stdout");
        fs::write(self.stub_dir.join("sign-stderr"), stderr).expect("stderr");
        fs::write(self.stub_dir.join("sign-exit"), exit.to_string()).expect("exit");
    }

    fn arm_verifier(&self, status: &VerifyStatus) {
        fs::write(self.stub_dir.join("verify-stdout"), status.status_lines()).expect("stdout");
        fs::write(
            self.stub_dir.join("verify-exit"),
            status.exit_code().to_string(),
        )
        .expect("exit");
    }

    fn call(&self, index: usize) -> RecordedCall {
        let directory = self.stub_dir.join("calls").join(index.to_string());
        let argv = fs::read(directory.join("argv")).expect("argv");
        RecordedCall {
            arguments: argv
                .split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| OsString::from(String::from_utf8(part.to_vec()).expect("utf-8")))
                .collect(),
            stdin: fs::read(directory.join("stdin")).expect("stdin"),
            signature: fs::read(directory.join("signature")).ok(),
        }
    }

    fn calls(&self) -> usize {
        fs::read_dir(self.stub_dir.join("calls"))
            .expect("calls")
            .count()
    }

    fn commit_file(&self, name: &str) {
        fs::write(self.repo.join(name), name).expect("file");
        assert!(self.in_repo(&["add", name]).status.success());
    }
}

struct RecordedCall {
    arguments: Vec<OsString>,
    stdin: Vec<u8>,
    signature: Option<Vec<u8>>,
}

fn envelope() -> GitSignatureEnvelope {
    GitSignatureEnvelope::new(b"proof-bytes".repeat(40), b"action-bytes".to_vec())
        .expect("envelope")
}

/// Splits a raw commit into (payload without `gpgsig`, the un-indented
/// signature). Continuation lines of a header start with one space.
fn split_commit_signature(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let text = std::str::from_utf8(raw).expect("utf-8 commit");
    let (headers, message) = text.split_once("\n\n").expect("header/message split");
    let mut payload = String::new();
    let mut signature = String::new();
    let mut in_signature = false;
    for line in headers.split('\n') {
        if let Some(first) = line.strip_prefix("gpgsig ") {
            in_signature = true;
            signature.push_str(first);
            signature.push('\n');
        } else if in_signature && let Some(rest) = line.strip_prefix(' ') {
            signature.push_str(rest);
            signature.push('\n');
        } else {
            in_signature = false;
            payload.push_str(line);
            payload.push('\n');
        }
    }
    payload.push('\n');
    payload.push_str(message);
    (payload.into_bytes(), signature.into_bytes())
}

#[test]
fn git_commit_signing_uses_the_program_protocol_and_stores_the_envelope() {
    let harness = Harness::new();
    let armored = envelope().to_armored();
    harness.arm_signer(armored.as_bytes(), sign_created_status(), 0);
    harness.commit_file("a");
    let output = harness.in_repo(&["commit", "-q", "-S", "-m", "signed by an agent"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let call = harness.call(0);
    assert_eq!(
        parse_arguments(call.arguments),
        Ok(ProgramRequest::Sign {
            key: SigningKeyRef::parse("auths:probe-agent").expect("key")
        })
    );
    let raw = harness.git_ok(&["cat-file", "commit", "HEAD"], Some(&harness.repo));
    let (payload, stored) = split_commit_signature(&raw);
    assert_eq!(
        call.stdin, payload,
        "Git signs the commit without its gpgsig header"
    );
    assert_eq!(
        stored,
        armored.as_bytes(),
        "Git stores the envelope byte for byte"
    );
    assert_eq!(
        GitSignatureEnvelope::from_armored(&stored).expect("stored envelope"),
        envelope()
    );
}

#[test]
fn git_tag_signing_uses_the_program_protocol_and_appends_the_envelope() {
    let harness = Harness::new();
    harness.commit_file("a");
    assert!(
        harness
            .in_repo(&["commit", "-q", "-m", "base"])
            .status
            .success()
    );
    let armored = envelope().to_armored();
    harness.arm_signer(armored.as_bytes(), sign_created_status(), 0);
    let output = harness.in_repo(&["tag", "-s", "v1.0.0", "-m", "release"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let call = harness.call(0);
    assert!(matches!(
        parse_arguments(call.arguments),
        Ok(ProgramRequest::Sign { .. })
    ));
    let raw = harness.git_ok(&["cat-file", "tag", "v1.0.0"], Some(&harness.repo));
    let mut expected = call.stdin.clone();
    expected.extend_from_slice(armored.as_bytes());
    assert_eq!(
        raw, expected,
        "a tag object is its signed payload followed by the envelope"
    );
    assert!(call.stdin.starts_with(b"object "));
    assert!(
        call.stdin
            .windows(11)
            .any(|window| window == b"\ntag v1.0.0")
    );
}

#[test]
fn git_refuses_to_sign_without_the_created_status() {
    let harness = Harness::new();
    harness.arm_signer(envelope().to_armored().as_bytes(), b"", 1);
    harness.commit_file("a");
    let output = harness.in_repo(&["commit", "-q", "-S", "-m", "must not exist"]);
    assert!(!output.status.success());
    assert!(
        !harness
            .in_repo(&["rev-parse", "--verify", "HEAD"])
            .status
            .success()
    );

    // A zero exit without the status line is also refused.
    harness.arm_signer(envelope().to_armored().as_bytes(), b"", 0);
    let output = harness.in_repo(&["commit", "-q", "-S", "-m", "must not exist"]);
    assert!(!output.status.success());
    assert!(
        !harness
            .in_repo(&["rev-parse", "--verify", "HEAD"])
            .status
            .success()
    );
}

#[test]
fn git_verification_is_good_only_for_the_good_status() {
    let harness = Harness::new();
    let armored = envelope().to_armored();
    harness.arm_signer(armored.as_bytes(), sign_created_status(), 0);
    harness.commit_file("a");
    assert!(
        harness
            .in_repo(&["commit", "-q", "-S", "-m", "one"])
            .status
            .success()
    );
    harness.commit_file("b");
    assert!(
        harness
            .in_repo(&["tag", "-s", "v1", "-m", "tag"])
            .status
            .success()
    );
    let signing_calls = harness.calls();

    let cases = [
        (
            VerifyStatus::Good(VerifiedSigner::new("did:key:z6MkProbe")),
            true,
        ),
        (VerifyStatus::Bad("git.payload-digest-mismatch"), false),
        (VerifyStatus::Error("git.envelope-malformed"), false),
    ];
    for (index, (status, accepted)) in cases.into_iter().enumerate() {
        harness.arm_verifier(&status);
        for (offset, arguments) in [["verify-commit", "HEAD"], ["verify-tag", "v1"]]
            .into_iter()
            .enumerate()
        {
            let output = harness.in_repo(&arguments);
            assert_eq!(
                output.status.success(),
                accepted,
                "{status:?} {arguments:?}"
            );
            let call = harness.call(signing_calls + index * 2 + offset);
            assert!(
                matches!(
                    parse_arguments(call.arguments),
                    Ok(ProgramRequest::Verify { .. })
                ),
                "verify argument form"
            );
            assert_eq!(
                call.signature.as_deref(),
                Some(armored.as_bytes()),
                "Git passes the stored envelope unchanged"
            );
            assert!(!call.stdin.is_empty());
        }
    }

    // Verification receives exactly the payload that was signed.
    assert_eq!(harness.call(signing_calls).stdin, harness.call(0).stdin);
    assert_eq!(harness.call(signing_calls + 1).stdin, harness.call(1).stdin);
}
