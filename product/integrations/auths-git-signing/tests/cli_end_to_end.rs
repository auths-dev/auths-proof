//! The operator journey through the real binaries and real Git: keys, trust
//! on a protected branch, a grant, headless `git commit -S`, verification,
//! the trust-source rule, and revocation; and workload method configuration
//! that travels with the trust it is bound into.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REPOSITORY: &str = "github.com/acme/app";

struct Journey {
    _root: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
    grant: PathBuf,
}

impl Journey {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let home = root.path().join("auths-home");
        let repo = root.path().join("repo");
        let grant = root.path().join("agent.grant.json");
        std::fs::create_dir_all(&repo).expect("repo dir");
        Self {
            _root: root,
            home,
            repo,
            grant,
        }
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.repo)
            .env("AUTHS_GIT_HOME", &self.home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        command
    }

    fn auths(&self, arguments: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_auths-git"))
            .args(arguments)
            .output()
            .expect("auths-git runs")
    }

    fn auths_ok(&self, arguments: &[&str]) -> String {
        let output = self.auths(arguments);
        assert!(
            output.status.success(),
            "auths-git {arguments:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("utf-8")
    }

    fn git(&self, arguments: &[&str]) -> Output {
        self.command("git")
            .args(arguments)
            .output()
            .expect("git runs")
    }

    fn git_ok(&self, arguments: &[&str]) -> String {
        let output = self.git(arguments);
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("utf-8")
    }

    fn write(&self, name: &str) {
        std::fs::write(self.repo.join(name), name).expect("file");
        self.git_ok(&["add", name]);
    }

    fn trust_dir(&self) -> PathBuf {
        self.repo.join(".auths/git")
    }
}

fn path(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

/// Initializes the repository, pins trust on `main`, and grants the agent.
/// Returns the agent's principal.
fn prepared(journey: &Journey) -> String {
    journey.git_ok(&["init", "-q", "-b", "main"]);
    for (key, value) in [
        ("user.name", "Agent"),
        ("user.email", "agent@example.invalid"),
        ("gpg.format", "x509"),
        ("gpg.x509.program", env!("CARGO_BIN_EXE_auths-git-sign")),
        ("user.signingkey", "auths:agent"),
        ("auths.repository", REPOSITORY),
    ] {
        journey.git_ok(&["config", key, value]);
    }
    let trust_dir = journey.trust_dir();
    journey.git_ok(&["config", "auths.trustDir", path(&trust_dir)]);

    // Root and agent keys; trust committed to the protected branch.
    let root = journey.auths_ok(&["key", "init", "--label", "root"]);
    assert!(root.starts_with("did:key:z"));
    let agent = journey.auths_ok(&["key", "init", "--label", "agent"]);
    let agent = agent.trim();
    journey.auths_ok(&[
        "trust",
        "init",
        "--root",
        "root",
        "--repository",
        REPOSITORY,
        "--out",
        path(&trust_dir),
    ]);
    journey.git_ok(&["add", ".auths/git/trust.cbor"]);
    journey.git_ok(&["commit", "-q", "-m", "pin git signing trust"]);

    // The root grants the agent; the agent installs the grant.
    let issued = journey.auths_ok(&[
        "grant",
        "--root",
        "root",
        "--subject",
        agent,
        "--repository",
        REPOSITORY,
        "--capability",
        "sign-commit,sign-tag",
        "--expires-in",
        "86400",
        "--out",
        path(&journey.grant),
    ]);
    assert!(issued.starts_with("grant "));
    journey.auths_ok(&["install-grant", "--label", "agent", path(&journey.grant)]);
    agent.to_owned()
}

fn sign_and_verify(journey: &Journey, agent: &str) {
    // Headless signing on a feature branch: no prompt, no re-signing.
    journey.git_ok(&["switch", "-q", "-c", "feature"]);
    journey.write("a");
    journey.git_ok(&["commit", "-q", "-S", "-m", "agent change"]);
    journey.git_ok(&["tag", "-s", "v1.0.0", "-m", "release"]);
    journey.git_ok(&["verify-commit", "HEAD"]);
    journey.git_ok(&["verify-tag", "v1.0.0"]);

    let verified = journey.auths_ok(&["verify", "main..feature", "--trust-from-ref", "main"]);
    assert!(
        verified.contains(&format!("verified  {agent} <- ")),
        "{verified}"
    );
    let json = journey.auths_ok(&["verify", "v1.0.0", "--trust-from-ref", "main", "--json"]);
    assert!(json.contains("\"tag_name\":\"v1.0.0\""), "{json}");
    assert!(json.contains("\"trusted_context_sha256\""), "{json}");
}

fn refuse_self_trust_and_unsigned(journey: &Journey) {
    // A pull request cannot supply its own trust.
    let own_trust = journey.auths(&["verify", "main..feature", "--trust-from-ref", "feature"]);
    assert_eq!(own_trust.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&own_trust.stderr).contains("git.trust-from-verified-range"));

    // An unsigned commit in the range is denied.
    journey.write("b");
    journey.git_ok(&["commit", "-q", "--no-gpg-sign", "-m", "unsigned change"]);
    let unsigned = journey.auths(&["verify", "main..feature", "--trust-from-ref", "main"]);
    assert_eq!(unsigned.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unsigned.stdout).contains("denied  git.unsigned"));
}

fn revoke_and_deny(journey: &Journey) {
    let trust_dir = journey.trust_dir();
    // The root revokes the grant on the protected branch.
    journey.git_ok(&["switch", "-q", "main"]);
    let revocation = trust_dir.join("revocations/agent.sig");
    journey.auths_ok(&[
        "revoke",
        "--root",
        "root",
        "--repository",
        REPOSITORY,
        "--grant",
        path(&journey.grant),
        "--out",
        path(&revocation),
    ]);
    journey.git_ok(&["add", ".auths/git/revocations/agent.sig"]);
    journey.git_ok(&["commit", "-q", "-m", "revoke agent grant"]);

    let revoked = journey.auths(&["verify", "v1.0.0", "--trust-from-ref", "main"]);
    assert_eq!(revoked.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&revoked.stdout).contains("denied  git.grant-revoked"),
        "{}",
        String::from_utf8_lossy(&revoked.stdout)
    );
    assert!(!journey.git(&["verify-tag", "v1.0.0"]).status.success());
}

fn commit_only_key_cannot_tag(journey: &Journey) {
    // A key whose grant covers only commits cannot sign a tag, and Git
    // creates no tag when the signer refuses.
    let committer = journey.auths_ok(&["key", "init", "--label", "committer"]);
    let commit_only = journey.grant.with_file_name("committer.grant.json");
    journey.auths_ok(&[
        "grant",
        "--root",
        "root",
        "--subject",
        committer.trim(),
        "--repository",
        REPOSITORY,
        "--capability",
        "sign-commit",
        "--expires-in",
        "86400",
        "--out",
        path(&commit_only),
    ]);
    journey.auths_ok(&["install-grant", "--label", "committer", path(&commit_only)]);
    journey.git_ok(&["config", "user.signingkey", "auths:committer"]);
    let refused = journey.git(&["tag", "-s", "v2.0.0", "-m", "not allowed"]);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("does not cover"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !journey
            .git(&["rev-parse", "--verify", "refs/tags/v2.0.0"])
            .status
            .success()
    );

    // Installing a grant issued to someone else is refused.
    let wrong = journey.auths(&[
        "install-grant",
        "--label",
        "committer",
        path(&journey.grant),
    ]);
    assert_eq!(wrong.status.code(), Some(2));
}

#[test]
fn delegated_agent_signs_headlessly_and_revocation_denies_it() {
    let journey = Journey::new();
    let agent = prepared(&journey);
    sign_and_verify(&journey, &agent);
    refuse_self_trust_and_unsigned(&journey);
    revoke_and_deny(&journey);
    commit_only_key_cannot_tag(&journey);
}

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const WORKLOAD_SUBJECT: &str = "repo:acme/app:ref:refs/heads/main";

/// A `methods.json` enabling the OIDC workload method for one pinned
/// Ed25519 issuer key.
fn workload_methods() -> String {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]);
    serde_json::json!({
        "schema": "auths.git-methods/1",
        "oidc_workload": {"issuers": [{
            "issuer": GITHUB_ISSUER,
            "max_token_lifetime_seconds": 600,
            "keys": [{
                "kid": "pinned",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": Base64UrlUnpadded::encode_string(key.verifying_key().as_bytes()),
            }],
            "profile": {"github_actions": [{"repository_id": "7001", "owner_id": "7002"}]},
        }]},
    })
    .to_string()
}

/// Pins trust with `methods.json` on `main`; returns the agent principal.
fn workload_trust(journey: &Journey) -> String {
    journey.git_ok(&["init", "-q", "-b", "main"]);
    for (key, value) in [
        ("user.name", "Agent"),
        ("user.email", "agent@example.invalid"),
        ("gpg.format", "x509"),
        ("gpg.x509.program", env!("CARGO_BIN_EXE_auths-git-sign")),
        ("user.signingkey", "auths:agent"),
        ("auths.repository", REPOSITORY),
    ] {
        journey.git_ok(&["config", key, value]);
    }
    let methods = journey.grant.with_file_name("methods.json");
    std::fs::write(&methods, workload_methods()).expect("methods");
    journey.auths_ok(&["key", "init", "--label", "root"]);
    let agent = journey.auths_ok(&["key", "init", "--label", "agent"]);
    let trust_dir = journey.trust_dir();
    journey.auths_ok(&[
        "trust",
        "init",
        "--root",
        "root",
        "--repository",
        REPOSITORY,
        "--out",
        path(&trust_dir),
        "--methods",
        path(&methods),
    ]);
    assert!(trust_dir.join("methods.json").is_file());
    journey.git_ok(&["add", ".auths/git"]);
    journey.git_ok(&["commit", "-q", "-m", "pin git signing trust"]);
    agent
}

/// Grants the workload principal and the agent, and installs both grants.
fn workload_grants(journey: &Journey, agent: &str) {
    // The workload principal is granted like any other subject; its grant
    // is installed without a local key.
    let workload = journey.auths_ok(&[
        "workload-principal",
        "--issuer",
        GITHUB_ISSUER,
        "--subject",
        WORKLOAD_SUBJECT,
    ]);
    assert_eq!(
        workload.trim(),
        "oidc-workload:https%3A%2F%2Ftoken.actions.githubusercontent.com#repo%3Aacme%2Fapp%3Aref%3Arefs%2Fheads%2Fmain"
    );
    let workload_grant = journey.grant.with_file_name("ci.grant.json");
    for (subject, out) in [
        (workload.trim(), &workload_grant),
        (agent.trim(), &journey.grant),
    ] {
        journey.auths_ok(&[
            "grant",
            "--root",
            "root",
            "--subject",
            subject,
            "--repository",
            REPOSITORY,
            "--capability",
            "sign-commit",
            "--expires-in",
            "86400",
            "--out",
            path(out),
        ]);
    }
    journey.auths_ok(&[
        "install-grant",
        "--workload",
        "--label",
        "ci",
        path(&workload_grant),
    ]);
    let not_workload = journey.auths(&[
        "install-grant",
        "--workload",
        "--label",
        "ci",
        path(&journey.grant),
    ]);
    assert_eq!(not_workload.status.code(), Some(2));
    journey.auths_ok(&["install-grant", "--label", "agent", path(&journey.grant)]);
}

#[test]
fn workload_methods_travel_with_trust_and_bind_the_verifier() {
    let journey = Journey::new();
    let agent = workload_trust(&journey);
    workload_grants(&journey, &agent);
    let trust_dir = journey.trust_dir();

    // A did:key commit verifies with the methods read from the trust commit.
    journey.git_ok(&["switch", "-q", "-c", "feature"]);
    journey.write("a");
    journey.git_ok(&["commit", "-q", "-S", "-m", "agent change"]);
    let verified = journey.auths_ok(&["verify", "main..feature", "--trust-from-ref", "main"]);
    assert!(verified.contains("verified  did:key:"), "{verified}");

    // Trust committed to the workload configuration refuses a verifier that
    // runs without it.
    let stripped = journey.grant.with_file_name("stripped");
    std::fs::create_dir_all(&stripped).expect("dir");
    std::fs::copy(trust_dir.join("trust.cbor"), stripped.join("trust.cbor")).expect("copy");
    let unbound = journey.auths(&["verify", "HEAD", "--trust-dir", path(&stripped)]);
    assert_eq!(unbound.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unbound.stdout).contains("verifier-configuration-mismatch"),
        "{}",
        String::from_utf8_lossy(&unbound.stdout)
    );

    // Workload signers refuse clearly, and Git creates no object.
    journey.git_ok(&["config", "user.signingkey", "auths:ci"]);
    for (signer, message) in [
        ("oidc-workload", "ACTIONS_ID_TOKEN_REQUEST_URL is unset"),
        ("sigstore-keyless", "sigstore-keyless is not available"),
    ] {
        journey.git_ok(&["config", "auths.signer", signer]);
        journey.write(signer);
        let refused = journey.git(&["commit", "-q", "-S", "-m", signer]);
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains(message),
            "{}",
            String::from_utf8_lossy(&refused.stderr)
        );
    }
}
