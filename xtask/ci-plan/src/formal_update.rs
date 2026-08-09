use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

pub const POLICY_PATH: &str = ".github/ci/formal-generated-paths.json";
const SCHEMA: &str = "auths-proof-formal-update/v1";

#[derive(Debug)]
pub struct Options {
    pub root: PathBuf,
    pub artifact: PathBuf,
    pub policy: PathBuf,
    pub repository: String,
    pub workflow: String,
    pub run_id: String,
    pub run_attempt: String,
    pub base_sha: String,
    pub head_sha: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    version: u32,
    exact_paths: Vec<String>,
    path_prefixes: Vec<String>,
    max_files: usize,
    max_total_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    repository: String,
    workflow: String,
    run_id: String,
    run_attempt: String,
    base_sha: String,
    head_sha: String,
    source_closure_digest: String,
    policy_sha256: String,
    files: Vec<FileEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileEntry {
    path: String,
    operation: String,
    mode: String,
    size: u64,
    sha256: String,
}

impl Policy {
    fn load(path: &Path) -> Result<(Self, String), String> {
        let bytes = fs::read(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        let policy: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid {}: {error}", path.display()))?;
        if policy.schema != "auths-proof-formal-generated-paths/v1"
            || policy.version == 0
            || policy.max_files == 0
            || policy.max_total_bytes == 0
        {
            return Err("formal update policy is unsupported or unbounded".to_owned());
        }
        for path in policy.exact_paths.iter().chain(&policy.path_prefixes) {
            validate_relative_path(path)?;
        }
        Ok((policy, hex::encode(Sha256::digest(&bytes))))
    }

    fn allows(&self, path: &str) -> bool {
        self.exact_paths.iter().any(|allowed| allowed == path)
            || self
                .path_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix) && path.len() > prefix.len())
    }
}

pub fn create(options: &Options) -> Result<bool, String> {
    require_exact_head(&options.root, &options.head_sha)?;
    let (policy, policy_sha256) = Policy::load(&options.policy)?;
    let changes = changed_paths(&options.root)?;
    if changes.is_empty() {
        write_output("update_required=false\n")?;
        append_summary("## Formal generated artifacts\n\nNo generated drift was found.\n")?;
        return Ok(false);
    }
    if changes.len() > policy.max_files {
        return Err(format!(
            "generated update has {} files; limit is {}",
            changes.len(),
            policy.max_files
        ));
    }
    let mut files = Vec::new();
    let mut total = 0_u64;
    for (status, path) in changes {
        if status != "M" && status != "A" {
            return Err(format!("generated update may not {status} {path}"));
        }
        validate_relative_path(&path)?;
        if !policy.allows(&path) {
            return Err(format!(
                "generated update contains non-allowlisted path: {path}"
            ));
        }
        let source = options.root.join(&path);
        let metadata = fs::symlink_metadata(&source)
            .map_err(|error| format!("could not inspect {}: {error}", source.display()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "generated update path is not a regular file: {path}"
            ));
        }
        ensure_no_symlink_components(&options.root, Path::new(&path))?;
        if status == "M" && tracked_mode(&options.root, &path)? != "100644" {
            return Err(format!("generated update file mode is not 100644: {path}"));
        }
        if executable(&metadata) {
            return Err(format!("generated update file is executable: {path}"));
        }
        let bytes = fs::read(&source)
            .map_err(|error| format!("could not read {}: {error}", source.display()))?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("generated update size overflow")?;
        if total > policy.max_total_bytes {
            return Err(format!(
                "generated update exceeds {} bytes",
                policy.max_total_bytes
            ));
        }
        let destination = options.artifact.join("files").join(&path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
        fs::write(&destination, &bytes)
            .map_err(|error| format!("could not write {}: {error}", destination.display()))?;
        files.push(FileEntry {
            path,
            operation: if status == "A" { "add" } else { "modify" }.to_owned(),
            mode: "100644".to_owned(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let closure: serde_json::Value = serde_json::from_slice(
        &fs::read(
            options
                .root
                .join("formal/qualification/aeneas/source-closure.json"),
        )
        .map_err(|error| format!("could not read source closure: {error}"))?,
    )
    .map_err(|error| format!("invalid source closure: {error}"))?;
    let source_closure_digest = closure["digest"]
        .as_str()
        .ok_or("source closure omits digest")?
        .to_owned();
    let manifest = Manifest {
        schema: SCHEMA.to_owned(),
        repository: options.repository.clone(),
        workflow: options.workflow.clone(),
        run_id: options.run_id.clone(),
        run_attempt: options.run_attempt.clone(),
        base_sha: options.base_sha.clone(),
        head_sha: options.head_sha.clone(),
        source_closure_digest,
        policy_sha256,
        files,
    };
    write_json(&options.artifact.join("manifest.json"), &manifest)?;
    write_output(&format!(
        "update_required=true\nartifact_path={}\n",
        options.artifact.display()
    ))?;
    append_summary(&format!(
        "## Formal generated artifacts\n\nA bounded update artifact contains **{} files** ({} bytes) for `{}`.\n",
        manifest.files.len(),
        total,
        manifest.head_sha
    ))?;
    Ok(true)
}

pub fn apply(options: &Options) -> Result<(), String> {
    require_exact_head(&options.root, &options.head_sha)?;
    if !git(&options.root, &["status", "--porcelain"])?
        .trim()
        .is_empty()
    {
        return Err("candidate checkout is not clean before applying formal update".to_owned());
    }
    let (policy, policy_sha256) = Policy::load(&options.policy)?;
    let manifest_path = options.artifact.join("manifest.json");
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("could not read {}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", manifest_path.display()))?;
    if manifest.schema != SCHEMA
        || manifest.repository != options.repository
        || manifest.workflow != options.workflow
        || manifest.run_id != options.run_id
        || manifest.run_attempt != options.run_attempt
        || manifest.base_sha != options.base_sha
        || manifest.head_sha != options.head_sha
        || manifest.policy_sha256 != policy_sha256
    {
        return Err("formal update provenance or trusted policy does not match".to_owned());
    }
    if manifest.files.is_empty() || manifest.files.len() > policy.max_files {
        return Err("formal update file count is empty or exceeds policy".to_owned());
    }
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for entry in &manifest.files {
        validate_relative_path(&entry.path)?;
        if !seen.insert(entry.path.clone()) || !policy.allows(&entry.path) || entry.mode != "100644"
        {
            return Err(format!(
                "formal update path or mode is rejected: {}",
                entry.path
            ));
        }
        let blob = options.artifact.join("files").join(&entry.path);
        let metadata = fs::symlink_metadata(&blob)
            .map_err(|error| format!("could not inspect {}: {error}", blob.display()))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != entry.size
        {
            return Err(format!(
                "formal update blob metadata is invalid: {}",
                entry.path
            ));
        }
        total = total
            .checked_add(entry.size)
            .ok_or("formal update size overflow")?;
        if total > policy.max_total_bytes {
            return Err("formal update exceeds policy size".to_owned());
        }
        let bytes = fs::read(&blob)
            .map_err(|error| format!("could not read {}: {error}", blob.display()))?;
        if hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
            return Err(format!("formal update digest mismatch: {}", entry.path));
        }
        let destination = options.root.join(&entry.path);
        ensure_no_symlink_components(&options.root, Path::new(&entry.path))?;
        match entry.operation.as_str() {
            "modify" => {
                let existing = fs::symlink_metadata(&destination).map_err(|error| {
                    format!(
                        "modified destination must already exist: {}: {error}",
                        entry.path
                    )
                })?;
                if !existing.file_type().is_file() || existing.file_type().is_symlink() {
                    return Err(format!(
                        "formal update destination is not a regular file: {}",
                        entry.path
                    ));
                }
                if tracked_mode(&options.root, &entry.path)? != entry.mode {
                    return Err(format!(
                        "formal update destination mode does not match: {}",
                        entry.path
                    ));
                }
            }
            "add" => {
                if fs::symlink_metadata(&destination).is_ok() {
                    return Err(format!("added destination already exists: {}", entry.path));
                }
                fs::create_dir_all(destination.parent().ok_or("added path has no parent")?)
                    .map_err(|error| {
                        format!("could not create parent for {}: {error}", entry.path)
                    })?;
            }
            _ => {
                return Err(format!(
                    "unsupported formal update operation: {}",
                    entry.operation
                ));
            }
        }
        fs::write(&destination, bytes)
            .map_err(|error| format!("could not update {}: {error}", destination.display()))?;
    }
    let actual: BTreeSet<_> = changed_paths(&options.root)?
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    if actual != seen {
        return Err(format!(
            "applied diff does not match manifest: actual={actual:?}, expected={seen:?}"
        ));
    }
    let mut command = Command::new("git");
    command.arg("add").arg("--");
    for path in &seen {
        command.arg(path);
    }
    let output = command
        .current_dir(&options.root)
        .output()
        .map_err(|error| format!("could not stage formal update: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not stage formal update: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!(
        "Formal generated artifact: VERIFIED AND STAGED ({} files)",
        seen.len()
    );
    Ok(())
}

fn changed_paths(root: &Path) -> Result<Vec<(String, String)>, String> {
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not inspect generated diff: {error}"))?;
    if !output.status.success() {
        return Err("could not inspect generated diff".to_owned());
    }
    let fields: Vec<_> = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| {
            String::from_utf8(field.to_vec()).map_err(|error| format!("non-UTF-8 diff: {error}"))
        })
        .collect::<Result<_, _>>()?;
    let mut changes = Vec::new();
    let mut index = 0;
    while index < fields.len() {
        let record = &fields[index];
        if record.len() < 4 || record.as_bytes()[2] != b' ' {
            return Err("malformed generated status".to_owned());
        }
        let state = &record[..2];
        if state.contains('R') || state.contains('C') {
            return Err("renames and copies are forbidden in generated updates".to_owned());
        }
        let path = record[3..].to_owned();
        let status = if state == "??" {
            "A"
        } else if state.contains('D') {
            "D"
        } else if state.contains('A') {
            "A"
        } else {
            "M"
        };
        changes.push((status.to_owned(), path));
        index += 1;
    }
    Ok(changes)
}

fn validate_relative_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || value.contains('\\')
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("unsafe repository-relative path: {value}"));
    }
    Ok(())
}

fn require_exact_head(root: &Path, expected: &str) -> Result<(), String> {
    let actual = git(root, &["rev-parse", "HEAD"])?;
    if actual.trim() != expected {
        return Err(format!(
            "stale candidate head: expected {expected}, found {}",
            actual.trim()
        ));
    }
    Ok(())
}

fn tracked_mode(root: &Path, path: &str) -> Result<String, String> {
    let output = git(root, &["ls-files", "--stage", "--", path])?;
    let mode = output
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("generated update path is not tracked: {path}"))?;
    Ok(mode.to_owned())
}

fn ensure_no_symlink_components(root: &Path, relative: &Path) -> Result<(), String> {
    let mut current = root.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(component) = component else {
            return Err("path contains a non-normal component".to_owned());
        };
        current.push(component);
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            return Err(format!("path traverses a symlink: {}", current.display()));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_metadata: &fs::Metadata) -> bool {
    false
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not run git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("git output was not UTF-8: {error}"))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode manifest: {error}"))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn write_output(value: &str) -> Result<(), String> {
    if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
        use std::io::Write as _;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(value.as_bytes()))
            .map_err(|error| format!("could not write GITHUB_OUTPUT: {error}"))?;
    }
    Ok(())
}

fn append_summary(value: &str) -> Result<(), String> {
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write as _;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(value.as_bytes()))
            .map_err(|error| format!("could not write GITHUB_STEP_SUMMARY: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "auths-ci-plan-formal-update-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("unique temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run_git(root: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(root)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {:?}: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn fixture() -> (TestDirectory, PathBuf, PathBuf, Options) {
        let temporary = TestDirectory::new();
        let root = temporary.path().join("candidate");
        let artifact = temporary.path().join("artifact");
        fs::create_dir_all(root.join("formal/qualification/aeneas")).expect("formal directory");
        fs::create_dir_all(root.join(".github/ci")).expect("policy directory");
        fs::write(
            root.join("formal/qualification/aeneas/source-closure.json"),
            b"{\"digest\":\"before\"}\n",
        )
        .expect("source closure");
        fs::write(
            root.join(POLICY_PATH),
            b"{\"schema\":\"auths-proof-formal-generated-paths/v1\",\"version\":1,\"exact_paths\":[\"formal/qualification/aeneas/source-closure.json\"],\"path_prefixes\":[\"formal/qualification/aeneas/generated/\"],\"max_files\":1,\"max_total_bytes\":1024}\n",
        )
        .expect("policy");
        run_git(&root, &["init"]);
        run_git(&root, &["config", "user.name", "Test"]);
        run_git(&root, &["config", "user.email", "test@example.invalid"]);
        run_git(&root, &["config", "commit.gpgsign", "false"]);
        run_git(&root, &["config", "core.hooksPath", "/dev/null"]);
        run_git(&root, &["add", "."]);
        run_git(&root, &["commit", "-m", "fixture"]);
        let head_sha = git(&root, &["rev-parse", "HEAD"])
            .expect("head")
            .trim()
            .to_owned();
        let options = Options {
            root: root.clone(),
            artifact: artifact.clone(),
            policy: root.join(POLICY_PATH),
            repository: "owner/repo".into(),
            workflow: "CI".into(),
            run_id: "7".into(),
            run_attempt: "1".into(),
            base_sha: "base".into(),
            head_sha,
        };
        (temporary, root, artifact, options)
    }

    #[test]
    fn paths_reject_traversal_absolute_and_backslash() {
        for path in [
            "../secret",
            "/etc/passwd",
            "formal\\escape",
            "formal/../escape",
            "",
        ] {
            assert!(validate_relative_path(path).is_err(), "accepted {path}");
        }
        assert!(validate_relative_path("formal/Auths/Generated/Algebra.lean").is_ok());
    }

    #[test]
    fn allowlist_prefix_requires_a_child() {
        let policy = Policy {
            schema: "auths-proof-formal-generated-paths/v1".into(),
            version: 1,
            exact_paths: vec!["exact".into()],
            path_prefixes: vec!["generated/".into()],
            max_files: 2,
            max_total_bytes: 10,
        };
        assert!(policy.allows("exact"));
        assert!(policy.allows("generated/file"));
        assert!(!policy.allows("generated/"));
        assert!(!policy.allows("generated-escape/file"));
    }

    #[test]
    fn artifact_round_trip_stages_only_the_hashed_allowlisted_file() {
        let (_temporary, root, _artifact, options) = fixture();
        fs::write(
            root.join("formal/qualification/aeneas/source-closure.json"),
            b"{\"digest\":\"after\"}\n",
        )
        .expect("updated closure");
        assert!(create(&options).expect("create artifact"));
        run_git(&root, &["checkout", "--", "."]);
        apply(&options).expect("apply artifact");
        assert_eq!(
            git(&root, &["diff", "--cached", "--name-only"])
                .expect("staged paths")
                .trim(),
            "formal/qualification/aeneas/source-closure.json"
        );
    }

    #[test]
    fn apply_rejects_a_tampered_blob() {
        let (_temporary, root, artifact, options) = fixture();
        fs::write(
            root.join("formal/qualification/aeneas/source-closure.json"),
            b"{\"digest\":\"after\"}\n",
        )
        .expect("updated closure");
        create(&options).expect("create artifact");
        run_git(&root, &["checkout", "--", "."]);
        fs::write(
            artifact.join("files/formal/qualification/aeneas/source-closure.json"),
            b"{\"digest\":\"evil!\"}\n",
        )
        .expect("tampered blob");
        assert!(
            apply(&options)
                .expect_err("tampering rejected")
                .contains("digest mismatch")
        );
    }

    #[test]
    fn artifact_round_trip_supports_a_new_allowlisted_regular_file() {
        let (_temporary, root, _artifact, options) = fixture();
        let generated = root.join("formal/qualification/aeneas/generated/new.lean");
        fs::create_dir_all(generated.parent().expect("generated parent")).expect("generated dir");
        fs::write(&generated, b"-- generated\n").expect("new generated file");
        create(&options).expect("create artifact");
        fs::remove_file(&generated).expect("restore clean checkout");
        apply(&options).expect("apply artifact");
        assert_eq!(
            git(&root, &["diff", "--cached", "--name-only"])
                .expect("staged paths")
                .trim(),
            "formal/qualification/aeneas/generated/new.lean"
        );
    }
}
