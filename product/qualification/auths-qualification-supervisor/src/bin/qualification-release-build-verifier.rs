use auths_qualification_supervisor::verify_hosted_release_build;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("qualification release-build verification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    reject_secret_environment()?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [
        command,
        release_build,
        surface,
        members,
        artifact_root,
        candidate_repository,
        hosted_metadata,
        provenance,
        attester_tools_verification,
        attester_tools_manifest,
        commit,
        now,
        output,
    ] = arguments.as_slice()
    else {
        return Err(usage());
    };
    if command != "verify-hosted" {
        return Err(usage());
    }
    let commit = commit.to_str().ok_or("candidate revision is not UTF-8")?;
    let now = now
        .to_str()
        .ok_or("verification time is not UTF-8")?
        .parse::<u64>()
        .map_err(|error| format!("verification time is invalid: {error}"))?;
    let output = PathBuf::from(output);
    if output.exists() {
        return Err(format!(
            "verified release-build output already exists: {}",
            output.display()
        ));
    }
    let bytes = verify_hosted_release_build(
        Path::new(release_build),
        Path::new(surface),
        Path::new(members),
        Path::new(artifact_root),
        Path::new(candidate_repository),
        Path::new(hosted_metadata),
        Path::new(provenance),
        Path::new(attester_tools_verification),
        Path::new(attester_tools_manifest),
        commit,
        now,
    )?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create verifier output directory: {error}"))?;
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output)
        .map_err(|error| format!("could not create verifier output: {error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not durably write verifier output: {error}"))?;
    Ok(())
}

fn reject_secret_environment() -> Result<(), String> {
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().to_ascii_uppercase();
        if [
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PRIVATE_KEY",
            "CREDENTIAL",
            "SIGNING_SEED",
        ]
        .iter()
        .any(|forbidden| name.contains(forbidden))
        {
            return Err(format!(
                "secret-bearing environment is forbidden for release verification: {name}"
            ));
        }
    }
    Ok(())
}

fn usage() -> String {
    "usage: qualification-release-build-verifier verify-hosted RELEASE_BUILD SURFACE MEMBERS ARTIFACT_ROOT CANDIDATE_REPOSITORY HOSTED_METADATA PROVENANCE_VERIFICATION ATTESTER_TOOLS_VERIFICATION ATTESTER_TOOLS_MANIFEST CANDIDATE_COMMIT NOW_UNIX_SECONDS OUTPUT".to_owned()
}
