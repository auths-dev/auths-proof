//! Bounded subprocess boundary for the reusable qualification stages.

use super::{Failure, json, write, write_cases};
use auths_recipe_qualification::{EvidenceMemberKind, LiveEffects, QualificationTuple};
use auths_recipe_qualification_issuance::{
    CaseReport, IssuanceError,
    execution::{RunCorpus, RunObservation, RunPhase},
};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn refused() -> Failure {
    // Child output can contain a provider credential. Never relay it.
    Failure("qualification.stage-execution-failed".to_owned())
}

fn execute_step(
    harness: &Path,
    id: &str,
    index: usize,
    operation: &str,
    work: &Path,
    timeout: Duration,
) -> Result<RunObservation, Failure> {
    // Unique paths, no stale output from an earlier step or failed run.
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| refused())?;
    let directory = work.join(format!(".qualification-step-{}", hex::encode(nonce)));
    fs::create_dir(&directory).map_err(|_| refused())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| refused())?;
    }
    let output = directory.join("observation.json");
    let result = (|| {
        let mut command = Command::new(harness);
        if operation == "installed-consumer" {
            // An installed consumer gets neither provider credentials nor
            // repository import paths. Family setup has already started the
            // gateway; this process only uses its application channel.
            command.env_clear();
            for name in [
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "AUTHS_GATEWAY",
                "AUTHS_QUALIFICATION",
                "VIRTUAL_ENV",
            ] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            command.env("PYTHONNOUSERSITE", "1").current_dir(work);
        }
        let mut child = command
            .args(["step", id, &index.to_string(), operation])
            .arg(work)
            .arg(&output)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| refused())?;
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(refused());
                    }
                    break;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(refused());
                }
            }
        }
        let metadata = fs::symlink_metadata(&output).map_err(|_| refused())?;
        if !metadata.is_file() || metadata.len() > 16 * 1024 {
            return Err(refused());
        }
        json(&output).map_err(|_| refused())
    })();
    let _ = fs::remove_dir_all(directory);
    result
}

/// Execute all cases of one phase; publish reports only after every case passes.
#[allow(
    clippy::too_many_lines,
    reason = "one bounded phase is collected before any report is published"
)]
pub(super) fn run(
    phase: &str,
    corpus: &Path,
    harness: &Path,
    tuple: &Path,
    work: &Path,
    timeout_seconds: u64,
) -> Result<(), Failure> {
    let phase = match phase {
        "offline" => RunPhase::Offline,
        "live" => RunPhase::Live,
        _ => return Err(refused()),
    };
    if !(1..=120).contains(&timeout_seconds) {
        return Err(refused());
    }
    fs::create_dir_all(work).map_err(|_| refused())?;
    let work = fs::canonicalize(work).map_err(|_| refused())?;
    let phase_token = match phase {
        RunPhase::Offline => "offline",
        RunPhase::Live => "live",
    };
    for member in EvidenceMemberKind::ALL {
        let token = serde_json::to_value(member).map_err(|_| refused())?;
        let path = work.join(format!(
            "cases/{}.{phase_token}.json",
            token.as_str().ok_or_else(refused)?
        ));
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(refused()),
        }
    }
    if phase == RunPhase::Live {
        match fs::remove_file(work.join("live-effects.json")) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(refused()),
        }
    }
    // Invalid inputs and a missing executable invalidate an earlier phase's
    // evidence just as a failed operation does.
    let corpus: RunCorpus = json(corpus)?;
    corpus.validate()?;
    let tuple: QualificationTuple = json(tuple)?;
    let harness = fs::canonicalize(harness).map_err(|_| refused())?;
    let mut reports: BTreeMap<String, Vec<CaseReport>> = BTreeMap::new();
    let mut live = LiveEffects {
        entered: 0,
        confirmed_by_read_back: 0,
    };
    for case in corpus.cases.iter().filter(|case| case.phase == phase) {
        let (report, effects) = case.execute(&tuple, |index, step| {
            let operation =
                serde_json::to_value(step.operation).map_err(|_| IssuanceError::CaseFailed)?;
            execute_step(
                &harness,
                case.id.as_str(),
                index,
                operation.as_str().ok_or(IssuanceError::CaseFailed)?,
                &work,
                Duration::from_secs(timeout_seconds),
            )
            .map_err(|_| IssuanceError::CaseFailed)
        })?;
        let member = case.scenario.member();
        let token = serde_json::to_value(member).map_err(|_| refused())?;
        reports
            .entry(token.as_str().ok_or_else(refused)?.to_owned())
            .or_default()
            .push(report);
        if member == EvidenceMemberKind::Live {
            live.entered = live
                .entered
                .checked_add(effects.entered)
                .ok_or_else(refused)?;
            live.confirmed_by_read_back = live
                .confirmed_by_read_back
                .checked_add(effects.confirmed_by_read_back)
                .ok_or_else(refused)?;
        }
    }
    if reports.is_empty()
        || (phase == RunPhase::Live
            && (live.entered == 0 || live.entered != live.confirmed_by_read_back))
    {
        return Err(refused());
    }
    for (member, cases) in reports {
        write_cases(
            &work.join(format!("cases/{member}.{phase_token}.json")),
            &cases,
        )?;
    }
    if phase == RunPhase::Live {
        let bytes = serde_json::to_vec(&live).map_err(|_| refused())?;
        write(&work.join("live-effects.json"), &bytes)?;
    }
    Ok(())
}
