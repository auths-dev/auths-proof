#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn cargo(args: &[&str]) -> Result<(), String> {
    command("cargo", args)
}

pub(crate) fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(root())
        .status()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} failed with {status}", args.join(" ")))
    }
}

pub(crate) fn command_in(
    program: &str,
    arguments: &[&str],
    directory: &Path,
    environment: Option<(&str, &Path)>,
) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(arguments).current_dir(directory);
    if let Some((key, value)) = environment {
        command.env(key, value);
    }
    let status = command
        .status()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {} failed with {status}",
            arguments.join(" ")
        ))
    }
}

pub(crate) fn command_output_in(
    program: &str,
    arguments: &[&str],
    directory: &Path,
    environment: Option<(&str, &Path)>,
) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(arguments).current_dir(directory);
    if let Some((key, value)) = environment {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

pub(crate) fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is inside repository root")
        .to_path_buf()
}
