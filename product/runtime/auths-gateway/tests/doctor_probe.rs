//! The doctor's privilege-dropped probe needs no environment and, on Linux,
//! refuses an inherited one, so operator store secrets never reach the
//! application UID.

#![cfg(unix)]

use std::{os::unix::net::UnixListener, path::Path, process::Command};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");

fn probe(state: &Path, app_socket: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .arg("probe")
        .arg("--state-dir")
        .arg(state)
        .arg("--app-socket")
        .arg(app_socket);
    command
}

#[test]
fn probe_runs_without_an_environment() {
    let root = tempfile::tempdir().expect("temporary root");
    let app_socket = root.path().join("app.sock");
    let _application = UnixListener::bind(&app_socket).expect("application socket");
    let output = probe(&root.path().join("state"), &app_socket)
        .env_clear()
        .output()
        .expect("run the probe");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn probe_refuses_an_inherited_environment() {
    let root = tempfile::tempdir().expect("temporary root");
    let app_socket = root.path().join("app.sock");
    let _application = UnixListener::bind(&app_socket).expect("application socket");
    let output = probe(&root.path().join("state"), &app_socket)
        .env_clear()
        .env("AUTHS_POSTGRES_URL", "sentinel-not-a-credential")
        .output()
        .expect("run the probe");
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "gateway.doctor.probe-environment-not-empty"
    );
}
