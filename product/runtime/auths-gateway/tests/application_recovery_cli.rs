//! Native CLI/socket artifact construction. No installed authority or provider
//! is represented by this refusal server.
#![cfg(unix)]

use base64ct::{Base64UrlUnpadded, Encoding as _};
use std::{
    io::{Read as _, Write as _},
    os::unix::net::UnixListener,
    process::Command,
};

#[test]
fn native_application_recovery_cli_fixture_is_current() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("application-recovery-frame.json")).expect("frame fixture"),
    )
    .expect("JSON");
    let request = &corpus["request"];
    let expected_response = corpus["cases"][0]["response"].clone();
    let directory = tempfile::Builder::new()
        .prefix("auths-recovery-")
        .tempdir_in("/tmp")
        .expect("directory");
    for (name, field) in [
        ("proof", "proof_b64"),
        ("action", "action_b64"),
        ("approval", "approval_b64"),
    ] {
        let bytes =
            Base64UrlUnpadded::decode_vec(request["submission"][field].as_str().expect("encoded"))
                .expect("bytes");
        std::fs::write(directory.path().join(name), bytes).expect("input");
    }
    let socket = directory.path().join("app.sock");
    let listener = UnixListener::bind(&socket).expect("listen");
    // Avoid an indefinitely blocked test if the CLI rejects arguments first.
    listener.set_nonblocking(true).expect("nonblocking");
    let reply = expected_response.clone();
    let server = std::thread::spawn(move || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < until =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("CLI did not connect: {error}"),
            }
        };
        // Darwin can inherit O_NONBLOCK from the listener. The bounded
        // read_exact protocol below needs blocking I/O with its own deadline.
        stream
            .set_nonblocking(false)
            .expect("blocking accepted stream");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("deadline");
        let mut length = [0; 4];
        stream.read_exact(&mut length).expect("length");
        let length = u32::from_be_bytes(length) as usize;
        assert!((1..=auths_gateway::app::MAX_FRAME_BYTES).contains(&length));
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).expect("request");
        let frame: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        let bytes = serde_json::to_vec(&reply).expect("reply");
        stream
            .write_all(&u32::try_from(bytes.len()).expect("bound").to_be_bytes())
            .expect("length");
        stream.write_all(&bytes).expect("reply");
        frame
    });
    let output = Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
        .arg("app-recover")
        .arg("--app-socket")
        .arg(&socket)
        .arg("--source-operation")
        .arg("source-1")
        .arg("--proof")
        .arg(directory.path().join("proof"))
        .arg("--action")
        .arg(directory.path().join("action"))
        .arg("--approval")
        .arg(directory.path().join("approval"))
        .output()
        .expect("CLI");
    assert!(
        output.status.success(),
        "CLI: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let captured = server.join().expect("server");
    assert_eq!(&captured, request);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).expect("CLI response");
    assert_eq!(response, expected_response);
    let fixture = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "auths.application-recovery-cli-fixture/1",
        "scope": "production CLI and real Unix socket with refusal server; no installed engine/provider claim",
        "request": captured, "response": response,
    })).expect("fixture");
    let path = root.join("application-recovery-cli.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), fixture);
}
