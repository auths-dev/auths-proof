//! Native CLI/control-frame artifact. Refusal servers prove framing only;
//! installed acquisition/disclosure and hostile-agent containment remain separate.
#![cfg(unix)]
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    os::unix::net::UnixListener,
    process::Command,
};

fn serve(listener: UnixListener, reply: Value) -> std::thread::JoinHandle<Value> {
    listener.set_nonblocking(true).expect("nonblocking");
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("CLI did not connect: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("deadline");
        let mut length = [0; 4];
        stream.read_exact(&mut length).expect("length");
        let length = u32::from_be_bytes(length) as usize;
        assert!((1..=auths_gateway::app::MAX_FRAME_BYTES).contains(&length));
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).expect("frame");
        let captured = serde_json::from_slice(&bytes).expect("request");
        let response = serde_json::to_vec(&reply).expect("response");
        stream
            .write_all(&u32::try_from(response.len()).expect("length").to_be_bytes())
            .expect("length");
        stream.write_all(&response).expect("response");
        captured
    })
}

#[test]
fn native_application_content_cli_fixture_is_current() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let corpus: Value = serde_json::from_slice(
        &std::fs::read(root.join("application-content-frame.json")).expect("native frame corpus"),
    )
    .expect("JSON");
    let requests = &corpus["requests"];
    let directory = tempfile::Builder::new()
        .prefix("auths-content-")
        .tempdir_in("/tmp")
        .expect("directory");
    for field in ["proof", "action", "approval"] {
        let bytes = Base64UrlUnpadded::decode_vec(
            requests["content"]["submission"][format!("{field}_b64")]
                .as_str()
                .expect("input"),
        )
        .expect("bytes");
        std::fs::write(directory.path().join(field), bytes).expect("input");
    }
    std::fs::write(
        directory.path().join("ack"),
        Base64UrlUnpadded::decode_vec(
            requests["disclosure-ack"]["acknowledgement_b64"]
                .as_str()
                .expect("ACK"),
        )
        .expect("bytes"),
    )
    .expect("input");
    let mut cases = Vec::new();
    for (name, command, code) in [
        ("content", "content-acquire", "gateway.acquisition.binding"),
        (
            "content-history",
            "content-history",
            "gateway.attempt.state-unavailable",
        ),
        (
            "disclosure-ack",
            "disclosure-acknowledge",
            "gateway.disclosure.acknowledgement",
        ),
    ] {
        let socket = directory.path().join(format!("{name}.sock"));
        let reply =
            json!({"outcome": "refused", "result": {"outcome": "not-entered", "code": code}});
        let server = serve(UnixListener::bind(&socket).expect("bind"), reply.clone());
        let mut cli = Command::new(env!("CARGO_BIN_EXE_auths-gateway"));
        cli.arg(command).arg("--app-socket").arg(socket);
        if name == "content" {
            for field in ["proof", "action", "approval"] {
                cli.arg(format!("--{field}"))
                    .arg(directory.path().join(field));
            }
        } else {
            cli.arg("--operation").arg("fixture-1");
            if name == "disclosure-ack" {
                cli.arg("--acknowledgement")
                    .arg(directory.path().join("ack"));
            }
        }
        let output = cli.output().expect("CLI");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let captured = server.join().expect("server");
        assert_eq!(captured, requests[name]);
        let response: Value = serde_json::from_slice(&output.stdout).expect("response");
        assert_eq!(response, reply);
        cases.push(json!({"command": command, "request": captured, "response": response}));
    }
    let fixture = json!({"schema": "auths.application-content-cli-fixture/1", "scope": "production CLI with real refusal sockets; no installed engine/provider/disclosure-receive claim", "cases": cases});
    let bytes = serde_json::to_vec_pretty(&fixture).expect("fixture");
    let path = root.join("application-content-cli.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
