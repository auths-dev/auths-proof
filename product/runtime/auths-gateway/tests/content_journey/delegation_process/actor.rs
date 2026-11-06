//! Persistent installed-language peers. The orchestration process never
//! receives any of their private keys. Linux mode additionally separates UIDs.
use super::*;
use std::io::{BufRead as _, BufReader};
use std::sync::mpsc::{self, Receiver};

#[derive(Clone, Copy)]
pub(super) enum Language {
    Python,
    Node,
}

pub(super) struct Actor {
    process: Child,
    input: std::process::ChildStdin,
    replies: Receiver<Vec<u8>>,
    reader: Option<JoinHandle<()>>,
    pub(super) public: PublicIdentity,
    pub(super) uid: u32,
    pub(super) pid: u32,
}

impl Actor {
    pub(super) fn start(language: Language, consumer: &Path, uid: Option<u32>) -> Self {
        let python = std::env::var_os("AUTHS_DELEGATION_PYTHON")
            .expect("installed wheel interpreter is required");
        let executable = match language {
            Language::Python => python,
            Language::Node => {
                std::env::var_os("AUTHS_DELEGATION_NODE").unwrap_or_else(|| "node".into())
            }
        };
        let mut process = if let Some(uid) = uid {
            assert!(
                cfg!(target_os = "linux"),
                "distinct UID mode requires Linux"
            );
            let mut command = if rustix::process::geteuid().as_raw() == 0 {
                Command::new("setpriv")
            } else {
                let mut command = Command::new("sudo");
                command.args(["-n", "setpriv"]);
                command
            };
            command
                .arg(format!("--reuid={uid}"))
                .arg(format!("--regid={}", rustix::process::getegid().as_raw()))
                .args([
                    "--clear-groups",
                    "--bounding-set=-all",
                    "--inh-caps=-all",
                    "--ambient-caps=-all",
                    "--no-new-privs",
                ])
                .arg(&executable);
            command
        } else {
            Command::new(&executable)
        };
        match language {
            Language::Python => {
                process.args(["-I", "-c", include_str!("../actors/actor.py")]);
            }
            Language::Node => {
                process.args([
                    "--input-type=module",
                    "-e",
                    include_str!("../actors/actor.mjs"),
                ]);
            }
        }
        let mut process = process
            .current_dir(consumer)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("PATH"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("installed actor process");
        let mut input = process.stdin.take().expect("private input pipe");
        let output = process.stdout.take().expect("private result pipe");
        let (sender, replies) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut input = BufReader::new(output);
            loop {
                let mut bytes = Vec::new();
                // Do not let an untrusted peer allocate an unbounded line.
                let count = input
                    .by_ref()
                    .take(8 * 1024 * 1024 + 1)
                    .read_until(b'\n', &mut bytes)
                    .expect("actor output");
                if count == 0 {
                    break;
                }
                if count > 8 * 1024 * 1024 || bytes.last() != Some(&b'\n') {
                    break;
                }
                if sender.try_send(bytes).is_err() {
                    break;
                }
            }
        });
        let hello = exchange(&mut input, &replies, json!({"operation":"public"}));
        let key = Base64UrlUnpadded::decode_vec(hello["public_key"].as_str().expect("public key"))
            .expect("public encoding");
        let public = PublicIdentity::new(key.try_into().expect("Ed25519 public key"));
        let actual_uid = u32::try_from(hello["uid"].as_u64().expect("UID")).expect("UID range");
        if let Some(expected) = uid {
            assert_eq!(actual_uid, expected);
        }
        let package = hello["package"].as_str().expect("installed package path");
        assert!(
            !package.contains("/bindings/"),
            "actor must not import repository source"
        );
        match language {
            Language::Python => assert!(package.contains("site-packages/auths/")),
            Language::Node => assert!(package.contains("node_modules/@auths-dev/sdk/")),
        }
        let pid = u32::try_from(hello["pid"].as_u64().expect("PID")).expect("PID range");
        Self {
            process,
            input,
            replies,
            reader: Some(reader),
            public,
            uid: actual_uid,
            pid,
        }
    }
    pub(super) fn call(&mut self, request: Value) -> Value {
        exchange(&mut self.input, &self.replies, request)
    }
    pub(super) fn sign(&mut self, message: &[u8]) -> SignatureBytes {
        let response = self
            .call(json!({"operation":"sign","message":Base64UrlUnpadded::encode_string(message)}));
        let bytes =
            Base64UrlUnpadded::decode_vec(response["signature"].as_str().expect("signature"))
                .expect("signature encoding");
        assert_eq!(bytes.len(), 64);
        SignatureBytes::new(bytes).expect("signature")
    }
    pub(super) fn control(
        &mut self,
        socket: &Path,
        evidence: &auths_gateway::EngagementControlEvidence,
    ) -> Value {
        self.call(json!({"operation":"control","socket":path(socket),
            "evidence":Base64UrlUnpadded::encode_string(&evidence.to_private_bytes().expect("native evidence"))}))
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn exchange(
    input: &mut std::process::ChildStdin,
    replies: &Receiver<Vec<u8>>,
    request: Value,
) -> Value {
    let mut bytes = serde_json::to_vec(&request).expect("typed fixture request");
    assert!(bytes.len() < 8 * 1024 * 1024);
    bytes.push(b'\n');
    input.write_all(&bytes).expect("actor request");
    input.flush().expect("flush");
    let reply = replies
        .recv_timeout(Duration::from_secs(45))
        .expect("bounded actor reply");
    let value: Value = serde_json::from_slice(&reply).expect("actor result JSON");
    assert!(
        value.get("actor_error").is_none(),
        "installed actor refused {}",
        request["operation"]
    );
    value
}
