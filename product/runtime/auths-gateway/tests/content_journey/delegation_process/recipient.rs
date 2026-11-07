//! Fault-only recipient process using the shipping native disclosure client.
//! The installed A process passes its key to its own same-UID child, never to
//! the orchestrator. No alternate verifier or transport protocol lives here.
use super::*;

#[test]
fn recipient_without_ack_process() {
    let Some(directory) = std::env::var_os("AUTHS_DELEGATION_RECIPIENT_DIR") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let metadata = std::fs::symlink_metadata(&directory).expect("recipient directory");
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    let mut seed = Zeroizing::new([0_u8; 32]);
    let mut input = std::io::stdin().lock();
    input
        .read_exact(seed.as_mut())
        .expect("own private child seed pipe");
    assert_eq!(input.read(&mut [0]).expect("seed EOF"), 0);
    let key = SigningKey::from_bytes(&seed);
    let read = |name: &str| {
        let bytes = std::fs::read(directory.join(name)).expect("own private input");
        assert!(bytes.len() <= 8 * 1024 * 1024);
        bytes
    };
    let details: Value = serde_json::from_slice(&read("details")).expect("details");
    let request = auths_gateway::app::AppDisclosure {
        schema: auths_gateway::app::APP_DISCLOSURE_SCHEMA.into(),
        target: serde_json::from_slice(&read("target")).expect("native target"),
        submission: auths_gateway::app::AppSubmission {
            schema: auths_gateway::app::APP_REQUEST_SCHEMA.into(),
            proof_b64: Base64UrlUnpadded::encode_string(&read("proof")),
            action_b64: Base64UrlUnpadded::encode_string(&read("action")),
            approval_b64: Base64UrlUnpadded::encode_string(&read("approval")),
        },
    };
    let binding = auths_gateway::effect::EffectBinding::from_private_bytes(&read("binding"))
        .expect("native binding");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            let stream =
                tokio::net::UnixStream::connect(details["socket"].as_str().expect("socket"))
                    .await
                    .expect("gateway connection");
            let received = auths_gateway::app::receive_content_disclosure(
                stream,
                &request,
                &binding,
                details["bytes"].as_u64().expect("length"),
                &key,
            )
            .await
            .expect("native authenticated receipt");
            let auths_gateway::app::AppDisclosureReception::Received(received) = received else {
                panic!("expected one native disclosure");
            };
            private(&directory.join("content"), received.content());
            private(
                &directory.join("ack"),
                &received
                    .acknowledgement(&key)
                    .expect("native ACK")
                    .to_private_bytes()
                    .expect("canonical ACK"),
            );
            for name in ["content", "ack"] {
                std::fs::File::open(directory.join(name))
                    .expect("private receipt")
                    .sync_all()
                    .expect("durable receipt");
            }
            private(
                &directory.join("ready"),
                b"received-native-ack-retained-not-sent",
            );
            std::fs::File::open(&directory)
                .expect("private directory")
                .sync_all()
                .expect("directory sync");
            // The orchestrator crashes the gateway and asks A to kill this
            // child while it still holds the original native reception.
            tokio::time::sleep(Duration::from_secs(45)).await;
            drop(received);
            panic!("recipient fault checkpoint was not crashed");
        });
}
