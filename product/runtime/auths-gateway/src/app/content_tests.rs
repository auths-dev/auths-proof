//! Application framing only: a counting refusal oracle is not installed authority.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counted(AtomicUsize);
impl GatewayApplication for Counted {
    async fn submit(&self, _: &[u8], _: &[u8], _: ExactEffectApproval) -> GatewaySubmitResult {
        panic!("wrong route")
    }
    async fn recover(
        &self,
        _: &str,
        _: &[u8],
        _: &[u8],
        _: ExactEffectApproval,
    ) -> AppRecoveryResult {
        panic!("wrong route")
    }
    async fn observe(&self, _: &GatewayObserveRequest) -> GatewayObserveResult {
        panic!("wrong route")
    }
    async fn acquire_content(&self, input: DecodedSubmission) -> AppContentResult {
        assert_eq!(&*input.proof, &[0]);
        assert_eq!(&*input.action, &[0]);
        self.0.fetch_add(1, Ordering::SeqCst);
        AppContentResult::refused("gateway.acquisition.binding")
    }
    async fn content_history(&self, operation: &str) -> AppContentResult {
        assert_eq!(operation, "fixture-1");
        self.0.fetch_add(1, Ordering::SeqCst);
        AppContentResult::refused("gateway.attempt.state-unavailable")
    }
    async fn acknowledge_disclosure(
        &self,
        operation: &str,
        _: crate::effect::DisclosureAcknowledgement,
    ) -> AppContentResult {
        assert_eq!(operation, "fixture-1");
        self.0.fetch_add(1, Ordering::SeqCst);
        AppContentResult::refused("gateway.disclosure.acknowledgement")
    }
    async fn disclose_content(
        &self,
        _: AppDisclosureTarget,
        _: DecodedSubmission,
        mut stream: UnixStream,
        clock: SessionClock,
    ) {
        self.0.fetch_add(1, Ordering::SeqCst);
        clock
            .write_frame(
                &mut stream,
                &serde_json::to_vec(&AppContentResult::refused("gateway.disclosure.binding"))
                    .expect("response"),
            )
            .await
            .expect("write");
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one closed-frame and native fact-decoding artifact"
)]
async fn native_application_content_frame_fixture_is_current() {
    use serde_json::{Value, json};
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let effect: Value = serde_json::from_slice(
        &std::fs::read(root.join("effect-binding.json")).expect("native fixture"),
    )
    .expect("JSON");
    let submission = json!({"schema": APP_REQUEST_SCHEMA, "proof_b64": "AA", "action_b64": "AA",
        "approval_b64": Base64UrlUnpadded::encode_string(effect["approval_canonical"].as_str().expect("approval").as_bytes())});
    let ack: Value = serde_json::from_slice(
        &std::fs::read(root.join("disclosure-acknowledgement.json")).expect("ACK fixture"),
    )
    .expect("JSON");
    let acknowledgement =
        serde_json_canonicalizer::to_vec(&ack["acknowledgement"]).expect("native canonical ACK");
    let channel = crate::effect::UnixDisclosurePolicy::new(100, 101, [19; 32]);
    let frames = [
        (
            "content",
            json!({"schema": APP_CONTENT_SCHEMA, "submission": submission}),
        ),
        (
            "disclose",
            json!({"schema": APP_DISCLOSURE_SCHEMA, "target": {"source_operation": "fixture-source", "recipient_key": vec![19;32], "channel": channel, "delivery_instance": vec![20;32]}, "submission": submission}),
        ),
        (
            "content-history",
            json!({"schema": APP_CONTENT_HISTORY_SCHEMA, "operation": "fixture-1"}),
        ),
        (
            "disclosure-ack",
            json!({"schema": APP_DISCLOSURE_ACK_SCHEMA, "operation": "fixture-1", "acknowledgement_b64": Base64UrlUnpadded::encode_string(&acknowledgement)}),
        ),
    ];
    let requests = frames
        .iter()
        .map(|(name, value)| (*name, value.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let app = Counted(AtomicUsize::new(0));
    let mut cases = Vec::new();
    for (name, valid) in frames {
        let mut mutations = vec![("valid", serde_json::to_vec(&valid).expect("frame"), true)];
        let mut obsolete = valid.clone();
        obsolete["schema"] = json!("auths.gateway-content/0");
        mutations.push((
            "obsolete",
            serde_json::to_vec(&obsolete).expect("frame"),
            false,
        ));
        let mut unknown = valid.clone();
        unknown["url"] = json!("https://attacker.invalid/private");
        mutations.push((
            "transport-override",
            serde_json::to_vec(&unknown).expect("frame"),
            false,
        ));
        let mut duplicate = serde_json::to_vec(&valid).expect("frame");
        duplicate.pop();
        duplicate.extend_from_slice(format!(",\"schema\":{}}}", valid["schema"]).as_bytes());
        mutations.push(("duplicate-schema", duplicate, false));
        if valid.get("submission").is_some() {
            let mut changed = valid.clone();
            changed["submission"]["approval_b64"] = json!("AA");
            mutations.push((
                "bad-approval",
                serde_json::to_vec(&changed).expect("frame"),
                false,
            ));
            let mut changed = valid.clone();
            changed["submission"]["action_b64"] =
                json!("A".repeat((64 * 1024 * 4_usize).div_ceil(3) + 1));
            mutations.push((
                "oversized-action",
                serde_json::to_vec(&changed).expect("frame"),
                false,
            ));
        }
        if name == "disclosure-ack" {
            let mut changed = valid.clone();
            changed["acknowledgement_b64"] = json!("A".repeat((4096 * 4_usize).div_ceil(3) + 1));
            mutations.push((
                "oversized-ack",
                serde_json::to_vec(&changed).expect("frame"),
                false,
            ));
        }
        if name == "disclose" {
            let mut changed = valid.clone();
            changed["target"]["channel"]["schema"] = json!("unknown");
            mutations.push((
                "unknown-channel",
                serde_json::to_vec(&changed).expect("frame"),
                false,
            ));
        }
        let seed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/target_gateway_app_frame")
            .join(name);
        let bytes = serde_json::to_vec(&valid).expect("seed");
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&seed, &bytes).expect("seed");
        }
        assert_eq!(std::fs::read(seed).expect("seed"), bytes);
        for (mutation, bytes, dispatch) in mutations {
            let before = app.0.load(Ordering::SeqCst);
            let (server, mut client) = UnixStream::pair().expect("pair");
            let client_work = async {
                write_frame(&mut client, &bytes).await.expect("write");
                let response = read_frame(&mut client).await.expect("response");
                let value: Value = serde_json::from_slice(&response).expect("JSON result");
                assert!(
                    !String::from_utf8(response)
                        .expect("UTF8")
                        .contains("attacker.invalid")
                );
                value
            };
            let ((), response) = tokio::join!(app_session(server, &app), client_work);
            assert_eq!(
                app.0.load(Ordering::SeqCst) - before,
                usize::from(dispatch),
                "{name}/{mutation}"
            );
            cases.push(json!({"route": name, "case": mutation, "dispatched": dispatch, "response": response}));
        }
    }
    let fixture = json!({"schema": "auths.gateway-application-content-fixture/1", "scope": "real socket framing with counting refusal oracle; no installed authority, provider I/O or content delivery", "requests": requests, "cases": cases});
    let bytes = serde_json::to_vec_pretty(&fixture).expect("fixture");
    let path = root.join("application-content-frame.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
