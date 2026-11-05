//! Real local sockets over the native installed file fence. Same-process UID
//! checks do not establish independent-process isolation or `PostgreSQL` evidence.
use super::*;
use crate::disclosure_transport::{
    AuthenticatedDisclosureChannel, DisclosureConnection, ReceivedDisclosure, deliver,
};
use crate::effect::UnixDisclosurePolicy;
use tokio::net::UnixStream;

async fn authenticate(
    approved: &ApprovedEffect,
    bytes: u64,
    recipient: &SigningKey,
    policy: &UnixDisclosurePolicy,
) -> (
    AuthenticatedDisclosureChannel,
    tokio::task::JoinHandle<Result<ReceivedDisclosure, &'static str>>,
) {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let (mut server, client) = UnixStream::pair().expect("socket pair");
    let binding = approved.effect().binding().clone();
    let source = approved
        .disclosure_plan()
        .expect("plan")
        .source()
        .expect("source");
    let wire: Value =
        serde_json::from_slice(&binding.to_private_bytes().expect("binding")).expect("JSON");
    let request = crate::app::AppDisclosure {
        schema: crate::app::APP_DISCLOSURE_SCHEMA.to_owned(),
        target: crate::app::AppDisclosureTarget {
            source_operation: source.journal_identity().1.to_owned(),
            recipient_key: recipient.verifying_key().to_bytes(),
            channel: policy.clone(),
            delivery_instance: serde_json::from_value(
                wire["protocol"]["delivery_instance"].clone(),
            )
            .expect("instance"),
        },
        // Framing shim only: the native installed grant below uses the real
        // approved proof from the corpus. No installed app dispatch is claimed.
        submission: crate::app::AppSubmission {
            schema: crate::app::APP_REQUEST_SCHEMA.to_owned(),
            proof_b64: "AA".to_owned(),
            action_b64: "AA".to_owned(),
            approval_b64: Base64UrlUnpadded::encode_string(
                &approved.approval().to_private_bytes().expect("approval"),
            ),
        },
    };
    let client_key = recipient.clone();
    let receiver = tokio::spawn(async move {
        match crate::app::receive_content_disclosure(client, &request, &binding, bytes, &client_key)
            .await?
        {
            crate::app::AppDisclosureReception::Received(delivery) => Ok(*delivery),
            _ => Err("test.unexpected-history"),
        }
    });
    let frame = crate::app::read_frame(&mut server)
        .await
        .expect("client request");
    let request: crate::app::AppDisclosure =
        serde_json::from_slice(&frame).expect("typed envelope");
    request.decode().expect("bounded envelope");
    crate::app::write_frame(
        &mut server,
        &serde_json::to_vec(&crate::app::AppContentResult::Ready).expect("ready"),
    )
    .await
    .expect("ready frame");
    let channel = AuthenticatedDisclosureChannel::authenticate(
        DisclosureConnection::new(server, policy.clone()),
        approved.effect().binding(),
        bytes,
        recipient.verifying_key().to_bytes(),
    )
    .await
    .expect("fresh recipient authentication");
    (channel, receiver)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one actual socket/fenced-journal artifact using its native installed context"
)]
pub(super) async fn corpus(
    attempts: &crate::GatewayAttempts,
    store: &Arc<dyn crate::GatewayAttemptStore>,
    path: &std::path::Path,
    policy: &EffectPolicy,
    recipe: &CompiledRecipe,
    connection: &ConnectionRecord,
    bytes: u64,
    recipient: &SigningKey,
    channel_policy: &UnixDisclosurePolicy,
    approve: impl Fn(u8, &UnixDisclosurePolicy) -> Arc<ApprovedEffect>,
    validation: impl Fn(u64) -> crate::entry::EntryValidation,
) {
    let first = approve(2, channel_policy);
    let operation = LogicalOperationId::parse("release-2").expect("operation");
    let (channel, receiver) = authenticate(&first, bytes, recipient, channel_policy).await;
    let transcript = channel.evidence();
    // A signed historical transcript is immutable data, never a live socket.
    let transcript_bytes = crate::effect::disclosure_auth::bounded(&transcript).expect("canonical");
    let decoded: crate::effect::disclosure_auth::RecipientAuthentication =
        crate::effect::disclosure_auth::decode(&transcript_bytes).expect("decode");
    decoded
        .validate(
            first.effect().binding(),
            bytes,
            recipient.verifying_key().to_bytes(),
        )
        .expect("history");
    let original: Value = serde_json::from_slice(&transcript_bytes).expect("JSON");
    for pointer in [
        "/policy/channel_id/0",
        "/policy/gateway_uid",
        "/policy/recipient_uid",
        "/challenge/nonce/0",
    ] {
        let mut changed = original.clone();
        let field = changed.pointer_mut(pointer).expect("field");
        *field = json!(field.as_u64().expect("integer") ^ 1);
        let changed: crate::effect::disclosure_auth::RecipientAuthentication =
            serde_json::from_value(changed).expect("shape");
        assert!(
            changed
                .validate(
                    first.effect().binding(),
                    bytes,
                    recipient.verifying_key().to_bytes()
                )
                .is_err(),
            "{pointer}"
        );
    }
    let mut noncanonical = transcript_bytes.to_vec();
    noncanonical.push(b' ');
    assert!(
        crate::effect::disclosure_auth::decode::<
            crate::effect::disclosure_auth::RecipientAuthentication,
        >(&noncanonical)
        .is_err()
    );
    assert!(
        crate::effect::disclosure_auth::decode::<
            crate::effect::disclosure_auth::RecipientAuthentication,
        >(&vec![b' '; 4097])
        .is_err()
    );
    let (_, permit) = attempts
        .grant_disclosure(Arc::clone(&first), validation(NOW), NOW, channel)
        .await
        .expect("grant");
    let receive_and_ack = async {
        let delivery = receiver.await.expect("receiver task").expect("delivery");
        assert_eq!(delivery.content(), b"PRIVATE-SYNTHETIC-CONTENT");
        assert_eq!(delivery.content().len() as u64, bytes);
        assert!(
            delivery
                .acknowledgement(&SigningKey::from_bytes(&[52; 32]))
                .is_err()
        );
        delivery.acknowledge(recipient).await.expect("ACK send");
    };
    let (ack, ()) = tokio::join!(deliver(permit), receive_and_ack);
    let ack = ack.expect("received ACK");
    let acknowledged = attempts
        .acknowledge_disclosure(recipe.namespace(), &operation, &ack)
        .await
        .expect("record ACK");
    assert_eq!(acknowledged.stage, crate::DisclosureStage::Acknowledged);
    assert_eq!(acknowledged.revision, 3);

    let first_key = crate::GatewayAttemptKey::for_operation(policy, recipe.namespace(), &operation)
        .expect("operation key");
    let first_bytes = store
        .load(crate::GatewayRecordKind::Attempt, &first_key)
        .expect("load")
        .expect("grant record");
    let original_record: Value = serde_json::from_slice(&first_bytes).expect("JSON");
    for field in ["authentication", "signature"] {
        let mut changed = original_record.clone();
        if field == "authentication" {
            changed["state"]["facts"]["authentication"] = Value::Null;
        } else {
            changed["state"]["facts"]["authentication"]["response"]["signature"] = json!("invalid");
        }
        let changed = serde_json::to_vec(&changed).expect("changed record");
        store
            .replace(
                crate::GatewayRecordKind::Attempt,
                &first_key,
                &first_bytes,
                &changed,
            )
            .expect("mutate retained authentication");
        assert!(attempts.read_disclosure(&first).await.is_err());
        store
            .replace(
                crate::GatewayRecordKind::Attempt,
                &first_key,
                &changed,
                &first_bytes,
            )
            .expect("restore record");
    }

    assert_eq!(
        attempts
            .content_history(recipe.namespace(), &operation, *recipe.digest())
            .await
            .expect("historical disclosure"),
        crate::ContentHistory::Disclosure(acknowledged.clone())
    );
    assert!(
        attempts
            .content_history(recipe.namespace(), &operation, [0; 32])
            .await
            .is_err()
    );

    // Actual receipt followed by loss of the ACK channel retains full charges.
    let second = approve(3, channel_policy);
    let second_operation = LogicalOperationId::parse("release-3").expect("operation");
    let (channel, receiver) = authenticate(&second, bytes, recipient, channel_policy).await;
    let (grant, permit) = attempts
        .grant_disclosure(Arc::clone(&second), validation(NOW), NOW, channel)
        .await
        .expect("grant");
    let lose_ack = async {
        let delivery = receiver.await.expect("receiver task").expect("delivery");
        assert_eq!(delivery.content(), b"PRIVATE-SYNTHETIC-CONTENT");
        delivery
            .acknowledgement(recipient)
            .expect("retain late ACK")
        // Owned client socket drops without sending its ACK.
    };
    let (lost, late_ack) = tokio::join!(deliver(permit), lose_ack);
    assert!(lost.is_none());
    let unknown = grant.record_unknown().await.expect("unknown");
    assert_eq!(unknown.stage, crate::DisclosureStage::Unknown);
    assert_eq!(unknown.reserved_bytes, bytes);
    let reopened = crate::GatewayAttempts::new(
        Arc::new(crate::FileGatewayAttemptStore::open(path).expect("reopen")),
        policy.clone(),
    )
    .expect("attempts");
    assert_eq!(
        reopened.read_disclosure(&second).await.expect("read"),
        Some(unknown.clone())
    );
    let (channel, receiver) = authenticate(&second, bytes, recipient, channel_policy).await;
    assert!(
        reopened
            .grant_disclosure(Arc::clone(&second), validation(NOW), NOW, channel)
            .await
            .is_err(),
        "fresh authentication cannot remint a permit"
    );
    assert!(
        receiver.await.expect("receiver task").is_err(),
        "replay receives no content frame"
    );
    assert_eq!(
        reopened.read_disclosure(&second).await.expect("read"),
        Some(unknown.clone())
    );
    let late = reopened
        .acknowledge_disclosure(recipe.namespace(), &second_operation, &late_ack)
        .await
        .expect("late ACK");
    assert_eq!(late.stage, crate::DisclosureStage::Acknowledged);
    assert_eq!(late.reserved_bytes, unknown.reserved_bytes);
    assert_eq!(late.revision, 4);

    // Revocation linearizes after successful peer authentication, before entry.
    let revoked = approve(4, channel_policy);
    let before = attempts.read_disclosure(&revoked).await.expect("before");
    let (channel, receiver) = authenticate(&revoked, bytes, recipient, channel_policy).await;
    let connection_key = crate::connection_key(connection.provider_kind(), connection.alias());
    let original_connection = connection.to_canonical_cbor().expect("connection");
    let disabled = connection
        .transition_state(ConnectionState::Disabled, NOW)
        .expect("disable")
        .to_canonical_cbor()
        .expect("connection bytes");
    store
        .replace(
            crate::GatewayRecordKind::Connection,
            &connection_key,
            &original_connection,
            &disabled,
        )
        .expect("disable after authentication");
    assert!(
        attempts
            .grant_disclosure(Arc::clone(&revoked), validation(NOW), NOW, channel)
            .await
            .is_err()
    );
    assert!(
        receiver.await.expect("receiver task").is_err(),
        "revoked recipient receives no content frame"
    );
    assert_eq!(
        attempts.read_disclosure(&revoked).await.expect("read"),
        before
    );
    store
        .replace(
            crate::GatewayRecordKind::Connection,
            &connection_key,
            &disabled,
            &original_connection,
        )
        .expect("restore connection");

    // An acknowledged grant lost before send is unknown and cannot be reminted.
    let dropped = approve(5, channel_policy);
    let (channel, receiver) = authenticate(&dropped, bytes, recipient, channel_policy).await;
    let (_, permit) = attempts
        .grant_disclosure(Arc::clone(&dropped), validation(NOW), NOW, channel)
        .await
        .expect("grant");
    drop(permit);
    assert!(receiver.await.expect("receiver task").is_err());
    let dropped_snapshot = reopened
        .read_disclosure(&dropped)
        .await
        .expect("read")
        .expect("record");
    assert_eq!(dropped_snapshot.stage, crate::DisclosureStage::Unknown);
    assert_eq!(dropped_snapshot.reserved_bytes, bytes);
    let (channel, receiver) = authenticate(&dropped, bytes, recipient, channel_policy).await;
    assert!(
        reopened
            .grant_disclosure(Arc::clone(&dropped), validation(NOW), NOW, channel)
            .await
            .is_err()
    );
    assert!(receiver.await.expect("receiver task").is_err());

    // Competing live authenticated sockets do not turn one reservation into two
    // permits. The failed channel closes before any content frame.
    let raced = approve(6, channel_policy);
    let (left, left_receiver) = authenticate(&raced, bytes, recipient, channel_policy).await;
    let (right, right_receiver) = authenticate(&raced, bytes, recipient, channel_policy).await;
    let (left, right) = tokio::join!(
        attempts.grant_disclosure(Arc::clone(&raced), validation(NOW), NOW, left),
        reopened.grant_disclosure(Arc::clone(&raced), validation(NOW), NOW, right),
    );
    let ((_, permit), winner, loser) = match (left, right) {
        (Ok(granted), Err(_)) => (granted, left_receiver, right_receiver),
        (Err(_), Ok(granted)) => (granted, right_receiver, left_receiver),
        _ => panic!("exactly one live grant"),
    };
    assert!(loser.await.expect("losing receiver").is_err());
    let receive = async {
        let delivery = winner.await.expect("winner").expect("one delivery");
        assert_eq!(delivery.content(), b"PRIVATE-SYNTHETIC-CONTENT");
        delivery.acknowledge(recipient).await.expect("ACK");
    };
    let (ack, ()) = tokio::join!(deliver(permit), receive);
    let raced_snapshot = attempts
        .acknowledge_disclosure(
            recipe.namespace(),
            &LogicalOperationId::parse("release-6").expect("operation"),
            &ack.expect("ACK"),
        )
        .await
        .expect("record");
    assert_eq!(raced_snapshot.reserved_deliveries, 1);
    assert_eq!(raced_snapshot.revision, 3);

    let expired = approve(7, channel_policy);
    let before_expiry = attempts.read_disclosure(&expired).await.expect("read");
    let (channel, receiver) = authenticate(&expired, bytes, recipient, channel_policy).await;
    assert!(
        attempts
            .grant_disclosure(Arc::clone(&expired), validation(NOW + 61), NOW, channel)
            .await
            .is_err()
    );
    assert!(receiver.await.expect("receiver").is_err());
    assert_eq!(
        attempts.read_disclosure(&expired).await.expect("read"),
        before_expiry
    );

    let changed = approve(8, channel_policy);
    let before_change = attempts.read_disclosure(&changed).await.expect("read");
    let (channel, receiver) = authenticate(&changed, bytes, recipient, channel_policy).await;
    let config_key = crate::GatewayAttemptKey::from_bytes(
        policy
            .configuration_key(recipe.namespace())
            .expect("configuration key"),
    );
    let config_bytes = store
        .load(crate::GatewayRecordKind::EffectConfiguration, &config_key)
        .expect("load configuration")
        .expect("configuration");
    let mut config: Value = serde_json::from_slice(&config_bytes).expect("configuration JSON");
    config["installation"][0] = json!(13);
    let changed_bytes = serde_json_canonicalizer::to_vec(&config).expect("changed configuration");
    store
        .replace(
            crate::GatewayRecordKind::EffectConfiguration,
            &config_key,
            &config_bytes,
            &changed_bytes,
        )
        .expect("change configuration after authentication");
    assert!(
        attempts
            .grant_disclosure(Arc::clone(&changed), validation(NOW), NOW, channel)
            .await
            .is_err()
    );
    assert!(receiver.await.expect("receiver").is_err());
    assert_eq!(
        attempts.read_disclosure(&changed).await.expect("read"),
        before_change
    );
    store
        .replace(
            crate::GatewayRecordKind::EffectConfiguration,
            &config_key,
            &changed_bytes,
            &config_bytes,
        )
        .expect("restore configuration");

    let changed_source = approve(9, channel_policy);
    let before_source = attempts
        .read_disclosure(&changed_source)
        .await
        .expect("read");
    let (channel, receiver) = authenticate(&changed_source, bytes, recipient, channel_policy).await;
    let source = changed_source
        .disclosure_plan()
        .expect("plan")
        .source()
        .expect("source");
    let source_operation =
        LogicalOperationId::parse(source.journal_identity().1).expect("source operation");
    let source_key =
        crate::GatewayAttemptKey::for_operation(policy, recipe.namespace(), &source_operation)
            .expect("source key");
    let source_bytes = store
        .load(crate::GatewayRecordKind::Attempt, &source_key)
        .expect("load source")
        .expect("source");
    let mut changed: Value = serde_json::from_slice(&source_bytes).expect("source JSON");
    changed["state"]["facts"]["phase"]["content"]["value"]["bytes"] = json!(bytes + 1);
    let corrupt = serde_json::to_vec(&changed).expect("mutated source");
    store
        .replace(
            crate::GatewayRecordKind::Attempt,
            &source_key,
            &source_bytes,
            &corrupt,
        )
        .expect("change source after authentication");
    assert!(
        attempts
            .grant_disclosure(Arc::clone(&changed_source), validation(NOW), NOW, channel)
            .await
            .is_err()
    );
    assert!(receiver.await.expect("receiver").is_err());
    assert_eq!(
        attempts
            .read_disclosure(&changed_source)
            .await
            .expect("read"),
        before_source
    );
    store
        .replace(
            crate::GatewayRecordKind::Attempt,
            &source_key,
            &corrupt,
            &source_bytes,
        )
        .expect("restore source");

    // The wrong OS identity cannot even complete the handshake.
    let (server, _client) = UnixStream::pair().expect("sockets");
    let wrong_uid = rustix::process::geteuid().as_raw() ^ 1;
    let wrong_policy = UnixDisclosurePolicy::new(wrong_uid, wrong_uid, [22; 32]);
    let wrong_effect = approve(6, &wrong_policy);
    assert!(matches!(
        AuthenticatedDisclosureChannel::authenticate(
            DisclosureConnection::new(server, wrong_policy),
            wrong_effect.effect().binding(),
            bytes,
            recipient.verifying_key().to_bytes()
        )
        .await,
        Err("gateway.disclosure.peer")
    ));
    authentication_failures(&first, bytes, recipient, channel_policy).await;

    let fixture = json!({"schema": "auths.gateway-disclosure-delivery-fixture/1",
        "scope": "native application client with a control-frame shim, real Unix socket pairs and installed native file fence; no installed app dispatcher, independent processes, hostile UID isolation or PostgreSQL claim",
        "native_application_client_protocol_switch": true, "authenticated_delivery": acknowledged, "lost_ack": unknown, "late_ack": late,
        "competing_live_channels": raced_snapshot, "approval_expired_after_authentication_refused": true,
        "configuration_changed_after_authentication_refused": true,
        "corrupt_source_after_authentication_refused": true, "retained_authentication_corruption_refused": true,
        "dropped_permit": dropped_snapshot, "reopened_grant_cannot_redeliver": true,
        "disable_after_authentication_refuses_entry": true, "wrong_recipient_signing_key_refused": true,
        "changed_authentication_fields_refused": true, "wrong_os_uid_refused": true,
        "fresh_challenge_substitution_refused": true, "wrong_key_response_refused": true,
        "duplicate_unknown_noncanonical_oversized_frames_refused": true, "noncanonical_and_oversized_authentication_refused": true,
        "historical_authentication_grants_no_socket": true});
    let output = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/disclosure-delivery.json");
    let bytes = serde_json::to_vec_pretty(&fixture).expect("fixture bytes");
    assert!(
        !std::str::from_utf8(&bytes)
            .expect("UTF8")
            .contains("PRIVATE-SYNTHETIC-CONTENT")
    );
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &bytes).expect("write");
    }
    assert_eq!(std::fs::read(output).expect("fixture"), bytes);
}

/// Each client answers the gateway's real fresh challenge with one specific
/// violation. None reaches the final grant or receives a content frame.
async fn authentication_failures(
    approved: &ApprovedEffect,
    bytes: u64,
    recipient: &SigningKey,
    policy: &UnixDisclosurePolicy,
) {
    use crate::effect::disclosure_auth::{Challenge, Response, bounded, decode};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    for mode in 0..6 {
        let (server, mut client) = UnixStream::pair().expect("sockets");
        let key = recipient.clone();
        let peer = tokio::spawn(async move {
            let length = client.read_u32().await.expect("challenge length") as usize;
            assert!(length <= 4096);
            let mut incoming = vec![0; length];
            client.read_exact(&mut incoming).await.expect("challenge");
            let mut challenge: Challenge = decode(&incoming).expect("canonical challenge");
            if mode == 0 {
                challenge.nonce[0] ^= 1;
            }
            let key = if mode == 1 {
                SigningKey::from_bytes(&[52; 32])
            } else {
                key
            };
            let response = Response::sign(&challenge, &key).expect("response");
            let mut response = bounded(&response).expect("bytes").to_vec();
            match mode {
                2 => response.push(b' '),
                3 => {
                    response.insert(1, b' ');
                    let mut unknown: Value = serde_json::from_slice(&response).expect("JSON");
                    unknown["unexpected"] = json!(true);
                    response = serde_json::to_vec(&unknown).expect("unknown field");
                }
                4 => {
                    response.splice(
                        1..1,
                        b"\"schema\":\"auths.gateway-disclosure-auth/1\","
                            .iter()
                            .copied(),
                    );
                }
                _ => {}
            }
            if mode == 5 {
                client.write_u32(4097).await.expect("oversized header");
            } else {
                client
                    .write_u32(u32::try_from(response.len()).expect("bounded frame"))
                    .await
                    .expect("length");
                client.write_all(&response).await.expect("response");
            }
            // A failed handshake closes without any content frame.
            assert!(client.read_u32().await.is_err());
        });
        let result = AuthenticatedDisclosureChannel::authenticate(
            DisclosureConnection::new(server, policy.clone()),
            approved.effect().binding(),
            bytes,
            recipient.verifying_key().to_bytes(),
        )
        .await;
        assert!(
            matches!(
                result,
                Err("gateway.disclosure.authentication" | "gateway.disclosure.frame")
            ),
            "mode {mode}"
        );
        peer.await.expect("peer task");
    }
}
