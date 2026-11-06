//! Scoped native grants over actual authenticated Unix sockets. Same-process
//! UIDs and injected source responses are explicit; this is no isolation claim.
use super::admission_tests::{FaultStore, Setup};
use super::information_tests::{
    acquire, allocation_rows, channel, content_effect, content_recipe_fixture, disclosure_effect,
    private, record,
};
use super::*;
use crate::disclosure_transport::{
    AuthenticatedDisclosureChannel, DisclosureConnection, ReceivedDisclosure, deliver,
};
use crate::effect::{ApprovedEffect, DisclosureAcknowledgement, UnixDisclosurePolicy};
use crate::store_testkit::{Backend, postgres_configured};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    task::JoinHandle,
};
use zeroize::Zeroizing;

const CONTENT: &[u8] = b"PRIVATE-NATIVE-INFORMATION";
const OPERATION: &str = "native-live-disclosure";

fn recipient() -> SigningKey {
    SigningKey::from_bytes(&[0x55; 32])
}
fn local_policy() -> UnixDisclosurePolicy {
    let uid = rustix::process::geteuid().as_raw();
    UnixDisclosurePolicy::new(uid, uid, [0x78; 32])
}

async fn setup(backend: Backend, policy: &UnixDisclosurePolicy) -> (Setup, Arc<ApprovedEffect>) {
    let setup = Setup::with_channel(
        backend,
        content_recipe_fixture(),
        [1; 32],
        policy.commitment().unwrap(),
    )
    .await;
    let read = Arc::new(approve(
        content_effect(&setup, "native-live-source", 0x44, RECORD).unwrap(),
    ));
    let retained = acquire(&setup, &read, CONTENT).await;
    let release = Arc::new(approve(
        disclosure_effect(&setup, retained, OPERATION, 0x55, channel(&setup)).unwrap(),
    ));
    (setup, release)
}

#[derive(Clone, Debug, serde::Serialize)]
struct Wire {
    challenge_complete: bool,
    following_wire_bytes: usize,
    content_frames: usize,
    content_bytes: usize,
}

/// Opaque forwarding captures every gateway byte, including partial prefixes.
/// Authentication and content interpretation remain in the maintained protocol.
async fn proxy(gateway: UnixStream, recipient: UnixStream) -> Wire {
    let (mut from_gateway, mut to_gateway) = gateway.into_split();
    let (mut from_recipient, mut to_recipient) = recipient.into_split();
    let outbound = async {
        let mut captured = Zeroizing::new(Vec::new());
        let mut buffer = [0; 1024];
        loop {
            let count = from_gateway.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            assert!(captured.len() + count <= 4096 + 65536 + 8);
            captured.extend_from_slice(&buffer[..count]);
            // A hostile recipient may close during a refused handshake.
            if to_recipient.write_all(&buffer[..count]).await.is_err() {
                break;
            }
        }
        let _ = to_recipient.shutdown().await;
        if captured.is_empty() {
            return Wire {
                challenge_complete: false,
                following_wire_bytes: 0,
                content_frames: 0,
                content_bytes: 0,
            };
        }
        let length = u32::from_be_bytes(captured[..4].try_into().unwrap()) as usize;
        assert!(length <= 4096 && captured.len() >= 4 + length);
        let following = &captured[4 + length..];
        if following.is_empty() {
            return Wire {
                challenge_complete: true,
                following_wire_bytes: 0,
                content_frames: 0,
                content_bytes: 0,
            };
        }
        assert!(following.len() >= 4);
        let bytes = u32::from_be_bytes(following[..4].try_into().unwrap()) as usize;
        assert_eq!(
            following.len(),
            4 + bytes,
            "exactly one complete content frame"
        );
        assert_eq!(&following[4..], CONTENT);
        Wire {
            challenge_complete: true,
            following_wire_bytes: following.len(),
            content_frames: 1,
            content_bytes: bytes,
        }
    };
    let inbound = async {
        let _ = tokio::io::copy(&mut from_recipient, &mut to_gateway).await;
        let _ = to_gateway.shutdown().await;
    };
    let (wire, ()) = tokio::join!(outbound, inbound);
    wire
}

struct Live {
    channel: AuthenticatedDisclosureChannel,
    receiver: JoinHandle<Result<ReceivedDisclosure, &'static str>>,
    wire: JoinHandle<Wire>,
}

async fn authenticate(approved: &ApprovedEffect, policy: &UnixDisclosurePolicy) -> Live {
    let (server, gateway_proxy) = UnixStream::pair().unwrap();
    let (recipient_proxy, client) = UnixStream::pair().unwrap();
    let wire = tokio::spawn(proxy(gateway_proxy, recipient_proxy));
    let binding = approved.effect().binding().clone();
    let receive_policy = policy.clone();
    let receiver = tokio::spawn(async move {
        crate::disclosure_transport::receive_disclosure(
            DisclosureConnection::new(client, receive_policy),
            &binding,
            CONTENT.len() as u64,
            &recipient(),
        )
        .await
    });
    let channel = AuthenticatedDisclosureChannel::authenticate(
        DisclosureConnection::new(server, policy.clone()),
        approved.effect().binding(),
        CONTENT.len() as u64,
        recipient().verifying_key().to_bytes(),
    )
    .await
    .unwrap();
    Live {
        channel,
        receiver,
        wire,
    }
}

async fn received_and_ack(task: JoinHandle<Result<ReceivedDisclosure, &'static str>>) -> usize {
    let received = task.await.unwrap().unwrap();
    assert_eq!(received.content(), CONTENT);
    let count = received.content().len();
    received.acknowledge(&recipient()).await.unwrap();
    count
}

async fn reserve(setup: &Setup, approved: &Arc<ApprovedEffect>) -> crate::DisclosureSnapshot {
    setup
        .attempts(Arc::clone(&setup.store))
        .claim_disclosure(approved, NOW, setup.validation())
        .await
        .unwrap()
}

async fn allocations(setup: &Setup, approved: &ApprovedEffect) -> Vec<Option<Value>> {
    let rows = allocation_rows(setup, approved, 0).await;
    assert_eq!(
        rows.len(),
        6,
        "distinct sender/recipient ancestors, shared root once"
    );
    assert!(rows.iter().all(Option::is_some));
    rows
}

async fn facts(
    setup: &Setup,
    approved: &ApprovedEffect,
    snapshot: crate::DisclosureSnapshot,
    wires: Vec<Wire>,
) -> Value {
    let stored = record(setup, OPERATION).await.unwrap();
    let refs = stored["engagement_allocations"].as_array().unwrap();
    assert_eq!(refs.len(), 6);
    assert_eq!(
        refs.iter()
            .filter(|r| r["reservation"]["unit"] == "disclosure-count")
            .count(),
        3
    );
    assert_eq!(
        refs.iter()
            .filter(|r| r["reservation"]["unit"] == "disclosure-bytes")
            .count(),
        3
    );
    assert_eq!(snapshot.reserved_deliveries, 1);
    assert_eq!(snapshot.reserved_bytes, CONTENT.len() as u64);
    let public = serde_json::to_string(&snapshot).unwrap();
    assert!(!public.contains("PRIVATE-NATIVE-INFORMATION"));
    assert!(!public.contains(setup.native.root.principal.as_str()));
    allocations(setup, approved).await;
    let phase = stored["state"]["facts"]["phase"]["stage"].as_str().unwrap();
    match snapshot.stage {
        crate::DisclosureStage::Reserved => assert_eq!(phase, "reserved"),
        crate::DisclosureStage::Unknown => assert!(["entry-granted", "unknown"].contains(&phase)),
        crate::DisclosureStage::Acknowledged => assert_eq!(phase, "acknowledged"),
        crate::DisclosureStage::NotEntered => assert_eq!(phase, "not-entered"),
    }
    json!({"schema":"auths.engagement-live-private-projection/1","snapshot":snapshot,
        "private_phase":phase,
        "durable_grants":usize::from(!stored["entry"].is_null()),"ancestor_allocations":refs.len(),
        "wire":wires,"uid_and_private_identities_omitted":true})
}

async fn acknowledged(backend: Backend) -> Value {
    let policy = local_policy();
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    let attempts = setup.attempts(Arc::clone(&setup.store));
    reserve(&setup, &approved).await;
    let rows = allocations(&setup, &approved).await;
    let Live {
        channel,
        receiver,
        wire,
    } = authenticate(&approved, &policy).await;
    let (grant, permit) = attempts
        .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
        .await
        .unwrap();
    let (ack, count) = tokio::join!(deliver(permit), received_and_ack(receiver));
    assert_eq!(count, CONTENT.len());
    drop(grant);
    let snapshot = attempts
        .acknowledge_disclosure(
            setup.recipe.namespace(),
            &crate::LogicalOperationId::parse(OPERATION).unwrap(),
            &ack.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(snapshot.stage, crate::DisclosureStage::Acknowledged);
    assert_eq!(snapshot.revision, 3);
    assert_eq!(allocations(&setup, &approved).await, rows);
    facts(&setup, &approved, snapshot, vec![wire.await.unwrap()]).await
}

async fn lost_ack(backend: Backend) -> Value {
    let policy = local_policy();
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    let attempts = setup.attempts(Arc::clone(&setup.store));
    reserve(&setup, &approved).await;
    let rows = allocations(&setup, &approved).await;
    let Live {
        channel,
        receiver,
        wire,
    } = authenticate(&approved, &policy).await;
    let (grant, permit) = attempts
        .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
        .await
        .unwrap();
    let retain_ack = async {
        let received = receiver.await.unwrap().unwrap();
        assert_eq!(received.content(), CONTENT);
        received.acknowledgement(&recipient()).unwrap()
        // Dropping the recipient closes the channel without sending the ACK.
    };
    let (reply, late) = tokio::join!(deliver(permit), retain_ack);
    assert!(reply.is_none());
    let unknown = grant.record_unknown().await.unwrap();
    assert_eq!(unknown.stage, crate::DisclosureStage::Unknown);
    let first_wire = wire.await.unwrap();
    assert_eq!(first_wire.content_bytes, CONTENT.len());
    let reopened = setup.attempts(setup.backend.raw());
    assert_eq!(
        reopened.read_disclosure(&approved).await.unwrap(),
        Some(unknown.clone())
    );
    let Live {
        channel,
        receiver,
        wire,
    } = authenticate(&approved, &policy).await;
    assert!(
        reopened
            .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
            .await
            .is_err()
    );
    assert!(receiver.await.unwrap().is_err());
    let replay_wire = wire.await.unwrap();
    assert_eq!(replay_wire.following_wire_bytes, 0);
    let before = record(&setup, OPERATION).await.unwrap();
    let mut invalid: Value = serde_json::from_slice(&late.to_private_bytes().unwrap()).unwrap();
    invalid["signature_b64"] = json!(base64ct::Base64UrlUnpadded::encode_string(&[0; 64]));
    let invalid = DisclosureAcknowledgement::from_private_bytes(
        &serde_json_canonicalizer::to_vec(&invalid).unwrap(),
    )
    .unwrap();
    assert!(
        reopened
            .acknowledge_disclosure(
                setup.recipe.namespace(),
                &crate::LogicalOperationId::parse(OPERATION).unwrap(),
                &invalid
            )
            .await
            .is_err()
    );
    assert_eq!(record(&setup, OPERATION).await.unwrap(), before);
    let final_snapshot = reopened
        .acknowledge_disclosure(
            setup.recipe.namespace(),
            &crate::LogicalOperationId::parse(OPERATION).unwrap(),
            &late,
        )
        .await
        .unwrap();
    assert_eq!(final_snapshot.stage, crate::DisclosureStage::Acknowledged);
    assert_eq!(final_snapshot.revision, 4);
    let acknowledged = record(&setup, OPERATION).await.unwrap();
    assert_eq!(
        reopened
            .acknowledge_disclosure(
                setup.recipe.namespace(),
                &crate::LogicalOperationId::parse(OPERATION).unwrap(),
                &late
            )
            .await
            .unwrap(),
        final_snapshot
    );
    assert_eq!(record(&setup, OPERATION).await.unwrap(), acknowledged);
    assert_eq!(allocations(&setup, &approved).await, rows);
    let mut result = facts(
        &setup,
        &approved,
        final_snapshot,
        vec![first_wire, replay_wire],
    )
    .await;
    result["before_late_ack"] = serde_json::to_value(unknown).unwrap();
    result
}

async fn dropped_grant(backend: Backend, lose_reply: bool) -> Value {
    let policy = local_policy();
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    reserve(&setup, &approved).await;
    let rows = allocations(&setup, &approved).await;
    let fault = Arc::new(FaultStore::new(setup.backend.raw()));
    if lose_reply {
        fault.lose_next_grant_reply();
    }
    let attempts = setup.attempts(fault);
    let Live {
        channel,
        receiver,
        wire,
    } = authenticate(&approved, &policy).await;
    let result = attempts
        .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
        .await;
    if lose_reply {
        assert!(result.is_err());
    } else {
        drop(result.unwrap());
    }
    assert!(receiver.await.unwrap().is_err());
    let lost_wire = wire.await.unwrap();
    assert_eq!(lost_wire.following_wire_bytes, 0);
    let reopened = setup.attempts(setup.backend.raw());
    let snapshot = reopened.read_disclosure(&approved).await.unwrap().unwrap();
    assert_eq!(snapshot.stage, crate::DisclosureStage::Unknown);
    let retained = record(&setup, OPERATION).await.unwrap();
    assert_eq!(
        retained["state"]["facts"]["phase"]["stage"],
        "entry-granted"
    );
    let Live {
        channel,
        receiver,
        wire,
    } = authenticate(&approved, &policy).await;
    assert!(
        reopened
            .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
            .await
            .is_err()
    );
    assert!(receiver.await.unwrap().is_err());
    let replay_wire = wire.await.unwrap();
    assert_eq!(replay_wire.following_wire_bytes, 0);
    assert_eq!(record(&setup, OPERATION).await.unwrap(), retained);
    assert_eq!(allocations(&setup, &approved).await, rows);
    facts(&setup, &approved, snapshot, vec![lost_wire, replay_wire]).await
}

fn withdraw(setup: &Setup, approved: &ApprovedEffect, recipient: bool) {
    let binding = private(approved.effect().binding());
    let path = if recipient {
        &binding["scope"]["bound"]["recipient"]["ancestors"]
    } else {
        &binding["scope"]["bound"]["ancestors"]
    };
    let target = serde_json::from_value(path[1]["enrollment"].clone()).unwrap();
    tokio::task::block_in_place(|| setup.native.withdraw_participant(&setup.controller, target));
}

async fn withdrawal(backend: Backend, after_grant: bool, recipient: bool) -> Value {
    let policy = local_policy();
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    let attempts = setup.attempts(Arc::clone(&setup.store));
    let reserved = reserve(&setup, &approved).await;
    let before = record(&setup, OPERATION).await.unwrap();
    let rows = allocations(&setup, &approved).await;
    let Live {
        channel,
        receiver,
        wire,
    } = authenticate(&approved, &policy).await;
    if after_grant {
        let (grant, permit) = attempts
            .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
            .await
            .unwrap();
        withdraw(&setup, &approved, recipient);
        let (ack, count) = tokio::join!(deliver(permit), received_and_ack(receiver));
        assert_eq!(count, CONTENT.len());
        drop(grant);
        let snapshot = attempts
            .acknowledge_disclosure(
                setup.recipe.namespace(),
                &crate::LogicalOperationId::parse(OPERATION).unwrap(),
                &ack.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(snapshot.stage, crate::DisclosureStage::Acknowledged);
        assert_eq!(allocations(&setup, &approved).await, rows);
        facts(&setup, &approved, snapshot, vec![wire.await.unwrap()]).await
    } else {
        withdraw(&setup, &approved, recipient);
        assert!(
            attempts
                .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
                .await
                .is_err()
        );
        assert!(receiver.await.unwrap().is_err());
        let wire = wire.await.unwrap();
        assert_eq!(wire.following_wire_bytes, 0);
        assert_eq!(record(&setup, OPERATION).await.unwrap(), before);
        assert_eq!(allocations(&setup, &approved).await, rows);
        facts(&setup, &approved, reserved, vec![wire]).await
    }
}

async fn concurrent_grants(backend: Backend) -> Value {
    let policy = local_policy();
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    reserve(&setup, &approved).await;
    let rows = allocations(&setup, &approved).await;
    let left = setup.attempts(Arc::clone(&setup.store));
    let right = setup.attempts(setup.backend.raw());
    let first = authenticate(&approved, &policy).await;
    let second = authenticate(&approved, &policy).await;
    let (one, two) = tokio::join!(
        left.grant_disclosure(
            Arc::clone(&approved),
            setup.validation(),
            NOW,
            first.channel
        ),
        right.grant_disclosure(
            Arc::clone(&approved),
            setup.validation(),
            NOW,
            second.channel
        )
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    let (grant, permit) = one.or(two).unwrap();
    let receive = async {
        let (first, second) = tokio::join!(first.receiver, second.receiver);
        let mut bytes = 0;
        for received in [first.unwrap(), second.unwrap()].into_iter().flatten() {
            assert_eq!(received.content(), CONTENT);
            bytes += received.content().len();
            received.acknowledge(&recipient()).await.unwrap();
        }
        bytes
    };
    let (ack, bytes) = tokio::join!(deliver(permit), receive);
    assert_eq!(bytes, CONTENT.len());
    drop(grant);
    let snapshot = left
        .acknowledge_disclosure(
            setup.recipe.namespace(),
            &crate::LogicalOperationId::parse(OPERATION).unwrap(),
            &ack.unwrap(),
        )
        .await
        .unwrap();
    let one = first.wire.await.unwrap();
    let two = second.wire.await.unwrap();
    assert_eq!(one.content_frames + two.content_frames, 1);
    assert_eq!(allocations(&setup, &approved).await, rows);
    // Winner order is deliberately absent from the portable projection.
    let mut wires = vec![one, two];
    wires.sort_by_key(|w| w.content_frames);
    facts(&setup, &approved, snapshot, wires).await
}

async fn wrong_key(backend: Backend) -> Value {
    use crate::effect::disclosure_auth::{Challenge, Response, bounded, decode};
    let policy = local_policy();
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    let reserved = reserve(&setup, &approved).await;
    let before = record(&setup, OPERATION).await.unwrap();
    let (server, gateway_proxy) = UnixStream::pair().unwrap();
    let (recipient_proxy, mut client) = UnixStream::pair().unwrap();
    let wire = tokio::spawn(proxy(gateway_proxy, recipient_proxy));
    let impostor = tokio::spawn(async move {
        let length = client.read_u32().await.unwrap() as usize;
        assert!(length <= 4096);
        let mut bytes = vec![0; length];
        client.read_exact(&mut bytes).await.unwrap();
        let challenge: Challenge = decode(&bytes).unwrap();
        let response = Response::sign(&challenge, &SigningKey::from_bytes(&[0x66; 32])).unwrap();
        let response = bounded(&response).unwrap();
        client
            .write_u32(u32::try_from(response.len()).unwrap())
            .await
            .unwrap();
        client.write_all(&response).await.unwrap();
        assert!(client.read_u32().await.is_err());
    });
    assert!(
        AuthenticatedDisclosureChannel::authenticate(
            DisclosureConnection::new(server, policy),
            approved.effect().binding(),
            CONTENT.len() as u64,
            recipient().verifying_key().to_bytes()
        )
        .await
        .is_err()
    );
    impostor.await.unwrap();
    let wire = wire.await.unwrap();
    assert_eq!(wire.following_wire_bytes, 0);
    assert_eq!(record(&setup, OPERATION).await.unwrap(), before);
    facts(&setup, &approved, reserved, vec![wire]).await
}

async fn wrong_peer_uid(backend: Backend) -> Value {
    let uid = rustix::process::geteuid().as_raw();
    let policy = UnixDisclosurePolicy::new(uid, uid ^ 1, [0x78; 32]);
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    let reserved = reserve(&setup, &approved).await;
    let before = record(&setup, OPERATION).await.unwrap();
    let (server, gateway_proxy) = UnixStream::pair().unwrap();
    let (recipient_proxy, client) = UnixStream::pair().unwrap();
    let wire = tokio::spawn(proxy(gateway_proxy, recipient_proxy));
    let binding = approved.effect().binding().clone();
    let receiver_policy = policy.clone();
    let receiver = tokio::spawn(async move {
        crate::disclosure_transport::receive_disclosure(
            DisclosureConnection::new(client, receiver_policy),
            &binding,
            CONTENT.len() as u64,
            &recipient(),
        )
        .await
    });
    assert!(
        AuthenticatedDisclosureChannel::authenticate(
            DisclosureConnection::new(server, policy),
            approved.effect().binding(),
            CONTENT.len() as u64,
            recipient().verifying_key().to_bytes()
        )
        .await
        .is_err()
    );
    assert!(receiver.await.unwrap().is_err());
    let wire = wire.await.unwrap();
    assert_eq!(wire.following_wire_bytes, 0);
    assert!(!wire.challenge_complete);
    assert_eq!(record(&setup, OPERATION).await.unwrap(), before);
    facts(&setup, &approved, reserved, vec![wire]).await
}

async fn lost_claim_reply(backend: Backend) -> Value {
    let policy = local_policy();
    let (setup, approved) = Box::pin(setup(backend, &policy)).await;
    let fault = Arc::new(FaultStore::new(setup.backend.raw()));
    fault.lose_next_claim_reply();
    let attempts = setup.attempts(fault);
    assert!(
        attempts
            .claim_disclosure(&approved, NOW, setup.validation())
            .await
            .is_err()
    );
    let before = record(&setup, OPERATION).await.unwrap();
    let rows = allocations(&setup, &approved).await;
    let reserved = attempts
        .claim_disclosure(&approved, NOW, setup.validation())
        .await
        .unwrap();
    assert_eq!(reserved.stage, crate::DisclosureStage::Reserved);
    assert_eq!(record(&setup, OPERATION).await.unwrap(), before);
    // Resume needs a fresh authenticated channel and full current native entry.
    let Live {
        channel,
        receiver,
        wire,
    } = authenticate(&approved, &policy).await;
    let (grant, permit) = attempts
        .grant_disclosure(Arc::clone(&approved), setup.validation(), NOW, channel)
        .await
        .unwrap();
    let (ack, count) = tokio::join!(deliver(permit), received_and_ack(receiver));
    assert_eq!(count, CONTENT.len());
    drop(grant);
    let snapshot = attempts
        .acknowledge_disclosure(
            setup.recipe.namespace(),
            &crate::LogicalOperationId::parse(OPERATION).unwrap(),
            &ack.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allocations(&setup, &approved).await, rows);
    facts(&setup, &approved, snapshot, vec![wire.await.unwrap()]).await
}

async fn corpus(backend: Backend) -> Value {
    // Independent cases use separate maintained stores and collect all failures.
    let cases = vec![
        ("acknowledged", tokio::spawn(acknowledged(backend))),
        ("lost-ack-and-late-ack", tokio::spawn(lost_ack(backend))),
        ("dropped-grant", tokio::spawn(dropped_grant(backend, false))),
        (
            "lost-grant-reply",
            tokio::spawn(dropped_grant(backend, true)),
        ),
        (
            "recipient-withdrawal-before-grant",
            tokio::spawn(withdrawal(backend, false, true)),
        ),
        (
            "actor-withdrawal-before-grant",
            tokio::spawn(withdrawal(backend, false, false)),
        ),
        (
            "recipient-withdrawal-after-grant",
            tokio::spawn(withdrawal(backend, true, true)),
        ),
        (
            "competing-live-channels",
            tokio::spawn(concurrent_grants(backend)),
        ),
        ("wrong-recipient-key", tokio::spawn(wrong_key(backend))),
        ("wrong-peer-uid", tokio::spawn(wrong_peer_uid(backend))),
        (
            "lost-claim-reply-fresh-grant",
            tokio::spawn(lost_claim_reply(backend)),
        ),
    ];
    let mut facts = Vec::new();
    let mut failures = Vec::new();
    for (name, case) in cases {
        match case.await {
            Ok(value) => facts.push(json!({"case":name,"facts":value})),
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
    json!(facts)
}

#[tokio::test(flavor = "multi_thread")]
async fn native_engagement_live_delivery_fixture_is_current() {
    let document = json!({"schema":"auths.engagement-live-information-vectors/1",
        "generated_by":"native_engagement_live_delivery_fixture_is_current",
        "scope":"native enrolled scope and independent exact approval; actual file admission/grant, Unix UID/key authentication, captured wire bytes and ACK; synthetic source-response facts",
        "not_established":["provider-HTTPS","independent-process-isolation","process-crash","postgres-execution",
            "installed-binding-journey","externally-anchored-time"],
        "projection":"private identities, host UID, effect/source IDs, content MAC, random authentication nonces and signatures omitted; not restorable journal bytes",
        "cases":corpus(Backend::File).await});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/live-information.json");
    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
    bytes.push(b'\n');
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_native_scoped_live_delivery_and_recovery() {
    if postgres_configured() {
        corpus(Backend::Postgres).await;
    }
}
