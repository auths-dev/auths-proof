use super::*;
use iroh::endpoint::presets;
use std::{
    future::Future as _,
    task::{Context, Waker},
};

async fn pair() -> (IrohChannel, IrohChannel, Endpoint, Endpoint) {
    let config = IrohConfig::new(
        Arc::<[u8]>::from(&b"/ap078/test/1"[..]),
        4096,
        Duration::from_secs(5),
        StreamInitiator::ConnectingEndpoint,
    )
    .unwrap();
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![config.alpn().to_vec()])
        .bind()
        .await
        .unwrap();
    let client_endpoint = Endpoint::bind(presets::N0).await.unwrap();
    let address = server_endpoint.addr();
    let direct = *address.ip_addrs().next().unwrap();
    let target = EndpointAddr::new(server_endpoint.id()).with_ip_addr(direct);
    let accepting_endpoint = server_endpoint.clone();
    let accepting_config = config.clone();
    let accepting = tokio::spawn(async move {
        IrohChannel::accept(&accepting_endpoint, accepting_config)
            .await
            .unwrap()
    });
    let mut client = IrohChannel::connect(&client_endpoint, target, config)
        .await
        .unwrap();
    client.send(b"stream establishment").await.unwrap();
    let mut server = accepting.await.unwrap();
    assert_eq!(
        server.receive().await.unwrap().payload(),
        b"stream establishment"
    );
    (client, server, client_endpoint, server_endpoint)
}

#[tokio::test]
async fn raw_iroh_cancelled_receive_and_malformed_frame_cannot_restart() {
    timeout(Duration::from_secs(20), async {
        let (mut client, mut server, client_endpoint, server_endpoint) = pair().await;
        assert_eq!(client.send(&[]).await, Err(IrohError::Limit));
        assert_eq!(client.send(&vec![0; 4097]).await, Err(IrohError::Limit));
        server
            .send(b"preflight rejection preserves framing")
            .await
            .unwrap();
        assert_eq!(
            client.receive().await.unwrap().payload(),
            b"preflight rejection preserves framing"
        );
        let mut receive = Box::pin(client.receive());
        assert!(
            receive
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(receive);
        assert_eq!(client.receive().await, Err(IrohError::Sequence));
        assert_eq!(client.send(b"late").await, Err(IrohError::Sequence));
        assert_eq!(client.finish_send(), Err(IrohError::Sequence));
        // An oversized declared frame consumes its header, but does not admit
        // another frame parse on the same stream.
        client
            .send
            .write_all(&4097_u32.to_be_bytes())
            .await
            .unwrap();
        assert_eq!(server.receive().await, Err(IrohError::Limit));
        assert_eq!(server.receive().await, Err(IrohError::Sequence));
        client_endpoint.close().await;
        server_endpoint.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn raw_iroh_peer_stop_and_abandoned_finish_retain_terminal_ownership() {
    timeout(Duration::from_secs(20), async {
        let (mut client, mut server, client_endpoint, server_endpoint) = pair().await;
        server.recv.stop(0_u32.into()).unwrap();
        client.send.stopped().await.unwrap();
        assert_eq!(client.send(b"stopped").await, Err(IrohError::Connection));
        assert_eq!(client.send(b"retry").await, Err(IrohError::Sequence));
        client_endpoint.close().await;
        server_endpoint.close().await;

        let (mut client, mut server, client_endpoint, server_endpoint) = pair().await;
        let mut finish = Box::pin(server.finish_send_and_wait());
        assert!(
            finish
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(finish);
        assert_eq!(server.finish_send(), Err(IrohError::Sequence));
        assert_eq!(server.receive().await, Err(IrohError::Sequence));
        // The peer can still observe the FIN; abandoning its acknowledgement
        // does not restore the sender's capability.
        assert!(client.recv.read(&mut [0_u8; 1]).await.unwrap().is_none());
        client_endpoint.close().await;
        server_endpoint.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_stop_is_not_a_clean_finish_acknowledgement() {
    timeout(Duration::from_secs(20), async {
        let (mut client, mut server, client_endpoint, server_endpoint) = pair().await;
        server.send.write_all(b"unread bytes").await.unwrap();
        client.recv.stop(17_u32.into()).unwrap();
        // Establish STOP receipt before FIN: otherwise QUIC could acknowledge
        // unread data and FIN before the STOP arrives, which is a valid race.
        assert_eq!(server.send.stopped().await.unwrap(), Some(17_u32.into()));
        assert_eq!(
            server.finish_send_and_wait().await,
            Err(IrohError::Connection)
        );
        assert_eq!(server.send(b"retry").await, Err(IrohError::Sequence));
        client_endpoint.close().await;
        server_endpoint.close().await;
    })
    .await
    .unwrap();
}
