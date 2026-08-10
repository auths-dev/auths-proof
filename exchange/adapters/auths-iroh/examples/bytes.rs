use std::{error::Error, io, sync::Arc, time::Duration};

use auths_iroh::{IrohChannel, IrohConfig, StreamInitiator};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};

const ALPN: &[u8] = b"/example/arbitrary-bytes/1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = IrohConfig::new(
        Arc::<[u8]>::from(ALPN),
        4096,
        Duration::from_secs(5),
        StreamInitiator::ConnectingEndpoint,
    )?;
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let target = direct_target(&server).ok_or_else(|| io::Error::other("no direct address"))?;
    let server_endpoint = server.clone();
    let server_config = config.clone();
    let server_task = tokio::spawn(async move {
        let mut channel = IrohChannel::accept(&server_endpoint, server_config).await?;
        let received = channel.receive().await?;
        println!(
            "server received: {}",
            String::from_utf8_lossy(received.payload())
        );
        channel.send(b"arbitrary response bytes").await?;
        channel.finish_send_and_wait().await
    });

    let client = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let mut channel = IrohChannel::connect(&client, target, config).await?;
    channel.send(b"not an identity or capability").await?;
    channel.finish_send()?;
    let response = channel.receive().await?;
    println!(
        "client received: {}",
        String::from_utf8_lossy(response.payload())
    );
    server_task.await??;
    client.close().await;
    server.close().await;
    Ok(())
}

fn direct_target(endpoint: &Endpoint) -> Option<EndpointAddr> {
    let direct = endpoint.addr().ip_addrs().next().copied()?;
    Some(EndpointAddr::new(endpoint.id()).with_ip_addr(direct))
}
