use std::{error::Error, io};

use auths_identity_iroh::{
    IDENTITY_ALPN_V1, IdentityPacket, IrohIdentityClient, IrohIdentityConfig, IrohIdentityServer,
    PublicIdentity,
};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![IDENTITY_ALPN_V1.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let target = direct_target(&server).ok_or_else(|| io::Error::other("no direct address"))?;
    let server_identity = PublicIdentity::from_ed25519([7; 32])?;
    let client_identity = PublicIdentity::from_ed25519([9; 32])?;
    let server_endpoint = server.clone();

    let server_task = tokio::spawn(async move {
        let mut channel =
            IrohIdentityServer::accept(&server_endpoint, IrohIdentityConfig::default()).await?;
        let received = channel.receive().await?;
        println!(
            "server received {} from Iroh peer {}",
            received.packet().identity().principal(),
            hex::encode(received.peer_endpoint_id())
        );
        channel
            .respond(&IdentityPacket::PublicIdentity(server_identity))
            .await
    });

    let client = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let channel =
        IrohIdentityClient::connect(&client, target, IrohIdentityConfig::default()).await?;
    let response = channel
        .exchange(&IdentityPacket::PublicIdentity(client_identity))
        .await?;
    println!(
        "client received {} from Iroh peer {}",
        response.packet().identity().principal(),
        hex::encode(response.peer_endpoint_id())
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
