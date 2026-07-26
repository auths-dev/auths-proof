//! Bounded raw TCP adapter for private and development deployments.

#![forbid(unsafe_code)]

use auths_proof_exchange_framing::{FramedClient, FramedServer, FramingConfig};
use auths_proof_exchange_model::PeerObservation;
use std::io;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Connects a raw unauthenticated TCP client channel.
///
/// # Errors
///
/// Returns the underlying connect error.
pub async fn connect(
    address: impl ToSocketAddrs,
    config: FramingConfig,
) -> Result<FramedClient<TcpStream>, io::Error> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let peer = stream.peer_addr()?.to_string();
    Ok(FramedClient::new(
        stream,
        PeerObservation::TcpEndpoint(peer),
        config,
    ))
}

/// Accepts one raw unauthenticated TCP service channel.
///
/// # Errors
///
/// Returns the underlying accept or socket-configuration error.
pub async fn accept(
    listener: &TcpListener,
    config: FramingConfig,
) -> Result<FramedServer<TcpStream>, io::Error> {
    let (stream, peer) = listener.accept().await?;
    stream.set_nodelay(true)?;
    Ok(FramedServer::new(
        stream,
        PeerObservation::TcpEndpoint(peer.to_string()),
        config,
    ))
}
