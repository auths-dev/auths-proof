//! Unix-domain socket exchange adapter with typed peer credentials.

#![forbid(unsafe_code)]

#[cfg(unix)]
mod implementation {
    use auths_proof_exchange_framing::{FramedClient, FramedServer, FramingConfig};
    use auths_proof_exchange_model::PeerObservation;
    use std::{io, path::Path};
    use tokio::net::{UnixListener, UnixStream};

    /// Connects a local Unix-domain client.
    ///
    /// # Errors
    ///
    /// Returns the underlying connect error.
    pub async fn connect(
        path: impl AsRef<Path>,
        config: FramingConfig,
    ) -> Result<FramedClient<UnixStream>, io::Error> {
        let stream = UnixStream::connect(path).await?;
        Ok(FramedClient::new(
            stream,
            PeerObservation::ServerAuthenticated,
            config,
        ))
    }

    /// Accepts one Unix-domain service channel and records OS peer
    /// credentials.
    ///
    /// # Errors
    ///
    /// Returns the underlying accept or credential-query error.
    pub async fn accept(
        listener: &UnixListener,
        config: FramingConfig,
    ) -> Result<FramedServer<UnixStream>, io::Error> {
        let (stream, _) = listener.accept().await?;
        let credentials = stream.peer_cred()?;
        Ok(FramedServer::new(
            stream,
            PeerObservation::UnixPeerCredentials {
                uid: credentials.uid(),
                gid: credentials.gid(),
                pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
            },
            config,
        ))
    }
}

#[cfg(unix)]
pub use implementation::{accept, connect};
