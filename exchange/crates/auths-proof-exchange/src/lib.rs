//! Supported semantic exchange API for Auths Proof Protocol V1.
//!
//! Applications use one [`ClientProofChannel`] or [`ServerProofChannel`]
//! implementation. Transports preserve the same challenge → submission →
//! response sequence and cannot manufacture an authorization verdict.

#![forbid(unsafe_code)]

use core::fmt;

pub use auths_proof_exchange_model as model;
pub use auths_proof_exchange_port::{
    ClientProofChannel, ProofExchangeService, ServeError, ServerProofChannel, ServiceError,
    serve_one,
};

#[cfg(feature = "file")]
pub use auths_proof_exchange_file as file;
#[cfg(feature = "https")]
pub use auths_proof_exchange_https as https;
#[cfg(feature = "iroh")]
pub use auths_proof_exchange_iroh as iroh;
#[cfg(feature = "memory")]
pub use auths_proof_exchange_memory as memory;
#[cfg(feature = "tcp")]
pub use auths_proof_exchange_tcp as tcp;
#[cfg(all(feature = "unix", unix))]
pub use auths_proof_exchange_unix as unix;

/// Runs the only client exchange sequence admitted by V1.
///
/// The callback constructs a submission from the exact challenge received on
/// the channel. Binding and sequencing remain enforced by the transport.
///
/// # Errors
///
/// Returns a typed preparation or transport error. It never turns a channel
/// failure into an Auths application verdict.
pub async fn exchange_one<C, F, E>(
    channel: &mut C,
    prepare: F,
) -> Result<model::ActionResponse, ClientExchangeError<C::Error, E>>
where
    C: ClientProofChannel + Send,
    F: FnOnce(&model::ActionChallenge) -> Result<model::ActionSubmission, E>,
{
    let challenge = channel
        .receive_challenge()
        .await
        .map_err(ClientExchangeError::Transport)?;
    let submission = prepare(&challenge).map_err(ClientExchangeError::Prepare)?;
    channel
        .submit_action(submission)
        .await
        .map_err(ClientExchangeError::Transport)
}

/// Client-side preparation or transport failure.
#[derive(Debug)]
pub enum ClientExchangeError<T, P> {
    /// Semantic channel failed before an application response was available.
    Transport(T),
    /// Caller could not build a challenge-bound submission.
    Prepare(P),
}

impl<T: fmt::Display, P: fmt::Display> fmt::Display for ClientExchangeError<T, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "proof exchange transport failed: {error}"),
            Self::Prepare(error) => {
                write!(formatter, "proof submission preparation failed: {error}")
            }
        }
    }
}

impl<T, P> std::error::Error for ClientExchangeError<T, P>
where
    T: std::error::Error + 'static,
    P: std::error::Error + 'static,
{
}
