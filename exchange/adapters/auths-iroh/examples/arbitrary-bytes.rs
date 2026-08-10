use auths_iroh::{IrohConfig, StreamInitiator};
use std::{sync::Arc, time::Duration};

fn main() -> Result<(), auths_iroh::IrohError> {
    let config = IrohConfig::new(
        Arc::<[u8]>::from(&b"/my-team/public-keys/1"[..]),
        64 * 1024,
        Duration::from_secs(5),
        StreamInitiator::ConnectingEndpoint,
    )?;
    assert_eq!(config.alpn(), b"/my-team/public-keys/1");
    Ok(())
}
