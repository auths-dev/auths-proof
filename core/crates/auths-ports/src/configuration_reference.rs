use super::*;
use sha2::{Digest as _, Sha256};

pub fn configuration_id<'a>(
    domain: &[u8],
    components: impl IntoIterator<Item = &'a [u8]>,
) -> AdapterConfigurationId {
    let mut hasher = Sha256::new();
    hasher.update(b"auths-proof-adapter-configuration-v1");
    hasher.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(domain);
    for component in components {
        hasher.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(component);
    }
    AdapterConfigurationId::new(hasher.finalize().into())
}

