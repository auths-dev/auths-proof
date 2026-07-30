use sha2::{Digest as _, Sha256};

/// A domain-separated exact 32-byte commitment.
pub trait TypedDigest: Sized {
    /// Constructs a typed commitment from exact bytes.
    fn from_bytes(bytes: [u8; 32]) -> Self;
    /// Returns the exact commitment bytes.
    fn as_bytes(&self) -> &[u8; 32];

    /// Hashes a bounded canonical payload with one immutable domain.
    #[must_use]
    fn commit(domain: &[u8], canonical: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([0]);
        hasher.update(canonical);
        Self::from_bytes(hasher.finalize().into())
    }
}

macro_rules! typed_digest {
    ($name:ident) => {
        #[doc = concat!("Exact 32-byte `", stringify!($name), "`.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl TypedDigest for $name {
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl $name {
            /// Constructs an exact typed commitment.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the exact commitment bytes.
            #[must_use]
            pub const fn bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

typed_digest!(DecisionReceiptDigest);
typed_digest!(DomainReceiptDigest);
typed_digest!(ExecutionIntentDigest);
typed_digest!(LifecycleReceiptDigest);
typed_digest!(ObservationDigest);
typed_digest!(ProviderConditionDigest);
typed_digest!(ProviderRequestDigest);
typed_digest!(ProviderResultDigest);
typed_digest!(ReservationSetDigest);
