# Sigstore keyless producer journey

This journey keeps Fulcio and Rekor acquisition outside the Auths verification
kernel. A producer creates an ephemeral key, signs the exact Auths preimage,
obtains a Fulcio certificate, submits the same signature to Rekor, and converts
the returned Sigstore bundle with `auths-sigstore-bundle-import`.

The resulting certificate-chain and Rekor-entry CBOR objects are immutable
inputs to `auths-sigstore-keyless`; verification itself performs no network,
clock, discovery, or operating-system trust-store access.
