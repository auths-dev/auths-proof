# About the identity-over-Iroh demo

This demo proves the smallest Auths adoption path. Two peers exchange canonical
Ed25519 public identities over a real local Iroh connection. They can also bind
an exact application message to the exchanged identity and verify it with the
core Ed25519 suite.

No grant, capability, approval, policy, lifecycle, store, or product runtime is
constructed. The identity transport package has no transitive workspace
dependency on those systems, and architecture CI preserves that boundary.

A successful Iroh handshake authenticates the Iroh endpoint. A successful
Ed25519 verification authenticates the exact message bytes to the carried
public identity. Neither fact authorizes an application action, supplies
freshness, or prevents replay. Teams add delegated authority only when their
application needs those properties.
