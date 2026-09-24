# Prompt: secrets, custody and operational security

Scope: `product/runtime/auths-connections`, `auths-gateway/src/transport.rs`, `product/integrations/auths-custody*`, `auths-node` (local agent and socket auth), `product/operations*`, `bindings/python`, `bindings/typescript`, `release/`, `.github/`.

Goal: follow every secret (provider credentials, signing keys, observer keys) from creation to disposal.

Answer:
1. **At rest.**
   - Where does each secret live on disk, and in what form (plaintext, encrypted, KMS/HSM handle)?
   - What are the file permissions?
   - Is custody actually connected, or only present as a crate?
2. **In memory.**
   - Is every secret type `Zeroize`/`ZeroizeOnDrop`?
   - Look for plain `fill(0)`, copies into `Vec`/`String`, clones, and encode buffers left unwiped.
3. **In flight.**
   - Are auth headers marked sensitive?
   - Can secrets reach logs, errors, `Debug`, OTel spans, receipts, panics or core dumps? Grep for every `Debug`/`Display`/`Serialize` on types that contain secrets.
4. **Who can call.**
   - How does the local agent authenticate the calling workload (peer credentials, `/proc` exe, cgroup)?
   - Can another process under the same user impersonate it?
   - What about containers, symlinked exes, or deleted-and-replaced binaries?
5. **Trust boundaries.**
   - Which code is trusted with raw secrets (profiles via `expose()`)?
   - Can a bug in one profile read another connection's credential?
6. **Network.** Check SSRF defences (DNS pinning, IPv6, redirects, proxies), TLS settings, and response-size limits.
7. **Keys and roles.**
   - Are root, operator and observer keys actually separated?
   - What does compromise of each one allow?
   - Is key rotation possible without downtime?
8. **Supply chain.** Check the `deny.toml` policy, pinned toolchains, release signing, and CI secrets exposure (`pull_request_target`, untrusted inputs in workflows).
