import type { IdentityClient } from "../../src/identity.js";
import type { RemoteVerifier } from "../../src/protocol.js";

declare function identityClient(): Promise<IdentityClient>;
declare function remoteVerifier(): Promise<RemoteVerifier>;

async function managed(): Promise<void> {
  await using identity = await identityClient();
  await using verifier = await remoteVerifier();
  void identity; void verifier;
}

void managed;
