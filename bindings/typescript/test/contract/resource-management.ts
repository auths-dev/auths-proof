import type { Client } from "../../src/index.js";
import type { IdentityClient } from "../../src/identity.js";
import type { RemoteVerifier } from "../../src/protocol.js";

declare function identityClient(): Promise<IdentityClient>;
declare function remoteVerifier(): Promise<RemoteVerifier>;
declare function session(): Promise<Client>;

async function managed(): Promise<void> {
  await using identity = await identityClient();
  await using verifier = await remoteVerifier();
  await using auths = await session();
  void identity; void verifier; void auths;
}

void managed;
