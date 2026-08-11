import {
  loadEd25519RawKeyAuthentication,
  loadIdentity,
  loadRawKeyIdentityAdapter,
} from "@auths-dev/sdk/identity";

export async function runIdentityOnly(message: Uint8Array): Promise<string> {
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const identity = await loadIdentity();
  const rawKey = await loadRawKeyIdentityAdapter();
  const ed25519 = await loadEd25519RawKeyAuthentication();

  const local = rawKey.create("ed25519-v1", publicKey);
  const received = identity.decodePublicIdentity(local.packet);
  const validated = identity.parseIdentity(received, rawKey);
  const preimage = identity.signingPreimage(validated, message);
  const signature = new Uint8Array(await crypto.subtle.sign(
    "Ed25519",
    keys.privateKey,
    Uint8Array.from(preimage),
  ));
  const signed = identity.encodeSignedMessage(validated, message, signature);
  const authenticated = identity.authenticate(
    identity.decodeSignedMessage(signed),
    validated,
    ed25519,
  );
  return authenticated.identity.identityId;
}
