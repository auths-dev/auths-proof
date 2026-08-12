import {
  loadEd25519RawKeyAuthentication,
  loadIdentity,
  loadRawKeyIdentityAdapter,
} from "@auths-dev/sdk/identity";

const message = new TextEncoder().encode("publish weekly report");
const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
const identity = await loadIdentity();
const method = await loadRawKeyIdentityAdapter();
const suite = await loadEd25519RawKeyAuthentication();
const sent = method.create("ed25519-v1", publicKey);
const received = identity.parseIdentity(identity.decodePublicIdentity(sent.packet), method);
const preimage = identity.signingPreimage(received, message);
const signingBytes = new Uint8Array(preimage.length);
signingBytes.set(preimage);
const signature = new Uint8Array(await crypto.subtle.sign(
  "Ed25519",
  keys.privateKey,
  signingBytes.buffer,
));
const authenticated = identity.authenticate(
  identity.decodeSignedMessage(identity.encodeSignedMessage(received, message, signature)),
  received,
  suite,
);
let changedRejected = false;
try {
  const changed = new TextEncoder().encode("delete weekly report");
  identity.authenticate(
    identity.decodeSignedMessage(identity.encodeSignedMessage(received, changed, signature)),
    received,
    suite,
  );
} catch {
  changedRejected = true;
}
if (!changedRejected) throw new Error("changed message authenticated");
console.log(JSON.stringify({ recipe: "01-authenticate-identity", outcome: "authenticated", changedRejected }));
