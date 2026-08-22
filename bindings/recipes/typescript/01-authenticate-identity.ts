import { createRawKeyEd25519IdentityClient } from "@auths-dev/sdk/identity";
import { createRawKeyEd25519Identity, prepareIdentityMessage } from "@auths-dev/sdk/identity/authoring";

const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
const identity = await createRawKeyEd25519Identity(publicKey);
const message = new TextEncoder().encode("publish weekly report");
const prepared = await prepareIdentityMessage({ identity, message });
const signingBytes = prepared.signingPreimage.slice().buffer as ArrayBuffer;
const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", keys.privateKey, signingBytes));
const client = await createRawKeyEd25519IdentityClient();
try {
  const result = await client.authenticate({ identity, message, signature });
  if (result.kind !== "ok") throw new Error(result.issue.code);
  console.log(JSON.stringify({ recipe: "01-authenticate-identity", outcome: "authenticated" }));
} finally {
  await client.close();
}
