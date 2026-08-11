import { loadVerifier } from "@auths-dev/sdk/verify";

export async function verifyLocally(
  proof: Uint8Array,
  action: Uint8Array,
  context: Uint8Array,
) {
  const auths = await loadVerifier();
  return auths.verify(proof, action, context);
}
