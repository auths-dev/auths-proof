import { loadPortableAuths } from "@auths-dev/sdk/advanced";

export async function verifyLocally(
  proof: Uint8Array,
  action: Uint8Array,
  context: Uint8Array,
) {
  const auths = await loadPortableAuths();
  return auths.verify(proof, action, context);
}
