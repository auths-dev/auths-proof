import { createRawKeyEd25519IdentityClient, type ValidatedIdentity } from "../identity.js";
import type { VerificationRelationship } from "./adapters.js";
import { loadPackagedWorkflowEngine } from "../verifier/wasm.js";

declare const preparedIdentityMessageBrand: unique symbol;
export interface PreparedIdentityMessage {
  readonly [preparedIdentityMessageBrand]: true;
  readonly identity: ValidatedIdentity;
  readonly relationshipId: string;
  readonly message: Uint8Array;
  readonly signingPreimage: Uint8Array;
}

interface AuthoringEngine {
  createRawKeyPublicIdentityV2(suiteId: string, publicKey: Uint8Array): Uint8Array;
  encodeIdentityDescriptorV1(value: unknown): Uint8Array;
  identityDescriptorSigningPreimageV1(packet: Uint8Array, relationshipId: string, message: Uint8Array): Uint8Array;
  identityMessageSigningPreimageV2(packet: Uint8Array, message: Uint8Array): Uint8Array;
}

export async function createRawKeyEd25519Identity(publicKey: Uint8Array): Promise<ValidatedIdentity> {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new TypeError("Ed25519 public key must contain exactly 32 bytes");
  const engine = await loadPackagedWorkflowEngine() as unknown as AuthoringEngine;
  const packet = new Uint8Array(engine.createRawKeyPublicIdentityV2("ed25519-v1", publicKey.slice()));
  const client = await createRawKeyEd25519IdentityClient();
  try {
    const decoded = client.decode(packet); if (decoded.kind !== "ok") throw new TypeError(decoded.issue.code);
    const resolved = await client.resolve(decoded.value); if (resolved.kind !== "ok") throw new TypeError(resolved.issue.code);
    const validated = await client.validate(resolved.value); if (validated.kind !== "ok") throw new TypeError(validated.issue.code);
    return validated.value;
  } finally { await client.close(); }
}

export async function encodeIdentity(input: Readonly<{ methodId: string; identityId: string; methodMaterial?: Uint8Array; relationships: readonly VerificationRelationship[] }>): Promise<Uint8Array> {
  const engine = await loadPackagedWorkflowEngine() as unknown as AuthoringEngine;
  return new Uint8Array(engine.encodeIdentityDescriptorV1({
    methodId: input.methodId,
    identityId: input.identityId,
    methodMaterial: input.methodMaterial?.slice() ?? new Uint8Array(),
    relationships: input.relationships.map((relationship) => ({
      relationshipId: relationship.id,
      purpose: relationship.purpose,
      suiteId: relationship.suiteId,
      verificationMaterial: relationship.verificationMaterial.map((material) => ({ materialId: material.id, bytes: material.bytes.slice() })),
    })),
  }));
}

export async function prepareIdentityMessage(input: Readonly<{ identity: ValidatedIdentity; relationshipId?: string; message: Uint8Array }>): Promise<PreparedIdentityMessage> {
  const relationshipId = input.relationshipId ?? "default-signing";
  if (!input.identity.relationships.includes(relationshipId)) throw new TypeError("identity relationship is unavailable");
  const engine = await loadPackagedWorkflowEngine() as unknown as AuthoringEngine;
  const packet = input.identity.toBytes();
  let signingPreimage: Uint8Array;
  try { signingPreimage = new Uint8Array(engine.identityDescriptorSigningPreimageV1(packet, relationshipId, input.message.slice())); }
  catch { signingPreimage = new Uint8Array(engine.identityMessageSigningPreimageV2(packet, input.message.slice())); }
  return Object.freeze({ identity: input.identity, relationshipId, message: input.message.slice(), signingPreimage }) as PreparedIdentityMessage;
}
