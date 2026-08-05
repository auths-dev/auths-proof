import { AuthsWorkflowError } from "./workflow/errors.js";

const MAX_COMMITMENT_INPUT_BYTES = 16 * 1024 * 1024;
const DOMAIN_PREFIX = new TextEncoder().encode("AUTHS-SDK-COMMITMENT\0\x01");

/** A copied SHA-256 commitment produced with an explicit application domain. */
export interface CanonicalCommitment {
  readonly algorithm: "sha-256";
  readonly domain: string;
  readonly digest: Uint8Array;
  readonly hex: string;
}

/** Commits to already-canonical bytes without inventing application semantics. */
export async function commitCanonical(
  domain: string,
  canonicalBytes: Uint8Array,
): Promise<CanonicalCommitment> {
  if (
    typeof domain !== "string" ||
    domain.length === 0 ||
    new TextEncoder().encode(domain).length > 128
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "commitment domain is outside SDK limits",
    );
  }
  if (
    !(canonicalBytes instanceof Uint8Array) ||
    canonicalBytes.length === 0 ||
    canonicalBytes.length > MAX_COMMITMENT_INPUT_BYTES
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "canonical commitment input is outside SDK limits",
    );
  }
  const domainBytes = new TextEncoder().encode(domain);
  const input = new Uint8Array(
    DOMAIN_PREFIX.length + 2 + domainBytes.length + 8 + canonicalBytes.length,
  );
  let offset = 0;
  input.set(DOMAIN_PREFIX, offset);
  offset += DOMAIN_PREFIX.length;
  new DataView(input.buffer).setUint16(offset, domainBytes.length, false);
  offset += 2;
  input.set(domainBytes, offset);
  offset += domainBytes.length;
  new DataView(input.buffer).setBigUint64(
    offset,
    BigInt(canonicalBytes.length),
    false,
  );
  offset += 8;
  input.set(canonicalBytes, offset);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  input.fill(0);
  return Object.freeze({
    algorithm: "sha-256" as const,
    domain,
    digest,
    hex: Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(""),
  });
}
