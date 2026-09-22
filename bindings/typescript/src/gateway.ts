/** Proof/action-only client for a separately operated local Auths gateway. */

import { createConnection } from "node:net";

const REQUEST_SCHEMA = "auths.gateway-submit/1";
const MAX_PROOF_BYTES = 4 * 1024 * 1024;
const MAX_ACTION_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024;
const MAX_FRAME_BYTES = 8 * 1024 * 1024;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** A socket or bounded gateway response could not be trusted. Never retry a write automatically. */
export class GatewayProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayProtocolError";
  }
}

/** Operator-provisioned local application socket, never a provider URL. */
export class GatewayEndpoint {
  readonly path: string;

  constructor(path: string) {
    if (typeof path !== "string" || !path.startsWith("/") || path.includes("\0") || new TextEncoder().encode(path).length > 100) {
      throw new TypeError("gateway endpoint must be a short absolute Unix socket path");
    }
    this.path = path;
  }
}

/** Proof decision and transport/observation stages, without effect qualification. */
export type GatewayResult =
  | Readonly<{ outcome: "denied"; code: string }>
  | Readonly<{ outcome: "indeterminate"; code: string }>
  | Readonly<{ outcome: "not-entered"; code: string }>
  | Readonly<{ outcome: "unknown" }>
  | Readonly<{ outcome: "response-recorded"; status: number }>
  | Readonly<{ outcome: "observed"; status: number; matched: boolean }>;

function encodeBase64Url(bytes: Uint8Array): string {
  let encoded = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index]!;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    encoded += ALPHABET[first >> 2]!;
    encoded += ALPHABET[((first & 3) << 4) | ((second ?? 0) >> 4)]!;
    if (second !== undefined) {
      encoded += ALPHABET[((second & 15) << 2) | ((third ?? 0) >> 6)]!;
    }
    if (third !== undefined) {
      encoded += ALPHABET[third & 63]!;
    }
  }
  return encoded;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function parseResult(bytes: Uint8Array): GatewayResult {
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new GatewayProtocolError("gateway returned invalid JSON");
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new GatewayProtocolError("gateway returned invalid result");
  }
  const value = decoded as Record<string, unknown>;
  const outcome = value.outcome;
  if (outcome === "denied" || outcome === "indeterminate" || outcome === "not-entered") {
    if (!exactKeys(value, ["outcome", "code"]) || typeof value.code !== "string" || value.code.length < 1 || value.code.length > 128) {
      throw new GatewayProtocolError("gateway returned invalid refusal");
    }
    return { outcome, code: value.code };
  }
  if (outcome === "unknown" && exactKeys(value, ["outcome"])) {
    return { outcome };
  }
  if (outcome === "response-recorded" || outcome === "observed") {
    const expected = outcome === "observed" ? ["outcome", "status", "matched"] : ["outcome", "status"];
    if (!exactKeys(value, expected) || typeof value.status !== "number" || !Number.isInteger(value.status) || value.status < 100 || value.status > 599) {
      throw new GatewayProtocolError("gateway returned invalid response stage");
    }
    if (outcome === "response-recorded") {
      return { outcome, status: value.status as number };
    }
    if (typeof value.matched !== "boolean") {
      throw new GatewayProtocolError("gateway returned invalid observation");
    }
    return { outcome, status: value.status as number, matched: value.matched };
  }
  throw new GatewayProtocolError("gateway returned unknown result stage");
}

function concatenate(parts: readonly Uint8Array[], total: number): Uint8Array {
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
}

/** Submit only canonical proof and action bytes; no credential or raw HTTP API exists. */
export class GatewayClient {
  readonly #endpoint: GatewayEndpoint;

  constructor(endpoint: GatewayEndpoint) {
    if (!(endpoint instanceof GatewayEndpoint)) {
      throw new TypeError("endpoint must be a GatewayEndpoint");
    }
    this.#endpoint = endpoint;
  }

  async submit(input: Readonly<{ proof: Uint8Array; action: Uint8Array }>): Promise<GatewayResult> {
    if (!(input.proof instanceof Uint8Array) || input.proof.length < 1 || input.proof.length > MAX_PROOF_BYTES) {
      throw new TypeError("proof must be bounded bytes");
    }
    if (!(input.action instanceof Uint8Array) || input.action.length < 1 || input.action.length > MAX_ACTION_BYTES) {
      throw new TypeError("action must be bounded bytes");
    }
    const payload = new TextEncoder().encode(JSON.stringify({
      schema: REQUEST_SCHEMA,
      proof_b64: encodeBase64Url(input.proof),
      action_b64: encodeBase64Url(input.action),
    }));
    if (payload.length > MAX_FRAME_BYTES) {
      throw new TypeError("gateway request exceeds frame bound");
    }
    const frame = new Uint8Array(payload.length + 4);
    new DataView(frame.buffer).setUint32(0, payload.length, false);
    frame.set(payload, 4);
    return new Promise<GatewayResult>((resolve, reject) => {
      const socket = createConnection({ path: this.#endpoint.path });
      const parts: Uint8Array[] = [];
      let received = 0;
      let settled = false;
      const finish = (result: GatewayResult | GatewayProtocolError): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (result instanceof GatewayProtocolError) reject(result);
        else resolve(result);
      };
      const timer = setTimeout(() => finish(new GatewayProtocolError("gateway exchange timed out; outcome may be unknown")), 45_000);
      socket.once("connect", () => { socket.write(frame); });
      socket.on("data", (chunk) => {
        parts.push(chunk);
        received += chunk.length;
        if (received > MAX_RESPONSE_BYTES + 4) {
          finish(new GatewayProtocolError("gateway response exceeded the bound"));
          return;
        }
        if (received < 4) return;
        const bytes = concatenate(parts, received);
        const length = new DataView(bytes.buffer).getUint32(0, false);
        if (length < 1 || length > MAX_RESPONSE_BYTES) {
          finish(new GatewayProtocolError("gateway response exceeded the bound"));
        } else if (received >= length + 4) {
          try {
            finish(parseResult(bytes.subarray(4, length + 4)));
          } catch {
            finish(new GatewayProtocolError("gateway returned invalid response; outcome may be unknown"));
          }
        }
      });
      socket.once("error", () => finish(new GatewayProtocolError("gateway exchange unavailable; outcome may be unknown")));
      socket.once("end", () => finish(new GatewayProtocolError("gateway response incomplete; outcome may be unknown")));
    });
  }
}
