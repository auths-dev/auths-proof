/**
 * Proof/action-only client for a separately operated local Auths gateway. It can also
 * ask the gateway for one read-only signed observation to attach to a later action.
 */

import { createConnection } from "node:net";

const REQUEST_SCHEMA = "auths.gateway-submit/1";
const OBSERVE_SCHEMA = "auths.gateway-observe/1";
const READ_BACK_SCHEMA = "auths.gateway-readback/1";
const OUTCOME_SCHEMA = "auths.gateway-outcome/1";
const OBSERVATION_MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor";
const MAX_OBSERVATION_BYTES = 4_096;
const MAX_SUBJECT_BYTES = 1_024;
const MAX_READ_BACK_ARGUMENTS = 16;
const MAX_ARGUMENT_BYTES = 128;
const MAX_PROOF_BYTES = 4 * 1024 * 1024;
const MAX_ACTION_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024;
const MAX_FRAME_BYTES = 8 * 1024 * 1024;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const ECHO = /^auths-e1-[0-9a-f]{64}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const FIELD_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

type ObservationSchema = typeof READ_BACK_SCHEMA | typeof OUTCOME_SCHEMA;

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

/**
 * Secret-free summary of provider-held read-back evidence. The response bytes and
 * observation locator stay in the operator's attempt store; `observedAt` is gateway
 * wall-clock seconds and is not authenticated.
 */
export type GatewayProviderEvidence = Readonly<{
  channel: "read-back";
  echo: string;
  evidenceDigest: string;
  observedAt: number;
}>;

/**
 * Proof decision and transport/observation stages, without effect qualification.
 * `observed-by-provider` means a read-back returned this attempt's echo token and the
 * verified value; anyone who knows the namespace, operation ID, and action commitment
 * can compute that token, so the link holds only while no other writer of that
 * provider field wrote the same token. Its `status` is `null` when the write was unknown.
 */
export type GatewayResult =
  | Readonly<{ outcome: "denied"; code: string }>
  | Readonly<{ outcome: "indeterminate"; code: string }>
  | Readonly<{ outcome: "not-entered"; code: string }>
  | Readonly<{ outcome: "unknown" }>
  | Readonly<{ outcome: "response-recorded"; status: number }>
  | Readonly<{ outcome: "observed"; status: number; matched: boolean }>
  | Readonly<{ outcome: "observed-by-provider"; status: number | null; evidence: GatewayProviderEvidence }>;

/**
 * One canonical gateway-signed observation. Attach `observation` unmodified as a
 * detached attachment whose descriptor media type is `mediaType`. It asserts only what
 * the gateway saw at `observedAt` (gateway wall-clock seconds, covered by the
 * signature); it is not a write receipt and does not prove the fact still holds.
 */
export type GatewaySignedObservation = Readonly<{
  outcome: "signed";
  schema: "auths.gateway-readback/1" | "auths.gateway-outcome/1";
  subject: string;
  observedAt: number;
  mediaType: "application/vnd.auths.observation.v1+cbor";
  observation: Uint8Array;
}>;

/** Closed result of an observation request: signed bytes, or a refusal that signed nothing. */
export type GatewayObserveResult =
  | GatewaySignedObservation
  | Readonly<{ outcome: "refused"; code: string }>;

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

/** Decodes canonical unpadded base64url only; any other spelling is rejected. */
function decodeBase64Url(text: string, maximum: number): Uint8Array {
  if (text.length > Math.ceil((maximum * 4) / 3) || !BASE64URL.test(text) || text.length % 4 === 1) {
    throw new GatewayProtocolError("gateway returned invalid observation encoding");
  }
  const bytes = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const character of text) {
    buffer = (buffer << 6) | ALPHABET.indexOf(character);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset] = (buffer >> bits) & 0xff;
      offset += 1;
    }
    buffer &= (1 << bits) - 1;
  }
  if (buffer !== 0 || bytes.length < 1 || bytes.length > maximum) {
    throw new GatewayProtocolError("gateway returned invalid observation encoding");
  }
  return bytes;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function validStatus(status: unknown): status is number {
  return typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599;
}

function parseEvidence(value: unknown): GatewayProviderEvidence {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GatewayProtocolError("gateway returned invalid evidence");
  }
  const evidence = value as Record<string, unknown>;
  const { channel, echo, evidence_digest: digest, observed_at: observedAt } = evidence;
  if (
    !exactKeys(evidence, ["channel", "echo", "evidence_digest", "observed_at"])
    || channel !== "read-back"
    || typeof echo !== "string" || !ECHO.test(echo)
    || typeof digest !== "string" || !DIGEST.test(digest)
    || typeof observedAt !== "number" || !Number.isSafeInteger(observedAt) || observedAt < 0
  ) {
    throw new GatewayProtocolError("gateway returned invalid evidence");
  }
  return { channel, echo, evidenceDigest: digest, observedAt };
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
  if (outcome === "observed-by-provider") {
    if (!exactKeys(value, ["outcome", "status", "evidence"]) || !(value.status === null || validStatus(value.status))) {
      throw new GatewayProtocolError("gateway returned invalid provider observation");
    }
    return { outcome, status: value.status, evidence: parseEvidence(value.evidence) };
  }
  if (outcome === "response-recorded" || outcome === "observed") {
    const expected = outcome === "observed" ? ["outcome", "status", "matched"] : ["outcome", "status"];
    if (!exactKeys(value, expected) || !validStatus(value.status)) {
      throw new GatewayProtocolError("gateway returned invalid response stage");
    }
    if (outcome === "response-recorded") {
      return { outcome, status: value.status };
    }
    if (typeof value.matched !== "boolean") {
      throw new GatewayProtocolError("gateway returned invalid observation");
    }
    return { outcome, status: value.status, matched: value.matched };
  }
  throw new GatewayProtocolError("gateway returned unknown result stage");
}

function parseObserveResult(bytes: Uint8Array, schema: ObservationSchema): GatewayObserveResult {
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new GatewayProtocolError("gateway returned invalid JSON");
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new GatewayProtocolError("gateway returned invalid observation result");
  }
  const value = decoded as Record<string, unknown>;
  if (value.outcome === "refused") {
    if (!exactKeys(value, ["outcome", "code"]) || typeof value.code !== "string" || value.code.length < 1 || value.code.length > 128) {
      throw new GatewayProtocolError("gateway returned invalid refusal");
    }
    return { outcome: "refused", code: value.code };
  }
  if (value.outcome !== "signed") {
    throw new GatewayProtocolError("gateway returned unknown observation result");
  }
  const { subject, observed_at: observedAt, observation_b64: encoded } = value;
  if (
    !exactKeys(value, ["outcome", "schema", "subject", "observed_at", "media_type", "observation_b64"])
    || value.schema !== schema
    || value.media_type !== OBSERVATION_MEDIA_TYPE
    || typeof subject !== "string" || subject.length < 1 || utf8Length(subject) > MAX_SUBJECT_BYTES
    || typeof observedAt !== "number" || !Number.isSafeInteger(observedAt) || observedAt < 0
    || typeof encoded !== "string"
  ) {
    throw new GatewayProtocolError("gateway returned invalid signed observation");
  }
  return {
    outcome: "signed",
    schema,
    subject,
    observedAt,
    mediaType: OBSERVATION_MEDIA_TYPE,
    observation: decodeBase64Url(encoded, MAX_OBSERVATION_BYTES),
  };
}

function readBackRequest(argumentsMap: Readonly<Record<string, string>>): Record<string, unknown> {
  if (typeof argumentsMap !== "object" || argumentsMap === null || Array.isArray(argumentsMap)) {
    throw new TypeError("read-back arguments must be a bounded object");
  }
  const entries = Object.entries(argumentsMap as Record<string, unknown>);
  if (entries.length < 1 || entries.length > MAX_READ_BACK_ARGUMENTS) {
    throw new TypeError("read-back arguments must be a bounded object");
  }
  const checked: Record<string, string> = {};
  for (const [name, value] of entries) {
    if (!FIELD_NAME.test(name)) {
      throw new TypeError("read-back argument names must be recipe field names");
    }
    if (typeof value !== "string" || value.includes("\0") || value.length < 1 || utf8Length(value) > MAX_ARGUMENT_BYTES) {
      throw new TypeError("read-back argument values must be bounded strings");
    }
    checked[name] = value;
  }
  return { kind: "read-back", arguments: checked };
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

/**
 * Submit only canonical proof and action bytes, or request one read-only signed
 * observation; no credential or raw HTTP API exists.
 */
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
    return this.#exchange(payload, "outcome may be unknown", parseResult);
  }

  /**
   * Asks the gateway to read the recipe's observed field now and sign what it read.
   * `argumentsMap` names exactly the recipe observation path's fields (for example
   * `{ record_id: "rec..." }`); the gateway derives URL, subject, and time itself, and
   * the application learns the observed value. Throws `TypeError` for unbounded or
   * non-string arguments and `GatewayProtocolError` for an unavailable or malformed
   * exchange; a refusal is a result, not an exception.
   */
  async observeReadBack(argumentsMap: Readonly<Record<string, string>>): Promise<GatewayObserveResult> {
    return this.#observe(readBackRequest(argumentsMap), READ_BACK_SCHEMA);
  }

  /**
   * Asks the gateway to sign the stored outcome of one logical operation. The gateway
   * reads only its own attempt store; no provider is contacted. Throws `TypeError` for a
   * noncanonical 1-128-byte operation ID.
   */
  async observeOutcome(operationId: string): Promise<GatewayObserveResult> {
    if (typeof operationId !== "string" || !OPERATION_ID.test(operationId)) {
      throw new TypeError("operation ID must be a canonical 1-128-byte token");
    }
    return this.#observe({ kind: "outcome", operation_id: operationId }, OUTCOME_SCHEMA);
  }

  #observe(request: Record<string, unknown>, schema: ObservationSchema): Promise<GatewayObserveResult> {
    const payload = new TextEncoder().encode(JSON.stringify({ schema: OBSERVE_SCHEMA, request }));
    return this.#exchange(payload, "observation not obtained", (bytes) => parseObserveResult(bytes, schema));
  }

  #exchange<T>(payload: Uint8Array, consequence: string, parse: (bytes: Uint8Array) => T): Promise<T> {
    if (payload.length > MAX_FRAME_BYTES) {
      throw new TypeError("gateway request exceeds frame bound");
    }
    const frame = new Uint8Array(payload.length + 4);
    new DataView(frame.buffer).setUint32(0, payload.length, false);
    frame.set(payload, 4);
    return new Promise<T>((resolve, reject) => {
      const socket = createConnection({ path: this.#endpoint.path });
      const parts: Uint8Array[] = [];
      let received = 0;
      let settled = false;
      const finish = (result: { value: T } | GatewayProtocolError): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (result instanceof GatewayProtocolError) reject(result);
        else resolve(result.value);
      };
      const timer = setTimeout(() => finish(new GatewayProtocolError(`gateway exchange timed out; ${consequence}`)), 45_000);
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
            finish({ value: parse(bytes.subarray(4, length + 4)) });
          } catch {
            finish(new GatewayProtocolError(`gateway returned invalid response; ${consequence}`));
          }
        }
      });
      socket.once("error", () => finish(new GatewayProtocolError(`gateway exchange unavailable; ${consequence}`)));
      socket.once("end", () => finish(new GatewayProtocolError(`gateway response incomplete; ${consequence}`)));
    });
  }
}
