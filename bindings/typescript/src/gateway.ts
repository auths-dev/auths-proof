/**
 * Proof/action/exact-approval client for a separately operated local Auths gateway. It can also
 * ask the gateway for one read-only signed observation to attach to a later action, or
 * for the signed pre-entry observations stored for one operation.
 */

import { createConnection } from "node:net";
import { platform } from "node:os";

const REQUEST_SCHEMA = "auths.gateway-submit/2";
const OBSERVE_SCHEMA = "auths.gateway-observe/4";
const READ_BACK_SCHEMA = "auths.gateway-readback/1";
const OUTCOME_SCHEMA = "auths.gateway-outcome/3";
const OBSERVATION_MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor";
const MAX_OBSERVATION_BYTES = 4_096;
const MAX_SUBJECT_BYTES = 1_024;
const MAX_PROOF_BYTES = 4 * 1024 * 1024;
const MAX_ACTION_BYTES = 64 * 1024;
const MAX_APPROVAL_BYTES = 4_096;
const MAX_PRE_ENTRY_OBSERVATIONS = 4;
// Room for four maximal pre-entry observations in one base64url response.
const MAX_RESPONSE_BYTES = 32 * 1024;
const MAX_FRAME_BYTES = 8 * 1024 * 1024;
// A Unix socket path must fit in `sun_path` with its terminating NUL.
const SUN_PATH_BYTES = platform() === "linux" ? 108 : 104;
const MAX_SOCKET_PATH_BYTES = SUN_PATH_BYTES - 1;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const DIGEST = /^[0-9a-f]{64}$/;
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

/**
 * Operator-provisioned local application socket, never a provider URL. A Unix socket
 * path must fit in the platform's `sun_path` with its terminating NUL: at most 107
 * UTF-8 bytes on Linux and 103 elsewhere. A longer path throws a `TypeError` giving
 * the path, its length in bytes, and the maximum.
 */
export class GatewayEndpoint {
  readonly path: string;

  constructor(path: string) {
    if (typeof path !== "string" || !path.startsWith("/") || path.includes("\0")) {
      throw new TypeError("gateway endpoint must be an absolute Unix socket path");
    }
    const size = new TextEncoder().encode(path).length;
    if (size > MAX_SOCKET_PATH_BYTES) {
      throw new TypeError(
        `gateway socket path is ${size} bytes; this platform allows at most ${MAX_SOCKET_PATH_BYTES} ` +
          `(sun_path is ${SUN_PATH_BYTES} bytes, including the terminating NUL): ${path}`,
      );
    }
    this.path = path;
  }
}

/**
 * Public hiding summary of provider-held read-back evidence. Raw response bytes,
 * digest and echo stay in the protected journal; `evidenceCommitment` is a native
 * scoped HMAC, never a raw body hash; `observedAt` is gateway
 * wall-clock seconds and is not authenticated.
 */
export type GatewayProviderEvidence = Readonly<{
  channel: "read-back";
  schema: "auths.gateway-public-evidence/1";
  evidenceCommitment: string;
  observedAt: number;
}>;

/**
 * Native decision and journal stages, without effect qualification. `reserved`
 * has no entry grant; continuation needs fresh authorization. `indeterminate`
 * can mean required journal state is unavailable, not that entry was absent.
 * `observed-by-provider` means a read-back returned this attempt's echo token and the
 * verified value; anyone who knows the namespace, operation ID, and action commitment
 * can compute that token, so the link holds only while no other writer of that
 * provider field wrote the same token. Its `status` is `null` when the write was unknown.
 */
export type GatewayResult =
  | Readonly<{ outcome: "denied"; code: string }>
  | Readonly<{ outcome: "indeterminate"; code: string }>
  | Readonly<{ outcome: "not-entered"; code: string }>
  | Readonly<{ outcome: "reserved"; revision: number }>
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
  schema: "auths.gateway-readback/1" | "auths.gateway-outcome/3";
  subject: string;
  observedAt: number;
  mediaType: "application/vnd.auths.observation.v1+cbor";
  observation: Uint8Array;
}>;

/** Closed result of an observation request: signed bytes, or a refusal that signed nothing. */
export type GatewayObserveResult =
  | GatewaySignedObservation
  | Readonly<{ outcome: "refused"; code: string }>;

/** Redacted pre-entry history; protected observation bytes stay with the operator. */
export type GatewayPreEntryObservations = Readonly<{
  outcome: "pre-entry";
  operationId: string;
  observations: number;
  recordCommitment: string;
}>;

/** Closed result of a pre-entry request: the stored observations, or a refusal. */
export type GatewayPreEntryResult =
  | GatewayPreEntryObservations
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
  const { schema, channel, evidence_commitment: commitment, observed_at: observedAt } = evidence;
  if (
    !exactKeys(evidence, ["schema", "channel", "evidence_commitment", "observed_at"])
    || channel !== "read-back"
    || schema !== "auths.gateway-public-evidence/1"
    || typeof commitment !== "string" || commitment.length !== 64 || !DIGEST.test(commitment)
    || typeof observedAt !== "number" || !Number.isSafeInteger(observedAt) || observedAt < 0
  ) {
    throw new GatewayProtocolError("gateway returned invalid evidence");
  }
  return { schema, channel, evidenceCommitment: commitment, observedAt };
}

// Wire validation only: native owners still decide every authorization and stage.
function parseGatewayJson(bytes: Uint8Array): unknown {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new TypeError("gateway JSON BOM");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const stack: Array<{ keys: Set<string>; key: boolean } | null> = [];
  for (const match of text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|[{}\[\],:]/gu)) {
    const token = match[0];
    if (token === "{" || token === "[") {
      if (stack.length >= 128) throw new TypeError("gateway JSON depth");
      stack.push(token === "{" ? { keys: new Set<string>(), key: true } : null);
    } else if (token === "}" || token === "]") {
      stack.pop();
    } else if (token === ":" || token === ",") {
      const object = stack[stack.length - 1];
      if (object) object.key = token === ",";
    } else if (!token.startsWith('"')) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(token)) throw new TypeError("gateway JSON integer");
    } else {
      const value = JSON.parse(token) as string;
      for (let index = 0; index < value.length; index++) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
          const next = value.charCodeAt(++index);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError("gateway JSON Unicode");
        } else if (code >= 0xdc00 && code <= 0xdfff) {
          throw new TypeError("gateway JSON Unicode");
        }
      }
      const object = stack[stack.length - 1];
      if (object?.key) {
        if (object.keys.size >= 16 || object.keys.has(value)) throw new TypeError("gateway JSON duplicate or oversized object");
        object.keys.add(value);
      }
    }
  }
  return JSON.parse(text) as unknown;
}

function parseResult(bytes: Uint8Array): GatewayResult {
  let decoded: unknown;
  try {
    decoded = parseGatewayJson(bytes);
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
  if (outcome === "reserved") {
    if (!exactKeys(value, ["outcome", "revision"]) || typeof value.revision !== "number" || !Number.isSafeInteger(value.revision) || value.revision < 1) {
      throw new GatewayProtocolError("gateway returned invalid reservation");
    }
    return { outcome, revision: value.revision };
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
    decoded = parseGatewayJson(bytes);
  } catch {
    throw new GatewayProtocolError("gateway returned invalid JSON");
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new GatewayProtocolError("gateway returned invalid observation result");
  }
  const value = decoded as Record<string, unknown>;
  if (value.outcome === "refused") {
    return parseRefusal(value);
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

function parseRefusal(value: Record<string, unknown>): Readonly<{ outcome: "refused"; code: string }> {
  if (!exactKeys(value, ["outcome", "code"]) || typeof value.code !== "string" || value.code.length < 1 || value.code.length > 128) {
    throw new GatewayProtocolError("gateway returned invalid refusal");
  }
  return { outcome: "refused", code: value.code };
}

function parsePreEntryResult(bytes: Uint8Array, operationId: string): GatewayPreEntryResult {
  let decoded: unknown;
  try {
    decoded = parseGatewayJson(bytes);
  } catch {
    throw new GatewayProtocolError("gateway returned invalid JSON");
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new GatewayProtocolError("gateway returned invalid pre-entry result");
  }
  const value = decoded as Record<string, unknown>;
  if (value.outcome === "refused") {
    return parseRefusal(value);
  }
  const observations = value.observations;
  const commitment = value.record_commitment;
  if (
    value.outcome !== "pre-entry"
    || !exactKeys(value, ["outcome", "operation_id", "observations", "record_commitment"])
    || value.operation_id !== operationId
    || !Number.isSafeInteger(observations)
    || (observations as number) < 0 || (observations as number) > MAX_PRE_ENTRY_OBSERVATIONS
    || typeof commitment !== "string" || commitment.length !== 64 || !/^[0-9a-f]{64}$/u.test(commitment)
  ) {
    throw new GatewayProtocolError("gateway returned invalid pre-entry history");
  }
  return { outcome: "pre-entry", operationId, observations: observations as number, recordCommitment: commitment };
}

function submission(input: Readonly<{ proof: Uint8Array; action: Uint8Array; approval: Uint8Array }>): Record<string, string> {
  if (!(input.proof instanceof Uint8Array) || input.proof.length < 1 || input.proof.length > MAX_PROOF_BYTES) {
    throw new TypeError("proof must be bounded bytes");
  }
  if (!(input.action instanceof Uint8Array) || input.action.length < 1 || input.action.length > MAX_ACTION_BYTES) {
    throw new TypeError("action must be bounded bytes");
  }
  if (!(input.approval instanceof Uint8Array) || input.approval.length < 1 || input.approval.length > MAX_APPROVAL_BYTES) {
    throw new TypeError("approval must be bounded native canonical bytes");
  }
  return { schema: REQUEST_SCHEMA, proof_b64: encodeBase64Url(input.proof),
    action_b64: encodeBase64Url(input.action), approval_b64: encodeBase64Url(input.approval) };
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
 * Submit exact approved effects, acquire approved recovery evidence, or inspect
 * retained local history. No credential or raw HTTP API exists.
 */
export class GatewayClient {
  readonly #endpoint: GatewayEndpoint;

  constructor(endpoint: GatewayEndpoint) {
    if (!(endpoint instanceof GatewayEndpoint)) {
      throw new TypeError("endpoint must be a GatewayEndpoint");
    }
    this.#endpoint = endpoint;
  }

  async submit(input: Readonly<{ proof: Uint8Array; action: Uint8Array; approval: Uint8Array }>): Promise<GatewayResult> {
    const payload = new TextEncoder().encode(JSON.stringify(submission(input)));
    return this.#exchange(payload, "outcome may be unknown", parseResult);
  }

  /** Returns bounded native recovery-report/refusal JSON unchanged. The separately
   * approved read uses native admission and accounting. No provider content is
   * disclosed. A lost response never authorizes a retry. */
  async recover(sourceOperation: string, input: Readonly<{ proof: Uint8Array; action: Uint8Array; approval: Uint8Array }>): Promise<Uint8Array> {
    if (typeof sourceOperation !== "string" || !OPERATION_ID.test(sourceOperation)) {
      throw new TypeError("operation ID must be a canonical 1-128-byte token");
    }
    const payload = new TextEncoder().encode(JSON.stringify({ schema: "auths.gateway-recover/1",
      source_operation: sourceOperation, submission: submission(input) }));
    return this.#exchange(payload, "recovery outcome may be unknown", (bytes) => bytes);
  }

  /** Native acquisition facts only. Resources come from the signed action;
   * no content is released and a lost reply never permits another read. */
  async acquireContent(input: Readonly<{ proof: Uint8Array; action: Uint8Array; approval: Uint8Array }>): Promise<Uint8Array> {
    const payload = new TextEncoder().encode(JSON.stringify({ schema: "auths.gateway-content/1", submission: submission(input) }));
    return this.#exchange(payload, "content acquisition may be unknown", (bytes) => bytes);
  }

  /** Redacted native history, unchanged, with no provider or recipient I/O. */
  async contentHistory(operation: string): Promise<Uint8Array> {
    if (typeof operation !== "string" || !OPERATION_ID.test(operation)) {
      throw new TypeError("operation ID must be a canonical 1-128-byte token");
    }
    const payload = new TextEncoder().encode(JSON.stringify({ schema: "auths.gateway-content-history/1", operation }));
    return this.#exchange(payload, "content history unavailable", (bytes) => bytes);
  }

  /** Carries canonical ACK bytes produced by the native recipient client.
   * Rust alone checks signatures and retained grants; this never redelivers. */
  async acknowledgeDisclosure(operation: string, acknowledgement: Uint8Array): Promise<Uint8Array> {
    if (typeof operation !== "string" || !OPERATION_ID.test(operation)) {
      throw new TypeError("operation ID must be a canonical 1-128-byte token");
    }
    if (!(acknowledgement instanceof Uint8Array) || acknowledgement.length < 1 || acknowledgement.length > 4096) {
      throw new TypeError("acknowledgement must be 1-4096 native canonical bytes");
    }
    const payload = new TextEncoder().encode(JSON.stringify({ schema: "auths.gateway-disclosure-acknowledge/1",
      operation, acknowledgement_b64: encodeBase64Url(acknowledgement) }));
    return this.#exchange(payload, "disclosure acknowledgement persistence may be unknown", (bytes) => bytes);
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

  /**
   * Asks the gateway for one operation's stored pre-entry observations. The gateway reads
   * only its own attempt store: it signs nothing new and contacts no provider. Throws
   * `TypeError` for a noncanonical 1-128-byte operation ID.
   */
  async observePreEntry(operationId: string): Promise<GatewayPreEntryResult> {
    if (typeof operationId !== "string" || !OPERATION_ID.test(operationId)) {
      throw new TypeError("operation ID must be a canonical 1-128-byte token");
    }
    const payload = new TextEncoder().encode(JSON.stringify({
      schema: OBSERVE_SCHEMA,
      request: { kind: "pre-entry", operation_id: operationId },
    }));
    return this.#exchange(payload, "observations not obtained", (bytes) => parsePreEntryResult(bytes, operationId));
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
      socket.once("error", (error) =>
        finish(new GatewayProtocolError(`gateway exchange unavailable; ${consequence}; path=${this.#endpoint.path}: ${error.message}`)),
      );
      socket.once("end", () => finish(new GatewayProtocolError(`gateway response incomplete; ${consequence}`)));
    });
  }
}
