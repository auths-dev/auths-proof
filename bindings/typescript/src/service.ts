import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";
import { classifyErrorCode, type ProductVerb } from "./product-errors.js";

/**
 * The remote Auths runtime client.
 *
 * This is a DIFFERENT product from the local facade at `@auths-dev/sdk`: it
 * calls an Auths service over HTTPS and shares no method with it. The two used
 * to be published side by side at one entry point as `X` and `ProductionX`,
 * which asked every reader to work out which of two APIs they were holding.
 * They are separate entry points now, and the local facade keeps no import edge
 * to this one.
 */

/** A profile the remote runtime routes on. */
export type ServiceProfileId =
  | "auths.opentofu.saved-plan-apply/1"
  | "auths.postgresql.bounded-update/1"
  | "auths.github.issue-address/1";

export interface ServiceProfile {
  readonly id: ServiceProfileId;
}

export function opentofuSavedPlanApply(): ServiceProfile {
  return Object.freeze({ id: "auths.opentofu.saved-plan-apply/1" });
}

export function postgresqlBoundedUpdate(): ServiceProfile {
  return Object.freeze({ id: "auths.postgresql.bounded-update/1" });
}

export function githubIssueAddress(): ServiceProfile {
  return Object.freeze({ id: "auths.github.issue-address/1" });
}

const CONTENT_TYPE = "application/auths+cbor";
const MAX_RESPONSE_BYTES = 1_048_576;
const DEFAULT_TIMEOUT_MS = 15_000;
const authorityBytes = new WeakMap<ServiceAuthority, Uint8Array>();
const receiptBytes = new WeakMap<ServiceReceipt, Uint8Array>();
const referenceValues = new WeakMap<ServiceRecoveryReference, string>();

/**
 * Answers *what should I call next?* — `auths_production_client::NextCall`.
 *
 * This is not {@link NextCall}, which answers *may I retry?*. Rust renamed
 * this type precisely so the two questions stop sharing an identifier: a
 * caller reading `backoff` is being told nothing happened, which is a claim
 * about the effect axis, not about permission to retry.
 */
export type NextCall = "never" | "backoff" | "resume" | "reconcile";

export interface ServiceTransportRequest {
  readonly url: URL;
  readonly body: Uint8Array;
  readonly contentType: typeof CONTENT_TYPE;
  readonly timeoutMs: number;
}

export interface ServiceTransportResponse {
  readonly status: number;
  readonly contentType: string;
  readonly body: Uint8Array;
}

export interface ServiceTransport {
  send(request: ServiceTransportRequest): Promise<ServiceTransportResponse>;
}

export interface ServiceClientOptions {
  readonly endpoint: string | URL;
  readonly identity: Uint8Array;
  readonly profile: ServiceProfile;
  readonly transport?: ServiceTransport;
  readonly timeoutMs?: number;
}

export interface ServiceAuthority {
  readonly kind: "authority";
  toJSON(): never;
}

class ServiceAuthorityValue implements ServiceAuthority {
  readonly kind = "authority" as const;

  constructor(bytes: Uint8Array) {
    authorityBytes.set(this, bytes.slice());
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError("Auths authority is opaque");
  }
}

export interface ServiceReceipt {
  readonly kind: "receipt";
  toJSON(): never;
}

class ServiceReceiptValue implements ServiceReceipt {
  readonly kind = "receipt" as const;

  constructor(bytes: Uint8Array) {
    receiptBytes.set(this, bytes.slice());
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError("Auths receipt bytes require an explicit disclosure operation");
  }
}

export interface ServiceRecoveryReference {
  readonly kind: "recovery-reference";
  toJSON(): never;
}

class ServiceRecoveryReferenceValue implements ServiceRecoveryReference {
  readonly kind = "recovery-reference" as const;

  constructor(value: string) {
    referenceValues.set(this, value);
    Object.freeze(this);
  }

  toJSON(): never {
    throw new TypeError("Auths recovery references are opaque");
  }
}

export interface ServiceDenied {
  readonly kind: "denied";
  readonly verb: ProductVerb;
  readonly code: string;
  readonly retry: "never";
}

export interface ServiceIndeterminate {
  readonly kind: "indeterminate";
  readonly verb: ProductVerb;
  readonly code: string;
  readonly retry: "backoff" | "reconcile";
}

export interface ServiceRecoverable {
  readonly kind: "recoverable";
  readonly verb: "execute" | "resume";
  readonly code: string;
  readonly retry: "resume";
  readonly reference: ServiceRecoveryReference;
}

export interface ServiceCompleted {
  readonly kind: "completed";
  readonly verb: "execute" | "resume";
  readonly value?: Uint8Array;
  readonly receipt: ServiceReceipt;
}

export interface ServiceVerified {
  readonly kind: "verified";
  readonly verb: "verify";
  readonly value?: Uint8Array;
}

export interface ServiceRejected {
  readonly kind: "rejected";
  readonly verb: "verify";
  readonly code: string;
  readonly retry: "never";
}

export type ServiceAuthorityResult = ServiceAuthority | ServiceDenied | ServiceIndeterminate;
export type ServiceExecutionResult = ServiceCompleted | ServiceDenied | ServiceIndeterminate | ServiceRecoverable;
export type ServiceVerificationResult = ServiceVerified | ServiceRejected | ServiceIndeterminate;

export interface ServiceClient {
  create(request: Uint8Array): Promise<ServiceAuthorityResult>;
  delegate(
    authority: ServiceAuthority,
    subject: Uint8Array,
    attenuation?: Uint8Array,
  ): Promise<ServiceAuthorityResult>;
  execute(authority: ServiceAuthority, action: Uint8Array): Promise<ServiceExecutionResult>;
  resume(reference: ServiceRecoveryReference): Promise<ServiceExecutionResult>;
  verify(value: ServiceAuthority | ServiceReceipt | Uint8Array): Promise<ServiceVerificationResult>;
}

interface NativeProductionEngine {
  productionClientContractVersionV1(): number;
  encodeProductionRequestV1(input: Readonly<{
    readonly verb: ProductVerb;
    readonly profile: string;
    readonly identity: Uint8Array;
    readonly authority?: Uint8Array;
    readonly body?: Uint8Array;
    readonly recoveryReference?: string;
  }>): Uint8Array;
  decodeProductionResponseV1(input: Uint8Array): string;
  productionTransportFailureV1(verb: string, failure: string): string;
  decodeProductionRequestV1(input: Uint8Array): string;
  encodeProductionDelegationV1(subject: Uint8Array, attenuation: Uint8Array): Uint8Array;
}

interface NativeProjection {
  readonly contractVersion: number;
  readonly kind: "completed" | "denied" | "indeterminate" | "recoverable" | "verified" | "rejected";
  readonly code: string | null;
  readonly retry: NextCall;
  readonly recoveryReference: string | null;
  readonly value: string | null;
  readonly receipt: string | null;
}

class ServiceClientValue implements ServiceClient {
  readonly #endpoint: URL;
  readonly #identity: Uint8Array;
  readonly #profile: ServiceProfile;
  readonly #transport: ServiceTransport;
  readonly #timeoutMs: number;

  constructor(options: ServiceClientOptions) {
    this.#endpoint = parseEndpoint(options.endpoint);
    if (!(options.identity instanceof Uint8Array) || options.identity.length === 0 || options.identity.length > 65_536) {
      throw new TypeError("Auths identity bytes are outside production bounds");
    }
    if (!isServiceProfile(options.profile)) throw new TypeError("Auths production profile is unsupported");
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
      throw new TypeError("Auths production timeout is outside bounds");
    }
    this.#identity = options.identity.slice();
    this.#profile = options.profile;
    this.#transport = options.transport ?? fetchServiceTransport;
    this.#timeoutMs = timeoutMs;
  }

  async create(request: Uint8Array): Promise<ServiceAuthorityResult> {
    const projection = await this.#call("create", request);
    if (projection.kind === "completed") {
      return serviceAuthority(requiredValue(projection));
    }
    return projectAuthorityFailure("create", projection);
  }

  async delegate(
    authority: ServiceAuthority,
    subject: Uint8Array,
    attenuation: Uint8Array = new Uint8Array([0x80]),
  ): Promise<ServiceAuthorityResult> {
    const authorityValue = readAuthority(authority);
    const body = await encodeDelegationInput(subject, attenuation);
    const projection = await this.#call("delegate", body, authorityValue);
    if (projection.kind === "completed") {
      return serviceAuthority(requiredValue(projection));
    }
    return projectAuthorityFailure("delegate", projection);
  }

  async execute(authority: ServiceAuthority, action: Uint8Array): Promise<ServiceExecutionResult> {
    return projectExecution("execute", await this.#call("execute", action, readAuthority(authority)));
  }

  async resume(reference: ServiceRecoveryReference): Promise<ServiceExecutionResult> {
    const value = referenceValues.get(reference);
    if (value === undefined) throw new TypeError("forged Auths recovery reference");
    return projectExecution("resume", await this.#call("resume", undefined, undefined, value));
  }

  async verify(value: ServiceAuthority | ServiceReceipt | Uint8Array): Promise<ServiceVerificationResult> {
    const bytes = value instanceof Uint8Array
      ? value
      : value.kind === "authority"
        ? readAuthority(value)
        : readReceipt(value);
    const projection = await this.#call("verify", bytes);
    if (projection.kind === "verified") {
      return Object.freeze({
        kind: "verified" as const,
        verb: "verify" as const,
        ...(projection.value === null ? {} : { value: decodeBase64Url(projection.value) }),
      });
    }
    if (projection.kind === "rejected") {
      return Object.freeze({ kind: "rejected" as const, verb: "verify" as const, code: requiredCode(projection), retry: "never" as const });
    }
    if (projection.kind === "indeterminate") return projectIndeterminate("verify", projection);
    throw new TypeError("native response outcome does not match verify");
  }

  async #call(
    verb: ProductVerb,
    body?: Uint8Array,
    authority?: Uint8Array,
    recoveryReference?: string,
  ): Promise<NativeProjection> {
    const engine = await productionEngine();
    const requestBody = engine.encodeProductionRequestV1({
      verb: verb,
      profile: this.#profile.id,
      identity: this.#identity,
      ...(authority === undefined ? {} : { authority }),
      ...(body === undefined ? {} : { body }),
      ...(recoveryReference === undefined ? {} : { recoveryReference }),
    });
    const path = endpointPath(verb, this.#profile.id);
    let response: ServiceTransportResponse;
    try {
      response = await this.#transport.send(Object.freeze({
        url: new URL(path, this.#endpoint),
        body: requestBody,
        contentType: CONTENT_TYPE,
        timeoutMs: this.#timeoutMs,
      }));
    } catch (error) {
      return await transportFailure(engine, verb, observedFailure(error));
    }
    // A response that is not a bounded product response proves nothing about
    // what the server did with the request it already received.
    if (response.status < 200 || response.status >= 300 || normalizeContentType(response.contentType) !== CONTENT_TYPE) {
      return await transportFailure(engine, verb, "unusable-response");
    }
    if (!(response.body instanceof Uint8Array) || response.body.length === 0 || response.body.length > MAX_RESPONSE_BYTES) {
      throw new TypeError("Auths production response is outside bounds");
    }
    return parseProjection(engine.decodeProductionResponseV1(response.body));
  }
}

export function createServiceClient(options: ServiceClientOptions): ServiceClient {
  return new ServiceClientValue(options);
}

const fetchServiceTransport: ServiceTransport = Object.freeze({
  async send(request: ServiceTransportRequest): Promise<ServiceTransportResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), request.timeoutMs);
    try {
      const response = await fetch(request.url, {
        method: "POST",
        body: request.body as BodyInit,
        headers: Object.freeze({ "content-type": request.contentType, accept: request.contentType }),
        redirect: "error",
        credentials: "omit",
        signal: controller.signal,
      });
      const declared = Number(response.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
        throw new TypeError("Auths production response is outside bounds");
      }
      const body = await readBoundedBody(response);
      return Object.freeze({
        status: response.status,
        contentType: response.headers.get("content-type") ?? "",
        body,
      });
    } finally {
      clearTimeout(timeout);
    }
  },
});

async function productionEngine(): Promise<NativeProductionEngine> {
  const engine = await loadPackagedWorkflowEngine();
  const native = engine as unknown as NativeProductionEngine;
  if (native.productionClientContractVersionV1() !== 1) {
    throw new TypeError("Auths production client contract mismatch");
  }
  return native;
}

async function encodeDelegationInput(subject: Uint8Array, attenuation: Uint8Array): Promise<Uint8Array> {
  if (!(subject instanceof Uint8Array) || subject.length === 0 || subject.length > 65_536
      || !(attenuation instanceof Uint8Array) || attenuation.length === 0 || attenuation.length > 65_536) {
    throw new TypeError("Auths delegation input is outside bounds");
  }
  return (await productionEngine()).encodeProductionDelegationV1(subject, attenuation);
}


/**
 * Closed classification of one transport failure — `TransportFailure` in Rust.
 *
 * The only thing this client may decide is what its transport can PROVE. Which
 * registry code and which next call that failure earns is Rust's, because the
 * answer is a claim about whether the real-world effect happened.
 */
export type TransportFailure =
  | "endpoint-unresolvable"
  | "connection-refused"
  | "connection-failed"
  | "connection-lost"
  | "response-timeout"
  | "cancelled"
  | "unusable-response";

/**
 * Reports only what the platform actually proved about a failed send.
 *
 * `fetch` rejects with an opaque `TypeError` for DNS failure, connection
 * refusal, and a connection lost after the request was written. Those are not
 * distinguishable here, so this reports `connection-failed`, the variant Rust
 * documents as "failed without proving whether request bytes were written" —
 * which fails closed to a possible effect. Claiming `connection-refused`
 * because the message happens to say so would be asserting a non-effect this
 * client cannot prove.
 */
function observedFailure(error: unknown): TransportFailure {
  if (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "AbortError") {
    return "response-timeout";
  }
  if (error instanceof Error && error.name === "TimeoutError") return "response-timeout";
  return "connection-failed";
}

/** Asks Rust what one transport failure means for this verb. */
async function transportFailure(
  engine: NativeProductionEngine,
  verb: ProductVerb,
  failure: TransportFailure,
): Promise<NativeProjection> {
  return parseProjection(engine.productionTransportFailureV1(verb, failure));
}

function parseEndpoint(value: string | URL): URL {
  const endpoint = new URL(value);
  if (endpoint.protocol !== "https:" || endpoint.username !== "" || endpoint.password !== ""
      || endpoint.search !== "" || endpoint.hash !== "" || !["", "/"].includes(endpoint.pathname)) {
    throw new TypeError("Auths production endpoint must be an HTTPS origin");
  }
  return endpoint;
}

function isServiceProfile(value: ServiceProfile): boolean {
  return value !== null && typeof value === "object" && [
    "auths.opentofu.saved-plan-apply/1",
    "auths.postgresql.bounded-update/1",
    "auths.github.issue-address/1",
  ].includes(value.id);
}

function endpointPath(verb: ProductVerb, profile: ServiceProfile["id"]): string {
  if (verb === "create") return "/v1/authority/create";
  if (verb === "delegate") return "/v1/authority/delegate";
  if (verb === "resume") return "/v1/workflows/resume";
  if (verb === "verify") return "/v1/authority/verify";
  if (profile === "auths.opentofu.saved-plan-apply/1") return "/v1/profiles/opentofu/saved-plan-apply/execute";
  if (profile === "auths.postgresql.bounded-update/1") return "/v1/profiles/postgresql/bounded-update/execute";
  return "/v1/profiles/github/issue-address/execute";
}

function parseProjection(value: string): NativeProjection {
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== "object") throw new TypeError("native response projection is invalid");
  const projection = parsed as Record<string, unknown>;
  if (projection.contractVersion !== 1
      || !["completed", "denied", "indeterminate", "recoverable", "verified", "rejected"].includes(String(projection.kind))
      || !["never", "backoff", "resume", "reconcile"].includes(String(projection.retry))) {
    throw new TypeError("native response projection is invalid");
  }
  return projection as unknown as NativeProjection;
}

function projectAuthorityFailure(verb: "create" | "delegate", projection: NativeProjection): ServiceDenied | ServiceIndeterminate {
  if (projection.kind === "denied") {
    return Object.freeze({ kind: "denied", verb, code: requiredCode(projection), retry: "never" });
  }
  if (projection.kind === "indeterminate") return projectIndeterminate(verb, projection);
  throw new TypeError(`native response outcome does not match ${verb}`);
}

function projectExecution(verb: "execute" | "resume", projection: NativeProjection): ServiceExecutionResult {
  if (projection.kind === "completed") {
    if (projection.receipt === null) throw new TypeError("native response omitted receipt bytes");
    return Object.freeze({
      kind: "completed",
      verb,
      ...(projection.value === null ? {} : { value: decodeBase64Url(projection.value) }),
      receipt: serviceReceipt(decodeBase64Url(projection.receipt)),
    });
  }
  if (projection.kind === "denied") {
    return Object.freeze({ kind: "denied", verb, code: requiredCode(projection), retry: "never" });
  }
  if (projection.kind === "indeterminate") return projectIndeterminate(verb, projection);
  if (projection.kind === "recoverable" && projection.recoveryReference !== null) {
    return Object.freeze({
      kind: "recoverable",
      verb,
      code: requiredCode(projection),
      retry: "resume",
      reference: serviceRecoveryReference(projection.recoveryReference),
    });
  }
  throw new TypeError(`native response outcome does not match ${verb}`);
}

function projectIndeterminate(verb: ProductVerb, projection: NativeProjection): ServiceIndeterminate {
  if (projection.retry !== "backoff" && projection.retry !== "reconcile") {
    throw new TypeError("native indeterminate result has invalid retry class");
  }
  return Object.freeze({ kind: "indeterminate", verb, code: requiredCode(projection), retry: projection.retry });
}

function serviceAuthority(bytes: Uint8Array): ServiceAuthority {
  if (bytes.length === 0) throw new TypeError("native response omitted authority bytes");
  return new ServiceAuthorityValue(bytes);
}

function serviceReceipt(bytes: Uint8Array): ServiceReceipt {
  if (bytes.length === 0) throw new TypeError("native response omitted receipt bytes");
  return new ServiceReceiptValue(bytes);
}

function serviceRecoveryReference(value: string): ServiceRecoveryReference {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new TypeError("native response returned an invalid recovery reference");
  }
  return new ServiceRecoveryReferenceValue(value);
}

function requiredValue(projection: NativeProjection): Uint8Array {
  if (projection.value === null) throw new TypeError("native response omitted value bytes");
  return decodeBase64Url(projection.value);
}

function requiredCode(projection: NativeProjection): string {
  if (projection.code === null) throw new TypeError("native response omitted stable error code");
  return projection.code;
}

function readAuthority(authority: ServiceAuthority): Uint8Array {
  const value = authorityBytes.get(authority);
  if (value === undefined) throw new TypeError("forged Auths authority");
  return value.slice();
}

function readReceipt(receipt: ServiceReceipt): Uint8Array {
  const value = receiptBytes.get(receipt);
  if (value === undefined) throw new TypeError("forged Auths receipt");
  return value.slice();
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new TypeError("native response encoding is invalid");
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function normalizeContentType(value: string): string {
  return value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
}

async function readBoundedBody(response: Response): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new TypeError("Auths production response is outside bounds");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}
