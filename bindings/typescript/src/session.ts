import { decodeDeterministic, encodeDeterministic } from "./internal/cbor.js";
import { parsePortableReceipt } from "./internal/receipt.js";
import { runtimeInfo, type Receipt } from "./index.js";
import type { AuthsIssue, EffectState, RecommendedAction, RetryClass } from "./product-errors.js";
import { AuthsError, parseAuthsErrorEnvelope } from "./product-errors.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

const MEDIA_TYPE = "application/auths+cbor;version=1";
const MAX_RESPONSE = 16_777_216;
const MAX_QUEUED_CALLS = 256;
const QUALIFICATION_RESULT_SOCKET_ENV = "AUTHS_QUALIFICATION_CLIENT_RESULT_SOCKET";
const recoveryToken = Symbol("auths recovery handle");
const operationErrorToken = Symbol("auths operation error");

export interface ClientOptions { readonly agentSocket?: string; readonly connectTimeoutMs?: number }
export interface OperationOptions { readonly idempotencyKey?: string; readonly timeoutMs?: number; readonly recoveryWaitMs?: number; readonly signal?: AbortSignal }
export interface RecoveryOptions { readonly timeoutMs?: number; readonly recoveryWaitMs?: number; readonly signal?: AbortSignal }
export interface OperationMetadata { readonly operationId: string; readonly profile: string; readonly connection: string | null; readonly completion: "fresh" | "replayed" | "reconciled"; readonly receiptIds: readonly string[] }
export type OperationState = "preparing" | "denied" | "unavailable" | "ready" | "executing" | "recovery-required" | "completed" | "partial" | "not-applied";
export interface OperationStatus { readonly operationId: string; readonly profile: string; readonly connection: string | null; readonly state: OperationState; readonly effect: "not-applied" | "possible" | "applied"; readonly terminal: boolean; readonly receiptIds: readonly string[]; readonly recovery?: RecoveryHandle }
export interface RecoveryHandle { toBytes(): Uint8Array }
export interface Operations { recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<OperationStatus>; pending(options?: { readonly signal?: AbortSignal }): Promise<readonly OperationStatus[]>; receipts(operationId: string, options?: { readonly signal?: AbortSignal }): Promise<readonly Receipt[]> }
export interface Client extends AsyncDisposable { readonly operations: Operations; close(): Promise<void> }

export class ClientStateError extends Error {}

class PostWriteRequestError extends Error {
  constructor(readonly cause: unknown) { super("local Auths request failed after the request may have been written"); this.name = "PostWriteRequestError"; }
}

/** @internal Used by the generated profile runtime to distinguish safe cancellation from ambiguity. */
export function isPostWriteRequestError(value: unknown): boolean { return value instanceof PostWriteRequestError; }

/** @internal Returns the exact transport cause after a possibly written request. */
export function postWriteRequestCause(value: unknown): unknown | undefined { return value instanceof PostWriteRequestError ? value.cause : undefined; }

export abstract class AuthsOperationError extends AuthsError {
  readonly operationId: string | null;
  readonly receiptIds: readonly string[];
  readonly recovery?: RecoveryHandle;
  readonly details?: unknown;
  readonly progress?: unknown;
  protected constructor(token: symbol, issue: AuthsIssue, operationId: string | null, receiptIds: readonly string[], extras: Readonly<{ recovery?: RecoveryHandle; details?: unknown; progress?: unknown }> = {}) {
    if (token !== operationErrorToken) throw new TypeError("Auths operation errors are SDK-constructible only");
    super(issue);
    this.operationId = operationId;
    this.receiptIds = Object.freeze([...receiptIds]);
    Object.assign(this, extras);
  }
}

let mintDeniedError: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[]) => DeniedError;
let mintUnavailableError: (issue: AuthsIssue, operationId: string | null, receiptIds: readonly string[]) => UnavailableError;
let mintConflictError: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[], recovery: RecoveryHandle) => ConflictError;
let mintNotAppliedError: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[]) => NotAppliedError;
let mintPartialError: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[], details: unknown) => PartialError;
let mintRecoveryRequiredError: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[], recovery: RecoveryHandle, progress: unknown) => RecoveryRequiredError;
let mintReceiptIntegrityError: (issue: AuthsIssue, operationId: string, state: OperationState, terminal: boolean) => ReceiptIntegrityError;

export class DeniedError extends AuthsOperationError { private constructor(token: symbol, issue: AuthsIssue, operationId: string, receiptIds: readonly string[]) { super(token, issue, operationId, receiptIds); } static { mintDeniedError = (issue, operationId, receiptIds) => new DeniedError(operationErrorToken, issue, operationId, receiptIds); } }
export class UnavailableError extends AuthsOperationError { private constructor(token: symbol, issue: AuthsIssue, operationId: string | null, receiptIds: readonly string[]) { super(token, issue, operationId, receiptIds); } static { mintUnavailableError = (issue, operationId, receiptIds) => new UnavailableError(operationErrorToken, issue, operationId, receiptIds); } }
export class ConflictError extends AuthsOperationError { declare readonly recovery: RecoveryHandle; private constructor(token: symbol, issue: AuthsIssue, operationId: string, receiptIds: readonly string[], recovery: RecoveryHandle) { super(token, issue, operationId, receiptIds, { recovery }); } static { mintConflictError = (issue, operationId, receiptIds, recovery) => new ConflictError(operationErrorToken, issue, operationId, receiptIds, recovery); } }
export class NotAppliedError extends AuthsOperationError { private constructor(token: symbol, issue: AuthsIssue, operationId: string, receiptIds: readonly string[]) { super(token, issue, operationId, receiptIds); } static { mintNotAppliedError = (issue, operationId, receiptIds) => new NotAppliedError(operationErrorToken, issue, operationId, receiptIds); } }
export class PartialError extends AuthsOperationError { declare readonly details: unknown; private constructor(token: symbol, issue: AuthsIssue, operationId: string, receiptIds: readonly string[], details: unknown) { super(token, issue, operationId, receiptIds, { details }); } static { mintPartialError = (issue, operationId, receiptIds, details) => new PartialError(operationErrorToken, issue, operationId, receiptIds, details); } }
export class RecoveryRequiredError extends AuthsOperationError { declare readonly recovery: RecoveryHandle; declare readonly progress: unknown; private constructor(token: symbol, issue: AuthsIssue, operationId: string, receiptIds: readonly string[], recovery: RecoveryHandle, progress: unknown) { super(token, issue, operationId, receiptIds, { recovery, progress }); } static { mintRecoveryRequiredError = (issue, operationId, receiptIds, recovery, progress) => new RecoveryRequiredError(operationErrorToken, issue, operationId, receiptIds, recovery, progress); } }
export class ReceiptIntegrityError extends AuthsOperationError { declare readonly state: OperationState; declare readonly terminal: boolean; private constructor(token: symbol, issue: AuthsIssue, operationId: string, state: OperationState, terminal: boolean) { super(token, issue, operationId, []); this.state = state; this.terminal = terminal; } static { mintReceiptIntegrityError = (issue, operationId, state, terminal) => new ReceiptIntegrityError(operationErrorToken, issue, operationId, state, terminal); } }

/** @internal Trusted SDK factories; not re-exported from the package root. */
export const operationErrors = Object.freeze({
  denied: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[]) => mintDeniedError(issue, operationId, receiptIds),
  unavailable: (issue: AuthsIssue, operationId: string | null, receiptIds: readonly string[]) => mintUnavailableError(issue, operationId, receiptIds),
  conflict: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[], recovery: RecoveryHandle) => mintConflictError(issue, operationId, receiptIds, recovery),
  notApplied: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[]) => mintNotAppliedError(issue, operationId, receiptIds),
  partial: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[], details: unknown) => mintPartialError(issue, operationId, receiptIds, details),
  recoveryRequired: (issue: AuthsIssue, operationId: string, receiptIds: readonly string[], recovery: RecoveryHandle, progress: unknown) => mintRecoveryRequiredError(issue, operationId, receiptIds, recovery, progress),
  receiptIntegrity: (issue: AuthsIssue, operationId: string, state: OperationState, terminal: boolean) => mintReceiptIntegrityError(issue, operationId, state, terminal),
});

class SealedRecoveryHandle implements RecoveryHandle {
  readonly #bytes: Uint8Array;
  constructor(token: symbol, value: Uint8Array) {
    if (token !== recoveryToken || !(value instanceof Uint8Array) || value.length < 1 || value.length > 16_384) throw new TypeError("invalid recovery handle");
    this.#bytes = value.slice(); Object.freeze(this);
  }
  toBytes(): Uint8Array { return this.#bytes.slice(); }
}

export function recoveryHandleFromBytes(value: Uint8Array): RecoveryHandle { return new SealedRecoveryHandle(recoveryToken, value); }

export interface ProfileCapability {
  readonly profileId: string; readonly version: number; readonly runtimeDigest: Uint8Array;
  readonly operationProtocol: "auths.profile-operation/1"; readonly errorDigest: Uint8Array;
  readonly connection: Readonly<{ providerKind: string; contract: string; descriptorSchema: string }> | null;
  readonly qualification: Readonly<{ qualificationId: string; target: "linux-x86_64" | "linux-aarch64" | "macos-x86_64" | "macos-aarch64"; semanticClosureSha256: Uint8Array }> | null;
}

interface AdmissionWaiter {
  readonly signal?: AbortSignal;
  readonly resolve: () => void;
  readonly reject: (error: unknown) => void;
  readonly abort: () => void;
}

export interface CoordinatedOperationIdentity {
  readonly requestId: Uint8Array;
  readonly operationId: string;
  readonly initial: Uint8Array;
}

export interface ProfileInvocationTicket {
  readonly role: "leader" | "follower" | "observer" | "conflict-probe";
  readonly requestId: Uint8Array;
  readonly identity: Promise<CoordinatedOperationIdentity | null>;
}

interface ProfileInvocationEntry {
  readonly fingerprint: string;
  readonly requestId: Uint8Array;
  readonly identity: Promise<CoordinatedOperationIdentity | null>;
  readonly resolveIdentity: (identity: CoordinatedOperationIdentity | null) => void;
  waiters: number;
  published: boolean;
  hasOperation: boolean;
  settled: boolean;
  status: Promise<Uint8Array> | undefined;
}

const profileInvocationTickets = new WeakMap<ProfileInvocationTicket, Readonly<{ client: LocalClient; scope: string; entry?: ProfileInvocationEntry; attached: boolean }>>();

/** @internal Bounded FIFO gate used by one authenticated SDK session. */
export class SdkAdmissionGate {
  readonly #maximum: number;
  readonly #waiters: AdmissionWaiter[] = [];
  #active = 0;
  #closed = false;

  constructor(maximum: number) {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 32) throw new RangeError("invalid SDK admission limit");
    this.#maximum = maximum;
  }

  async run<T>(action: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    await this.acquire(signal);
    try {
      if (signal?.aborted) throw cancellationError();
      return await action();
    } finally {
      this.release();
    }
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    const error = new ClientStateError("auths client is closed");
    for (const waiter of this.#waiters.splice(0)) {
      waiter.signal?.removeEventListener("abort", waiter.abort);
      waiter.reject(error);
    }
  }

  private async acquire(signal?: AbortSignal): Promise<void> {
    if (this.#closed) throw new ClientStateError("auths client is closed");
    if (signal?.aborted) throw cancellationError();
    if (this.#active < this.#maximum) { this.#active += 1; return; }
    if (this.#waiters.length >= MAX_QUEUED_CALLS) throw operationErrors.unavailable(admissionIssue(), null, []);
    await new Promise<void>((resolve, reject) => {
      const waiter: AdmissionWaiter = {
        ...(signal === undefined ? {} : { signal }),
        resolve,
        reject,
        abort: () => {
          const index = this.#waiters.indexOf(waiter);
          if (index < 0) return;
          this.#waiters.splice(index, 1);
          reject(cancellationError());
        },
      };
      this.#waiters.push(waiter);
      signal?.addEventListener("abort", waiter.abort, { once: true });
    });
  }

  private release(): void {
    for (;;) {
      const waiter = this.#waiters.shift();
      if (waiter === undefined) { this.#active -= 1; return; }
      waiter.signal?.removeEventListener("abort", waiter.abort);
      if (waiter.signal?.aborted) { waiter.reject(cancellationError()); continue; }
      waiter.resolve();
      return;
    }
  }
}

/** @internal Safe control requests bypass ordinary effect-call admission. */
export function isReservedSdkRequest(method: string, path: string): boolean {
  return method === "GET"
    || method === "POST" && path === "/v1/operations/recover"
    || method === "POST" && /^\/v1\/profiles\/[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*\/[1-9][0-9]{0,4}\/operations\/op_[A-Za-z0-9_-]{22}\/recover$/u.test(path);
}

class LocalOperations implements Operations {
  constructor(private readonly client: LocalClient) {}
  async recover(recovery: RecoveryHandle, options: RecoveryOptions = {}): Promise<OperationStatus> {
    const timeout = recoveryOptions(options).timeoutMs; const identity = recoveryIdentity(recovery.toBytes()); const request = requestId();
    let responseReceived = false;
    try {
      const raw = await this.client.request("POST", "/v1/operations/recover", encodeDeterministic(new Map<unknown, unknown>([[1, 1], [2, request], [3, recovery.toBytes()]])), timeout, options.signal);
      responseReceived = true;
      return await statusFromOutcome(integerMap(decodeDeterministic(raw)), identity, request);
    } catch (error) {
      if (error instanceof AuthsError) throw error;
      if (this.client.recoveryOnly || responseReceived || error instanceof PostWriteRequestError) throw operationErrors.recoveryRequired(recoveryUnavailableIssue(identity.operationId), identity.operationId, [], recovery, Object.freeze({}));
      throw error;
    }
  }
  async pending(options: { readonly signal?: AbortSignal } = {}): Promise<readonly OperationStatus[]> {
    const raw = await this.client.request("GET", "/v1/operations/pending", new Uint8Array(), 30_000, options.signal);
    const value = integerMap(decodeDeterministic(raw));
    const rows = value.get(2);
    if (value.size !== 2 || value.get(1) !== 1 || !Array.isArray(rows) || rows.length > 256) throw new TypeError("invalid pending-operation response");
    const decoded = rows.map(pendingRow);
    for (let index = 1; index < decoded.length; index += 1) {
      const previous = decoded[index - 1]; const current = decoded[index];
      if (previous.updatedAt > current.updatedAt || (previous.updatedAt === current.updatedAt && previous.status.operationId >= current.status.operationId)) throw new TypeError("pending operations are not strictly ordered");
    }
    return Object.freeze(decoded.map((row) => row.status));
  }
  async receipts(operationId: string, options: { readonly signal?: AbortSignal } = {}): Promise<readonly Receipt[]> {
    assertOperationId(operationId);
    const raw = await this.client.request("GET", `/v1/operations/${operationId}/receipts`, new Uint8Array(), 30_000, options.signal);
    const value = integerMap(decodeDeterministic(raw)); const rows = value.get(3);
    if (value.get(2) === "receipt-integrity-failed") {
      if (!exactIntegerKeys(value, 9) || value.get(1) !== 1 || fixedBytes(value.get(3), 16).length !== 16 || text(value.get(4)) !== operationId) throw new TypeError("invalid receipt integrity outcome");
      throw receiptIntegrityFailure(value, operationId);
    }
    if (value.size !== 3 || value.get(1) !== 1 || value.get(2) !== operationId || !Array.isArray(rows) || rows.length > 64) throw new TypeError("invalid receipt response");
    let total = 0;
    const engine = await loadPackagedWorkflowEngine();
    const receipts = rows.map((row) => {
      const item = integerMap(row); const id = item.get(1); const bytes = item.get(2);
      if (item.size !== 2 || typeof id !== "string" || !(bytes instanceof Uint8Array)) throw new TypeError("invalid receipt entry");
      total += bytes.length; if (total > MAX_RESPONSE) throw new RangeError("receipt response exceeds bound");
      const parsed = parsePortableReceipt(new Uint8Array(bytes), engine);
      if (id !== parsed.portableReceiptId) throw new TypeError("portable receipt ID mismatch");
      return parsed.receipt;
    });
    return Object.freeze(receipts);
  }
}

class LocalClient implements Client {
  readonly operations: Operations;
  readonly #socket: string;
  readonly #sessionId: string;
  readonly #profiles: ReadonlyMap<string, ProfileCapability>;
  readonly #admission: SdkAdmissionGate;
  readonly #qualificationResultSocket: string | undefined;
  readonly #activeRequests = new Set<AbortController>();
  readonly #activeRequestPromises = new Set<Promise<Uint8Array>>();
  readonly #profileInvocations = new Map<string, ProfileInvocationEntry>();
  readonly recoveryOnly: boolean;
  #closed = false;
  constructor(socket: string, sessionId: string, profiles: ReadonlyMap<string, ProfileCapability>, mode: "full" | "recovery-only", maximumInFlight: number, qualificationResultSocket?: string) {
    this.#socket = socket; this.#sessionId = sessionId; this.#profiles = profiles; this.recoveryOnly = mode === "recovery-only";
    this.#qualificationResultSocket = qualificationResultSocket;
    this.#admission = new SdkAdmissionGate(maximumInFlight);
    this.operations = new LocalOperations(this);
  }
  profile(profileId: string, version: number, forRecovery = false): ProfileCapability {
    this.ensureOpen(); const profile = this.#profiles.get(`${profileId}/${version}`);
    if (this.recoveryOnly && !forRecovery) throw operationErrors.unavailable(clientIssue("client.profile-unavailable", "the local Auths session permits recovery only"), null, []);
    if (profile === undefined) throw operationErrors.unavailable(clientIssue("client.profile-unavailable", "the local Auths agent did not advertise this profile"), null, []);
    this.requireQualificationProfile(profile);
    return profile;
  }
  recoveryProfile(profileId: string, version: number): ProfileCapability | undefined {
    this.ensureOpen();
    const profile = this.#profiles.get(`${profileId}/${version}`);
    if (profile !== undefined) this.requireQualificationProfile(profile);
    return profile;
  }
  qualificationResultSocket(profileId: string, version: number): string | undefined {
    this.ensureOpen();
    if (this.#qualificationResultSocket === undefined) return undefined;
    const capability = this.#profiles.get(`${profileId}/${version}`);
    if (this.recoveryOnly || capability === undefined || capability.qualification !== null) {
      throw new TypeError("qualification result handoff is outside the exercised unqualified profile");
    }
    return this.#qualificationResultSocket;
  }
  private requireQualificationProfile(profile: ProfileCapability): void {
    if (this.#qualificationResultSocket !== undefined && (this.recoveryOnly || profile.qualification !== null)) {
      throw new TypeError("qualification result handoff is outside the exercised unqualified profile");
    }
  }
  beginProfileInvocation(scope: string, fingerprint: string, requestId: Uint8Array): ProfileInvocationTicket {
    this.ensureOpen();
    const existing = this.#profileInvocations.get(scope);
    if (existing !== undefined && existing.fingerprint !== fingerprint) {
      if (existing.waiters >= 256) throw operationErrors.unavailable(admissionIssue(), null, []);
      existing.waiters += 1;
      return this.ticket("conflict-probe", scope, existing, true, requestId);
    }
    if (existing !== undefined) {
      const attached = existing.waiters < 256;
      if (attached) existing.waiters += 1;
      return this.ticket(attached ? "follower" : "observer", scope, existing, attached);
    }
    let resolveIdentity!: (identity: CoordinatedOperationIdentity | null) => void;
    const identity = new Promise<CoordinatedOperationIdentity | null>((resolve) => { resolveIdentity = resolve; });
    const entry: ProfileInvocationEntry = { fingerprint, requestId: requestId.slice(), identity, resolveIdentity, waiters: 0, published: false, hasOperation: false, settled: false, status: undefined };
    this.#profileInvocations.set(scope, entry);
    return this.ticket("leader", scope, entry, false);
  }
  publishProfileInvocation(ticket: ProfileInvocationTicket, operationId: string | null, initial: Uint8Array = new Uint8Array()): void {
    const state = profileInvocationTickets.get(ticket);
    if (state?.client !== this || ticket.role !== "leader" || state.entry === undefined || state.entry.published) return;
    state.entry.published = true;
    state.entry.hasOperation = operationId !== null;
    state.entry.resolveIdentity(operationId === null ? null : Object.freeze({ requestId: state.entry.requestId.slice(), operationId, initial: initial.slice() }));
  }
  finishProfileInvocation(ticket: ProfileInvocationTicket): void {
    const state = profileInvocationTickets.get(ticket);
    if (state?.client !== this) return;
    profileInvocationTickets.delete(ticket);
    const entry = state.entry;
    if (entry === undefined) return;
    if (ticket.role === "leader") {
      if (!entry.published) { entry.published = true; entry.resolveIdentity(null); }
      entry.settled = true;
    } else if (state.attached) {
      entry.waiters -= 1;
    }
    if (entry.settled && (!entry.hasOperation || entry.waiters === 0) && this.#profileInvocations.get(state.scope) === entry) this.#profileInvocations.delete(state.scope);
  }
  profileInvocationStatus(ticket: ProfileInvocationTicket, fetch: () => Promise<Uint8Array>): Promise<Uint8Array> {
    const state = profileInvocationTickets.get(ticket);
    if (state?.client !== this || state.entry === undefined || (ticket.role !== "follower" && ticket.role !== "observer")) throw new ClientStateError("invalid coordinated profile status request");
    const entry = state.entry;
    if (entry.status === undefined) {
      const pending = fetch();
      entry.status = pending;
      void pending.finally(() => { if (entry.status === pending) entry.status = undefined; }).catch(() => undefined);
    }
    return entry.status.then((value) => value.slice());
  }
  async request(method: string, path: string, body: Uint8Array, timeoutMs: number, signal?: AbortSignal, coordination?: ProfileInvocationTicket): Promise<Uint8Array> {
    this.ensureOpen();
    const send = async () => {
      this.ensureOpen();
      const shutdown = new AbortController();
      this.#activeRequests.add(shutdown);
      const pending = localRequest(this.#socket, method, path, body, this.#sessionId, timeoutMs, signal, shutdown.signal);
      this.#activeRequestPromises.add(pending);
      try { return await pending; }
      finally { this.#activeRequests.delete(shutdown); this.#activeRequestPromises.delete(pending); }
    };
    return isReservedSdkRequest(method, path) ? send() : this.#admission.run(send, signal);
  }
  async close(): Promise<void> {
    if (this.#closed) return; this.#closed = true;
    this.#admission.close();
    for (const entry of this.#profileInvocations.values()) if (!entry.published) entry.resolveIdentity(null);
    this.#profileInvocations.clear();
    for (const request of this.#activeRequests) request.abort();
    await Promise.allSettled([...this.#activeRequestPromises]);
    await localRequest(this.#socket, "DELETE", `/v1/session/${this.#sessionId}`, new Uint8Array(), this.#sessionId, 5_000).catch(() => undefined);
  }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
  private ensureOpen(): void { if (this.#closed) throw new ClientStateError("auths client is not open"); }
  private ticket(role: ProfileInvocationTicket["role"], scope: string, entry: ProfileInvocationEntry, attached: boolean, requestId: Uint8Array = entry.requestId): ProfileInvocationTicket {
    const ticket = Object.freeze({ role, requestId: requestId.slice(), identity: entry.identity });
    profileInvocationTickets.set(ticket, Object.freeze({ client: this, scope, entry, attached }));
    return ticket;
  }
}

export async function connect(options: ClientOptions = {}): Promise<Client> {
  try { return await connectLocal(options); }
  catch (error) { if (error instanceof AuthsError) throw error; throw operationErrors.unavailable(clientIssue("client.agent-unavailable", "the local Auths agent session could not be established"), null, []); }
}

async function connectLocal(options: ClientOptions): Promise<Client> {
  const platform = (globalThis as typeof globalThis & { readonly process?: { readonly platform?: string } }).process?.platform;
  if (platform === "win32") throw operationErrors.unavailable(clientIssue("client.agent-unavailable", "the local Auths agent transport is not yet qualified on Windows"), null, []);
  const timeout = duration(options.connectTimeoutMs, 5_000, 1, 30_000, "connectTimeoutMs");
  const socket = discoverSocket(options.agentSocket);
  const qualificationResultSocket = discoverQualificationResultSocket();
  if (qualificationResultSocket === undefined) await validateSocket(socket);
  else await validateQualificationSocketPair(socket, qualificationResultSocket);
  const info = await runtimeInfo(); const digest = fromHex(info.errorRegistryDigest); const request = requestId();
  const body = encodeDeterministic(new Map<unknown, unknown>([[1, 1], [2, request], [3, "typescript"], [4, info.sdkVersion], [5, digest], [6, "full"]]));
  const raw = await localRequest(socket, "POST", "/v1/session", body, null, timeout);
  const value = integerMap(decodeDeterministic(raw));
  if (value.size !== 8 || value.get(1) !== 1 || !equalBytes(fixedBytes(value.get(2), 16), request)) throw new TypeError("invalid Auths session response");
  const agentDigest = fixedBytes(value.get(5), 32); const mode = value.get(8);
  if ((mode !== "full" && mode !== "recovery-only") || (mode === "full") !== equalBytes(agentDigest, digest)) throw new TypeError("invalid Auths session mode");
  const sessionId = sessionIdText(value.get(3)); principalText(value.get(4)); const advertised = value.get(6); const maximum = value.get(7);
  if (!Array.isArray(advertised) || advertised.length > 256 || !Number.isSafeInteger(maximum) || Number(maximum) < 1 || Number(maximum) > 32) throw new TypeError("invalid Auths session response");
  const profiles = new Map<string, ProfileCapability>();
  let previousProfile: string | undefined;
  for (const candidate of advertised) {
    const item = integerMap(candidate); const profileId = profileIdText(item.get(1)); const version = integer(item.get(2)); if (version < 1 || version > 65_535) throw new TypeError("invalid profile advertisement");
    const operation = item.get(4); if (item.size !== 7 || operation !== "auths.profile-operation/1") throw new TypeError("invalid profile advertisement");
    const rawConnection = item.get(6); let connection: ProfileCapability["connection"] = null;
    if (rawConnection !== null) { const projected = integerMap(rawConnection); if (!exactIntegerKeys(projected, 3)) throw new TypeError("invalid connection advertisement"); connection = Object.freeze({ providerKind: lowerToken(projected.get(1)), contract: semanticId(projected.get(2)), descriptorSchema: semanticId(projected.get(3)) }); }
    const rawQualification = item.get(7); let qualification: ProfileCapability["qualification"] = null;
    if (rawQualification !== null) {
      const projected = integerMap(rawQualification); const qualificationId = text(projected.get(1)); const target = text(projected.get(2)); const closure = bytes(projected.get(3));
      if (projected.size !== 3 || !/^qlf_[A-Za-z0-9_-]{43}$/u.test(qualificationId) || !["linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64"].includes(target) || closure.length !== 32) throw new TypeError("invalid qualification advertisement");
      qualification = Object.freeze({ qualificationId, target: target as NonNullable<ProfileCapability["qualification"]>["target"], semanticClosureSha256: closure.slice() });
    }
    const capability = Object.freeze({ profileId, version, runtimeDigest: fixedBytes(item.get(3), 32).slice(), operationProtocol: operation, errorDigest: fixedBytes(item.get(5), 32).slice(), connection, qualification });
    const key = `${profileId}/${version.toString().padStart(5, "0")}`; if (profiles.has(`${profileId}/${version}`) || previousProfile !== undefined && previousProfile >= key) throw new TypeError("duplicate or unordered profile advertisement"); previousProfile = key; profiles.set(`${profileId}/${version}`, capability);
  }
  if (qualificationResultSocket !== undefined && mode !== "full") {
    throw new TypeError("qualification result handoff requires a full local session");
  }
  return new LocalClient(
    socket, sessionId, profiles, mode, Number(maximum), qualificationResultSocket,
  );
}

export function profileCapability(client: Client, profileId: string, version: number): ProfileCapability {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  return client.profile(profileId, version);
}
export function profileCapabilityForRecovery(client: Client, profileId: string, version: number): ProfileCapability | undefined {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  return client.recoveryProfile(profileId, version);
}
export function profileSessionRecoveryOnly(client: Client): boolean {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  return client.recoveryOnly;
}
/** @internal Reports one fully projected generated-profile result. */
export async function reportQualificationResult(client: Client, profileId: string, version: number, requestId: Uint8Array, result: Uint8Array): Promise<void> {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  const socket = client.qualificationResultSocket(profileId, version);
  if (socket === undefined) return;
  await sendQualificationResult(socket, requestId, result, 0);
}
/** @internal Reports cancellation after a written generated-profile request. */
export async function reportQualificationCancellation(client: Client, profileId: string, version: number, requestId: Uint8Array): Promise<void> {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  const socket = client.qualificationResultSocket(profileId, version);
  if (socket === undefined) return;
  if (requestId.length !== 16) throw new TypeError("invalid qualification request ID");
  const engine = await loadPackagedWorkflowEngine();
  const result = engine.qualificationClientCancellationResultV1(requestId);
  await sendQualificationResult(socket, requestId, result, 1);
}
export function beginProfileInvocation(client: Client, scope: string, fingerprint: string, requestId: Uint8Array): ProfileInvocationTicket {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  return client.beginProfileInvocation(scope, fingerprint, requestId);
}
export function publishProfileInvocation(client: Client, ticket: ProfileInvocationTicket, operationId: string | null, initial: Uint8Array = new Uint8Array()): void {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  client.publishProfileInvocation(ticket, operationId, initial);
}
export function finishProfileInvocation(client: Client, ticket: ProfileInvocationTicket): void {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  client.finishProfileInvocation(ticket);
}
export function profileInvocationStatus(client: Client, ticket: ProfileInvocationTicket, fetch: () => Promise<Uint8Array>): Promise<Uint8Array> {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  return client.profileInvocationStatus(ticket, fetch);
}
export function profileRequest(client: Client, method: string, path: string, body: Uint8Array, timeoutMs: number, signal?: AbortSignal, coordination?: ProfileInvocationTicket): Promise<Uint8Array> {
  if (!(client instanceof LocalClient)) throw new TypeError("generated profile requires an Auths local client");
  return client.request(method, path, body, timeoutMs, signal, coordination);
}

function discoverSocket(explicit?: string): string {
  const globals = globalThis as typeof globalThis & { readonly process?: { readonly env?: Record<string, string | undefined>; readonly platform?: string } };
  const environment = globals.process?.env ?? {}; const platform = globals.process?.platform;
  const value = explicit ?? environment.AUTHS_AGENT_SOCKET ?? (platform === "win32" ? "\\\\.\\pipe\\auths-agent" : environment.XDG_RUNTIME_DIR?.startsWith("/") ? `${environment.XDG_RUNTIME_DIR}/auths/agent.sock` : undefined);
  if (value === undefined) throw operationErrors.unavailable(clientIssue("client.agent-unavailable", "no safe local Auths agent socket is configured"), null, []);
  const length = new TextEncoder().encode(value).length;
  if (length < 1 || length > 1024 || /[\u0000-\u001f\u007f]/u.test(value) || (platform !== "win32" && !value.startsWith("/")) || (platform === "win32" && !value.startsWith("\\\\.\\pipe\\"))) throw new TypeError("invalid local Auths agent address");
  return value;
}
function discoverQualificationResultSocket(): string | undefined {
  const globals = globalThis as typeof globalThis & {
    readonly process?: {
      readonly env?: Record<string, string | undefined>;
      readonly platform?: string;
    };
  };
  const value = globals.process?.env?.[QUALIFICATION_RESULT_SOCKET_ENV];
  if (value === undefined) return undefined;
  const length = new TextEncoder().encode(value).length;
  if (
    globals.process?.platform !== "linux"
    || length < 1
    || length > 1_024
    || !value.startsWith("/")
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError("invalid qualification result socket");
  }
  return value;
}
async function validateSocket(path: string): Promise<void> {
  const globals = globalThis as typeof globalThis & { readonly process?: { readonly platform?: string; getuid?: () => number } };
  if (globals.process?.platform === "win32") return;
  const { lstat } = await import("node:fs/promises"); const item = await lstat(path); const uid = globals.process?.getuid?.();
  if (item.isSymbolicLink() || !item.isSocket() || (uid !== undefined && item.uid !== 0 && item.uid !== uid) || (item.mode & 0o002) !== 0) throw operationErrors.unavailable(clientIssue("client.agent-unavailable", "Auths agent socket is unsafe"), null, []);
}
async function validateQualificationSocketPair(agentSocket: string, resultSocket: string): Promise<void> {
  const globals = globalThis as typeof globalThis & {
    readonly process?: {
      readonly platform?: string;
      getuid?: () => number;
      getgid?: () => number;
    };
  };
  const uid = globals.process?.getuid?.(); const gid = globals.process?.getgid?.();
  if (globals.process?.platform !== "linux" || uid === undefined || gid === undefined) throw new TypeError("qualification sockets require Linux process credentials");
  const { dirname, join, resolve } = await import("node:path");
  if (agentSocket === resultSocket || resolve(agentSocket) !== agentSocket || resolve(resultSocket) !== resultSocket || dirname(agentSocket) !== dirname(resultSocket)) throw new TypeError("qualification sockets are not one normalized protected pair");
  const parentPath = dirname(agentSocket); const { lstat } = await import("node:fs/promises");
  let current = "/";
  for (const component of parentPath.split("/").filter((item) => item.length > 0)) {
    current = join(current, component);
    const item = await lstat(current);
    if (item.isSymbolicLink() || !item.isDirectory()) throw new TypeError("qualification socket parent is not a no-symlink directory");
  }
  const parent = await lstat(parentPath); const agent = await lstat(agentSocket); const result = await lstat(resultSocket);
  const owner = parent.uid;
  if (
    owner === 0 || owner === uid
    || parent.gid !== gid || (parent.mode & 0o777) !== 0o710
    || parent.isSymbolicLink() || !parent.isDirectory()
    || agent.uid !== owner || result.uid !== owner
    || agent.gid !== gid || result.gid !== gid
    || (agent.mode & 0o777) !== 0o660 || (result.mode & 0o777) !== 0o660
    || agent.isSymbolicLink() || result.isSymbolicLink()
    || !agent.isSocket() || !result.isSocket()
  ) {
    throw new TypeError("qualification sockets are not exact protected shared state");
  }
}
async function sendQualificationResult(socketPath: string, requestId: Uint8Array, result: Uint8Array, newMode: 0 | 1): Promise<void> {
  if (requestId.length !== 16 || result.length < 1 || result.length > MAX_RESPONSE) throw new TypeError("invalid qualification result handoff");
  const deadline = performance.now() + 30_000; let mode: 0 | 1 | 2 | 3 = newMode;
  for (;;) {
    const remaining = Math.floor(deadline - performance.now());
    if (remaining < 1) throw new TypeError("qualification result acknowledgement timed out");
    const status = await sendQualificationResultOnce(socketPath, requestId, result, mode, remaining);
    if (status === "acknowledged") return;
    if (status === "ambiguous") mode = (newMode + 2) as 2 | 3;
    await new Promise((resolve) => setTimeout(resolve, Math.min(10, remaining)));
  }
}
async function sendQualificationResultOnce(socketPath: string, requestId: Uint8Array, result: Uint8Array, mode: 0 | 1 | 2 | 3, timeoutMs: number): Promise<"acknowledged" | "prewrite" | "ambiguous"> {
  const { createConnection } = await import("node:net");
  const engine = await loadPackagedWorkflowEngine();
  const frame = engine.encodeQualificationClientResultFrameV1(mode, requestId, result);
  return new Promise((resolve) => {
    const socket = createConnection({ path: socketPath }); let total = 0; let settled = false; let sent = false;
    const finish = (status: "acknowledged" | "prewrite" | "ambiguous") => { if (settled) return; settled = true; clearTimeout(timer); socket.destroy(); resolve(status); };
    const timer = setTimeout(() => finish(sent ? "ambiguous" : "prewrite"), timeoutMs);
    socket.once("error", () => finish(sent ? "ambiguous" : "prewrite"));
    socket.on("data", (chunk) => { total += chunk.length; if (total > 32) finish("ambiguous"); });
    socket.once("end", () => finish(sent && total === 32 ? "acknowledged" : sent ? "ambiguous" : "prewrite"));
    socket.once("connect", () => {
      socket.write(frame); socket.end(() => { sent = true; });
    });
  });
}
async function localRequest(socketPath: string, method: string, path: string, body: Uint8Array, session: string | null, timeoutMs: number, signal?: AbortSignal, shutdownSignal?: AbortSignal): Promise<Uint8Array> {
  if (!path.startsWith("/") || /[?%\r\n]/u.test(path) || body.length > 33_554_432) throw new TypeError("invalid local Auths request");
  const { createConnection } = await import("node:net");
  return new Promise<Uint8Array>((resolve, reject) => {
    const socket = createConnection({ path: socketPath }); const chunks: Uint8Array[] = []; let total = 0; let settled = false; let written = false;
    const finish = (action: () => void) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener("abort", abort); shutdownSignal?.removeEventListener("abort", abort); action(); };
    const fail = (error: unknown) => reject(written ? new PostWriteRequestError(error) : error);
    const abort = () => { const error = new DOMException("Auths operation cancelled", "AbortError"); socket.destroy(error); finish(() => fail(error)); };
    const timer = setTimeout(() => { const error = new DOMException("Auths operation timed out", "TimeoutError"); socket.destroy(error); finish(() => fail(error)); }, timeoutMs);
    signal?.addEventListener("abort", abort, { once: true }); shutdownSignal?.addEventListener("abort", abort, { once: true }); if (signal?.aborted || shutdownSignal?.aborted) { abort(); return; }
    socket.once("error", (error) => finish(() => fail(error)));
    socket.on("data", (chunk) => { total += chunk.length; if (total > MAX_RESPONSE + 16_384) { socket.destroy(new RangeError("Auths response exceeds bound")); return; } chunks.push(chunk.slice()); });
    socket.once("end", () => finish(() => { try { resolve(parseHttp(concat(chunks))); } catch (error) { fail(error); } }));
    socket.once("connect", () => {
      const headers = [`${method} ${path} HTTP/1.1`, "Host: localhost", `Content-Type: ${MEDIA_TYPE}`, `Content-Length: ${body.length}`, "Connection: close", ...(session === null ? [] : [`Auths-Session: ${session}`]), "", ""];
      // Content-Length frames the complete request. Keep the writable half
      // open until the HTTP/1.1 `Connection: close` response arrives: some
      // local HTTP servers treat an early client FIN as an aborted request,
      // especially for authenticated GETs with an empty body.
      written = true; socket.write(concat([new TextEncoder().encode(headers.join("\r\n")), body]));
    });
  });
}
function parseHttp(value: Uint8Array): Uint8Array {
  const marker = find(value, Uint8Array.of(13, 10, 13, 10)); if (marker < 0 || marker > 16_384) throw new TypeError("invalid Auths HTTP response");
  const header = new TextDecoder("ascii", { fatal: true }).decode(value.slice(0, marker)); const lines = header.split("\r\n"); const status = lines.shift()?.split(" ")[1];
  if (status !== "200") throw new ClientStateError(`local Auths agent refused request (${status ?? "invalid"})`);
  const headers = new Map<string, string>(); for (const line of lines) { const index = line.indexOf(":"); const name = line.slice(0, index).trim().toLowerCase(); if (index < 1 || headers.has(name)) throw new TypeError("invalid Auths response headers"); headers.set(name, line.slice(index + 1).trim()); }
  if (headers.get("content-type") !== MEDIA_TYPE) throw new TypeError("invalid Auths response media type"); const length = Number(headers.get("content-length")); const body = value.slice(marker + 4);
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_RESPONSE || body.length !== length) throw new TypeError("invalid Auths response length"); return body;
}
async function statusFromOutcome(value: Map<number, unknown>, identity: RecoveryIdentity, request: Uint8Array): Promise<OperationStatus> {
  const kind = text(value.get(2)); const sizes: Readonly<Record<string, number>> = { ready: 8, "in-progress": 9, denied: 7, unavailable: 7, conflict: 8, completed: 8, partial: 9, "not-applied": 8, "recovery-required": 9, "receipt-integrity-failed": 9 };
  const maximum = sizes[kind]; if (maximum === undefined || !exactIntegerKeys(value, maximum) || value.get(1) !== 1 || !equalBytes(fixedBytes(value.get(3), 16), request)) throw new TypeError("invalid recovery outcome");
  const operationId = text(value.get(4)); assertOperationId(operationId); if (operationId !== identity.operationId) throw new TypeError("recovery outcome changed operation identity");
  if (kind === "receipt-integrity-failed") throw receiptIntegrityFailure(value, operationId);
  let state: OperationState; let effect: EffectState; let terminal: boolean; let receiptIds: readonly string[]; let recovery: RecoveryHandle | undefined; let connection: string | null;
  if (kind === "ready") {
    fixedBytes(value.get(5), 32); receiptIds = await portableReceiptIds([value.get(6)]); recovery = statusRecovery(value.get(7), identity); connection = optionalConnection(value.get(8)); state = "ready"; effect = "not-applied"; terminal = false;
  } else if (kind === "in-progress") {
    const selectedState = text(value.get(5)); effect = effectState(value.get(6)); if ((selectedState !== "preparing" && selectedState !== "executing") || (selectedState === "preparing" && effect !== "not-applied")) throw new TypeError("invalid in-progress truth"); state = selectedState; receiptIds = receiptIdList(value.get(7)); recovery = statusRecovery(value.get(8), identity); connection = optionalConnection(value.get(9)); terminal = false;
  } else if (kind === "denied") {
    statusIssue(value.get(5), "not-applied", operationId); receiptIds = await portableReceiptIds([value.get(6)]); connection = optionalConnection(value.get(7)); state = "denied"; effect = "not-applied"; terminal = true;
  } else if (kind === "unavailable") {
    statusIssue(value.get(5), "not-applied", operationId); const receipts = array(value.get(6)); if (receipts.length > 1) throw new TypeError("unavailable outcome has too many receipts"); receiptIds = await portableReceiptIds(receipts); connection = optionalConnection(value.get(7)); state = "unavailable"; effect = "not-applied"; terminal = true;
  } else if (kind === "conflict") {
    statusIssue(value.get(5), "possible", operationId); recovery = statusRecovery(value.get(6), identity); receiptIds = await portableReceiptIds(value.get(7)); connection = optionalConnection(value.get(8)); state = "recovery-required"; effect = "possible"; terminal = false;
  } else if (kind === "completed") {
    fixedBoundedBytes(value.get(5), MAX_RESPONSE); receiptIds = await portableReceiptIds(value.get(6)); completion(value.get(7)); connection = optionalConnection(value.get(8)); state = "completed"; effect = "applied"; terminal = true;
  } else if (kind === "partial") {
    fixedBoundedBytes(value.get(5), MAX_RESPONSE); statusIssue(value.get(6), "applied", operationId); receiptIds = await portableReceiptIds(value.get(7)); completion(value.get(8)); connection = optionalConnection(value.get(9)); state = "partial"; effect = "applied"; terminal = true;
  } else if (kind === "not-applied") {
    statusIssue(value.get(5), "not-applied", operationId); receiptIds = await portableReceiptIds(value.get(6)); completion(value.get(7)); connection = optionalConnection(value.get(8)); state = "not-applied"; effect = "not-applied"; terminal = true;
  } else {
    statusIssue(value.get(5), "possible", operationId); recovery = statusRecovery(value.get(6), identity); receiptIds = await portableReceiptIds(value.get(7)); if (value.get(8) !== null) fixedBoundedBytes(value.get(8), MAX_RESPONSE); connection = optionalConnection(value.get(9)); state = "recovery-required"; effect = "possible"; terminal = false;
  }
  return Object.freeze({ operationId, profile: `${identity.profileId}/${identity.version}`, connection, state, effect, terminal, receiptIds, ...(recovery === undefined ? {} : { recovery }) });
}
function receiptIntegrityFailure(value: Map<number, unknown>, operationId: string): ReceiptIntegrityError { const state = operationState(value.get(6)); const effect = effectState(value.get(7)); const terminal = boolean(value.get(8)); if (!validIntegrityTruth(state, effect, terminal)) throw new TypeError("receipt integrity outcome contradicts durable truth"); optionalConnection(value.get(9)); const issue = issueFromCbor(value.get(5)); if (issue.code !== "core.terminal-receipt-integrity-failed" || issue.effect !== effect || issue.correlationId !== operationId || issue.executionReference !== operationId || !integrityProviderBoundary(state, effect, issue.enteredBoundaries.provider)) throw new TypeError("invalid receipt integrity issue"); return operationErrors.receiptIntegrity(issue, operationId, state, terminal); }
function operationState(value: unknown): OperationState { const state = text(value); if (!["preparing", "denied", "unavailable", "ready", "executing", "recovery-required", "completed", "partial", "not-applied"].includes(state)) throw new TypeError("invalid operation state"); return state as OperationState; }
function validIntegrityTruth(state: OperationState, effect: EffectState, terminal: boolean): boolean { if (state === "preparing" || state === "ready") return effect === "not-applied" && !terminal; if (state === "executing") return (effect === "not-applied" || effect === "possible") && !terminal; if (state === "denied" || state === "unavailable" || state === "not-applied") return effect === "not-applied" && terminal; if (state === "recovery-required") return effect === "possible" && !terminal; return (state === "completed" || state === "partial") && effect === "applied" && terminal; }
function integrityProviderBoundary(state: OperationState, effect: EffectState, entered: boolean): boolean { if (state === "preparing" || state === "ready" || state === "denied" || state === "unavailable") return !entered; if (effect === "possible" || effect === "applied") return entered; return true; }
function pendingRow(raw: unknown): Readonly<{ status: OperationStatus; updatedAt: number }> { const value = integerMap(raw); if (!exactIntegerKeys(value, 10)) throw new TypeError("invalid pending-operation row"); const operationId = text(value.get(1)); assertOperationId(operationId); const profileId = text(value.get(2)); const version = integer(value.get(3)); if (!/^auths\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$/u.test(profileId) || version < 1 || version > 65_535) throw new TypeError("invalid pending-operation profile"); const state = text(value.get(4)); const effect = effectState(value.get(5)); if (![["preparing", "not-applied"], ["ready", "not-applied"], ["executing", "not-applied"], ["executing", "possible"], ["recovery-required", "possible"]].some(([expectedState, expectedEffect]) => state === expectedState && effect === expectedEffect) || value.get(6) !== false) throw new TypeError("invalid pending-operation truth"); const updatedAt = integer(value.get(7)); if (updatedAt < 1) throw new TypeError("invalid pending-operation timestamp"); const receiptIds = receiptIdList(value.get(8)); const rawRecovery = bytes(value.get(9)); const identity = recoveryIdentity(rawRecovery); if (identity.operationId !== operationId || identity.profileId !== profileId || identity.version !== version) throw new TypeError("pending recovery handle changed operation identity"); const recovery = recoveryHandleFromBytes(rawRecovery); const connection = optionalConnection(value.get(10)); return Object.freeze({ status: Object.freeze({ operationId, profile: `${profileId}/${version}`, connection, state: state as OperationState, effect, terminal: false, receiptIds, recovery }), updatedAt }); }
function clientIssue(code: "client.agent-unavailable" | "client.profile-unavailable", summary: string): AuthsIssue { const unavailable = code === "client.agent-unavailable"; return Object.freeze({ schema: "auths.error/1", family: unavailable ? "runtime" : "configuration", code, operation: "connect", stage: unavailable ? "local-agent" : "negotiation", summary, correlationId: "auths-typescript", retry: (unavailable ? "conditional" : "never") as RetryClass, effect: "not-applied" as EffectState, enteredBoundaries: Object.freeze({ approval: false, signer: false, state: false, credential: false, provider: false }), recommendedAction: (unavailable ? "correct-configuration" : "install-compatible-runtime") as RecommendedAction, causes: Object.freeze([]) }); }
function admissionIssue(): AuthsIssue { return Object.freeze({ schema: "auths.error/1", family: "state", code: "operation.admission-exhausted", operation: "execute", stage: "admission", summary: "Operation admission exhausted", correlationId: "auths-typescript-admission", retry: "conditional", effect: "not-applied", enteredBoundaries: Object.freeze({ approval: false, signer: false, state: false, credential: false, provider: false }), recommendedAction: "retry-execution", causes: Object.freeze(["unknown"] as const) }); }
function recoveryUnavailableIssue(operationId: string): AuthsIssue { return Object.freeze({ schema: "auths.error/1", family: "state", code: "operation.recovery-unavailable", operation: "recover", stage: "reconciliation", summary: "recovery could not safely decode the installed operation outcome", correlationId: operationId, retry: "unknown", effect: "possible", enteredBoundaries: Object.freeze({ approval: false, signer: false, state: false, credential: false, provider: true }), recommendedAction: "resume-and-reconcile", executionReference: operationId, causes: Object.freeze(["unknown"] as const) }); }
function cancellationError(): DOMException { return new DOMException("Auths operation cancelled", "AbortError"); }
function operationOptions(value: OperationOptions): Required<Pick<OperationOptions, "timeoutMs" | "recoveryWaitMs">> { const timeoutMs = duration(value.timeoutMs, 30_000, 1, 300_000, "timeoutMs"); const recoveryWaitMs = duration(value.recoveryWaitMs, 5_000, 1, timeoutMs, "recoveryWaitMs"); return { timeoutMs, recoveryWaitMs }; }
function recoveryOptions(value: RecoveryOptions): Required<Pick<RecoveryOptions, "timeoutMs" | "recoveryWaitMs">> { return operationOptions(value); }
export function validatedOperationOptions(value: OperationOptions = {}): Readonly<{ timeoutMs: number; recoveryWaitMs: number }> { if (value.idempotencyKey !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.idempotencyKey)) throw new TypeError("invalid idempotency key"); return Object.freeze(operationOptions(value)); }
function duration(value: number | undefined, fallback: number, minimum: number, maximum: number, name: string): number { const selected = value ?? fallback; if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) throw new RangeError(`${name} is outside bounds`); return selected; }
function requestId(): Uint8Array { return crypto.getRandomValues(new Uint8Array(16)); }
function integerMap(value: unknown): Map<number, unknown> { if (!(value instanceof Map) || [...value.keys()].some((key) => !Number.isInteger(key))) throw new TypeError("expected integer-keyed Auths map"); return value as Map<number, unknown>; }
function stringMap(value: unknown): Map<string, unknown> { if (!(value instanceof Map) || [...value.keys()].some((key) => typeof key !== "string")) throw new TypeError("expected string-keyed Auths map"); return value as Map<string, unknown>; }
function exactIntegerKeys(value: Map<number, unknown>, maximum: number): boolean { return value.size === maximum && Array.from({ length: maximum }, (_, index) => index + 1).every((key) => value.has(key)); }
function exactStringKeys(value: Map<string, unknown>, expected: readonly string[]): void { if (value.size !== expected.length || expected.some((key) => !value.has(key))) throw new TypeError("Auths envelope has unknown or missing fields"); }
function text(value: unknown): string { if (typeof value !== "string") throw new TypeError("expected Auths text"); return value; }
function sessionIdText(value: unknown): string { const selected = text(value); const encoded = /^ses_([A-Za-z0-9_-]{22})$/u.exec(selected)?.[1]; if (encoded === undefined) throw new TypeError("invalid Auths session ID"); let decoded: Uint8Array; try { decoded = Uint8Array.from(atob(encoded.replaceAll("-", "+").replaceAll("_", "/") + "=="), (character) => character.charCodeAt(0)); } catch { throw new TypeError("invalid Auths session ID"); } if (decoded.length !== 16 || decoded.every((byte) => byte === 0) || base64url(decoded) !== encoded) throw new TypeError("invalid Auths session ID"); return selected; }
function principalText(value: unknown): string { const selected = text(value); const separator = selected.indexOf(":"); if (selected.length < 3 || selected.length > 512 || separator < 1 || separator === selected.length - 1 || !/^[a-z][a-z0-9+.-]*$/u.test(selected.slice(0, separator)) || !/^[!-~]+$/u.test(selected)) throw new TypeError("invalid Auths principal"); return selected; }
function profileIdText(value: unknown): string { const selected = text(value); if (selected.length > 128 || !/^auths\.[a-z][a-z0-9-]{0,63}\.[a-z][a-z0-9-]{0,63}$/u.test(selected)) throw new TypeError("invalid profile advertisement"); return selected; }
function lowerToken(value: unknown): string { const selected = text(value); if (selected.length > 64 || !/^[a-z][a-z0-9-]*$/u.test(selected)) throw new TypeError("invalid connection provider kind"); return selected; }
function semanticId(value: unknown): string { const selected = text(value); if (selected.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(selected)) throw new TypeError("invalid connection semantic ID"); return selected; }
function bytes(value: unknown): Uint8Array { if (!(value instanceof Uint8Array)) throw new TypeError("expected Auths bytes"); return value; }
function fixedBytes(value: unknown, length: number): Uint8Array { const selected = bytes(value); if (selected.length !== length) throw new TypeError("Auths bytes have the wrong length"); return selected; }
function fixedBoundedBytes(value: unknown, maximum: number): Uint8Array { const selected = bytes(value); if (selected.length < 1 || selected.length > maximum) throw new RangeError("Auths bytes are outside bounds"); return selected; }
function boolean(value: unknown): boolean { if (typeof value !== "boolean") throw new TypeError("expected Auths boolean"); return value; }
function integer(value: unknown): number { if (!Number.isSafeInteger(value)) throw new TypeError("expected Auths integer"); return value as number; }
function array(value: unknown): readonly unknown[] { if (!Array.isArray(value)) throw new TypeError("expected Auths array"); return value; }
function assertOperationId(value: string): void { if (!/^op_[A-Za-z0-9_-]{22}$/u.test(value)) throw new TypeError("invalid operation id"); }
interface RecoveryIdentity { readonly operationId: string; readonly profileId: string; readonly version: number }
function recoveryIdentity(value: Uint8Array): RecoveryIdentity { const raw = integerMap(decodeDeterministic(value)); if (!exactIntegerKeys(raw, 11) || raw.get(1) !== 1) throw new TypeError("invalid recovery handle"); const operationId = text(raw.get(2)); assertOperationId(operationId); const profileId = text(raw.get(3)); const version = integer(raw.get(4)); if (!/^auths\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$/u.test(profileId) || version < 1 || version > 65_535) throw new TypeError("invalid recovery handle profile"); fixedBytes(raw.get(5), 32); integer(raw.get(6)); if (raw.get(7) !== null) integer(raw.get(7)); fixedBytes(raw.get(8), 32); if (raw.get(9) !== "Ed25519") throw new TypeError("invalid recovery handle algorithm"); text(raw.get(10)); fixedBytes(raw.get(11), 64); return Object.freeze({ operationId, profileId, version }); }
function optionalConnection(value: unknown): string | null { if (value === null) return null; const selected = text(value); if (!/^[a-z][a-z0-9-]{0,63}$/u.test(selected)) throw new TypeError("invalid connection alias"); return selected; }
function effectState(value: unknown): "not-applied" | "possible" | "applied" { if (value !== "not-applied" && value !== "possible" && value !== "applied") throw new TypeError("invalid effect state"); return value; }
function issueFromCbor(value: unknown): AuthsIssue { const raw = stringMap(decodeDeterministic(fixedBoundedBytes(value, 65_536))); exactStringKeys(raw, ["schema", "family", "code", "operation", "stage", "summary", "correlationId", "retry", "effect", "entered", "recommendedAction", "executionReference", "decisionReference", "receiptReference", "causes"]); const entered = stringMap(raw.get("entered")); exactStringKeys(entered, ["approval", "signer", "state", "credential", "provider"]); return parseAuthsErrorEnvelope({ schema: text(raw.get("schema")), family: text(raw.get("family")), code: text(raw.get("code")), operation: text(raw.get("operation")), stage: text(raw.get("stage")), summary: text(raw.get("summary")), correlationId: text(raw.get("correlationId")), retry: text(raw.get("retry")), effect: text(raw.get("effect")), entered: { approval: boolean(entered.get("approval")), signer: boolean(entered.get("signer")), state: boolean(entered.get("state")), credential: boolean(entered.get("credential")), provider: boolean(entered.get("provider")) }, recommendedAction: text(raw.get("recommendedAction")), executionReference: raw.get("executionReference") === null ? null : text(raw.get("executionReference")), decisionReference: raw.get("decisionReference") === null ? null : text(raw.get("decisionReference")), receiptReference: raw.get("receiptReference") === null ? null : text(raw.get("receiptReference")), causes: array(raw.get("causes")).map(text) }).issue; }
function statusIssue(value: unknown, expectedEffect: EffectState, operationId: string): AuthsIssue { const parsed = issueFromCbor(value); if (parsed.effect !== expectedEffect || parsed.correlationId !== operationId || (parsed.executionReference !== undefined && parsed.executionReference !== operationId)) throw new TypeError("recovery outcome issue changed operation truth"); return parsed; }
function statusRecovery(value: unknown, expected: RecoveryIdentity): RecoveryHandle { const raw = bytes(value); const actual = recoveryIdentity(raw); if (actual.operationId !== expected.operationId || actual.profileId !== expected.profileId || actual.version !== expected.version) throw new TypeError("recovery outcome returned a foreign handle"); return recoveryHandleFromBytes(raw); }
function completion(value: unknown): "fresh" | "replayed" | "reconciled" { if (value !== "fresh" && value !== "replayed" && value !== "reconciled") throw new TypeError("invalid operation completion"); return value; }
function receiptIdList(value: unknown): readonly string[] { const values = array(value); if (values.length > 64) throw new RangeError("too many receipt IDs"); return Object.freeze(values.map((item) => { const selected = text(item); if (!/^rcpt_[A-Za-z0-9_-]{43}$/u.test(selected)) throw new TypeError("invalid receipt ID"); return selected; })); }
async function portableReceiptIds(value: unknown): Promise<readonly string[]> { const values = array(value); if (values.length > 64) throw new RangeError("too many receipts"); const engine = await loadPackagedWorkflowEngine(); return Object.freeze(values.map((item) => { const input = bytes(item); if (input.length < 1 || input.length > 1_048_576) throw new RangeError("portable receipt is outside bounds"); return parsePortableReceipt(input, engine).portableReceiptId; })); }
function base64url(value: Uint8Array): string { return btoa(String.fromCharCode(...value)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, ""); }
function fromHex(value: string): Uint8Array { if (!/^[0-9a-f]{64}$/u.test(value)) throw new TypeError("invalid digest"); return Uint8Array.from(value.match(/../gu) ?? [], (part) => Number.parseInt(part, 16)); }
function equalBytes(left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]); }
function concat(values: readonly Uint8Array[]): Uint8Array { const output = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0)); let offset = 0; for (const value of values) { output.set(value, offset); offset += value.length; } return output; }
function find(haystack: Uint8Array, needle: Uint8Array): number { outer: for (let index = 0; index <= haystack.length - needle.length; index += 1) { for (let offset = 0; offset < needle.length; offset += 1) if (haystack[index + offset] !== needle[offset]) continue outer; return index; } return -1; }
