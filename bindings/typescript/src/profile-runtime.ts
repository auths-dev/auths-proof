import type {
  AuthsIssue, Client, OperationMetadata, OperationOptions, RecoveryHandle, RecoveryOptions,
} from "./index.js";
import { recoveryHandleFromBytes } from "./index.js";
import { parseAuthsErrorEnvelope } from "./product-errors.js";
import { decodeDeterministic, encodeDeterministic } from "./internal/cbor.js";
import { readBoundedProfileFile } from "./internal/profile-file-node.js";
import { parsePortableReceipt } from "./internal/receipt.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";
import {
  beginProfileInvocation, finishProfileInvocation, isPostWriteRequestError, operationErrors,
  postWriteRequestCause, profileCapability, profileCapabilityForRecovery, profileInvocationStatus, profileRequest,
  profileSessionRecoveryOnly, publishProfileInvocation, validatedOperationOptions,
  reportQualificationCancellation, reportQualificationResult,
  type CoordinatedOperationIdentity, type ProfileInvocationTicket,
} from "./session.js";

export const PROFILE_CLIENT_RUNTIME = "auths.profile-client-runtime/1" as const;

export interface ProfileDescriptor {
  readonly profileId: string; readonly version: number; readonly collectionRoute: string;
  readonly profileClientRuntime: typeof PROFILE_CLIENT_RUNTIME;
  readonly runtimeContractDigest: string; readonly errorProjectionDigest: string;
  readonly preparationEvidence: "protected-lease" | null;
  readonly requestBytes: number; readonly responseBytes: number; readonly executionMilliseconds: number;
  readonly receiptCount: number; readonly receiptBytes: number;
  readonly profileApi: Readonly<Record<string, unknown>>; readonly inputType: string;
  readonly successType: string; readonly partialType?: string | null; readonly progressType?: string | null;
}
export interface Completed<T> { readonly kind: "completed"; readonly value: T }
export interface Denied { readonly kind: "denied"; readonly operationId: string; readonly issue: AuthsIssue; readonly receiptIds: readonly string[] }
export interface Unavailable { readonly kind: "unavailable"; readonly operationId: string | null; readonly issue: AuthsIssue; readonly receiptIds: readonly string[] }
export interface Conflict { readonly kind: "conflict"; readonly operationId: string; readonly issue: AuthsIssue; readonly recovery: RecoveryHandle; readonly receiptIds: readonly string[] }
export interface NotApplied { readonly kind: "not-applied"; readonly operationId: string; readonly issue: AuthsIssue; readonly receiptIds: readonly string[]; readonly completion: Completion }
export interface Partial<P> { readonly kind: "partial"; readonly operationId: string; readonly issue: AuthsIssue; readonly details: P; readonly receiptIds: readonly string[]; readonly completion: Completion }
export interface RecoveryRequired<G> { readonly kind: "recovery-required"; readonly operationId: string; readonly issue: AuthsIssue; readonly recovery: RecoveryHandle; readonly receiptIds: readonly string[]; readonly progress: G | null }
export interface ReceiptIntegrityFailed { readonly kind: "receipt-integrity-failed"; readonly operationId: string; readonly issue: AuthsIssue; readonly state: import("./index.js").OperationState; readonly effect: AuthsIssue["effect"]; readonly terminal: boolean; readonly receiptIds: readonly string[] }
export type ProfileOutcome<T, P = never, G = never> = Completed<T> | Denied | Unavailable | Conflict | NotApplied | Partial<P> | RecoveryRequired<G> | ReceiptIntegrityFailed;
type Completion = "fresh" | "replayed" | "reconciled";

export interface BoundProfile<T, P = never, G = never> {
  invoke(input: unknown, options?: OperationOptions): Promise<T>;
  invokeOutcome(input: unknown, options?: OperationOptions): Promise<ProfileOutcome<T, P, G>>;
  recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<T>;
  recoverOutcome(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<ProfileOutcome<T, P, G>>;
}

class GeneratedProfile<T, P, G> implements BoundProfile<T, P, G> {
  constructor(private readonly client: Client, private readonly descriptor: ProfileDescriptor, private readonly connection: string | undefined) {
    if (connection !== undefined && !/^[a-z][a-z0-9-]{0,63}$/u.test(connection)) throw new TypeError("invalid connection alias");
    if (descriptor.collectionRoute !== route(descriptor.profileId, descriptor.version)) throw new TypeError("generated profile route mismatch");
    if (descriptor.profileClientRuntime !== PROFILE_CLIENT_RUNTIME) throw new TypeError("generated profile client runtime mismatch");
    boundedInteger(descriptor.requestBytes, 1, 64 * 1024 * 1024, "requestBytes");
    boundedInteger(descriptor.responseBytes, 1, 64 * 1024 * 1024, "responseBytes");
    boundedInteger(descriptor.executionMilliseconds, 1, 300_000, "executionMilliseconds");
    boundedInteger(descriptor.receiptCount, 1, 64, "receiptCount");
    boundedInteger(descriptor.receiptBytes, 1, descriptor.responseBytes, "receiptBytes");
    fromHex(descriptor.runtimeContractDigest); fromHex(descriptor.errorProjectionDigest);
    if (descriptor.preparationEvidence !== null && descriptor.preparationEvidence !== "protected-lease") throw new TypeError("unknown preparation evidence contract");
  }
  async invoke(input: unknown, options: OperationOptions = {}): Promise<T> {
    const outcome = await this.invokeOutcome(input, options);
    if (outcome.kind === "completed") return outcome.value;
    raiseOutcome(outcome);
  }
  async invokeOutcome(input: unknown, options: OperationOptions = {}): Promise<ProfileOutcome<T, P, G>> {
    try {
      const outcome = await this.invokeOutcomeInner(input, options);
      await reportRetainedQualificationResult(this.client, this.descriptor, outcome);
      return outcome;
    } catch (error) {
      await reportRetainedQualificationCancellation(this.client, this.descriptor, error);
      throw error;
    }
  }
  private async invokeOutcomeInner(input: unknown, options: OperationOptions): Promise<ProfileOutcome<T, P, G>> {
    const descriptor = this.descriptor; const selected = profileOperationOptions(options, descriptor.executionMilliseconds);
    const deadline = performance.now() + selected.timeoutMs;
    const advancementDeadline = deadline - selected.recoveryWaitMs;
    this.verifyCapability();
    const profileInput = await encodeProfileInput(descriptor.profileApi, descriptor.inputType, input);
    if (profileInput.length < 1 || profileInput.length > descriptor.requestBytes) throw new RangeError("profile input exceeds declared bound");
    const idempotency = options.idempotencyKey ?? null;
    if (idempotency === null) return await this.invokeLeader(requestId(), idempotency, profileInput, advancementDeadline, deadline, selected.recoveryWaitMs, options.signal);
    const fingerprint = await invocationFingerprint(profileInput, this.connection ?? null);
    const scope = `${descriptor.profileId}/${descriptor.version}:${idempotency}`;
    for (;;) {
      const ticket = beginProfileInvocation(this.client, scope, fingerprint, requestId());
      if (ticket.role === "follower" || ticket.role === "observer") {
        try {
          const identity = await waitForCoordinatedIdentity(ticket, deadline);
          if (identity === null) continue;
          const outcome = await this.observeCoordinated(ticket, identity, deadline);
          qualificationResults.delete(outcome as object);
          return outcome;
        } finally { finishProfileInvocation(this.client, ticket); }
      }
      let conflictOperation: string | undefined;
      if (ticket.role === "conflict-probe") {
        const identity = await waitForCoordinatedIdentity(ticket, deadline);
        if (identity === null) { finishProfileInvocation(this.client, ticket); continue; }
        conflictOperation = identity.operationId;
      }
      return await this.invokeLeader(ticket.requestId, idempotency, profileInput, advancementDeadline, deadline, selected.recoveryWaitMs, options.signal, ticket, conflictOperation);
    }
  }
  private async invokeLeader(request: Uint8Array, idempotency: string | null, profileInput: Uint8Array, advancementDeadline: number, deadline: number, recoveryWaitMs: number, signal?: AbortSignal, ticket?: ProfileInvocationTicket, conflictOperation?: string): Promise<ProfileOutcome<T, P, G>> {
    try {
      const conflictProbe = ticket?.role === "conflict-probe" ? ticket : undefined;
      const acquisition = await this.acquirePreparationEvidence(request, idempotency, profileInput, advancementDeadline, deadline, signal, conflictProbe);
      if (acquisition.outcome !== null) {
        const wire = profileOutcome(acquisition.outcome, request, this.descriptor); await this.publishInitial(ticket, wire);
        if (ticket?.role === "conflict-probe") return await this.projectConflictProbe(wire, conflictOperation);
        return acquisition.cancellation === null
          ? await this.driveOutcome(request, wire, advancementDeadline, deadline, recoveryWaitMs, signal)
          : await this.driveCancelledOutcome(request, wire, deadline, recoveryWaitMs, acquisition.cancellation);
      }
      if (acquisition.cancellation !== null) { acquisition.handle?.fill(0); throw acquisition.cancellation; }
      const evidenceHandle = acquisition.handle;
      const prepare = encodeDeterministic(new Map<unknown, unknown>([[1, 1], [2, request], [3, idempotency], [4, fromHex(this.descriptor.runtimeContractDigest)], [5, profileInput], [6, this.connection ?? null], [7, evidenceHandle]]));
      evidenceHandle?.fill(0);
      let wire: Map<number, unknown>; let cancellation: unknown | null = null;
      try {
        wire = profileOutcome(await profileRequest(this.client, "POST", this.descriptor.collectionRoute, prepare, remainingMilliseconds(advancementDeadline), signal, conflictProbe), request, this.descriptor);
      } catch (error) {
        if (!isPostWriteRequestError(error) && !(error instanceof TypeError) && !(error instanceof RangeError)) throw error;
        const cause = postWriteRequestCause(error); if (isCancellation(cause) || isTimeout(cause)) cancellation = cause;
        wire = profileOutcome(await profileRequest(this.client, "POST", this.descriptor.collectionRoute, prepare, remainingMilliseconds(deadline), undefined, conflictProbe), request, this.descriptor);
      }
      await this.publishInitial(ticket, wire);
      if (ticket?.role === "conflict-probe") return await this.projectConflictProbe(wire, conflictOperation);
      return cancellation === null
        ? await this.driveOutcome(request, wire, advancementDeadline, deadline, recoveryWaitMs, signal)
        : await this.driveCancelledOutcome(request, wire, deadline, recoveryWaitMs, cancellation);
    } finally { if (ticket !== undefined) finishProfileInvocation(this.client, ticket); }
  }
  private async projectConflictProbe(wire: Map<number, unknown>, expectedOperation?: string): Promise<ProfileOutcome<T, P, G>> {
    const kind = wire.get(2);
    if ((kind !== "conflict" && kind !== "receipt-integrity-failed") || expectedOperation === undefined) throw new TypeError("changed idempotency intent did not return Conflict");
    const operation = operationId(wire.get(4));
    if (operation !== expectedOperation) throw new TypeError("idempotency conflict changed operation identity");
    bindRecoveryResponse(wire, Object.freeze({ operationId: expectedOperation, profileId: this.descriptor.profileId, version: this.descriptor.version }), this.descriptor);
    const projected = await projectAndRetain<T, P, G>(this.descriptor, wire);
    if (projected.kind === "conflict" && (projected.issue.code !== "operation.idempotency-conflict" || projected.issue.correlationId !== expectedOperation || projected.issue.executionReference !== expectedOperation)) throw new TypeError("changed idempotency intent returned an unrelated conflict");
    return projected;
  }
  private async publishInitial(ticket: ProfileInvocationTicket | undefined, wire: Map<number, unknown>): Promise<void> {
    if (ticket?.role !== "leader") return;
    const raw = wire.get(4);
    if (typeof raw !== "string") { publishProfileInvocation(this.client, ticket, null); return; }
    const operation = operationId(raw);
    bindRecoveryResponse(wire, Object.freeze({ operationId: operation, profileId: this.descriptor.profileId, version: this.descriptor.version }), this.descriptor);
    publishProfileInvocation(this.client, ticket, operation, encodeDeterministic(wire));
  }
  private async observeCoordinated(ticket: ProfileInvocationTicket, identity: CoordinatedOperationIdentity, deadline: number, signal?: AbortSignal): Promise<ProfileOutcome<T, P, G>> {
    const expected = Object.freeze({ operationId: identity.operationId, profileId: this.descriptor.profileId, version: this.descriptor.version });
    let fallback: Readonly<{ recovery: Uint8Array; receipts: readonly string[] }> | null = null;
    if (identity.initial.length > 0) {
      try {
        const initial = profileOutcome(identity.initial, identity.requestId, this.descriptor);
        if (operationId(initial.get(4)) !== identity.operationId) throw new TypeError("coordinated snapshot changed operation identity");
        if (initial.get(2) === "ready") {
          const recovery = bytes(initial.get(7)); assertRecoveryIdentity(recovery, expected);
          fallback = Object.freeze({ recovery: recovery.slice(), receipts: Object.freeze([]) });
          fixedBytes(initial.get(5), 32); optionalText(initial.get(8));
          fallback = Object.freeze({ recovery: recovery.slice(), receipts: await receiptIdsFrom([initial.get(6)], this.descriptor) });
        } else if (initial.get(2) === "in-progress") {
          const recovery = bytes(initial.get(8)); assertRecoveryIdentity(recovery, expected);
          fallback = Object.freeze({ recovery: recovery.slice(), receipts: Object.freeze([]) });
          validateInProgress(initial, this.descriptor);
          const receipts = receiptIdList(initial.get(7), this.descriptor.receiptCount);
          if (initial.get(6) === "possible") return recoveryRequired(identity.operationId, recoveryHandleFromBytes(recovery), receipts);
          fallback = Object.freeze({ recovery: recovery.slice(), receipts });
        } else return await projectAndRetain<T, P, G>(this.descriptor, coordinatedReplayWire(initial));
      } catch (error) {
        if (error instanceof DOMException) throw error;
        // The operation identity is still durable. Fall through to the fixed
        // read-only status route rather than erasing it as a prewrite failure.
      }
    }
    for (;;) {
      const remaining = Math.floor(deadline - performance.now());
      if (remaining < 1) {
        if (fallback === null) throw new DOMException("Auths operation timed out", "TimeoutError");
        return recoveryRequired(identity.operationId, recoveryHandleFromBytes(fallback.recovery), fallback.receipts);
      }
      let raw: Uint8Array;
      try {
        const status = profileInvocationStatus(this.client, ticket, () => profileRequest(
          this.client, "GET", `${this.descriptor.collectionRoute}/${identity.operationId}`,
          new Uint8Array(), Math.min(1_000, remaining),
        ));
        raw = await waitForCoordinatedStatus(status, deadline, signal);
      } catch {
        if (fallback === null) throw new DOMException("Auths operation timed out", "TimeoutError");
        return recoveryRequired(identity.operationId, recoveryHandleFromBytes(fallback.recovery), fallback.receipts);
      }
      try {
        const wire = profileOutcome(raw, identity.requestId, this.descriptor);
        if (operationId(wire.get(4)) !== identity.operationId) throw new TypeError("coordinated status changed operation identity");
        bindRecoveryResponse(wire, expected, this.descriptor);
        if (wire.get(2) === "ready") {
          const recovery = bytes(wire.get(7)); assertRecoveryIdentity(recovery, expected);
          fallback = Object.freeze({ recovery: recovery.slice(), receipts: Object.freeze([]) });
          fixedBytes(wire.get(5), 32); optionalText(wire.get(8));
          fallback = Object.freeze({ recovery: recovery.slice(), receipts: await receiptIdsFrom([wire.get(6)], this.descriptor) });
        } else if (wire.get(2) === "in-progress") {
          const recovery = bytes(wire.get(8)); assertRecoveryIdentity(recovery, expected);
          fallback = Object.freeze({ recovery: recovery.slice(), receipts: Object.freeze([]) });
          validateInProgress(wire, this.descriptor);
          const receipts = receiptIdList(wire.get(7), this.descriptor.receiptCount);
          if (wire.get(6) === "possible") return recoveryRequired(identity.operationId, recoveryHandleFromBytes(recovery), receipts);
          fallback = Object.freeze({ recovery: recovery.slice(), receipts });
        } else {
          return await projectAndRetain<T, P, G>(this.descriptor, coordinatedReplayWire(wire));
        }
      } catch {
        if (fallback === null) throw new TypeError("invalid coordinated profile status");
        return recoveryRequired(identity.operationId, recoveryHandleFromBytes(fallback.recovery), fallback.receipts);
      }
      await retryPause(Math.min(25, remainingMilliseconds(deadline)), signal);
    }
  }
  private async driveOutcome(request: Uint8Array, initial: Map<number, unknown>, advancementDeadline: number, deadline: number, recoveryWaitMs: number, signal?: AbortSignal): Promise<ProfileOutcome<T, P, G>> {
    let wire = initial;
    if (wire.get(2) === "ready") {
      const operation = operationId(wire.get(4)); const preparedRecovery = bytes(wire.get(7));
      const expected = Object.freeze({ operationId: operation, profileId: this.descriptor.profileId, version: this.descriptor.version });
      assertRecoveryIdentity(preparedRecovery, expected);
      let commitment: Uint8Array; let preparedReceiptIds: readonly string[];
      try {
        commitment = fixedBytes(wire.get(5), 32); optionalText(wire.get(8));
        preparedReceiptIds = await receiptIdsFrom([wire.get(6)], this.descriptor);
      } catch {
        return recoveryRequired(operation, recoveryHandleFromBytes(preparedRecovery), []);
      }
      const execute = encodeDeterministic(new Map<unknown, unknown>([[1, 1], [2, request], [3, operation], [4, commitment]]));
      const recoveryDeadline = Math.min(deadline, performance.now() + recoveryWaitMs);
      try {
        wire = profileOutcome(await profileRequest(this.client, "POST", `${this.descriptor.collectionRoute}/${operation}/execute`, execute, remainingMilliseconds(advancementDeadline), signal), request, this.descriptor);
      } catch {
        return await this.recoverWithinDeadline(request, operation, preparedRecovery, preparedReceiptIds, recoveryDeadline);
      }
      if (wire.get(2) === "in-progress") {
        return await this.waitForAcceptedExecute(request, operation, wire, preparedRecovery, preparedReceiptIds, recoveryDeadline, signal);
      }
    }
    if (wire.get(2) === "in-progress") {
      const operation = operationId(wire.get(4));
      const recovery = bytes(wire.get(8));
      assertRecoveryIdentity(recovery, Object.freeze({ operationId: operation, profileId: this.descriptor.profileId, version: this.descriptor.version }));
      let receipts: readonly string[];
      try { validateInProgress(wire, this.descriptor); receipts = receiptIdList(wire.get(7), this.descriptor.receiptCount); }
      catch { return recoveryRequired(operation, recoveryHandleFromBytes(recovery), []); }
      return await this.waitForAcceptedExecute(request, operation, wire, recovery, receipts, Math.min(deadline, performance.now() + recoveryWaitMs), signal);
    }
    return await projectAndRetain<T, P, G>(this.descriptor, wire);
  }
  private async driveCancelledOutcome(request: Uint8Array, wire: Map<number, unknown>, deadline: number, recoveryWaitMs: number, cancellation: unknown): Promise<ProfileOutcome<T, P, G>> {
    let outcome: ProfileOutcome<T, P, G>;
    let projectedHere = false;
    if (wire.get(2) === "ready") {
      const operation = operationId(wire.get(4)); const recovery = bytes(wire.get(7));
      assertRecoveryIdentity(recovery, Object.freeze({ operationId: operation, profileId: this.descriptor.profileId, version: this.descriptor.version }));
      let receipts: readonly string[] = [];
      try { fixedBytes(wire.get(5), 32); optionalText(wire.get(8)); receipts = await receiptIdsFrom([wire.get(6)], this.descriptor); }
      catch { /* The bound handle is sufficient for shielded release. */ }
      outcome = await this.recoverWithinDeadline(request, operation, recovery, receipts, Math.min(deadline, performance.now() + recoveryWaitMs));
    } else if (wire.get(2) === "in-progress") {
      const operation = operationId(wire.get(4)); const recovery = bytes(wire.get(8));
      assertRecoveryIdentity(recovery, Object.freeze({ operationId: operation, profileId: this.descriptor.profileId, version: this.descriptor.version }));
      let receipts: readonly string[] = [];
      try { validateInProgress(wire, this.descriptor); receipts = receiptIdList(wire.get(7), this.descriptor.receiptCount); }
      catch { /* The bound handle is sufficient for shielded recovery. */ }
      outcome = await this.recoverWithinDeadline(
        request,
        operation,
        recovery,
        receipts,
        Math.min(deadline, performance.now() + recoveryWaitMs),
      );
    } else {
      outcome = await project<T, P, G>(this.descriptor, wire);
      projectedHere = true;
    }
    if (outcome.kind === "completed" || outcome.kind === "partial" || outcome.kind === "conflict" || outcome.kind === "recovery-required" || outcome.kind === "receipt-integrity-failed") {
      if (projectedHere) retainQualificationResult(outcome, wire);
      return outcome;
    }
    if (!isCancellation(cancellation)) {
      if (projectedHere) retainQualificationResult(outcome, wire);
      return outcome;
    }
    qualificationResults.delete(outcome as object);
    if (typeof cancellation === "object" && cancellation !== null) qualificationCancellations.set(cancellation, request.slice());
    throw cancellation;
  }
  private async acquirePreparationEvidence(request: Uint8Array, idempotency: string | null, profileInput: Uint8Array, advancementDeadline: number, deadline: number, signal?: AbortSignal, coordination?: ProfileInvocationTicket): Promise<{ readonly handle: Uint8Array | null; readonly outcome: Uint8Array | null; readonly cancellation: unknown | null }> {
    if (this.descriptor.preparationEvidence === null) return { handle: null, outcome: null, cancellation: null };
    const body = encodeDeterministic(new Map<unknown, unknown>([[1, 1], [2, request], [3, idempotency], [4, fromHex(this.descriptor.runtimeContractDigest)], [5, profileInput], [6, this.connection ?? null]]));
    const route = this.descriptor.collectionRoute.replace(/\/operations$/u, "/preparation-evidence");
    let decoded: { readonly handle: Uint8Array | null; readonly outcome: Uint8Array | null };
    let cancellation: unknown | null = null;
    try {
      decoded = this.decodePreparationEvidenceResponse(
        await profileRequest(this.client, "POST", route, body, remainingMilliseconds(advancementDeadline), signal, coordination),
        request,
      );
    } catch (error) {
      if (!isPostWriteRequestError(error) && !(error instanceof TypeError) && !(error instanceof RangeError)) throw error;
      const cause = postWriteRequestCause(error);
      if (isCancellation(cause) || isTimeout(cause)) cancellation = cause;
      decoded = this.decodePreparationEvidenceResponse(
        await profileRequest(this.client, "POST", route, body, remainingMilliseconds(deadline), undefined, coordination),
        request,
      );
    }
    return { ...decoded, cancellation };
  }
  private decodePreparationEvidenceResponse(response: Uint8Array, request: Uint8Array): { readonly handle: Uint8Array | null; readonly outcome: Uint8Array | null } {
    if (response.length < 1 || response.length > this.descriptor.responseBytes + 256) throw new RangeError("preparation evidence response exceeds bound");
    const wire = integerMap(decodeDeterministic(response));
    if (wire.get(1) !== 1 || !equalBytes(fixedBytes(wire.get(2), 16), request)) throw new TypeError("invalid preparation evidence response");
    if (wire.get(3) === "lease") {
      if (!exactIntegerKeys(wire, 6)) throw new TypeError("invalid preparation evidence lease");
      const handle = fixedBytes(wire.get(4), 32).slice(); fixedBytes(wire.get(5), 32);
      const expiresAt = integer(wire.get(6));
      if (expiresAt < 1) throw new TypeError("invalid preparation evidence expiry");
      return { handle, outcome: null };
    }
    if (wire.get(3) === "outcome") {
      if (!exactIntegerKeys(wire, 4)) throw new TypeError("invalid preparation evidence outcome");
      const outcome = bytes(wire.get(4));
      if (outcome.length < 1 || outcome.length > this.descriptor.responseBytes) throw new RangeError("preparation evidence outcome exceeds profile bound");
      return { handle: null, outcome };
    }
    throw new TypeError("unknown preparation evidence response");
  }
  private async waitForAcceptedExecute(request: Uint8Array, operation: string, initial: Map<number, unknown>, preparedRecovery: Uint8Array, preparedReceiptIds: readonly string[], deadline: number, signal?: AbortSignal): Promise<ProfileOutcome<T, P, G>> {
    let wire = initial; let recovery = preparedRecovery; let receipts = preparedReceiptIds;
    while (wire.get(2) === "in-progress") {
      try {
        const candidate = bytes(wire.get(8));
        assertRecoveryIdentity(candidate, Object.freeze({ operationId: operation, profileId: this.descriptor.profileId, version: this.descriptor.version }));
        validateInProgress(wire, this.descriptor);
        recovery = candidate; receipts = receiptIdList(wire.get(7), this.descriptor.receiptCount);
      } catch {
        return await this.recoverWithinDeadline(request, operation, recovery, receipts, deadline);
      }
      const remaining = Math.max(0, Math.floor(deadline - performance.now()));
      if (wire.get(6) !== "not-applied") return await this.recoverWithinDeadline(request, operation, recovery, receipts, deadline);
      if (remaining < 1) return recoveryRequired(operation, recoveryHandleFromBytes(recovery), receipts);
      try {
        await retryPause(Math.min(25, remaining), signal);
        wire = profileOutcome(await profileRequest(this.client, "GET", `${this.descriptor.collectionRoute}/${operation}`, new Uint8Array(), remainingMilliseconds(deadline), signal), request, this.descriptor);
      } catch (error) {
        // The execute request was already accepted. Cancellation, status
        // transport failure, and malformed status all enter recovery without
        // forwarding the caller's signal, so the durable pre-entry reservation
        // is proved/released before control returns to the application.
        return await this.recoverWithinDeadline(request, operation, recovery, receipts, deadline);
      }
    }
    let projected: ProfileOutcome<T, P, G>;
    try { projected = await project<T, P, G>(this.descriptor, wire); }
    catch { return await this.recoverWithinDeadline(request, operation, recovery, receipts, deadline); }
    retainQualificationResult(projected, wire);
    return projected;
  }
  private async recoverWithinDeadline(request: Uint8Array, operation: string, recoveryBytes: Uint8Array, receiptIds: readonly string[], deadline: number): Promise<ProfileOutcome<T, P, G>> {
    const expected = Object.freeze({ operationId: operation, profileId: this.descriptor.profileId, version: this.descriptor.version });
    assertRecoveryIdentity(recoveryBytes, expected);
    const remaining = Math.max(0, Math.floor(deadline - performance.now()));
    if (remaining < 1) return recoveryRequired(operation, recoveryHandleFromBytes(recoveryBytes), receiptIds);
    return await this.recoverAmbiguous(request, operation, recoveryBytes, receiptIds, remaining, expected);
  }
  async recover(recovery: RecoveryHandle, options: RecoveryOptions = {}): Promise<T> {
    const outcome = await this.recoverOutcome(recovery, options);
    if (outcome.kind === "completed") return outcome.value;
    raiseOutcome(outcome);
  }
  async recoverOutcome(recovery: RecoveryHandle, options: RecoveryOptions = {}): Promise<ProfileOutcome<T, P, G>> {
    try {
      const outcome = await this.recoverOutcomeInner(recovery, options);
      await reportRetainedQualificationResult(this.client, this.descriptor, outcome);
      return outcome;
    } catch (error) {
      await reportRetainedQualificationCancellation(this.client, this.descriptor, error);
      throw error;
    }
  }
  private async recoverOutcomeInner(recovery: RecoveryHandle, options: RecoveryOptions): Promise<ProfileOutcome<T, P, G>> {
    const recoveryOnly = profileSessionRecoveryOnly(this.client);
    const advertised = profileCapabilityForRecovery(this.client, this.descriptor.profileId, this.descriptor.version);
    const compatible = advertised !== undefined && equalBytes(advertised.runtimeDigest, fromHex(this.descriptor.runtimeContractDigest)) && equalBytes(advertised.errorDigest, fromHex(this.descriptor.errorProjectionDigest)) && advertised.operationProtocol === "auths.profile-operation/1";
    if (!compatible && !recoveryOnly) throw operationErrors.unavailable(profileContractIssue(), null, []);
    const timeoutMs = profileOperationOptions(options, this.descriptor.executionMilliseconds).timeoutMs;
    const identity = recoveryIdentity(recovery.toBytes());
    if (identity.profileId !== this.descriptor.profileId || identity.version !== this.descriptor.version) throw new TypeError("recovery handle belongs to another profile");
    const request = requestId(); const body = encodeDeterministic(new Map<unknown, unknown>([[1, 1], [2, request], [3, recovery.toBytes()]]));
    let terminal: Map<number, unknown> | null = null;
    try {
      const raw = await profileRequest(this.client, "POST", "/v1/operations/recover", body, timeoutMs, options.signal);
      if (!compatible) return recoveryUnavailable(identity.operationId, recovery, []);
      const wire = profileOutcome(raw, request, this.descriptor);
      bindRecoveryResponse(wire, identity, this.descriptor);
      if (wire.get(2) === "in-progress") { validateInProgress(wire, this.descriptor); return recoveryRequired(identity.operationId, recoveryHandleFromBytes(bytes(wire.get(8))), receiptIdList(wire.get(7), this.descriptor.receiptCount)); }
      if (wire.get(2) === "ready") { optionalText(wire.get(8)); return recoveryRequired(identity.operationId, recoveryHandleFromBytes(bytes(wire.get(7))), await receiptIdsFrom([wire.get(6)], this.descriptor)); }
      terminal = wire;
    } catch {
      return recoveryOnly ? recoveryUnavailable(identity.operationId, recovery, []) : recoveryRequired(identity.operationId, recovery, []);
    }
    return await projectAndRetain<T, P, G>(this.descriptor, terminal);
  }
  private verifyCapability(): void {
    const advertised = profileCapability(this.client, this.descriptor.profileId, this.descriptor.version);
    if (!equalBytes(advertised.runtimeDigest, fromHex(this.descriptor.runtimeContractDigest)) || !equalBytes(advertised.errorDigest, fromHex(this.descriptor.errorProjectionDigest)) || advertised.operationProtocol !== "auths.profile-operation/1") throw operationErrors.unavailable(profileContractIssue(), null, []);
  }
  private async recoverAmbiguous(request: Uint8Array, operation: string, recoveryBytes: Uint8Array, receiptIds: readonly string[], timeoutMs: number, expected: Readonly<{ operationId: string; profileId: string; version: number }>): Promise<ProfileOutcome<T, P, G>> {
    const recovery = recoveryHandleFromBytes(recoveryBytes);
    const body = encodeDeterministic(new Map<unknown, unknown>([[1, 1], [2, request], [3, recoveryBytes]]));
    let terminal: Map<number, unknown> | null = null;
    try {
      const wire = profileOutcome(await profileRequest(this.client, "POST", `${this.descriptor.collectionRoute}/${operation}/recover`, body, timeoutMs), request, this.descriptor);
      bindRecoveryResponse(wire, expected, this.descriptor);
      if (wire.get(2) === "in-progress") { validateInProgress(wire, this.descriptor); return recoveryRequired(operation, recoveryHandleFromBytes(bytes(wire.get(8))), receiptIdList(wire.get(7), this.descriptor.receiptCount)); }
      if (wire.get(2) === "ready") { optionalText(wire.get(8)); return recoveryRequired(operation, recoveryHandleFromBytes(bytes(wire.get(7))), await receiptIdsFrom([wire.get(6)], this.descriptor)); }
      terminal = wire;
    } catch {
      return recoveryRequired(operation, recovery, receiptIds);
    }
    return await projectAndRetain<T, P, G>(this.descriptor, terminal);
  }
}

async function invocationFingerprint(profileInput: Uint8Array, connection: string | null): Promise<string> {
  const tuple = encodeDeterministic(new Map<unknown, unknown>([[1, profileInput], [2, connection]]));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(tuple).buffer));
  tuple.fill(0);
  return base64url(digest);
}

async function waitForCoordinatedIdentity(ticket: ProfileInvocationTicket, deadline: number): Promise<CoordinatedOperationIdentity | null> {
  // Once attached, caller cancellation cannot prove that the coalesced
  // operation stayed pre-entry. Await the leader's durable identity/null proof
  // without forwarding this waiter's signal to the leader.
  const remaining = remainingMilliseconds(deadline);
  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (action: () => void) => { if (settled) return; settled = true; clearTimeout(timer); action(); };
    const timer = setTimeout(() => finish(() => reject(new DOMException("Auths operation timed out", "TimeoutError"))), remaining);
    ticket.identity.then((identity) => finish(() => resolve(identity)), (error) => finish(() => reject(error)));
  });
}

async function waitForCoordinatedStatus(status: Promise<Uint8Array>, deadline: number, signal?: AbortSignal): Promise<Uint8Array> {
  const remaining = remainingMilliseconds(deadline);
  if (signal?.aborted) throw new DOMException("Auths operation cancelled", "AbortError");
  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (action: () => void) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener("abort", abort); action(); };
    const abort = () => finish(() => reject(new DOMException("Auths operation cancelled", "AbortError")));
    const timer = setTimeout(() => finish(() => reject(new DOMException("Auths operation timed out", "TimeoutError"))), remaining);
    signal?.addEventListener("abort", abort, { once: true });
    status.then((value) => finish(() => resolve(value)), (error) => finish(() => reject(error)));
  });
}

function remainingMilliseconds(deadline: number): number {
  const remaining = Math.floor(deadline - performance.now());
  if (remaining < 1) throw new RangeError("profile operation deadline exceeded");
  return remaining;
}

function isCancellation(value: unknown): boolean {
  return value instanceof DOMException && value.name === "AbortError";
}

function isTimeout(value: unknown): boolean {
  return value instanceof DOMException && value.name === "TimeoutError";
}

async function retryPause(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted === true) throw signal.reason;
  await new Promise<void>((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(signal?.reason); };
    const timer = setTimeout(() => { signal?.removeEventListener("abort", abort); resolve(); }, milliseconds);
    signal?.addEventListener("abort", abort, { once: true });
  });
}

export function bindProfile<T = unknown, P = never, G = never>(client: Client, descriptor: ProfileDescriptor, connection?: string): BoundProfile<T, P, G> {
  return new GeneratedProfile<T, P, G>(client, Object.freeze({ ...descriptor }), connection);
}

async function encodeProfileInput(api: Readonly<Record<string, unknown>>, typeName: string, input: unknown): Promise<Uint8Array> {
  const types = record(api.types); const node = types[typeName]; if (node === undefined) throw new TypeError("generated input type is absent");
  return encodeDeterministic(await validateValue(node, input, types, true));
}
function decodeProfileValue(api: Readonly<Record<string, unknown>>, typeName: string, input: unknown, auths?: OperationMetadata): unknown {
  const types = record(api.types); const node = types[typeName]; if (node === undefined || !(input instanceof Uint8Array)) throw new TypeError("invalid profile result");
  const value = validateValueSync(node, decodeDeterministic(input), types);
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("profile result must be a record");
  return Object.freeze({ ...(value as Record<string, unknown>), ...(auths === undefined ? {} : { auths }) });
}
async function validateValue(nodeValue: unknown, value: unknown, types: Record<string, unknown>, encode: boolean): Promise<unknown> {
  const node = record(nodeValue); const kind = text(node.kind);
  if (kind === "ref") return validateValue(types[text(node.name)], value, types, encode);
  if (kind === "bytes" && encode && typeof value === "object" && value !== null && "file" in value) {
    if (node.sourceConvenience !== "file") throw new TypeError("profile byte field does not accept a file source");
    const source = record(value);
    if (Object.keys(source).length !== 1) throw new TypeError("profile file source is not closed");
    return readBoundedProfileFile(text(source.file), integer(node.maximumBytes));
  }
  if (kind === "record") { const source = record(value); const fields = array(node.fields); const names = fields.map((field) => text(record(field).name)); if (Object.keys(source).some((key) => !names.includes(key)) || Object.keys(source).length !== names.length) throw new TypeError("profile record is not closed"); const output: Record<string, unknown> = {}; for (const field of fields) { const item = record(field); const name = text(item.name); output[name] = await validateValue(item.value, source[name], types, encode); } return output; }
  if (kind === "list") { const values = array(value); const minimum = integer(node.minimumItems); const maximum = integer(node.maximumItems); if (values.length < minimum || values.length > maximum) throw new RangeError("profile list is outside bounds"); return Promise.all(values.map((item) => validateValue(node.value, item, types, encode))); }
  return validateScalar(node, value, types);
}
function validateValueSync(nodeValue: unknown, value: unknown, types: Record<string, unknown>): unknown {
  const node = record(nodeValue); const kind = text(node.kind);
  if (kind === "ref") return validateValueSync(types[text(node.name)], value, types);
  if (kind === "record") { const source = mapOrRecord(value); const fields = array(node.fields); const names = fields.map((field) => text(record(field).name)); if ([...source.keys()].some((key) => typeof key !== "string" || !names.includes(key)) || source.size !== names.length) throw new TypeError("profile result record is not closed"); return Object.freeze(Object.fromEntries(fields.map((field) => { const item = record(field); const name = text(item.name); return [name, validateValueSync(item.value, source.get(name), types)]; }))); }
  if (kind === "list") { const values = array(value); if (values.length < integer(node.minimumItems) || values.length > integer(node.maximumItems)) throw new RangeError("profile list is outside bounds"); return Object.freeze(values.map((item) => validateValueSync(node.value, item, types))); }
  return validateScalar(node, value, types);
}
function validateScalar(node: Record<string, unknown>, value: unknown, types: Record<string, unknown>): unknown {
  const kind = text(node.kind); if (kind === "boolean") { if (typeof value !== "boolean") throw new TypeError("expected boolean"); return value; }
  if (kind === "uint" || kind === "int") { if ((typeof value !== "number" || !Number.isSafeInteger(value)) && typeof value !== "bigint") throw new TypeError("expected integer"); const compared = BigInt(value); if (compared < BigInt(text(node.minimum)) || compared > BigInt(text(node.maximum)) || (kind === "uint" && compared < 0n)) throw new RangeError("integer outside bounds"); return value; }
  if (kind === "string" || kind === "enum") { const selected = text(value); if (kind === "enum") { if (!array(node.values).includes(selected)) throw new TypeError("unknown enum value"); return selected; } const length = new TextEncoder().encode(selected).length; if (length < integer(node.minimumBytes) || length > integer(node.maximumBytes)) throw new RangeError("string outside bounds"); alphabet(selected, text(node.alphabet)); return selected; }
  if (kind === "bytes") { const selected = bytes(value); if (selected.length < integer(node.minimumBytes) || selected.length > integer(node.maximumBytes)) throw new RangeError("bytes outside bounds"); return selected.slice(); }
  if (kind === "option") return value === null ? null : validateScalar(record(node.value), value, types);
  throw new TypeError("unsupported generated profile type");
}
type RetainedQualificationResult = Readonly<{ requestId: Uint8Array; result: Uint8Array }>;
const qualificationResults = new WeakMap<object, RetainedQualificationResult>();
const qualificationCancellations = new WeakMap<object, Uint8Array>();

async function projectAndRetain<T, P, G>(descriptor: ProfileDescriptor, wire: Map<number, unknown>): Promise<ProfileOutcome<T, P, G>> {
  const projected = await project<T, P, G>(descriptor, wire);
  retainQualificationResult(projected, wire);
  return projected;
}
function retainQualificationResult(projected: object, wire: Map<number, unknown>): void {
  qualificationResults.set(projected, Object.freeze({
    requestId: fixedBytes(wire.get(3), 16).slice(),
    result: projectedResultBytes(wire).slice(),
  }));
}
async function reportRetainedQualificationResult(client: Client, descriptor: ProfileDescriptor, projected: object): Promise<void> {
  const retained = qualificationResults.get(projected);
  qualificationResults.delete(projected);
  if (retained !== undefined) await reportQualificationResult(client, descriptor.profileId, descriptor.version, retained.requestId, retained.result);
}
async function reportRetainedQualificationCancellation(client: Client, descriptor: ProfileDescriptor, error: unknown): Promise<void> {
  if (typeof error !== "object" || error === null) return;
  const requestId = qualificationCancellations.get(error);
  qualificationCancellations.delete(error);
  if (requestId !== undefined) await reportQualificationCancellation(client, descriptor.profileId, descriptor.version, requestId);
}
function projectedResultBytes(wire: Map<number, unknown>): Uint8Array {
  const kind = text(wire.get(2));
  if (!["completed", "denied", "unavailable", "conflict", "not-applied", "partial", "recovery-required", "receipt-integrity-failed"].includes(kind)) throw new TypeError("profile outcome has no terminal projection");
  return fixedBoundedBytes(wire.get(5), 16_777_216);
}
async function project<T, P, G>(descriptor: ProfileDescriptor, wire: Map<number, unknown>): Promise<ProfileOutcome<T, P, G>> {
  const kind = text(wire.get(2));
  if (kind === "completed") { const operation = operationId(wire.get(4)); const completion = completionKind(wire.get(7)); const receiptIds = await receiptIdsFrom(wire.get(6), descriptor); const auths = Object.freeze({ operationId: operation, profile: `${descriptor.profileId}/${descriptor.version}`, connection: optionalText(wire.get(8)), completion, receiptIds }); return Object.freeze({ kind, value: decodeProfileValue(descriptor.profileApi, descriptor.successType, wire.get(5), auths) as T }); }
  if (kind === "denied") { optionalText(wire.get(7)); return Object.freeze({ kind, operationId: operationId(wire.get(4)), issue: issueForEffect(wire.get(5), "not-applied"), receiptIds: await receiptIdsFrom([wire.get(6)], descriptor) }); }
  if (kind === "unavailable") { optionalText(wire.get(7)); return Object.freeze({ kind, operationId: wire.get(4) === null ? null : operationId(wire.get(4)), issue: issueForEffect(wire.get(5), "not-applied"), receiptIds: await receiptIdsFrom(wire.get(6), descriptor) }); }
  if (kind === "conflict") { optionalText(wire.get(8)); return Object.freeze({ kind, operationId: operationId(wire.get(4)), issue: issueForEffect(wire.get(5), "possible"), recovery: recoveryHandleFromBytes(bytes(wire.get(6))), receiptIds: await receiptIdsFrom(wire.get(7), descriptor) }); }
  if (kind === "not-applied") { optionalText(wire.get(8)); return Object.freeze({ kind, operationId: operationId(wire.get(4)), issue: issueForEffect(wire.get(5), "not-applied"), receiptIds: await receiptIdsFrom(wire.get(6), descriptor), completion: completionKind(wire.get(7)) }); }
  if (kind === "partial") { optionalText(wire.get(9)); if (descriptor.partialType == null) throw new TypeError("undeclared partial result"); return Object.freeze({ kind, operationId: operationId(wire.get(4)), details: decodeProfileValue(descriptor.profileApi, descriptor.partialType, wire.get(5)) as P, issue: issueForEffect(wire.get(6), "applied"), receiptIds: await receiptIdsFrom(wire.get(7), descriptor), completion: completionKind(wire.get(8)) }); }
  if (kind === "recovery-required") { optionalText(wire.get(9)); let progress: G | null = null; if (wire.get(8) !== null) { if (descriptor.progressType == null) throw new TypeError("undeclared recovery progress"); progress = decodeProfileValue(descriptor.profileApi, descriptor.progressType, wire.get(8)) as G; } return Object.freeze({ kind, operationId: operationId(wire.get(4)), issue: issueForEffect(wire.get(5), "possible"), recovery: recoveryHandleFromBytes(bytes(wire.get(6))), receiptIds: await receiptIdsFrom(wire.get(7), descriptor), progress }); }
  if (kind === "receipt-integrity-failed") { optionalText(wire.get(9)); const operation = operationId(wire.get(4)); const state = integrityState(wire.get(6)); const effect = integrityEffect(wire.get(7)); const terminal = boolean(wire.get(8)); if (!validIntegrityTruth(state, effect, terminal)) throw new TypeError("receipt integrity outcome contradicts durable truth"); const parsed = issueForEffect(wire.get(5), effect); if (parsed.code !== "core.terminal-receipt-integrity-failed" || parsed.correlationId !== operation || parsed.executionReference !== operation || !integrityProviderBoundary(state, effect, parsed.enteredBoundaries.provider)) throw new TypeError("unexpected receipt integrity issue"); return Object.freeze({ kind, operationId: operation, issue: parsed, state, effect, terminal, receiptIds: Object.freeze([]) }); }
  throw new TypeError("unknown profile outcome");
}
function raiseOutcome(value: Exclude<ProfileOutcome<unknown, unknown, unknown>, Completed<unknown>>): never { if (value.kind === "denied") throw operationErrors.denied(value.issue, value.operationId, value.receiptIds); if (value.kind === "unavailable") throw operationErrors.unavailable(value.issue, value.operationId, value.receiptIds); if (value.kind === "conflict") throw operationErrors.conflict(value.issue, value.operationId, value.receiptIds, value.recovery); if (value.kind === "not-applied") throw operationErrors.notApplied(value.issue, value.operationId, value.receiptIds); if (value.kind === "partial") throw operationErrors.partial(value.issue, value.operationId, value.receiptIds, value.details); if (value.kind === "receipt-integrity-failed") throw operationErrors.receiptIntegrity(value.issue, value.operationId, value.state, value.terminal); throw operationErrors.recoveryRequired(value.issue, value.operationId, value.receiptIds, value.recovery, value.progress); }
function outcome(value: Uint8Array, expectedRequest: Uint8Array): Map<number, unknown> { const decoded = integerMap(decodeDeterministic(value)); const kind = text(decoded.get(2)); const sizes: Readonly<Record<string, number>> = { ready: 8, "in-progress": 9, denied: 7, unavailable: 7, conflict: 8, completed: 8, partial: 9, "not-applied": 8, "recovery-required": 9, "receipt-integrity-failed": 9 }; const size = sizes[kind]; if (size === undefined || decoded.get(1) !== 1 || !exactIntegerKeys(decoded, size) || !equalBytes(fixedBytes(decoded.get(3), 16), expectedRequest)) throw new TypeError("invalid profile outcome"); return decoded; }
function profileOutcome(value: Uint8Array, expectedRequest: Uint8Array, descriptor: ProfileDescriptor): Map<number, unknown> { if (value.length < 1 || value.length > descriptor.responseBytes) throw new RangeError("profile response exceeds declared bound"); return outcome(value, expectedRequest); }
function issue(value: unknown): AuthsIssue { const raw = stringMap(decodeDeterministic(fixedBoundedBytes(value, 65_536))); exactStringKeys(raw, ["schema", "family", "code", "operation", "stage", "summary", "correlationId", "retry", "effect", "entered", "recommendedAction", "executionReference", "decisionReference", "receiptReference", "causes"]); const entered = stringMap(raw.get("entered")); exactStringKeys(entered, ["approval", "signer", "state", "credential", "provider"]); return parseAuthsErrorEnvelope({ schema: text(raw.get("schema")), family: text(raw.get("family")), code: text(raw.get("code")), operation: text(raw.get("operation")), stage: text(raw.get("stage")), summary: text(raw.get("summary")), correlationId: text(raw.get("correlationId")), retry: text(raw.get("retry")), effect: text(raw.get("effect")), entered: { approval: boolean(entered.get("approval")), signer: boolean(entered.get("signer")), state: boolean(entered.get("state")), credential: boolean(entered.get("credential")), provider: boolean(entered.get("provider")) }, recommendedAction: text(raw.get("recommendedAction")), executionReference: raw.get("executionReference") === null ? null : text(raw.get("executionReference")), decisionReference: raw.get("decisionReference") === null ? null : text(raw.get("decisionReference")), receiptReference: raw.get("receiptReference") === null ? null : text(raw.get("receiptReference")), causes: array(raw.get("causes")).map(text) }).issue; }
function issueForEffect(value: unknown, expected: AuthsIssue["effect"]): AuthsIssue { const parsed = issue(value); if (parsed.effect !== expected) throw new TypeError("profile outcome contradicts its Auths issue effect"); return parsed; }
function integrityEffect(value: unknown): AuthsIssue["effect"] { const selected = text(value); if (selected !== "not-applied" && selected !== "possible" && selected !== "applied") throw new TypeError("invalid receipt integrity effect"); return selected; }
function integrityState(value: unknown): import("./index.js").OperationState { const selected = text(value); if (!["preparing", "denied", "unavailable", "ready", "executing", "recovery-required", "completed", "partial", "not-applied"].includes(selected)) throw new TypeError("invalid receipt integrity state"); return selected as import("./index.js").OperationState; }
function validIntegrityTruth(state: import("./index.js").OperationState, effect: AuthsIssue["effect"], terminal: boolean): boolean { if (state === "preparing" || state === "ready") return effect === "not-applied" && !terminal; if (state === "executing") return (effect === "not-applied" || effect === "possible") && !terminal; if (state === "denied" || state === "unavailable" || state === "not-applied") return effect === "not-applied" && terminal; if (state === "recovery-required") return effect === "possible" && !terminal; return (state === "completed" || state === "partial") && effect === "applied" && terminal; }
function integrityProviderBoundary(state: import("./index.js").OperationState, effect: AuthsIssue["effect"], entered: boolean): boolean { if (state === "preparing" || state === "ready" || state === "denied" || state === "unavailable") return !entered; if (effect === "possible" || effect === "applied") return entered; return true; }
function profileContractIssue(): AuthsIssue { return Object.freeze({ schema: "auths.error/1", family: "configuration", code: "client.profile-contract-mismatch", operation: "connect", stage: "negotiation", summary: "generated profile contract does not match the local Auths agent", correlationId: "auths-typescript", retry: "never", effect: "not-applied", enteredBoundaries: Object.freeze({ approval: false, signer: false, state: false, credential: false, provider: false }), recommendedAction: "install-compatible-runtime", causes: Object.freeze([]) }); }
function recoveryRequired<T, P, G>(operationIdValue: string, recovery: RecoveryHandle, receiptIds: readonly string[]): ProfileOutcome<T, P, G> { return Object.freeze({ kind: "recovery-required", operationId: operationIdValue, issue: outcomeUnknownIssue(operationIdValue), recovery, receiptIds: Object.freeze([...receiptIds]), progress: null }); }
function coordinatedReplayWire(value: Map<number, unknown>): Map<number, unknown> { const wire = new Map(value); const kind = wire.get(2); if (kind === "completed" || kind === "not-applied") { completionKind(wire.get(7)); wire.set(7, "replayed"); } else if (kind === "partial") { completionKind(wire.get(8)); wire.set(8, "replayed"); } return wire; }
function recoveryUnavailable<T, P, G>(operationIdValue: string, recovery: RecoveryHandle, receiptIds: readonly string[]): ProfileOutcome<T, P, G> { return Object.freeze({ kind: "recovery-required", operationId: operationIdValue, issue: recoveryUnavailableIssue(operationIdValue), recovery, receiptIds: Object.freeze([...receiptIds]), progress: null }); }
function outcomeUnknownIssue(operation: string): AuthsIssue { return Object.freeze({ schema: "auths.error/1", family: "state", code: "operation.outcome-unknown", operation: "execute", stage: "provider", summary: "the provider outcome remains unknown; recover this operation", correlationId: operation, retry: "unknown", effect: "possible", enteredBoundaries: Object.freeze({ approval: false, signer: false, state: true, credential: true, provider: true }), recommendedAction: "resume-and-reconcile", executionReference: operation, causes: Object.freeze(["unknown"] as const), }); }
function recoveryUnavailableIssue(operation: string): AuthsIssue { return Object.freeze({ schema: "auths.error/1", family: "state", code: "operation.recovery-unavailable", operation: "recover", stage: "reconciliation", summary: "recovery could not safely decode the installed operation outcome", correlationId: operation, retry: "unknown", effect: "possible", enteredBoundaries: Object.freeze({ approval: false, signer: false, state: false, credential: false, provider: true }), recommendedAction: "resume-and-reconcile", executionReference: operation, causes: Object.freeze(["unknown"] as const), }); }
async function receiptIdsFrom(value: unknown, descriptor: ProfileDescriptor): Promise<readonly string[]> { const items = array(value); if (items.length > descriptor.receiptCount) throw new RangeError("too many receipts for profile"); let total = 0; const inputs = items.map((item) => { const input = new Uint8Array(fixedBoundedBytes(item, Math.min(1_048_576, descriptor.receiptBytes))); total += input.length; if (total > descriptor.receiptBytes) throw new RangeError("profile receipt bytes exceed declared bound"); return input; }); const engine = await loadPackagedWorkflowEngine(); return Object.freeze(inputs.map((input) => parsePortableReceipt(input, engine).portableReceiptId)); }
function receiptIdList(value: unknown, maximum: number): readonly string[] { const items = array(value); if (items.length > maximum) throw new RangeError("too many receipt IDs for profile"); return Object.freeze(items.map((item) => { const selected = text(item); if (!/^rcpt_[A-Za-z0-9_-]{43}$/u.test(selected)) throw new TypeError("invalid receipt ID"); return selected; })); }
function recoveryIdentity(value: Uint8Array): Readonly<{ operationId: string; profileId: string; version: number }> { const raw = integerMap(decodeDeterministic(fixedBoundedBytes(value, 16_384))); if (!exactIntegerKeys(raw, 11) || raw.get(1) !== 1) throw new TypeError("invalid recovery handle"); const operation = operationId(raw.get(2)); const profileId = text(raw.get(3)); const version = integer(raw.get(4)); if (!/^auths\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$/u.test(profileId) || version < 1 || version > 65_535) throw new TypeError("invalid recovery handle profile"); fixedBytes(raw.get(5), 32); integer(raw.get(6)); if (raw.get(7) !== null) integer(raw.get(7)); fixedBytes(raw.get(8), 32); if (raw.get(9) !== "Ed25519") throw new TypeError("invalid recovery handle algorithm"); text(raw.get(10)); fixedBytes(raw.get(11), 64); return Object.freeze({ operationId: operation, profileId, version }); }
function bindRecoveryResponse(wire: Map<number, unknown>, expected: Readonly<{ operationId: string; profileId: string; version: number }>, descriptor: ProfileDescriptor): void {
  const operation = operationId(wire.get(4));
  if (operation !== expected.operationId || expected.profileId !== descriptor.profileId || expected.version !== descriptor.version) throw new TypeError("recovery response changed operation identity");
  const kind = text(wire.get(2));
  const rawHandle = kind === "ready" ? wire.get(7) : kind === "in-progress" ? wire.get(8) : kind === "conflict" || kind === "recovery-required" ? wire.get(6) : undefined;
  if (rawHandle !== undefined) {
    const actual = recoveryIdentity(bytes(rawHandle));
    if (actual.operationId !== expected.operationId || actual.profileId !== expected.profileId || actual.version !== expected.version) throw new TypeError("recovery response returned a foreign handle");
  }
}

function assertRecoveryIdentity(value: Uint8Array, expected: Readonly<{ operationId: string; profileId: string; version: number }>): void {
  const actual = recoveryIdentity(value);
  if (actual.operationId !== expected.operationId || actual.profileId !== expected.profileId || actual.version !== expected.version) throw new TypeError("recovery handle changed operation identity");
}
function alphabet(value: string, kind: string): void { const patterns: Record<string, RegExp> = { "ascii-graphic": /^[!-~]*$/u, "registered-token": /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u, "lower-token": /^[a-z][a-z0-9-]*$/u, "lower-hex": /^[0-9a-f]+$/u, base64url: /^[A-Za-z0-9_-]+$/u }; if (kind === "utf8") { if (/[\u0000-\u001f\u007f-\u009f]/u.test(value)) throw new TypeError("forbidden control character"); } else if (patterns[kind]?.test(value) !== true) throw new TypeError("profile string violates alphabet"); }
function route(profileId: string, version: number): string { const match = /^auths\.([a-z][a-z0-9-]*)\.([a-z][a-z0-9-]*)$/u.exec(profileId); if (match === null || !Number.isSafeInteger(version) || version < 1) throw new TypeError("invalid profile identity"); return `/v1/profiles/${match[1]}/${match[2]}/${version}/operations`; }
function operationId(value: unknown): string { const selected = text(value); if (!/^op_[A-Za-z0-9_-]{22}$/u.test(selected)) throw new TypeError("invalid operation ID"); return selected; }
function completionKind(value: unknown): Completion { if (value !== "fresh" && value !== "replayed" && value !== "reconciled") throw new TypeError("invalid completion"); return value; }
function optionalText(value: unknown): string | null { if (value === null) return null; const selected = text(value); if (!/^[a-z][a-z0-9-]{0,63}$/u.test(selected)) throw new TypeError("invalid connection alias"); return selected; }
function validateInProgress(value: Map<number, unknown>, descriptor: ProfileDescriptor): void { operationId(value.get(4)); if (value.get(5) !== "preparing" && value.get(5) !== "executing") throw new TypeError("invalid in-progress state"); if (value.get(6) !== "not-applied" && value.get(6) !== "possible") throw new TypeError("invalid in-progress effect"); receiptIdList(value.get(7), descriptor.receiptCount); recoveryHandleFromBytes(bytes(value.get(8))); optionalText(value.get(9)); }
function profileOperationOptions(options: OperationOptions | RecoveryOptions, maximum: number): Readonly<{ timeoutMs: number; recoveryWaitMs: number }> { const defaultTimeout = Math.min(30_000, maximum); const selected = validatedOperationOptions({ ...options, timeoutMs: options.timeoutMs ?? defaultTimeout, recoveryWaitMs: options.recoveryWaitMs ?? Math.min(5_000, defaultTimeout) }); if (selected.timeoutMs > maximum) throw new RangeError("timeoutMs exceeds the generated profile execution bound"); return selected; }
function boundedInteger(value: number, minimum: number, maximum: number, name: string): void { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new RangeError(`${name} is outside bounds`); }
function fromHex(value: string): Uint8Array { if (!/^[0-9a-f]{64}$/u.test(value)) throw new TypeError("invalid digest"); return Uint8Array.from(value.match(/../gu) ?? [], (part) => Number.parseInt(part, 16)); }
function base64url(value: Uint8Array): string { return btoa(String.fromCharCode(...value)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, ""); }
function requestId(): Uint8Array { return crypto.getRandomValues(new Uint8Array(16)); }
function integerMap(value: unknown): Map<number, unknown> { if (!(value instanceof Map) || [...value.keys()].some((key) => !Number.isInteger(key))) throw new TypeError("expected integer map"); return value as Map<number, unknown>; }
function stringMap(value: unknown): Map<string, unknown> { if (!(value instanceof Map) || [...value.keys()].some((key) => typeof key !== "string")) throw new TypeError("expected string map"); return value as Map<string, unknown>; }
function exactIntegerKeys(value: Map<number, unknown>, maximum: number): boolean { return value.size === maximum && Array.from({ length: maximum }, (_, index) => index + 1).every((key) => value.has(key)); }
function exactStringKeys(value: Map<string, unknown>, expected: readonly string[]): void { if (value.size !== expected.length || expected.some((key) => !value.has(key))) throw new TypeError("Auths envelope has unknown or missing fields"); }
function mapOrRecord(value: unknown): Map<string, unknown> { if (value instanceof Map) return stringMap(value); const source = record(value); return new Map(Object.entries(source)); }
function record(value: unknown): Record<string, unknown> { if (typeof value !== "object" || value === null || Array.isArray(value) || value instanceof Map || value instanceof Uint8Array) throw new TypeError("expected record"); return value as Record<string, unknown>; }
function array(value: unknown): readonly unknown[] { if (!Array.isArray(value)) throw new TypeError("expected array"); return value; }
function text(value: unknown): string { if (typeof value !== "string") throw new TypeError("expected text"); return value; }
function integer(value: unknown): number { if (!Number.isSafeInteger(value)) throw new TypeError("expected integer"); return value as number; }
function boolean(value: unknown): boolean { if (typeof value !== "boolean") throw new TypeError("expected boolean"); return value; }
function bytes(value: unknown): Uint8Array { if (!(value instanceof Uint8Array)) throw new TypeError("expected bytes"); return value; }
function fixedBytes(value: unknown, length: number): Uint8Array { const selected = bytes(value); if (selected.length !== length) throw new TypeError("wrong byte length"); return selected; }
function fixedBoundedBytes(value: unknown, maximum: number): Uint8Array { const selected = bytes(value); if (selected.length < 1 || selected.length > maximum) throw new RangeError("bytes outside bounds"); return selected; }
function equalBytes(left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((item, index) => item === right[index]); }
