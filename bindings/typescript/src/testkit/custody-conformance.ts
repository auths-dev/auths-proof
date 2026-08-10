import {
  ProviderOperationError,
  type ProviderFailureKind,
  type Signer,
  type SigningRequest,
  type SigningResponse,
} from "../custody.js";

export type CustodyConformanceCase =
  | "transaction-binding"
  | "principal-binding"
  | "descriptor-binding"
  | "request-binding"
  | "expiry"
  | "duplicate"
  | "cancellation"
  | "disposal";

export interface CustodyConformanceResult {
  readonly name: CustodyConformanceCase;
  readonly passed: boolean;
}

export interface CustodyConformanceReport {
  readonly passed: boolean;
  readonly results: readonly CustodyConformanceResult[];
}

export interface CustodyConformanceOptions {
  create(): Promise<Signer>;
  readonly now?: () => bigint;
}

export async function custodyConformance(
  options: CustodyConformanceOptions,
): Promise<CustodyConformanceReport> {
  const now = options.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
  const results = await Promise.all([
    boundResponseCase(options, now, "transaction-binding", (response, request) =>
      equalBytes(response.transactionDigest, request.transactionDigest)),
    boundResponseCase(options, now, "principal-binding", (response, request) =>
      response.principal.principal === request.principal.principal),
    boundResponseCase(options, now, "descriptor-binding", (response, request) =>
      response.principal.principalMethod === request.principal.principalMethod &&
      response.principal.verificationMethod === request.principal.verificationMethod &&
      response.principal.suite === request.principal.suite),
    boundResponseCase(options, now, "request-binding", (response, request) =>
      response.requestId === request.requestId),
    rejectionCase(options, now, "expiry", ["rejected", "timeout"], async (signer, request) => {
      await signer.sign({ ...request, expiresAt: now() - 1n });
    }),
    duplicateCase(options, now),
    rejectionCase(options, now, "cancellation", ["cancelled"], async (signer, request) => {
      const controller = new AbortController();
      controller.abort();
      await signer.sign({ ...request, signal: controller.signal });
    }),
    rejectionCase(options, now, "disposal", ["cancelled", "unsupported"], async (signer, request) => {
      if (signer.dispose === undefined) throw new Error("custody signer has no disposal operation");
      await signer.dispose();
      await signer.sign(request);
    }),
  ]);
  return Object.freeze({
    passed: results.every((result) => result.passed),
    results: Object.freeze(results),
  });
}

async function boundResponseCase(
  options: CustodyConformanceOptions,
  now: () => bigint,
  name: CustodyConformanceCase,
  predicate: (response: SigningResponse, request: SigningRequest) => boolean,
): Promise<CustodyConformanceResult> {
  const signer = await options.create();
  try {
    const request = await validRequest(signer, now(), name);
    const response = await signer.sign(request);
    return result(name, predicate(response, request) && response.signature.length > 0);
  } catch {
    return result(name, false);
  } finally {
    await signer.dispose?.();
  }
}

async function rejectionCase(
  options: CustodyConformanceOptions,
  now: () => bigint,
  name: CustodyConformanceCase,
  expected: readonly ProviderFailureKind[],
  exercise: (signer: Signer, request: SigningRequest) => Promise<void>,
): Promise<CustodyConformanceResult> {
  const signer = await options.create();
  try {
    const request = await validRequest(signer, now(), name);
    try {
      await exercise(signer, request);
      return result(name, false);
    } catch (error) {
      return result(
        name,
        error instanceof ProviderOperationError && expected.includes(error.kind),
      );
    }
  } finally {
    await signer.dispose?.();
  }
}

async function duplicateCase(
  options: CustodyConformanceOptions,
  now: () => bigint,
): Promise<CustodyConformanceResult> {
  const signer = await options.create();
  try {
    const request = await validRequest(signer, now(), "duplicate");
    try {
      await signer.sign(request);
    } catch {
      return result("duplicate", false);
    }
    try {
      await signer.sign(request);
      return result("duplicate", false);
    } catch (error) {
      return result(
        "duplicate",
        error instanceof ProviderOperationError && error.kind === "rejected",
      );
    }
  } finally {
    await signer.dispose?.();
  }
}

async function validRequest(
  signer: Signer,
  now: bigint,
  suffix: string,
): Promise<SigningRequest> {
  const principal = await signer.publicIdentity();
  return Object.freeze({
    requestId: `conformance.${suffix}`,
    objectKind: "action" as const,
    objectId: new Uint8Array(32).fill(1),
    principal: Object.freeze({ ...principal }),
    transactionDigest: new Uint8Array(32).fill(2),
    signingPreimage: new Uint8Array([3, 4, 5]),
    expiresAt: now + 60n,
    display: Object.freeze([Object.freeze({ label: "Conformance", value: suffix })]),
  });
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function result(name: CustodyConformanceCase, passed: boolean): CustodyConformanceResult {
  return Object.freeze({ name, passed });
}
