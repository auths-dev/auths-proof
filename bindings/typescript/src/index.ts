/** Stable shared values for the Auths profile-first SDK. */
export {
  AuthsError,
  isAuthsError,
  type AuthsIssue,
  type EffectState,
  type KnownAuthsErrorCode,
  type RecommendedAction,
  type RetryClass,
} from "./product-errors.js";

import { diagnoseSdk } from "./diagnostics.js";
import { ERROR_REGISTRY_SHA256 } from "./generated/error-registry-digest.js";

declare const receiptBrand: unique symbol;

/** Portable opaque receipt. Receipts can only be minted by trusted runtimes. */
export interface Receipt {
  readonly [receiptBrand]: true;
  readonly id: string;
  toBytes(): Uint8Array;
  toJSON(): never;
}

export interface RuntimeInfo {
  readonly sdkVersion: string;
  readonly host: "node" | "browser" | "worker";
  readonly hostVersion: string;
  readonly platform: string;
  readonly authoringAbi: number;
  readonly identityAbi: number;
  readonly errorRegistryDigest: string;
  readonly compatible: boolean;
  readonly semanticSubjects: readonly string[];
  readonly profiles: readonly string[];
  readonly capabilities: readonly string[];
  readonly warnings: readonly string[];
}

/** Reports the packaged runtime actually loaded by this SDK build. */
export async function runtimeInfo(): Promise<RuntimeInfo> {
  const report = await diagnoseSdk();
  const globals = globalThis as typeof globalThis & {
    readonly process?: Readonly<{
      readonly versions?: Readonly<{ readonly node?: string }>;
      readonly platform?: string;
    }>;
    readonly navigator?: Readonly<{ readonly userAgent?: string }>;
  };
  const family = report.runtime.family;
  if (family === "unknown") throw new TypeError("unsupported Auths host runtime");
  return Object.freeze({
    sdkVersion: report.sdkVersion,
    host: family,
    hostVersion: globals.process?.versions?.node ?? globals.navigator?.userAgent ?? "unknown",
    platform: globals.process?.platform ?? family,
    authoringAbi: report.wasm.authoringAbi,
    identityAbi: report.wasm.identityAbi,
    errorRegistryDigest: ERROR_REGISTRY_SHA256,
    compatible: report.runtimeContract.satisfied,
    semanticSubjects: Object.freeze([
      "auths.profile-operation/1",
    ]),
    // Concrete profile inventory belongs to installed generated domain
    // packages and the authenticated agent negotiation, never the root SDK.
    profiles: Object.freeze([]),
    capabilities: Object.freeze([...report.wasm.capabilities]),
    warnings: Object.freeze(
      report.checks.filter((check) => check.status === "fail").map((check) => check.detail),
    ),
  });
}

export {
  AuthsOperationError,
  ClientStateError,
  ConflictError,
  DeniedError,
  NotAppliedError,
  PartialError,
  ReceiptIntegrityError,
  RecoveryRequiredError,
  UnavailableError,
  connect,
  recoveryHandleFromBytes,
  type Client,
  type ClientOptions,
  type OperationMetadata,
  type OperationOptions,
  type OperationState,
  type OperationStatus,
  type Operations,
  type RecoveryHandle,
  type RecoveryOptions,
} from "./session.js";
