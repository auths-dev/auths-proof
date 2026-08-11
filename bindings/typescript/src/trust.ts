import { statusSnapshotBytes } from "./internal/lifecycle-resources.js";
import type { GrantStatusSnapshot, PrincipalStatusSnapshot } from "./lifecycle.js";
import { AuthsWorkflowError } from "./workflow/errors.js";
import { trustedContextSource, type TrustedContextSource } from "./workflow.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";
import { emitAuthsEvent, type TelemetryPort } from "./observability.js";

export interface TrustProfile {
  readonly id: string;
  readonly version: number;
}

export interface TrustPermission {
  readonly capability: string;
  readonly resource: string;
}

export interface TrustBudget {
  readonly algebra: string;
  readonly value: bigint;
}

export type TrustStatusPolicy =
  | Readonly<{ mode: "expiry-only" }>
  | Readonly<{ mode: "snapshot-required"; method: string; maxAge: bigint }>;

export interface TrustAnchorConfiguration {
  readonly id: string;
  readonly principal: string;
  readonly acceptedMethods: readonly string[];
  readonly profiles: readonly TrustProfile[];
  readonly permissions: readonly TrustPermission[];
  readonly resourceNamespaces: readonly string[];
  readonly audiences: readonly string[];
  readonly notBefore: bigint;
  readonly expiresAt: bigint;
  readonly budget?: TrustBudget;
  readonly maxDelegationDepth: number;
  readonly assurancePolicy: string;
  readonly statusPolicy: TrustStatusPolicy;
}

export type AssuranceParticipantRole = "root" | "intermediate" | "actor" | "external-issuer";
export type AssuranceQuantifier = "any" | "every";

export interface AssuranceRequirementConfiguration {
  readonly role: AssuranceParticipantRole;
  readonly quantifier: AssuranceQuantifier;
  readonly claimKind: string;
  readonly maximumAge?: bigint;
}

export interface AssurancePolicyConfiguration {
  readonly id: string;
  readonly requirements: readonly AssuranceRequirementConfiguration[];
}

export interface AcceptedRegistryConfiguration {
  readonly principalMethods: readonly string[];
  readonly signatureSuites: readonly string[];
  readonly evidenceTypes: readonly string[];
  readonly principalStatusMethods: readonly string[];
  readonly grantStatusMethods: readonly string[];
  readonly assuranceClaims: readonly string[];
  readonly assuranceImplications?: readonly string[];
  readonly resourceMatchers: readonly string[];
  readonly budgetAlgebras?: readonly string[];
  readonly criticalExtensions?: readonly string[];
  readonly profiles: readonly TrustProfile[];
  readonly profilePolicies: readonly string[];
}

export type VerifierLimitKind =
  | "bundle-bytes"
  | "action-bytes"
  | "context-bytes"
  | "grants"
  | "actions"
  | "plan-leaves"
  | "plan-depth"
  | "plan-branching"
  | "evidence-objects"
  | "evidence-bytes"
  | "control-bindings"
  | "principal-status-statements"
  | "grant-status-statements"
  | "attachments"
  | "attachment-bytes"
  | "signatures"
  | "signature-bytes"
  | "permissions"
  | "audiences"
  | "critical-extensions"
  | "critical-extension-bytes"
  | "allowed-body-digests"
  | "binding-evidence"
  | "canonical-body-bytes"
  | "registry-entries"
  | "trust-anchors";

export interface TrustedContextConfiguration {
  readonly sourceId: string;
  readonly composition: Readonly<{
    minimumAuthorizedBranches: number;
    minimumDistinctActors: number;
    minimumDistinctRoots: number;
  }>;
  readonly trustAnchors: readonly TrustAnchorConfiguration[];
  readonly registries: AcceptedRegistryConfiguration;
  readonly expectedAudience: string;
  readonly evaluationTime: bigint;
  readonly assurance: AssurancePolicyConfiguration;
  readonly principalStatus: PrincipalStatusSnapshot;
  readonly grantStatus: GrantStatusSnapshot;
  readonly resourceMatcher: string;
  readonly profilePolicy: string;
  readonly channelPolicy: string;
  readonly limits?: Readonly<Partial<Record<VerifierLimitKind, number>>>;
  readonly workUnits?: bigint;
}

export interface CompiledTrustedContext {
  readonly source: TrustedContextSource;
  readonly verifierConfiguration: Uint8Array;
  readonly roots: readonly string[];
  readonly offlineBundle: OfflineTrustBundle;
}

const OFFLINE_TRUST_TOKEN = Symbol("auths-offline-trust");
const offlineTrustBytes = new WeakMap<OfflineTrustBundle, Uint8Array>();
let mintOfflineTrustBundle: (
  bytes: Uint8Array,
  provenance: EvidenceProvenance,
) => OfflineTrustBundle;

export interface EvidenceProvenance {
  readonly source: string;
  readonly observedAt: bigint;
  readonly validUntil: bigint;
  readonly version: string;
}

export class OfflineTrustBundle {
  readonly provenance: EvidenceProvenance;

  private constructor(
    token: typeof OFFLINE_TRUST_TOKEN,
    bytes: Uint8Array,
    provenance: EvidenceProvenance,
  ) {
    if (token !== OFFLINE_TRUST_TOKEN) throw new TypeError("sealed Auths trust bundle");
    this.provenance = copyEvidenceProvenance(provenance);
    offlineTrustBytes.set(this, bytes.slice());
    Object.freeze(this);
  }

  private static create(
    token: typeof OFFLINE_TRUST_TOKEN,
    bytes: Uint8Array,
    provenance: EvidenceProvenance,
  ): OfflineTrustBundle {
    return new OfflineTrustBundle(token, bytes, provenance);
  }

  static {
    mintOfflineTrustBundle = (bytes, provenance) =>
      OfflineTrustBundle.create(OFFLINE_TRUST_TOKEN, bytes, provenance);
  }

  export(): Uint8Array {
    const bytes = offlineTrustBytes.get(this);
    if (bytes === undefined) throw new TypeError("invalid Auths trust bundle");
    return bytes.slice();
  }
}

export interface EvidenceSourceRequest {
  readonly sourceId: string;
  readonly signal: AbortSignal;
  readonly maximumBytes: number;
  readonly maximumRedirects: number;
  readonly allowPrivateNetwork: boolean;
}

export interface EvidenceSourceResult {
  readonly bytes: Uint8Array;
  readonly provenance: EvidenceProvenance;
}

export interface EvidenceSourcePort {
  load(request: EvidenceSourceRequest): Promise<EvidenceSourceResult>;
}

export interface EvidenceSourceOptions {
  readonly sourceId: string;
  readonly port: EvidenceSourcePort;
  readonly timeoutMs?: number;
  readonly maximumBytes?: number;
  readonly maximumRedirects?: number;
  readonly allowPrivateNetwork?: boolean;
  readonly signal?: AbortSignal;
  readonly evaluationTime: bigint;
  readonly telemetry?: TelemetryPort;
  readonly correlationId?: string;
}

export async function compileTrustedContext(
  configuration: TrustedContextConfiguration,
): Promise<CompiledTrustedContext> {
  if (configuration === null || typeof configuration !== "object") {
    throw new AuthsWorkflowError("invalid-trusted-context", "trusted context configuration is missing");
  }
  const copied = copyConfiguration(configuration);
  const sourceId = configuration.sourceId;
  const roots = Object.freeze(configuration.trustAnchors.map((anchor) => anchor.principal));
  const principalStatus = statusSnapshotBytes(configuration.principalStatus);
  const grantStatus = statusSnapshotBytes(configuration.grantStatus);
  const engine = await loadPackagedWorkflowEngine();
  let native;
  try {
    native = engine.compileTrustedContextV1(
      copied,
      principalStatus,
      grantStatus,
    );
  } catch {
    throw new AuthsWorkflowError(
      "invalid-trusted-context",
      "Rust rejected the typed trusted context configuration",
    );
  }
  try {
    const context = new Uint8Array(native.cbor);
    const verifierConfiguration = new Uint8Array(native.verifierConfiguration);
    const source = trustedContextSource({
      sourceId,
      provider: Object.freeze({
        async loadTrustedContext(): Promise<Uint8Array> {
          return context.slice();
        },
      }),
    });
    return Object.freeze({
      source,
      verifierConfiguration,
      roots,
      offlineBundle: mintOfflineTrustBundle(context, {
        source: sourceId,
        observedAt: configuration.evaluationTime,
        validUntil: configuration.evaluationTime,
        version: "compiled-v1",
      }),
    });
  } finally {
    native.free?.();
  }
}

/** Acquires bounded evidence through an explicit I/O port and returns inert offline bytes. */
export async function loadOfflineTrustBundle(options: EvidenceSourceOptions): Promise<OfflineTrustBundle> {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const maximumBytes = options.maximumBytes ?? 1_048_576;
  const maximumRedirects = options.maximumRedirects ?? 0;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000 ||
      !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 16_777_216 ||
      !Number.isSafeInteger(maximumRedirects) || maximumRedirects < 0 || maximumRedirects > 4 ||
      options.sourceId.length === 0 || options.sourceId.length > 128) {
    throw new AuthsWorkflowError("invalid-trusted-context", "evidence source limits are invalid");
  }
  const controller = new AbortController();
  const correlationId = options.correlationId ?? nextEvidenceCorrelationId();
  const started = performance.now();
  void emitAuthsEvent(options.telemetry, {
    name: "auths.acquisition.started",
    timestamp: Date.now(),
    correlationId,
    operation: "load-trust-evidence",
    stage: "acquisition",
    outcome: "started",
  });
  const abort = () => controller.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(new DOMException("timed out", "TimeoutError")), timeoutMs);
  try {
    const result = await options.port.load(Object.freeze({
      sourceId: options.sourceId,
      signal: controller.signal,
      maximumBytes,
      maximumRedirects,
      allowPrivateNetwork: options.allowPrivateNetwork ?? false,
    }));
    controller.signal.throwIfAborted();
    if (!(result.bytes instanceof Uint8Array) || result.bytes.length === 0 ||
        result.bytes.length > maximumBytes) {
      throw new AuthsWorkflowError("invalid-trusted-context", "evidence source returned invalid bytes");
    }
    const provenance = copyEvidenceProvenance(result.provenance);
    if (provenance.observedAt > options.evaluationTime || provenance.validUntil < options.evaluationTime) {
      throw new AuthsWorkflowError("invalid-trusted-context", "evidence source returned stale evidence");
    }
    const bundle = mintOfflineTrustBundle(result.bytes, provenance);
    void emitAuthsEvent(options.telemetry, {
      name: "auths.acquisition.completed",
      timestamp: Date.now(),
      correlationId,
      operation: "load-trust-evidence",
      stage: "acquisition",
      outcome: "succeeded",
      durationMs: performance.now() - started,
    });
    return bundle;
  } catch (error) {
    void emitAuthsEvent(options.telemetry, {
      name: "auths.acquisition.failed",
      timestamp: Date.now(),
      correlationId,
      operation: "load-trust-evidence",
      stage: "acquisition",
      outcome: "failed",
      durationMs: performance.now() - started,
    });
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError(
      "trusted-context-source-failed",
      "evidence source operation failed",
      { operation: "load-evidence", stage: "acquisition", retry: "conditional" },
    );
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }
}

let evidenceCorrelationSequence = 0;

function nextEvidenceCorrelationId(): string {
  evidenceCorrelationSequence = (evidenceCorrelationSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `auths-evidence-${Date.now().toString(36)}-${evidenceCorrelationSequence.toString(36)}`;
}

/** Validates imported offline evidence against an exact root and WASM configuration. */
export async function trustedContextFromOfflineBundle(
  sourceId: string,
  bundle: OfflineTrustBundle,
  rootPrincipal: string,
  verifierConfiguration: Uint8Array,
): Promise<TrustedContextSource> {
  const bytes = bundle.export();
  const engine = await loadPackagedWorkflowEngine();
  try {
    engine.validateTrustedContextV1(bytes, rootPrincipal, verifierConfiguration);
  } catch {
    throw new AuthsWorkflowError("invalid-trusted-context", "offline evidence does not match trust inputs");
  }
  return trustedContextSource({
    sourceId,
    provider: Object.freeze({ async loadTrustedContext() { return bytes.slice(); } }),
  });
}

function copyEvidenceProvenance(provenance: EvidenceProvenance): EvidenceProvenance {
  if (provenance.source.length === 0 || provenance.source.length > 512 ||
      provenance.version.length === 0 || provenance.version.length > 128 ||
      provenance.observedAt > provenance.validUntil) {
    throw new AuthsWorkflowError("invalid-trusted-context", "evidence provenance is invalid");
  }
  return Object.freeze({ ...provenance });
}

function copyConfiguration(configuration: TrustedContextConfiguration): object {
  const registries = configuration.registries;
  const limits = Object.entries(configuration.limits ?? {}).map(([kind, value]) => {
    if (!Number.isSafeInteger(value) || (value ?? -1) < 0) {
      throw new AuthsWorkflowError("invalid-trusted-context", "verifier limit is outside bounds");
    }
    return Object.freeze({ kind, value });
  });
  return Object.freeze({
    composition: Object.freeze({
      expectedPlan: undefined,
      ...configuration.composition,
    }),
    trustAnchors: Object.freeze(configuration.trustAnchors.map((anchor) => Object.freeze({
      ...anchor,
      acceptedMethods: Object.freeze([...anchor.acceptedMethods]),
      profiles: copyProfiles(anchor.profiles),
      permissions: Object.freeze(anchor.permissions.map((permission) => Object.freeze({ ...permission }))),
      resourceNamespaces: Object.freeze([...anchor.resourceNamespaces]),
      audiences: Object.freeze([...anchor.audiences]),
      ...(anchor.budget === undefined ? {} : { budget: Object.freeze({ ...anchor.budget }) }),
      statusPolicy: Object.freeze({ ...anchor.statusPolicy }),
    }))),
    registries: Object.freeze({
      principalMethods: Object.freeze([...registries.principalMethods]),
      signatureSuites: Object.freeze([...registries.signatureSuites]),
      evidenceTypes: Object.freeze([...registries.evidenceTypes]),
      principalStatusMethods: Object.freeze([...registries.principalStatusMethods]),
      grantStatusMethods: Object.freeze([...registries.grantStatusMethods]),
      assuranceClaims: Object.freeze([...registries.assuranceClaims]),
      assuranceImplications: Object.freeze([...(registries.assuranceImplications ?? [])]),
      resourceMatchers: Object.freeze([...registries.resourceMatchers]),
      budgetAlgebras: Object.freeze([...(registries.budgetAlgebras ?? [])]),
      criticalExtensions: Object.freeze([...(registries.criticalExtensions ?? [])]),
      profiles: copyProfiles(registries.profiles),
      profilePolicies: Object.freeze([...registries.profilePolicies]),
    }),
    expectedAudience: configuration.expectedAudience,
    evaluationTime: configuration.evaluationTime,
    assurance: Object.freeze({
      id: configuration.assurance.id,
      requirements: Object.freeze(configuration.assurance.requirements.map((requirement) => Object.freeze({ ...requirement }))),
    }),
    resourceMatcher: configuration.resourceMatcher,
    profilePolicy: configuration.profilePolicy,
    channelPolicy: configuration.channelPolicy,
    limits: Object.freeze(limits),
    workUnits: configuration.workUnits ?? 50_000n,
  });
}

function copyProfiles(profiles: readonly TrustProfile[]): readonly Readonly<TrustProfile>[] {
  return Object.freeze(profiles.map((profile) => Object.freeze({ ...profile })));
}
