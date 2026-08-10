import { statusSnapshotBytes } from "./internal/lifecycle-resources.js";
import type { GrantStatusSnapshot, PrincipalStatusSnapshot } from "./lifecycle.js";
import { AuthsWorkflowError } from "./workflow/errors.js";
import { trustedContextSource, type TrustedContextSource } from "./workflow.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

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
    });
  } finally {
    native.free?.();
  }
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
