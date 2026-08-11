export const SDK_COMPATIBILITY = Object.freeze({
  schemaVersion: "auths.compatibility/1" as const,
  sdkVersion: "1.0.0-rc.1",
  authoringAbi: Object.freeze({ minimum: 1, maximum: 1 }),
  identityAbi: Object.freeze({ minimum: 1, maximum: 1 }),
  profiles: Object.freeze({
    "auths.mcp": 1,
    "auths.http": 1,
    "auths.git": 1,
    "auths.deploy": 1,
    "auths.supply-chain": 1,
    "auths.edge": 1,
  }),
  capabilities: Object.freeze([
    "authority.author",
    "authority.delegate",
    "authority.plans",
    "diagnostics.compatibility-v1",
    "identity.compact-v2",
    "identity.descriptor-v1",
    "identity.registry-v1",
    "identity.resolution",
    "inspection.safe-projection",
    "observability.telemetry-v1",
    "runtime.artifact-cache-v1",
    "runtime.closed-execution",
    "trust.offline-bundle-v1",
    "verification.batch-v1",
    "verification.single-v1",
    "workflow.approval",
  ]),
});

export interface AbiCapabilities {
  readonly authoringAbi: number;
  readonly identityAbi: number;
  readonly capabilities: readonly string[];
}

export interface CompatibilityResult {
  readonly compatible: boolean;
  readonly missing: readonly string[];
}

export function negotiateCompatibility(subject: AbiCapabilities): CompatibilityResult {
  const missing: string[] = [];
  if (subject.authoringAbi < SDK_COMPATIBILITY.authoringAbi.minimum ||
      subject.authoringAbi > SDK_COMPATIBILITY.authoringAbi.maximum) {
    missing.push(`authoring-abi:${subject.authoringAbi}`);
  }
  if (subject.identityAbi < SDK_COMPATIBILITY.identityAbi.minimum ||
      subject.identityAbi > SDK_COMPATIBILITY.identityAbi.maximum) {
    missing.push(`identity-abi:${subject.identityAbi}`);
  }
  const available = new Set(subject.capabilities);
  for (const capability of SDK_COMPATIBILITY.capabilities) {
    if (!available.has(capability)) missing.push(capability);
  }
  return Object.freeze({ compatible: missing.length === 0, missing: Object.freeze(missing) });
}
