export const SDK_RUNTIME_CONTRACT = Object.freeze({
  schemaVersion: "auths.runtime-contract/1" as const,
  sdkVersion: "1.0.0-rc.1",
  authoringAbi: 1,
  identityAbi: 1,
  profiles: Object.freeze({}),
  capabilities: Object.freeze([
    "diagnostics.doctor",
    "identity.compact-v2",
    "local-agent.session-v1",
    "profile-operation.v1",
    "profile-runtime.v1",
    "verification.batch-v1",
    "verification.single-v1",
  ]),
});

export interface RuntimeSubject {
  readonly authoringAbi: number;
  readonly identityAbi: number;
  readonly capabilities: readonly string[];
}

export interface RuntimeContractResult {
  readonly satisfied: boolean;
  readonly missing: readonly string[];
}

export function evaluateRuntimeContract(subject: RuntimeSubject): RuntimeContractResult {
  const missing: string[] = [];
  if (subject.authoringAbi !== SDK_RUNTIME_CONTRACT.authoringAbi) {
    missing.push(`authoring-abi:${subject.authoringAbi}`);
  }
  if (subject.identityAbi !== SDK_RUNTIME_CONTRACT.identityAbi) {
    missing.push(`identity-abi:${subject.identityAbi}`);
  }
  const available = new Set(subject.capabilities);
  for (const capability of SDK_RUNTIME_CONTRACT.capabilities) {
    if (!available.has(capability)) missing.push(capability);
  }
  return Object.freeze({ satisfied: missing.length === 0, missing: Object.freeze(missing) });
}
