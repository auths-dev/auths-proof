import { AuthsWorkflowError } from "../errors.js";
import { TrustedContextSource } from "../trusted-context.js";
import type { GrantControlMaterial } from "./orchestrator.js";
import type {
  ApprovalPolicy,
  ApprovalPolicyReference,
  ControlEvidence,
  PrincipalDescriptor,
  SignedGrantMaterial,
  TrustedAuthority,
  TrustedAuthoritySnapshot,
} from "../contracts.js";

const MAX_IDENTIFIER_BYTES = 128;
const DIGEST_BYTES = 32;

export function copyPrincipal(value: PrincipalDescriptor): PrincipalDescriptor {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-principal",
      "principal descriptor is missing",
    );
  }
  return {
    principal: boundedIdentifier(value.principal, "principal"),
    principalMethod: boundedIdentifier(
      value.principalMethod,
      "principal method",
    ),
    verificationMethod: boundedIdentifier(
      value.verificationMethod,
      "verification method",
    ),
    suite: boundedIdentifier(value.suite, "signature suite"),
  };
}

export function copyPolicy(
  value: ApprovalPolicyReference,
): ApprovalPolicyReference {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval policy is missing",
    );
  }
  return Object.freeze({
    policyId: boundedIdentifier(value.policyId, "approval policy"),
    evaluatorVersion: boundedIdentifier(
      value.evaluatorVersion,
      "approval evaluator version",
    ),
    configurationDigest: copyExactBytes(
      value.configurationDigest,
      DIGEST_BYTES,
      "approval configuration digest",
    ),
  });
}

export function copyApprovalPolicy(value: ApprovalPolicy): ApprovalPolicy {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError("invalid-provider", "approval policy is missing");
  }
  if (
    !["none", "grant-only", "risk-based", "every-action", "plan-once", "headless", "custom"].includes(
      value.mode,
    ) ||
    !Number.isSafeInteger(value.maxUses) ||
    value.maxUses < 1 ||
    value.maxUses > 256 ||
    !Number.isSafeInteger(value.expiresInSeconds) ||
    value.expiresInSeconds < 1 ||
    value.expiresInSeconds > 86_400 ||
    !Array.isArray(value.requirements) ||
    value.requirements.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new AuthsWorkflowError("invalid-provider", "approval policy bounds are invalid");
  }
  return Object.freeze({
    reference: copyPolicy(value.reference),
    mode: value.mode,
    maxUses: value.maxUses,
    expiresInSeconds: value.expiresInSeconds,
    requirements: Object.freeze([...value.requirements]),
  });
}

export function policiesEqual(
  left: ApprovalPolicyReference,
  right: ApprovalPolicyReference,
): boolean {
  if (
    left === null ||
    right === null ||
    typeof left !== "object" ||
    typeof right !== "object" ||
    !(left.configurationDigest instanceof Uint8Array) ||
    !(right.configurationDigest instanceof Uint8Array)
  ) {
    return false;
  }
  return (
    left.policyId === right.policyId &&
    left.evaluatorVersion === right.evaluatorVersion &&
    bytesEqual(left.configurationDigest, right.configurationDigest)
  );
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) {
    return false;
  }
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function copyExactBytes(
  value: Uint8Array,
  length: number,
  label: string,
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} must contain exactly ${length} bytes`,
    );
  }
  return value.slice();
}

export function boundedBytes(value: Uint8Array, label: string): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.length === 0 ||
    value.length > 16 * 1024 * 1024
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} must be a non-empty bounded byte array`,
    );
  }
  return value.slice();
}

export function boundedIdentifier(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > MAX_IDENTIFIER_BYTES ||
    !/^[\x21-\x7e]+$/.test(value)
  ) {
    throw new AuthsWorkflowError(
      "invalid-provider",
      `${label} is outside the supported identifier bound`,
    );
  }
  return value;
}

export function copyTrustedAuthority(
  value: TrustedAuthority,
): TrustedAuthoritySnapshot {
  if (value === null || typeof value !== "object") {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "trusted authority is missing",
    );
  }
  return Object.freeze({
    authorityId: boundedIdentifier(value.authorityId, "trusted authority"),
    rootPrincipal: boundedIdentifier(value.rootPrincipal, "trusted root"),
    verifierConfiguration: copyExactBytes(
      value.verifierConfiguration,
      DIGEST_BYTES,
      "verifier configuration",
    ),
    contextSourceId:
      value.context instanceof TrustedContextSource
        ? value.context.sourceId
        : (() => {
            throw new AuthsWorkflowError(
              "invalid-trusted-context",
              "trusted authority must use a package-created context source",
            );
          })(),
    requiredApproval: copyPolicy(value.requiredApproval),
  });
}

export function copyTrustedAuthoritySnapshot(
  value: TrustedAuthoritySnapshot,
): TrustedAuthoritySnapshot {
  return Object.freeze({
    authorityId: value.authorityId,
    rootPrincipal: value.rootPrincipal,
    verifierConfiguration: value.verifierConfiguration.slice(),
    contextSourceId: value.contextSourceId,
    requiredApproval: copyPolicy(value.requiredApproval),
  });
}

export function copyControlEvidence(value: ControlEvidence): ControlEvidence {
  if (
    value === null ||
    typeof value !== "object" ||
    !(value.bytes instanceof Uint8Array) ||
    value.bytes.length === 0
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "control evidence is malformed",
    );
  }
  return Object.freeze({
    evidenceType: boundedIdentifier(value.evidenceType, "evidence type"),
    mediaType: boundedIdentifier(value.mediaType, "evidence media type"),
    bytes: value.bytes.slice(),
  });
}

export function copySignedGrantMaterial(
  value: SignedGrantMaterial,
): SignedGrantMaterial {
  if (
    value === null ||
    typeof value !== "object" ||
    !(value.signedGrant instanceof Uint8Array) ||
    value.signedGrant.length === 0 ||
    value.signedGrant.length > 16 * 1024 * 1024 ||
    !Array.isArray(value.evidence)
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "signed-grant provider returned invalid proof material",
    );
  }
  if (value.evidence.length > 32) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "signed-grant control evidence exceeds the supported count",
    );
  }
  const evidence = value.evidence.map(copyControlEvidence);
  if (
    evidence.reduce((total, item) => total + item.bytes.length, 0) >
    64 * 1024
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "signed-grant control evidence exceeds the supported byte bound",
    );
  }
  return Object.freeze({
    signedGrant: value.signedGrant.slice(),
    evidence: Object.freeze(evidence),
  });
}

export function copyGrantChain(
  value: readonly GrantControlMaterial[],
): readonly GrantControlMaterial[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new AuthsWorkflowError(
      "invalid-authority",
      "grant chain exceeds the supported count",
    );
  }
  return Object.freeze(
    value.map((material) => copySignedGrantMaterial(material)),
  );
}

export function copyAgentName(value: string): string {
  try {
    return boundedIdentifier(value, "agent name");
  } catch {
    throw new AuthsWorkflowError(
      "invalid-agent-name",
      "agent name is outside the supported identifier bound",
    );
  }
}
