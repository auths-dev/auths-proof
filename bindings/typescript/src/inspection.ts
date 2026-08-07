import type { VerificationResult } from "./verifier/client.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

export interface DecisionInspection {
  readonly decision: Readonly<{ kind: VerificationResult["kind"] }>;
  readonly kernel: Readonly<{ stage: string; code: string }>;
  readonly commitments: Readonly<{
    result: Uint8Array;
    localConfiguration: Uint8Array;
    requiredConfiguration?: Uint8Array;
    action?: Uint8Array;
  }>;
  readonly metrics: VerificationResult["metrics"];
  readonly approval?: Readonly<{
    policyId: string;
    evaluatorVersion: string;
    requiredConfiguration: Uint8Array;
    executedConfiguration: Uint8Array;
    executedMode: string;
    executedMaxUses: number;
    executedExpiresInSeconds: number;
    executedRequirements: readonly string[];
  }>;
  readonly safeToLog: Readonly<Record<string, string | boolean>>;
}

/** Produces copied, browser-safe evidence without promoting it to a command. */
export async function inspectDecision(result: VerificationResult): Promise<DecisionInspection> {
  // Commitments are stated by the core so the same decision inspects to the
  // same digests in every SDK.
  const engine = await loadPackagedWorkflowEngine();
  const commit = (domain: string, canonical: Uint8Array) =>
    engine.commitCanonicalV1(domain, canonical).slice();
  const resultCommitment = commit("auths.verification-result.v1", result.resultCbor);
  const local = commit("auths.verifier-configuration.v1", result.localConfiguration);
  const required = result.requiredConfiguration === undefined
    ? undefined
    : commit("auths.required-configuration.v1", result.requiredConfiguration);
  const action = result.kind === "authorized"
    ? commit("auths.canonical-action.v1", result.action.canonicalBytes())
    : undefined;
  const approval = "approval" in result && result.approval !== null && typeof result.approval === "object"
    ? result.approval as {
        readonly policyId: string;
        readonly evaluatorVersion: string;
        readonly requiredConfiguration: Uint8Array;
        readonly executedConfiguration: Uint8Array;
        readonly executedMode: string;
        readonly executedMaxUses: number;
        readonly executedExpiresInSeconds: number;
        readonly executedRequirements: readonly string[];
      }
    : undefined;
  return Object.freeze({
    decision: Object.freeze({ kind: result.kind }),
    kernel: Object.freeze({ stage: result.stage, code: result.code }),
    commitments: Object.freeze({
      result: resultCommitment,
      localConfiguration: local,
      ...(required === undefined ? {} : { requiredConfiguration: required }),
      ...(action === undefined ? {} : { action }),
    }),
    metrics: result.metrics,
    ...(approval === undefined
      ? {}
      : {
          approval: Object.freeze({
            policyId: approval.policyId,
            evaluatorVersion: approval.evaluatorVersion,
            requiredConfiguration: approval.requiredConfiguration.slice(),
            executedConfiguration: approval.executedConfiguration.slice(),
            executedMode: approval.executedMode,
            executedMaxUses: approval.executedMaxUses,
            executedExpiresInSeconds: approval.executedExpiresInSeconds,
            executedRequirements: Object.freeze([...approval.executedRequirements]),
          }),
        }),
    safeToLog: Object.freeze({
      kind: result.kind,
      stage: result.stage,
      code: result.code,
      retryable: result.explanation.retryable,
    }),
  });
}
