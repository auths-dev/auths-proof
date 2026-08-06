import { mintPackagedVerifierEngine } from "../verifier/result.js";
import {
  type AttachedAgent,
  type ApprovalConfiguration,
  type Profile,
  type ReviewField,
  type WorkflowActionPreparation,
  type WorkflowVerificationResult,
  engineForClient,
  resourcesForAttachedAgent,
  trustedContextForClient,
} from "../workflow.js";
import { SigningCoordinator, WasmSigningAdapter } from "./signing.js";

/** Completes the profile-independent signing, proof, and verification path. */
export async function authorizePreparedAction(
  agent: AttachedAgent<Profile>,
  preparation: WorkflowActionPreparation,
  display: readonly ReviewField[],
  approvalOverride?: ApprovalConfiguration,
): Promise<WorkflowVerificationResult> {
  const resources = resourcesForAttachedAgent(agent);
  const engine = engineForClient(resources.client);
  let builder;
  let artifacts;
  try {
    const evaluationTime = BigInt(Math.floor(Date.now() / 1000));
    const signed = await new SigningCoordinator(
      new WasmSigningAdapter(engine),
    ).execute({
      objectKind: "action",
      unsignedObject: preparation.actionEnvelopeCbor,
      principal: agent.identity.principal,
      signer: resources.signer,
      approval: approvalOverride ?? resources.approval,
      requiredApproval: resources.client.trustedAuthority.requiredApproval,
      expiresAt: evaluationTime + 300n,
      display,
    });
    builder = new engine.WorkflowProofBuilderV1();
    for (const grant of resources.grantChain) {
      const index = builder.pushGrant(grant.signedGrant.slice());
      for (const evidence of grant.evidence) {
        builder.bindGrantEvidence(
          index,
          evidence.evidenceType,
          evidence.mediaType,
          evidence.bytes.slice(),
        );
      }
    }
    for (const evidence of signed.evidence) {
      builder.bindActionEvidence(
        evidence.evidenceType,
        evidence.mediaType,
        evidence.bytes.slice(),
      );
    }
    artifacts = builder.finish(
      signed.signedObject,
      preparation.canonicalActionCbor,
      trustedContextForClient(resources.client),
    );
    const verifier = mintPackagedVerifierEngine(engine);
    const result = verifier.verify(
      artifacts.proofCbor,
      preparation.canonicalActionCbor,
      artifacts.trustedContextCbor,
    );
    const executed = approvalOverride ?? resources.approval;
    const required = resources.client.trustedAuthority.requiredApproval;
    return Object.freeze({
      ...result,
      approval: Object.freeze({
        policyId: required.policyId,
        evaluatorVersion: required.evaluatorVersion,
        requiredConfiguration: required.configurationDigest.slice(),
        executedConfiguration: executed.policy.reference.configurationDigest.slice(),
        executedMode: executed.policy.mode,
        executedMaxUses: executed.policy.maxUses,
        executedExpiresInSeconds: executed.policy.expiresInSeconds,
        executedRequirements: Object.freeze([...executed.policy.requirements]),
      }),
    });
  } finally {
    artifacts?.free?.();
    builder?.free?.();
    preparation.free?.();
  }
}
