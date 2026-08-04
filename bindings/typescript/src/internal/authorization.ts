import { Auths, type VerificationResult } from "../index.js";
import {
  type AttachedAgent,
  type Profile,
  type ReviewField,
  type WorkflowActionPreparation,
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
): Promise<VerificationResult> {
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
      approval: resources.approval,
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
    const verifier = new Auths({
      verifyV1: (proof, canonicalAction, trustedContext) =>
        engine.verifyV1(proof, canonicalAction, trustedContext),
    });
    return verifier.verify(
      artifacts.proofCbor,
      preparation.canonicalActionCbor,
      artifacts.trustedContextCbor,
    );
  } finally {
    artifacts?.free?.();
    builder?.free?.();
    preparation.free?.();
  }
}
