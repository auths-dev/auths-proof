import type { WorkflowWasmEngine } from "../workflow.js";
import type { PortableWasmEngine } from "./result.js";
import { registerPackagedEngine } from "./packaged-registry.js";

export type PackagedWorkflowEngine = WorkflowWasmEngine & PortableWasmEngine;

let packaged: Promise<PackagedWorkflowEngine> | undefined;

/**
 * Loads the SDK-packaged WASM subject exactly once per module instance.
 *
 * Memoising matters beyond cost: the packaged registry identifies the engine
 * by object identity, so every caller must observe the same module object.
 */
export async function loadPackagedWorkflowEngine(): Promise<PackagedWorkflowEngine> {
  packaged ??= loadPackagedWorkflowEngineOnce();
  return packaged;
}

async function loadPackagedWorkflowEngineOnce(): Promise<PackagedWorkflowEngine> {
  const moduleUrl = new URL("../../wasm/auths_proof_wasm.js", import.meta.url).href;
  const loaded = (await import(moduleUrl)) as PackagedWorkflowEngine & {
    default?: (input?: {
      module_or_path: RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
    }) => Promise<unknown>;
  };
  if (loaded.default !== undefined) {
    const wasmUrl = new URL("../../wasm/auths_proof_wasm_bg.wasm", import.meta.url);
    if (wasmUrl.protocol === "file:") {
      const { readFile } = await import("node:fs/promises");
      await loaded.default({ module_or_path: await readFile(wasmUrl) });
    } else {
      await loaded.default({ module_or_path: wasmUrl });
    }
  }
  const untyped = loaded as unknown as Record<string, unknown>;
  if (
    typeof loaded.authoringAbiVersionV1 !== "function" ||
    typeof untyped.identityAbiVersionV1 !== "function" ||
    typeof untyped.encodeIdentityDescriptorV1 !== "function" ||
    typeof untyped.decodeIdentityDescriptorV1 !== "function" ||
    typeof untyped.identityDescriptorSigningPreimageV1 !== "function" ||
    typeof loaded.canonicalPrincipalV1 !== "function" ||
    typeof loaded.encodePrincipalStatusStatementV1 !== "function" ||
    typeof loaded.encodeGrantStatusStatementV1 !== "function" ||
    typeof loaded.parsePrincipalStatusSnapshotV1 !== "function" ||
    typeof loaded.parseGrantStatusSnapshotV1 !== "function" ||
    typeof loaded.compileTrustedContextV1 !== "function" ||
    typeof loaded.configurationV1 !== "function" ||
    typeof loaded.validateTrustedContextV1 !== "function" ||
    typeof loaded.parseHttpActionV1 !== "function" ||
    typeof loaded.parseGitActionV1 !== "function" ||
    typeof loaded.parseDeploymentActionV1 !== "function" ||
    typeof loaded.parseSupplyChainActionV1 !== "function" ||
    typeof loaded.parseEdgeActionV1 !== "function" ||
    typeof loaded.parseCanonicalHttpActionV1 !== "function" ||
    typeof loaded.parseCanonicalGitActionV1 !== "function" ||
    typeof loaded.parseCanonicalDeploymentActionV1 !== "function" ||
    typeof loaded.parseCanonicalSupplyChainActionV1 !== "function" ||
    typeof loaded.parseCanonicalEdgeActionV1 !== "function" ||
    typeof loaded.prepareMcpActionV1 !== "function" ||
    typeof loaded.canonicalizeMcpPlanMemberV1 !== "function" ||
    typeof loaded.beginMcpExecutionV1 !== "function" ||
    typeof loaded.resumeMcpExecutionV1 !== "function" ||
    typeof loaded.canonicalizeProfilePlanMemberV1 !== "function" ||
    typeof loaded.prepareProfileActionV1 !== "function" ||
    typeof loaded.profileReceiptBindingsV1 !== "function" ||
    typeof loaded.prepareAuthorizedDecisionReceiptV1 !== "function" ||
    typeof loaded.prepareApplicationExecutionReceiptV1 !== "function" ||
    typeof loaded.attestDecisionReceiptV1 !== "function" ||
    typeof loaded.attestExecutionReceiptV1 !== "function" ||
    typeof loaded.verifyRawKeyReceiptV1 !== "function" ||
    typeof loaded.verifyReceiptLinkV1 !== "function" ||
    typeof loaded.prepareRawKeyAuthorityV1 !== "function" ||
    typeof loaded.deriveEd25519RawKeyIdentityV1 !== "function" ||
    typeof loaded.developmentEd25519PublicKeyV1 !== "function" ||
    typeof loaded.AuthorizationPlanBuilderV1 !== "function" ||
    typeof loaded.WorkflowProofBuilderV1 !== "function" ||
    typeof loaded.inspectSignedGrantV1 !== "function" ||
    typeof loaded.validateRootAuthorityV1 !== "function" ||
    typeof loaded.planChildGrantFieldsV1 !== "function" ||
    typeof loaded.prepareGrantSigningV1 !== "function" ||
    typeof loaded.prepareActionSigningV1 !== "function" ||
    typeof loaded.preparePrincipalStatusSigningV1 !== "function" ||
    typeof loaded.prepareGrantStatusSigningV1 !== "function" ||
    typeof loaded.completeGrantSigningV1 !== "function" ||
    typeof loaded.completeActionSigningV1 !== "function" ||
    typeof loaded.completePrincipalStatusSigningV1 !== "function" ||
    typeof loaded.completeGrantStatusSigningV1 !== "function" ||
    typeof loaded.commitCanonicalV1 !== "function" ||
    typeof loaded.commitApprovalPolicyV1 !== "function" ||
    typeof loaded.commitProfilePlanV1 !== "function" ||
    typeof loaded.commitPlanApprovalV1 !== "function" ||
    typeof loaded.verifyBatchV1 !== "function" ||
    typeof loaded.verifyV1 !== "function"
  ) {
    throw new TypeError("Auths WASM module omitted workflow authoring exports");
  }
  return registerPackagedEngine(loaded);
}
