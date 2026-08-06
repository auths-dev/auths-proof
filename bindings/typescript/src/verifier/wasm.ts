import type { WorkflowWasmEngine } from "../workflow.js";
import type { PortableWasmEngine } from "./result.js";
import { registerPackagedEngine } from "./packaged-registry.js";

export type PackagedWorkflowEngine = WorkflowWasmEngine & PortableWasmEngine;

export async function loadPackagedWorkflowEngine(): Promise<PackagedWorkflowEngine> {
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
  if (
    typeof loaded.authoringAbiVersionV1 !== "function" ||
    typeof loaded.canonicalPrincipalV1 !== "function" ||
    typeof loaded.configurationV1 !== "function" ||
    typeof loaded.validateTrustedContextV1 !== "function" ||
    typeof loaded.prepareMcpActionV1 !== "function" ||
    typeof loaded.prepareProfileActionV1 !== "function" ||
    typeof loaded.prepareRawKeyAuthorityV1 !== "function" ||
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
    typeof loaded.verifyV1 !== "function"
  ) {
    throw new TypeError("Auths WASM module omitted workflow authoring exports");
  }
  return registerPackagedEngine(loaded);
}
