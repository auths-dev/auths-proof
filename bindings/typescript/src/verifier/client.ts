import { mintPackagedVerifierEngine, type Verifier } from "./result.js";
import { loadPackagedWorkflowEngine } from "./wasm.js";

export {
  Verifier,
  VerifiedAction,
  type AuthorizedResult,
  type DeniedResult,
  type Explanation,
  type IndeterminateResult,
  type PortableWasmEngine,
  type VerdictKind,
  type VerificationMetrics,
  type VerificationBatchOptions,
  type VerificationInput,
  type VerificationOptions,
  type VerificationResult,
  type VerificationStage,
} from "./result.js";
/**
 * Loads the raw verifier over the SDK-packaged WASM subject.
 *
 * It accepts no module URL, WASM input, or engine: the capability-minting
 * path resolves only the reviewed implementation shipped with this package.
 */
export async function loadVerifier(): Promise<Verifier> {
  return mintPackagedVerifierEngine(await loadPackagedWorkflowEngine());
}
