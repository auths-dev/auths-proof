// Identity depends on the packaged native engine, not on verification semantics.
// This private adapter keeps that dependency below the public identity layer.
export { loadPackagedWorkflowEngine as loadIdentityEngine } from "../verifier/wasm.js";
