declare const AUTHORIZED_TOKEN: unique symbol;
export type VerdictKind = "authorized" | "denied" | "indeterminate";
export type VerificationStage = "decode" | "resolve" | "principal-control" | "authority" | "complete";
export interface Explanation {
    readonly code: string;
    readonly message: string;
    readonly retryable: boolean;
}
export interface VerificationMetrics {
    readonly proofBytes: bigint;
    readonly actionBytes: bigint;
    readonly contextBytes: bigint;
    readonly objectCount: bigint;
    readonly planLeaves: bigint;
    readonly planDepth: bigint;
    readonly workUnits: bigint;
}
export declare class VerifiedAction {
    #private;
    private constructor();
    static fromEngine(token: typeof AUTHORIZED_TOKEN, canonicalAction: Uint8Array): VerifiedAction;
    canonicalBytes(): Uint8Array;
}
interface CommonResult {
    readonly code: string;
    readonly stage: VerificationStage;
    readonly explanation: Explanation;
    readonly metrics: VerificationMetrics;
    readonly resultCbor: Uint8Array;
}
export interface AuthorizedResult extends CommonResult {
    readonly kind: "authorized";
    readonly action: VerifiedAction;
}
export interface DeniedResult extends CommonResult {
    readonly kind: "denied";
}
export interface IndeterminateResult extends CommonResult {
    readonly kind: "indeterminate";
}
export type VerificationResult = AuthorizedResult | DeniedResult | IndeterminateResult;
export interface PortableWasmEngine {
    verifyV1(proofCbor: Uint8Array, canonicalActionCbor: Uint8Array, trustedContextCbor: Uint8Array): Uint8Array;
}
export declare class Auths {
    #private;
    constructor(engine: PortableWasmEngine);
    verify(proofCbor: Uint8Array, canonicalActionCbor: Uint8Array, trustedContextCbor: Uint8Array): VerificationResult;
}
export interface LoadAuthsOptions {
    readonly moduleUrl?: string;
    readonly wasmInput?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
}
export declare function loadAuths(options?: LoadAuthsOptions): Promise<Auths>;
export {};
