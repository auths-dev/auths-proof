import type { OperationMetadata } from "@auths-dev/sdk";
export interface ApplyPreparedPlanInput {
    readonly preparedPlan: string;
}
export interface ApplyResult {
    readonly workspace: string;
    readonly stateSerial: bigint;
    readonly auths: OperationMetadata;
}
export interface ModulePin {
    readonly source: string;
    readonly version: string;
    readonly digest: string;
}
export interface PlanPreflightInput {
    readonly sourceFiles: readonly SourceFile[];
    readonly variables: readonly Variable[];
    readonly dependencyLock: string;
    readonly modules: readonly ModulePin[];
    readonly workspace: string;
}
export interface PreparedPlan {
    readonly preparedPlan: string;
    readonly actionDigest: string;
    readonly workspace: string;
    readonly priorStateSerial: bigint;
    readonly creates: number;
    readonly updates: number;
    readonly reads: number;
    readonly noOps: number;
    readonly expiresAt: bigint;
    readonly auths: OperationMetadata;
}
export interface SourceFile {
    readonly path: string;
    readonly contents: string;
}
export interface Variable {
    readonly name: string;
    readonly value: string;
}
