import type { OperationMetadata } from "@auths-dev/sdk";
export interface Assignment {
    readonly column: string;
    readonly value: string;
}
export interface PreparedUpdate {
    readonly preparedUpdate: string;
    readonly actionDigest: string;
    readonly matchedRows: number;
    readonly expiresAt: bigint;
    readonly auths: OperationMetadata;
}
export interface PreparedUpdateInput {
    readonly preparedUpdate: string;
}
export interface UpdatePreflightInput {
    readonly relation: string;
    readonly tenantKey: string;
    readonly assignments: readonly Assignment[];
}
export interface UpdateResult {
    readonly affectedRows: number;
    readonly afterStateDigest: string;
    readonly auths: OperationMetadata;
}
