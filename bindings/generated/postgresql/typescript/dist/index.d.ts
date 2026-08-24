import type { Client, OperationOptions, RecoveryHandle, RecoveryOptions } from "@auths-dev/sdk";
import { type ProfileOutcome } from "@auths-dev/sdk/profile-runtime";
export * from "./generated.js";
import type * as Types from "./generated.js";
export declare const PROFILE_CLIENT_RUNTIME: "auths.profile-client-runtime/1";
export type UpdatesOutcome = ProfileOutcome<Types.UpdateResult, never, never>;
export declare class Updates {
    #private;
    constructor(session: Client, connection: string | undefined);
    execute(input: Types.PreparedUpdateInput, options?: OperationOptions): Promise<Types.UpdateResult>;
    executeOutcome(input: Types.PreparedUpdateInput, options?: OperationOptions): Promise<UpdatesOutcome>;
    recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<Types.UpdateResult>;
    recoverOutcome(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<UpdatesOutcome>;
}
export type UpdatePreflightsOutcome = ProfileOutcome<Types.PreparedUpdate, never, never>;
export declare class UpdatePreflights {
    #private;
    constructor(session: Client, connection: string | undefined);
    create(input: Types.UpdatePreflightInput, options?: OperationOptions): Promise<Types.PreparedUpdate>;
    createOutcome(input: Types.UpdatePreflightInput, options?: OperationOptions): Promise<UpdatePreflightsOutcome>;
    recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<Types.PreparedUpdate>;
    recoverOutcome(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<UpdatePreflightsOutcome>;
}
export declare class PostgreSQL {
    readonly updates: Updates;
    readonly updatePreflights: UpdatePreflights;
    constructor(session: Client, options?: Readonly<{
        connection?: string;
    }>);
}
