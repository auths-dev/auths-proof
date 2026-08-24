import type { Client, OperationOptions, RecoveryHandle, RecoveryOptions } from "@auths-dev/sdk";
import { type ProfileOutcome } from "@auths-dev/sdk/profile-runtime";
export * from "./generated.js";
import type * as Types from "./generated.js";
export declare const PROFILE_CLIENT_RUNTIME: "auths.profile-client-runtime/1";
export type PlansOutcome = ProfileOutcome<Types.PreparedPlan, never, never>;
export declare class Plans {
    #private;
    constructor(session: Client, connection: string | undefined);
    create(input: Types.PlanPreflightInput, options?: OperationOptions): Promise<Types.PreparedPlan>;
    createOutcome(input: Types.PlanPreflightInput, options?: OperationOptions): Promise<PlansOutcome>;
    recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<Types.PreparedPlan>;
    recoverOutcome(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<PlansOutcome>;
}
export type SavedPlansOutcome = ProfileOutcome<Types.ApplyResult, never, never>;
export declare class SavedPlans {
    #private;
    constructor(session: Client, connection: string | undefined);
    apply(input: Types.ApplyPreparedPlanInput, options?: OperationOptions): Promise<Types.ApplyResult>;
    applyOutcome(input: Types.ApplyPreparedPlanInput, options?: OperationOptions): Promise<SavedPlansOutcome>;
    recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<Types.ApplyResult>;
    recoverOutcome(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<SavedPlansOutcome>;
}
export declare class OpenTofu {
    readonly plans: Plans;
    readonly savedPlans: SavedPlans;
    constructor(session: Client, options?: Readonly<{
        connection?: string;
    }>);
}
