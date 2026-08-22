import type { Client, OperationOptions, RecoveryHandle, RecoveryOptions } from "@auths-dev/sdk";
import { type ProfileOutcome } from "@auths-dev/sdk/profile-runtime";
export * from "./generated.js";
import type * as Types from "./generated.js";
export declare const PROFILE_CLIENT_RUNTIME: "auths.profile-client-runtime/1";
export type RefundsOutcome = ProfileOutcome<Types.Refund, never, never>;
export declare class Refunds {
    #private;
    constructor(session: Client, connection: string | undefined);
    create(input: Types.RefundInput, options?: OperationOptions): Promise<Types.Refund>;
    createOutcome(input: Types.RefundInput, options?: OperationOptions): Promise<RefundsOutcome>;
    recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<Types.Refund>;
    recoverOutcome(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<RefundsOutcome>;
}
export declare class Stripe {
    readonly refunds: Refunds;
    constructor(session: Client, options?: Readonly<{
        connection?: string;
    }>);
}
