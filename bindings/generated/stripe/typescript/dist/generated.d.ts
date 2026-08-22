import type { OperationMetadata } from "@auths-dev/sdk";
export type Currency = "eur" | "gbp" | "usd";
export interface Refund {
    readonly id: string;
    readonly status: "pending" | "succeeded";
    readonly auths: OperationMetadata;
}
export interface RefundInput {
    readonly paymentIntent: string;
    readonly amount: number;
    readonly currency: Currency;
}
