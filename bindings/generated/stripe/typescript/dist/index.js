import { bindProfile } from "@auths-dev/sdk/profile-runtime";
export * from "./generated.js";
const PROFILE_API = { "schema": "auths.profile-api/1", "types": { "Currency": { "kind": "enum", "values": ["eur", "gbp", "usd"] }, "Refund": { "kind": "record", "fields": [{ "name": "id", "value": { "kind": "string", "minimumBytes": 1, "maximumBytes": 128, "alphabet": "registered-token" }, "sensitive": false }, { "name": "status", "value": { "kind": "enum", "values": ["pending", "succeeded"] }, "sensitive": false }] }, "RefundInput": { "kind": "record", "fields": [{ "name": "paymentIntent", "value": { "kind": "string", "minimumBytes": 1, "maximumBytes": 128, "alphabet": "registered-token" }, "sensitive": false }, { "name": "amount", "value": { "kind": "uint", "bits": 64, "minimum": "1", "maximum": "100000000" }, "sensitive": false }, { "name": "currency", "value": { "kind": "ref", "name": "Currency" }, "sensitive": false }] } } };
export const PROFILE_CLIENT_RUNTIME = "auths.profile-client-runtime/1";
export class Refunds {
    #profile;
    constructor(session, connection) {
        this.#profile = bindProfile(session, Object.freeze({ profileClientRuntime: PROFILE_CLIENT_RUNTIME, profileId: "auths.stripe.refund", version: 1, collectionRoute: "/v1/profiles/stripe/refund/1/operations", runtimeContractDigest: "b839f07b9302e6aeea5a44f0a2faf2af3f06dbf8ced6b69a011b7d8c680cf6ba", errorProjectionDigest: "2cb029e0c02bef1d493bde4b659d00659e99b3d063248b36dcb9d09fcb84528c", preparationEvidence: "protected-lease", requestBytes: 262144, responseBytes: 262144, executionMilliseconds: 30000, receiptCount: 4, receiptBytes: 65536, profileApi: PROFILE_API, inputType: "RefundInput", successType: "Refund" }), connection);
    }
    async create(input, options) { return this.#profile.invoke(input, options); }
    async createOutcome(input, options) { return this.#profile.invokeOutcome(input, options); }
    async recover(recovery, options) { return this.#profile.recover(recovery, options); }
    async recoverOutcome(recovery, options) { return this.#profile.recoverOutcome(recovery, options); }
}
export class Stripe {
    refunds;
    constructor(session, options = {}) {
        this.refunds = new Refunds(session, options.connection);
        Object.freeze(this);
    }
}
