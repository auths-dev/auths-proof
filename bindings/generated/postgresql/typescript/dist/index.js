import { bindProfile } from "@auths-dev/sdk/profile-runtime";
export * from "./generated.js";
const PROFILE_API = { "schema": "auths.profile-api/1", "types": { "Assignment": { "kind": "record", "fields": [{ "name": "column", "value": { "kind": "string", "minimumBytes": 1, "maximumBytes": 63, "alphabet": "utf8" }, "sensitive": false }, { "name": "value", "value": { "kind": "string", "minimumBytes": 0, "maximumBytes": 4096, "alphabet": "utf8" }, "sensitive": true }] }, "PreparedUpdate": { "kind": "record", "fields": [{ "name": "preparedUpdate", "value": { "kind": "string", "minimumBytes": 48, "maximumBytes": 96, "alphabet": "registered-token" }, "sensitive": true }, { "name": "actionDigest", "value": { "kind": "string", "minimumBytes": 64, "maximumBytes": 64, "alphabet": "lower-hex" }, "sensitive": false }, { "name": "matchedRows", "value": { "kind": "uint", "bits": 32, "minimum": "1", "maximum": "256" }, "sensitive": false }, { "name": "expiresAt", "value": { "kind": "uint", "bits": 64, "minimum": "1", "maximum": "18446744073709551615" }, "sensitive": false }] }, "PreparedUpdateInput": { "kind": "record", "fields": [{ "name": "preparedUpdate", "value": { "kind": "string", "minimumBytes": 48, "maximumBytes": 96, "alphabet": "registered-token" }, "sensitive": true }] }, "UpdatePreflightInput": { "kind": "record", "fields": [{ "name": "relation", "value": { "kind": "string", "minimumBytes": 3, "maximumBytes": 127, "alphabet": "utf8" }, "sensitive": false }, { "name": "tenantKey", "value": { "kind": "string", "minimumBytes": 1, "maximumBytes": 256, "alphabet": "utf8" }, "sensitive": true }, { "name": "assignments", "value": { "kind": "list", "value": { "kind": "ref", "name": "Assignment" }, "minimumItems": 1, "maximumItems": 32 }, "sensitive": true }] }, "UpdateResult": { "kind": "record", "fields": [{ "name": "affectedRows", "value": { "kind": "uint", "bits": 32, "minimum": "1", "maximum": "256" }, "sensitive": false }, { "name": "afterStateDigest", "value": { "kind": "string", "minimumBytes": 64, "maximumBytes": 64, "alphabet": "lower-hex" }, "sensitive": false }] } } };
export const PROFILE_CLIENT_RUNTIME = "auths.profile-client-runtime/1";
export class Updates {
    #profile;
    constructor(session, connection) {
        this.#profile = bindProfile(session, Object.freeze({ profileClientRuntime: PROFILE_CLIENT_RUNTIME, profileId: "auths.postgresql.bounded-update", version: 1, collectionRoute: "/v1/profiles/postgresql/bounded-update/1/operations", runtimeContractDigest: "0094f7036e29f68f7d9d5fdca47b7316e599c7c6d7c8cc2ac1aac983e087c647", errorProjectionDigest: "0faeee9aae6c30a20d71f50898f4ed838615e5039f0185bb132b37c92fcac6cb", preparationEvidence: null, requestBytes: 4096, responseBytes: 262144, executionMilliseconds: 30000, receiptCount: 4, receiptBytes: 65536, profileApi: PROFILE_API, inputType: "PreparedUpdateInput", successType: "UpdateResult" }), connection);
    }
    async execute(input, options) { return this.#profile.invoke(input, options); }
    async executeOutcome(input, options) { return this.#profile.invokeOutcome(input, options); }
    async recover(recovery, options) { return this.#profile.recover(recovery, options); }
    async recoverOutcome(recovery, options) { return this.#profile.recoverOutcome(recovery, options); }
}
export class UpdatePreflights {
    #profile;
    constructor(session, connection) {
        this.#profile = bindProfile(session, Object.freeze({ profileClientRuntime: PROFILE_CLIENT_RUNTIME, profileId: "auths.postgresql.update-preflight", version: 1, collectionRoute: "/v1/profiles/postgresql/update-preflight/1/operations", runtimeContractDigest: "4dce64379ffda13e4df70946bd5454706ffeb028b0734efde612c10ee5f24113", errorProjectionDigest: "06894a3b27b27c77bf1c420294d3c0a37c55ad91de952d8d1893071969e269c4", preparationEvidence: null, requestBytes: 262144, responseBytes: 262144, executionMilliseconds: 30000, receiptCount: 4, receiptBytes: 65536, profileApi: PROFILE_API, inputType: "UpdatePreflightInput", successType: "PreparedUpdate" }), connection);
    }
    async create(input, options) { return this.#profile.invoke(input, options); }
    async createOutcome(input, options) { return this.#profile.invokeOutcome(input, options); }
    async recover(recovery, options) { return this.#profile.recover(recovery, options); }
    async recoverOutcome(recovery, options) { return this.#profile.recoverOutcome(recovery, options); }
}
export class PostgreSQL {
    updates;
    updatePreflights;
    constructor(session, options = {}) {
        this.updates = new Updates(session, options.connection);
        this.updatePreflights = new UpdatePreflights(session, options.connection);
        Object.freeze(this);
    }
}
