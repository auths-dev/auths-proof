import test from "node:test";
import { connectRemoteVerifier } from "../../dist/protocol.js";
import { createIdentityClient } from "../../dist/identity/adapters.js";
import { adapterLifecycleContract } from "../helpers/adapter-lifecycle-contract.mjs";
test("AP076 identity and remote owner integration", (t) => adapterLifecycleContract(t, { connectRemoteVerifier, createIdentityClient }));
