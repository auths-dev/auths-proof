import test from "node:test";
import * as lifecycle from "../../dist/internal/resource-lifecycle.js";
import { resourceLifecycleContract } from "../helpers/resource-lifecycle-contract.mjs";
test("AP076 local resource ownership", (t) => resourceLifecycleContract(t, lifecycle));
