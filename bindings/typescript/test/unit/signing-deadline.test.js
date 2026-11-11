import test from "node:test";
import * as signing from "../../dist/internal/signing.js";
import { signingDeadlineContract } from "../helpers/signing-deadline-contract.mjs";

test("AP078 signing deadline ownership", { timeout: 10_000 }, (t) => signingDeadlineContract(t, signing));
