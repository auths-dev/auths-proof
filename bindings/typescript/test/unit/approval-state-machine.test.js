import test from "node:test";
import * as approvals from "../../dist/approvals.js";
import { approvalStateContract } from "../helpers/approval-state-contract.mjs";

test("AP076 approval transition contract", (t) => approvalStateContract(t, approvals));
