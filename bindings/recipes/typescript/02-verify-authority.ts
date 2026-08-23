import { readFile } from "node:fs/promises";
import { createVerifier } from "@auths-dev/sdk/verify";

const fixture = process.env.AUTHS_RECIPE_FIXTURE;
if (fixture === undefined) throw new Error("AUTHS_RECIPE_FIXTURE is required");
const [proof, action, trustedContext] = await Promise.all([
  readFile(`${fixture}/workflow.proof.cbor`),
  readFile(`${fixture}/workflow.action.cbor`),
  readFile(`${fixture}/workflow.context.cbor`),
]);
const verifier = await createVerifier();
const result = verifier.verify({ proof: new Uint8Array(proof), action: new Uint8Array(action), trustedContext: new Uint8Array(trustedContext) });
if (result.kind !== "authorized") throw new Error(result.code);
console.log(JSON.stringify({ recipe: "02-verify-authority", outcome: result.kind }));
