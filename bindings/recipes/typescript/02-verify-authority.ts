import { readFile } from "node:fs/promises";
import { createVerifier } from "@auths-dev/sdk/verify";

const fixture = process.env.AUTHS_RECIPE_FIXTURE;
if (fixture === undefined) throw new Error("Set AUTHS_RECIPE_FIXTURE to the directory containing workflow.proof.cbor, workflow.action.cbor and workflow.context.cbor; see the recipe setup instructions.");
const [proof, action, trustedContext] = await Promise.all([
  readFile(`${fixture}/workflow.proof.cbor`),
  readFile(`${fixture}/workflow.action.cbor`),
  readFile(`${fixture}/workflow.context.cbor`),
]);
const verifier = await createVerifier();
const result = verifier.verify({ proof: new Uint8Array(proof), action: new Uint8Array(action), trustedContext: new Uint8Array(trustedContext) });
if (result.kind !== "authorized") throw new Error(result.code);
console.log(JSON.stringify({ recipe: "02-verify-authority", outcome: result.kind }));
