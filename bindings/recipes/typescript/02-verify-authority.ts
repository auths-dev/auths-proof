import { readFile } from "node:fs/promises";
import { loadVerifier } from "@auths-dev/sdk/verify";

const fixture = process.env.AUTHS_RECIPE_FIXTURE;
if (fixture === undefined) throw new Error("AUTHS_RECIPE_FIXTURE is required");
const [proof, action, context] = await Promise.all([
  readFile(`${fixture}/workflow.proof.cbor`),
  readFile(`${fixture}/workflow.action.cbor`),
  readFile(`${fixture}/workflow.context.cbor`),
]);
const verifier = await loadVerifier();
const verified = verifier.verify(proof, action, context);
if (verified.kind !== "authorized") throw new Error(`unexpected verdict: ${verified.kind}`);
const changed = action.slice();
changed[changed.length - 1] ^= 1;
let changedRejected = false;
try {
  changedRejected = verifier.verify(proof, changed, context).kind !== "authorized";
} catch {
  changedRejected = true;
}
if (!changedRejected) throw new Error("mutated action remained authorized");
console.log(JSON.stringify({ recipe: "02-verify-authority", outcome: verified.kind, changedRejected }));
