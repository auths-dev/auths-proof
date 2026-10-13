import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const recipes = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repository = resolve(recipes, "../..");
const manifest = JSON.parse(readFileSync(join(recipes, "manifest.json"), "utf8"));
const descriptions = {
  "01-authenticate-identity": ["01_AUTHENTICATE_IDENTITY.md", "Authenticate an identity", "Authenticate exact bytes without creating authority or approval state.", "Replace the development/test identity adapters with maintained method resolution and custody for your selected signature suite."],
  "02-verify-authority": ["02_VERIFY_AUTHORITY.md", "Verify existing authority", "Verify existing proof, action, and trust bytes without gaining an execution capability.", "Load the verification context from your governed trust source and retain the exact profile/semantic versions used by issued evidence."],
};

const authoritySetup = [
  "This recipe reads a signed proof, its exact action and verification settings describing which signing identities you accept. Put them in one directory as `workflow.proof.cbor`, `workflow.action.cbor` and `workflow.context.cbor`, and set `AUTHS_RECIPE_FIXTURE` to that directory.",
  "",
  "For a disposable example, run this with the installed Python package. It generates its own in-memory signing key and public test artifacts; it needs no checkout, provider credential or downloaded fixture. The generated context trusts that disposable key only and is not production trust.",
  "",
  "```python",
  "from pathlib import Path",
  "from auths.testkit import development_mcp_artifacts",
  "",
  'artifacts = development_mcp_artifacts(',
  '    service="recipe-demo", name="publish_report", arguments={"report": "weekly"}',
  ")",
  'directory = Path("auths-demo-evidence")',
  "directory.mkdir(exist_ok=True)",
  "for name, data in [",
  '    ("proof", artifacts.proof),',
  '    ("action", artifacts.action),',
  '    ("context", artifacts.trusted_context),',
  "]:",
  '    (directory / ("workflow." + name + ".cbor")).write_bytes(data)',
  "```",
  "",
  "Save the verification program below as `verify_authority.py` or compile the TypeScript program, then run:",
  "",
  "```sh",
  'AUTHS_RECIPE_FIXTURE="$PWD/auths-demo-evidence" python verify_authority.py',
  'AUTHS_RECIPE_FIXTURE="$PWD/auths-demo-evidence" node verify_authority.js',
  "```",
].join("\n");
const protectedClaims = {
  "01-authenticate-identity": "The native Rust implementation checks the identity, signature and exact message binding. This authenticates bytes; it grants no authority and performs no provider write.",
  "02-verify-authority": "The native Rust verifier checks the supplied proof against the exact action and your explicit verification settings. An authorized result is an offline verification result; it acquires no credential and performs no provider write.",
};
const failureExercises = {
  "01-authenticate-identity": "The Python example changes the message while keeping the original signature and requires authentication to fail. No provider is contacted.",
  "02-verify-authority": "The Python example changes one action byte and requires authorization to fail. The trust context is an explicit input; do not replace governed production trust with a self-trusting test context.",
};

for (const recipe of manifest.recipes) {
  const [filename, title, outcome, production] = descriptions[recipe.id];
  const typescript = readFileSync(join(recipes, recipe.typescript), "utf8").trimEnd();
  const python = readFileSync(join(recipes, recipe.python), "utf8").trimEnd();
  const number = recipe.id.slice(0, 2);
  const setup = recipe.id === "02-verify-authority" ? `\n\n${authoritySetup}` : "";
  const document = `# ${number} — ${title}\n\n` +
    `## Outcome\n\n${outcome}\n\n` +
    `## Before you start\n\nUse a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.${setup}\n\n` +
    `## TypeScript\n\nSource: \`${recipe.typescript}\`\n\n\`\`\`typescript\n${typescript}\n\`\`\`\n\n` +
    `## Python\n\nSource: \`${recipe.python}\`\n\n\`\`\`python\n${python}\n\`\`\`\n\n` +
    `## What Auths protected\n\n${protectedClaims[recipe.id]}\n\n` +
    `## Break it safely\n\n${failureExercises[recipe.id]}\n\n` +
    `## Take it to production\n\n${production}\n`;
  writeFileSync(join(repository, "docs/product/recipes", filename), document);
}
