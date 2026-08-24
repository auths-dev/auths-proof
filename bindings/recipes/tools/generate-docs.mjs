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

for (const recipe of manifest.recipes) {
  const [filename, title, outcome, production] = descriptions[recipe.id];
  const typescript = readFileSync(join(recipes, recipe.typescript), "utf8").trimEnd();
  const python = readFileSync(join(recipes, recipe.python), "utf8").trimEnd();
  const number = recipe.id.slice(0, 2);
  const document = `# ${number} — ${title}\n\n` +
    `## Outcome\n\n${outcome}\n\n` +
    `## Before you start\n\nUse a supported Node.js or CPython runtime and install the single Auths package. The executable source below is run against the packed npm artifact and wheel in CI.\n\n` +
    `## TypeScript\n\nSource: \`${recipe.typescript}\`\n\n\`\`\`typescript\n${typescript}\n\`\`\`\n\n` +
    `## Python\n\nSource: \`${recipe.python}\`\n\n\`\`\`python\n${python}\n\`\`\`\n\n` +
    `## What Auths protected\n\nThe recipe uses Rust-owned canonicalization, commitments, authorization, and receipt/recovery semantics. TypeScript and Python coordinate bounded I/O but cannot mint an effect-capable authorization object.\n\n` +
    `## Break it safely\n\nThe executable includes its failure exercise and asserts that no unauthorized or duplicate provider entry occurs. CI fails if the adversarial result changes.\n\n` +
    `## Take it to production\n\n${production}\n`;
  writeFileSync(join(repository, "docs/product/recipes", filename), document);
}
