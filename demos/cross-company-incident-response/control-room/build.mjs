import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const sdk = join(here, "../../../bindings/typescript");
const output = join(here, "public");
await mkdir(join(output, "vendor-v3"), { recursive: true });
await rm(join(output, "vendor-v3", "dist"), { recursive: true, force: true });
await rm(join(output, "vendor-v3", "wasm"), { recursive: true, force: true });
await cp(join(sdk, "dist"), join(output, "vendor-v3", "dist"), { recursive: true });
await cp(join(sdk, "wasm"), join(output, "vendor-v3", "wasm"), { recursive: true });
await cp(join(here, "build", "app.js"), join(output, "app.js"));
const api = process.env.AUTHS_INCIDENT_AGENT_API ?? "http://localhost:7103";
await writeFile(join(output, "config.js"), `globalThis.AUTHS_INCIDENT_AGENT_API=${JSON.stringify(api)};\n`);
const html = await readFile(join(output, "index.html"), "utf8");
if (!html.includes("auths-incident-demo")) throw new Error("control-room build lost its schema marker");
