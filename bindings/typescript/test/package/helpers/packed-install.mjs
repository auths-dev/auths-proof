import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const packageRootPath = fileURLToPath(new URL("../../../", import.meta.url));

function npmSync(arguments_, options) {
  const npmCli = process.env.npm_execpath;
  return npmCli === undefined
    ? execFileSync("npm", arguments_, options)
    : execFileSync(process.execPath, [npmCli, ...arguments_], options);
}

/**
 * Packs this SDK and installs the tarball into a fresh directory that contains
 * no Auths source checkout, so consumer fixtures exercise published artifacts.
 */
export async function installPackedSdk(prefix) {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  const environment = { ...process.env, npm_config_cache: join(directory, "npm-cache") };
  const [{ filename }] = JSON.parse(npmSync(
    ["pack", packageRootPath, "--json", "--pack-destination", directory],
    { encoding: "utf8", env: environment },
  ));
  await writeFile(join(directory, "package.json"), JSON.stringify({ type: "module" }));
  npmSync(
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(directory, filename)],
    { cwd: directory, stdio: "pipe", env: environment },
  );
  return { directory, environment, tarball: join(directory, filename) };
}

/** Runs the repository's TypeScript compiler against a consumer project. */
export function compileConsumer(directory, project = "tsconfig.json") {
  return execFileSync(
    process.execPath,
    [join(packageRootPath, "node_modules", "typescript", "bin", "tsc"), "-p", project],
    { cwd: directory, encoding: "utf8", stdio: "pipe" },
  );
}
