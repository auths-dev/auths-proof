import { execFileSync } from "node:child_process";
import { createReadStream } from "node:fs";
import { cp, mkdtemp, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const temporary = await mkdtemp(join(tmpdir(), "auths-typescript-browser-"));
const npmEnvironment = { ...process.env, npm_config_cache: join(temporary, "npm-cache") };
let browser;
let server;
try {
  const [{ filename }] = JSON.parse(execFileSync(
    "npm",
    ["pack", fileURLToPath(new URL("../../", import.meta.url)), "--json", "--pack-destination", temporary],
    { encoding: "utf8", env: npmEnvironment },
  ));
  await writeFile(join(temporary, "package.json"), JSON.stringify({ type: "module" }));
  execFileSync(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", join(temporary, filename)],
    { cwd: temporary, env: npmEnvironment, stdio: "pipe" },
  );
  await mkdir(join(temporary, "fixtures"));
  const fixtures = new URL("../../../../core/fixtures/v1/", import.meta.url);
  const vectors = new URL("../../../../target/binding-vectors/", import.meta.url);
  await cp(new URL("valid/raw-key-chain.proof.cbor", fixtures), join(temporary, "fixtures/proof.cbor"));
  await cp(new URL("valid/raw-key-chain.action.cbor", fixtures), join(temporary, "fixtures/action.cbor"));
  await cp(new URL("authorized.context.cbor", vectors), join(temporary, "fixtures/authorized.context.cbor"));
  await cp(new URL("valid/raw-key-chain.context.cbor", fixtures), join(temporary, "fixtures/denied.context.cbor"));
  await writeFile(join(temporary, "index.html"), `<!doctype html>
    <meta charset="utf-8">
    <title>Auths packed browser conformance</title>
    <output id="result">starting</output>
    <script type="module">
      import {
        approvalPolicy,
        commandsForGateway,
        loadAuths,
        loadPortableAuths,
        prepareRawKeyAuthority,
      } from "/node_modules/@auths-dev/sdk/dist/index.js";
      import { mcp } from "/node_modules/@auths-dev/sdk/dist/mcp.js";
      import { development } from "/node_modules/@auths-dev/sdk/dist/testkit/index.js";
      const bytes = async (name) => new Uint8Array(await (await fetch('/fixtures/' + name)).arrayBuffer());
      const action = await bytes('action.cbor');
      const first = await loadPortableAuths();
      const authorized = first.verify(
        await bytes('proof.cbor'), action, await bytes('authorized.context.cbor'),
      );
      const denied = first.verify(
        await bytes('proof.cbor'), action, await bytes('denied.context.cbor'),
      );
      const second = await loadPortableAuths();
      const repeated = second.verify(
        await bytes('proof.cbor'), action, await bytes('authorized.context.cbor'),
      );
      const profile = mcp.profile({ service: 'browser-records' });
      const policy = await approvalPolicy.planOnce({ maxUses: 2, expiresInSeconds: 120 });
      const approval = development.approval(policy);
      const rootSigner = await development.ephemeralSigner();
      const agentSigner = await development.ephemeralSigner();
      const principal = await agentSigner.publicIdentity();
      const now = BigInt(Math.floor(Date.now() / 1000));
      const prepared = await prepareRawKeyAuthority({
        authorityId: 'browser.owner',
        rootSigner,
        subjectPrincipal: principal.principal,
        profile,
        permissions: [{ capability: 'tools/call', resource: 'mcp://browser-records/tools/update' }],
        resourceNamespaces: ['mcp://browser-records'],
        validity: { notBefore: now - 30n, expiresAt: now + 600n },
        audiences: ['mcp://browser-records'],
        budget: { algebra: 'numeric-ceiling-v1', value: 2n },
        remainingDepth: 0,
        approval,
      });
      const client = await loadAuths({ signer: agentSigner, trustedAuthority: prepared.trustedAuthority });
      let gatewayCalls = 0;
      let planKind;
      let deniedKind;
      try {
        const agent = await client.attachAgent({
          name: 'browser-agent', profile, authority: prepared.authority, approval,
        });
        const plan = await profile.plan([
          profile.call('update', { record: 'one' }),
          profile.call('update', { record: 'two' }),
        ]);
        const planDecision = await agent.authorizePlan(plan);
        planKind = planDecision.kind;
        if (planDecision.kind === 'authorized') {
          const gateway = profile.gateway(async () => { gatewayCalls += 1; });
          for (const command of commandsForGateway(planDecision.command)) await gateway.execute(command);
        }
        const deniedDecision = await agent.authorize(profile.call('delete', { record: 'one' }));
        deniedKind = deniedDecision.kind;
      } finally {
        await client.dispose();
        await rootSigner.dispose();
      }
      document.querySelector('#result').textContent =
        [authorized.kind, denied.kind, repeated.kind, planKind, gatewayCalls, deniedKind].join(',');
    </script>`);

  server = createServer(async (request, response) => {
    const requested = request.url === "/" ? "/index.html" : request.url ?? "/index.html";
    const relative = normalize(decodeURIComponent(requested)).replace(/^[/\\]+/, "");
    const path = join(temporary, relative);
    if (!path.startsWith(temporary)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const info = await stat(path);
      if (!info.isFile()) throw new Error("not a file");
      const type = new Map([
        [".html", "text/html; charset=utf-8"],
        [".js", "text/javascript; charset=utf-8"],
        [".wasm", "application/wasm"],
        [".cbor", "application/cbor"],
      ]).get(extname(path)) ?? "application/octet-stream";
      response.writeHead(200, { "content-type": type });
      createReadStream(path).pipe(response);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("browser server did not bind");
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${address.port}/`);
  await page.waitForFunction(() => document.querySelector("#result")?.textContent !== "starting");
  const result = await page.textContent("#result");
  if (result !== "authorized,denied,authorized,authorized,2,denied") {
    throw new Error(`packed browser result drifted: ${result}`);
  }
} finally {
  await browser?.close();
  if (server !== undefined) await new Promise((resolve) => server.close(resolve));
  await rm(temporary, { recursive: true, force: true });
}
