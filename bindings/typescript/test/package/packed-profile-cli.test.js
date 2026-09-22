import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { compileConsumer, installPackedSdk } from "./helpers/packed-install.mjs";

const vectors = fileURLToPath(new URL("../../../../target/binding-vectors/", import.meta.url));
const vector = (name) => readFile(join(vectors, name));

test("packed SDK generates and checks a typed external exact-tool consumer", async () => {
  const { directory } = await installPackedSdk("auths-typescript-profile-");
  const cli = join(directory, "node_modules", "@auths-dev", "sdk", "tools", "profile-cli.mjs");
  const profile = join(directory, "profile");
  execFileSync(process.execPath, [cli, "init", "--language", "typescript",
    "--name", "example-create", "--directory", profile], { cwd: directory });
  const manifest = join(profile, "profile.toml");
  const source = await readFile(manifest, "utf8");
  const original = '[arguments.fields.value]\ntype = "string"\nmin_bytes = 1\nmax_bytes = 256\n';
  assert.ok(source.includes(original));
  await writeFile(manifest, source.replace(original,
    '[arguments.fields.value]\ntype = "enum"\nvariants = ["open", "closed"]\n'));
  execFileSync(process.execPath, [cli, "generate", manifest], { cwd: directory });
  execFileSync(process.execPath, [cli, "check", manifest], { cwd: directory });
  const generated = await readFile(join(profile, "generated.ts"), "utf8");
  assert.match(generated, /invoke_v1/);
  assert.match(generated, /enumField\(\["open","closed"\]\)/);
  assert.match(await readFile(join(profile, "adapter.ts"), "utf8"), /ApplicationAdapter/);
  assert.match(await readFile(join(profile, "run.ts"), "utf8"), /runOnce/);
  await writeFile(join(directory, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      strict: true, target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext",
      lib: ["DOM", "ES2022", "ESNext.Disposable"], noEmit: true,
    },
    include: ["profile/**/*.ts", "consumer.ts"],
  }));
  await writeFile(join(directory, "consumer.ts"), `
    import type { ExampleCreate } from "./profile/generated.js";
    const valid: ExampleCreate = { value: "open" };
    // @ts-expect-error an undeclared variant cannot type-check
    const invalid: ExampleCreate = { value: "unknown" };
    void valid; void invalid;
  `);
  compileConsumer(directory);
  await writeFile(join(profile, "generated.ts"), `${generated}\n// drift\n`);
  assert.throws(() => execFileSync(process.execPath, [cli, "check", manifest],
    { cwd: directory, stdio: "pipe" }));
});

test("packed SDK signs under supplied trust, makes one write, and reconciles an unknown result", async () => {
  const { directory } = await installPackedSdk("auths-typescript-signed-consumer-");
  try {
    const sdk = await import(pathToFileURL(join(directory, "node_modules", "@auths-dev", "sdk",
      "dist", "self-hosted.js")).href);
    const seed = await vector("mcp.actor-seed.bin");
    const privateKey = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
      format: "der", type: "pkcs8",
    });
    const actor = "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E";
    const signature = { principalMethod: "raw-key-v1", verificationMethod: actor,
      suite: "ed25519-v1" };
    const descriptor = { contract: "signer-custody/2", kind: "workload",
      adapterId: "test.external-custody", principal: actor, signature,
      keyVersion: "fixture-key-1", keyState: "active-current", lifecycle: "ephemeral" };
    let signings = 0;
    const signer = { descriptor, async sign(request) {
      signings += 1;
      return { kind: "signed", response: {
        requestId: request.requestId, objectId: request.objectId,
        principal: actor, descriptor: signature, providerKeyVersion: descriptor.keyVersion,
        transactionDigest: request.transactionDigest,
        signature: new Uint8Array(signBytes(null, request.signingPreimage, privateKey)),
        evidence: [{ type: "raw-key-v1", mediaType: "application/vnd.auths.raw-key.v1",
          bytes: await vector("mcp.actor-evidence.bin") }],
      } };
    } };
    const contract = sdk.exactMcpTool({ service: "reports", name: "update_demo_record",
      fields: { value: sdk.stringField({ minBytes: 1, maxBytes: 32 }) } });
    const grants = [{ signedGrant: await vector("mcp.signed-root-grant.cbor"), evidence: [{
      type: "raw-key-v1", mediaType: "application/vnd.auths.raw-key.v1",
      bytes: await vector("mcp.root-evidence.bin"),
    }] }];
    const trustedContextTemplate = await vector("mcp.context.cbor");
    const author = (value) => sdk.authorMcpProof({
      contract, command: { value }, signer, grants, trustedContextTemplate,
      challenge: new Uint8Array(32).fill(0x22), evaluationTime: 50n,
    });
    const first = await author("reviewed");
    const records = new Map();
    const keys = new Set();
    const attempts = {
      async claimOnce(commitment, key) {
        const id = Buffer.from(commitment).toString("hex");
        if (records.has(id) || keys.has(key)) return false;
        keys.add(key);
        records.set(id, { actionCommitment: commitment, operationKey: key, state: "attempting" });
        return true;
      },
      async read(commitment) { return records.get(Buffer.from(commitment).toString("hex")); },
      async finish(commitment, state) {
        const id = Buffer.from(commitment).toString("hex");
        const record = { ...records.get(id), state };
        records.set(id, record);
        return record;
      },
    };
    let writes = 0;
    let credentials = 0;
    const adapter = {
      credential() { credentials += 1; return "synthetic-token"; },
      async invoke() { writes += 1; return { kind: "accepted", value: "synthetic-write" }; },
      async observe() { return "observed"; },
    };
    const base = { contract, proof: first.proof, action: first.action,
      trustedContext: first.trustedContext, attempts, operationKey: "signed-write-one", adapter };
    const wrong = sdk.exactMcpTool({ service: "reports", name: "other_record",
      fields: { value: sdk.stringField({ minBytes: 1, maxBytes: 32 }) } });
    assert.equal((await sdk.runOnce({ ...base, contract: wrong })).kind, "denied");
    assert.equal(credentials, 0);
    const written = await sdk.runOnce(base);
    assert.equal(written.kind, "attempted");
    assert.equal(written.provider.kind, "accepted");
    assert.equal(written.observation, "observed");
    assert.equal((await sdk.runOnce(base)).kind, "replay");
    assert.equal(writes, 1);

    const second = await author("queued");
    const ambiguous = { ...adapter,
      async invoke() { writes += 1; throw new Error("synthetic timeout after provider entry"); } };
    await assert.rejects(sdk.runOnce({ ...base, proof: second.proof, action: second.action,
      trustedContext: second.trustedContext, operationKey: "signed-write-two", adapter: ambiguous }),
    /synthetic timeout/);
    assert.equal((await attempts.read(second.actionCommitment)).state, "unknown");
    const authorization = await sdk.verifyCommand({ contract, proof: second.proof,
      action: second.action, trustedContext: second.trustedContext });
    assert.equal(authorization.kind, "authorized");
    assert.equal(await sdk.reconcileReadOnly({ authorization, adapter: ambiguous }), "observed");
    assert.equal(writes, 2);
    assert.equal(signings, 2);

    const cli = await import(pathToFileURL(join(directory, "node_modules", "@auths-dev", "sdk",
      "tools", "profile-cli.mjs")).href);
    const starterContract = {
      name: "signed-starter", version: 1, service: "reports", tool: "update_demo_record",
      command: "SignedStarter",
      fields: [{ name: "value", kind: "string", minimum: 1, maximum: 32 }],
    };
    const starter = join(directory, "starter");
    await mkdir(starter);
    await writeFile(join(starter, "generated.ts"), cli.renderGenerated(starterContract));
    await writeFile(join(starter, "adapter.ts"), cli.renderAdapter(starterContract));
    await writeFile(join(starter, "conformance.ts"), cli.renderConformance(starterContract));
    await writeFile(join(directory, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        strict: true, target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext",
        lib: ["DOM", "ES2022", "ESNext.Disposable"], outDir: "out", rootDir: ".",
      },
      include: ["starter/**/*.ts"],
    }));
    compileConsumer(directory);
    const generatedStarter = await import(pathToFileURL(join(directory, "out", "starter", "conformance.js")).href);
    const starterArtifacts = await author("x");
    const report = await generatedStarter.run({
      artifacts: { proof: starterArtifacts.proof, action: starterArtifacts.action,
        trustedContext: starterArtifacts.trustedContext },
      adapterFactory(provider) {
        return {
          credential() { return "synthetic-token"; },
          invoke(command, credential) { return provider.write(command, credential); },
          observe(command) { return provider.read(command); },
        };
      },
    });
    assert.equal(report.passed, true, JSON.stringify(report.cases));
    assert.equal(signings, 3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
