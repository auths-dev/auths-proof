/**
 * Run the whole README journey unattended from the npm package and check every
 * claim it makes, case for case with ../journey.py.
 *
 *   node build/journey.js --gateway PATH/TO/auths-gateway [--summary out.json]
 *
 * By default the gateway sends refunds to ../mock_stripe.py, the counting
 * Stripe double on 127.0.0.1; that needs a gateway built with
 * `--features loopback-provider` and a `python3` (or `--python`). With
 * `--stripe-test-mode` the same journey calls Stripe's test mode instead,
 * using the developer's own STRIPE_TEST_SECRET_KEY (sk_test_ only) and a
 * refundable `--payment-intent` of at least 55.00 USD. The key is piped to the
 * gateway install and nowhere else.
 */

import { type ChildProcess, spawn, spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";

import { EXAMPLE, type SetupFacts } from "./refunds.js";

const REFUNDS = fileURLToPath(new URL("./refunds.js", import.meta.url));
// The packaged approval CLI installed with @auths-dev/sdk.
const APPROVE_CLI = fileURLToPath(new URL("../node_modules/@auths-dev/sdk/tools/profile-cli.mjs", import.meta.url));

type Json = Record<string, unknown>;
type Step = { step: string; seconds: number };

class Journey {
  readonly state: string;
  readonly gatewayState: string;
  readonly socket: string;
  readonly ledger: string;
  readonly env: NodeJS.ProcessEnv;
  readonly steps: Step[] = [];
  readonly started = performance.now();
  #processes: ChildProcess[] = [];

  constructor(readonly gateway: string, readonly python: string, readonly work: string) {
    this.state = join(work, "state");
    this.gatewayState = join(work, "gateway");
    this.socket = join(work, "app.sock");
    this.ledger = join(work, "ledger.jsonl");
    // No child process inherits a Stripe key; the install reads it on stdin.
    this.env = { ...process.env };
    delete this.env.STRIPE_TEST_SECRET_KEY;
  }

  async step<T>(name: string, action: () => T | Promise<T>): Promise<T> {
    const begun = performance.now();
    const result = await action();
    const seconds = Math.round(performance.now() - begun) / 1000;
    this.steps.push({ step: name, seconds });
    process.stderr.write(`[${String(this.steps.length).padStart(2)}] ${name} (${seconds}s)\n`);
    return result;
  }

  run(command: string, args: readonly string[], input?: string, check = true): SpawnSyncReturns<string> {
    const result = spawnSync(command, args, {
      cwd: EXAMPLE, env: this.env, encoding: "utf8", ...(input === undefined ? {} : { input }),
    });
    if (check && result.status !== 0) {
      throw new Error(`${[command, ...args.slice(0, 2)].join(" ")} failed: ${result.stderr?.trim()}`);
    }
    return result;
  }

  background(command: string, args: readonly string[], stdout: "pipe" | "ignore"): ChildProcess {
    const child = spawn(command, args, { cwd: EXAMPLE, env: this.env, stdio: ["ignore", stdout, "ignore"] });
    this.#processes.push(child);
    return child;
  }

  async stop(): Promise<void> {
    for (const child of this.#processes) {
      if (child.exitCode !== null || child.signalCode !== null) continue;
      const exited = new Promise((done) => child.once("exit", done));
      child.kill("SIGTERM");
      if (await Promise.race([exited.then(() => true), sleep(5_000, false, { ref: false })]) === false) {
        child.kill("SIGKILL");
      }
    }
    this.#processes = [];
  }

  providerEntries(): Json[] {
    if (!existsSync(this.ledger)) return [];
    return readFileSync(this.ledger, "utf8").split("\n").filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Json);
  }

  /** The agent writes one request per manager (and its own response). */
  request(operation: string, amount: number, approvers: string, paymentIntent: string): string {
    const folder = join(this.work, "approvals", operation);
    this.run(process.execPath, [
      REFUNDS, "request", "--state", this.state, "--operation-id", operation,
      "--payment-intent", paymentIntent, "--amount", String(amount), "--approvers", approvers,
      "--out", folder,
    ]);
    return folder;
  }

  /** One manager answers on their own machine with the packaged CLI. */
  answer(folder: string, manager: string, options: Readonly<{ decline?: boolean; request?: string }> = {}):
    SpawnSyncReturns<string> {
    return this.run(process.execPath, [
      APPROVE_CLI, "approve", options.request ?? join(folder, `${manager}.request`),
      "--signer", join(this.state, "signers", `${manager}.json`), "--yes",
      "--out", join(folder, `${manager}.response`), ...(options.decline === true ? ["--decline"] : []),
    ], undefined, false);
  }

  refund(operation: string, amount: number, approvers: string, paymentIntent: string,
    declines: readonly string[] = []): Json {
    const folder = this.request(operation, amount, approvers, paymentIntent);
    for (const manager of approvers.split(",")) {
      const answered = this.answer(folder, manager, { decline: declines.includes(manager) });
      if (answered.status !== 0) throw new Error(`${manager} could not answer: ${answered.stderr.trim()}`);
    }
    return JSON.parse(this.run(process.execPath, [
      REFUNDS, "submit", "--state", this.state, "--socket", this.socket, "--operation-id", operation,
      "--responses", folder,
    ]).stdout) as Json;
  }

  audit(bundle: string, trust: string, observer: string): SpawnSyncReturns<string> {
    let command = this.gateway;
    let args = ["audit", "--bundle", bundle, "--trusted-context-sha256", trust, "--observer", observer];
    // Prove the audit needs no network where the platform allows it.
    if (platform() === "linux" && spawnSync("unshare", ["-rn", "true"]).status === 0) {
      args = ["-rn", command, ...args];
      command = "unshare";
    }
    return this.run(command, args, undefined, false);
  }
}

function expect(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`journey check failed: ${message}`);
}

function tamper(bundle: Json, operation: string, change: (entry: Json) => void): Json {
  const copy = JSON.parse(JSON.stringify(bundle)) as { entries: Json[] };
  change(copy.entries.find((entry) => entry.operation_id === operation)!);
  return copy as unknown as Json;
}

function flipProofByte(entry: Json): void {
  const raw = Buffer.from(entry.proof_b64 as string, "base64url");
  raw[Math.floor(raw.length / 2)]! ^= 0x01;
  entry.proof_b64 = raw.toString("base64url");
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      gateway: { type: "string" },
      summary: { type: "string" },
      python: { type: "string", default: "python3" },
      "stripe-test-mode": { type: "boolean", default: false },
      "payment-intent": { type: "string", default: "pi_mock_journey" },
    },
  });
  if (values.gateway === undefined) throw new Error("--gateway PATH/TO/auths-gateway is required");
  const live = values["stripe-test-mode"]!;
  const paymentIntent = values["payment-intent"]!;
  let secret: string;
  if (live) {
    secret = process.env.STRIPE_TEST_SECRET_KEY ?? "";
    if (!secret.startsWith("sk_test_")) {
      throw new Error("--stripe-test-mode needs STRIPE_TEST_SECRET_KEY=sk_test_...; live keys are refused");
    }
    if (!paymentIntent.startsWith("pi_") || paymentIntent === "pi_mock_journey") {
      throw new Error("--stripe-test-mode needs --payment-intent pi_... from your test account");
    }
  } else {
    secret = `sk_test_mock_${randomBytes(12).toString("hex")}`;
  }

  const work = realpathSync(mkdtempSync("/tmp/auths-refunds-"));
  const journey = new Journey(values.gateway, values.python!, work);
  try {
    // README step 3: principals, trust, and the agent's bounded grant.
    const facts = await journey.step("setup: root, three managers, agent, trust, bounded grant", () =>
      JSON.parse(journey.run(process.execPath, [
        REFUNDS, "setup", "--state", journey.state, "--gateway", journey.gateway,
      ]).stdout) as SetupFacts);
    // README step 4: the gateway takes the Stripe key on stdin, and only it.
    await journey.step("gateway install with the key on stdin", () => {
      mkdirSync(journey.gatewayState, { mode: 0o700 });
      journey.run(journey.gateway, [
        "install", "--state-dir", journey.gatewayState, "--recipe", "recipe.json",
        "--profile-lock", "profile.lock.json",
        "--trusted-context", join(journey.state, "trust", "gateway.context.cbor"),
        "--approve-digest", facts.recipe_digest, "--provider", "stripe", "--alias", "refunds",
        "--account-label", "stripe-test-account", "--credential-stdin",
      ], `${secret}\n`);
    });
    const observer = await journey.step("gateway observer key", () =>
      ((JSON.parse(journey.run(journey.gateway, ["observer-init", "--state-dir", journey.gatewayState]).stdout) as
        { observer_anchor: { principal: string } }).observer_anchor.principal));
    // The double checks the bearer token by digest; the key itself stays
    // only in the gateway's credential store.
    const mockTokenSha256 = createHash("sha256").update(secret).digest("hex");

    // README step 5: Stripe (or its double) and the gateway.
    await journey.step(`gateway serve${live ? "" : " (to the counting Stripe double)"}`, async () => {
      const serve = ["serve", "--state-dir", journey.gatewayState, "--app-socket", journey.socket];
      if (!live) {
        const mock = journey.background(journey.python, [
          "mock_stripe.py", "--ledger", journey.ledger, "--token-sha256", mockTokenSha256,
        ], "pipe");
        const port = await Promise.race([
          new Promise<string>((done) => createInterface({ input: mock.stdout! }).once("line", done)),
          sleep(10_000, "", { ref: false }),
        ]);
        expect(/^\d+$/.test(port.trim()), "mock Stripe did not start");
        serve.push("--loopback-provider", port.trim());
      }
      journey.background(journey.gateway, serve, "ignore");
      const deadline = performance.now() + 10_000;
      while (!existsSync(journey.socket)) {
        expect(performance.now() < deadline, "gateway did not open its app socket");
        await sleep(50);
      }
    });

    const results: Record<string, Json> = {};
    const submit = (operation: string, amount: number, approvers: string, declines: readonly string[] = []): void => {
      const before = journey.providerEntries().length;
      results[operation] = journey.refund(operation, amount, approvers, paymentIntent, declines);
      results[operation]!.provider_entries = journey.providerEntries().length - before;
    };

    // README steps 6 and 7: the agent writes a request per manager, each
    // manager answers with `auths-profile approve`, the gateway submits; then
    // a decline, a tampered request, and the three refusals.
    await journey.step("refund 1: 15.00, agent + manager-a + manager-b (remote approvals)",
      () => submit("refund-1", 1_500, "manager-a,manager-b"));
    await journey.step("declined: manager-b declines, nothing is submitted",
      () => submit("refund-declined", 2_000, "manager-a,manager-b", ["manager-b"]));
    const tamperedRun = await journey.step("tampered request: the manager's CLI refuses and signs nothing", () => {
      const folder = journey.request("refund-tampered", 1_500, "manager-a,manager-b", paymentIntent);
      const original = readFileSync(join(folder, "manager-a.request"), "utf8").trim();
      const raw = Buffer.from(original.slice("auths-ar1-".length), "base64url");
      const at = raw.indexOf('"amount":1500');
      raw.write('"amount":9500', at, "latin1");
      const edited = join(folder, "manager-a.edited");
      writeFileSync(edited, `auths-ar1-${raw.toString("base64url")}`);
      const answered = journey.answer(folder, "manager-a", { request: edited });
      return {
        exit: answered.status,
        refused: answered.stderr.includes("approval.action-mismatch"),
        signed: existsSync(join(folder, "manager-a.response")),
      };
    });
    await journey.step("hostile: 1 of 3 approvals",
      () => submit("refund-2-one-approval", 1_200, "manager-a"));
    await journey.step("hostile: over the 50.00 ceiling",
      () => submit("refund-3-over-ceiling", 9_000, "manager-a,manager-b"));
    await journey.step("refund 4: 40.00, agent + manager-b + manager-c",
      () => submit("refund-4", 4_000, "manager-b,manager-c"));
    await journey.step("hostile: third refund in the window",
      () => submit("refund-5-window", 1_000, "manager-a,manager-c"));

    for (const operation of ["refund-1", "refund-4"]) {
      const got = results[operation]!;
      expect(got.outcome === "response-recorded" && got.status === 200, `${operation}: ${JSON.stringify(got)}`);
    }
    const declined = results["refund-declined"]!;
    expect(declined.outcome === "declined" && JSON.stringify(declined.declined) === JSON.stringify(["manager-b"]) &&
      declined.provider_entries === 0, `refund-declined: ${JSON.stringify(declined)}`);
    expect(JSON.stringify(tamperedRun) === JSON.stringify({ exit: 1, refused: true, signed: false }),
      `tampered request: ${JSON.stringify(tamperedRun)}`);
    const expectedRefusals: Record<string, readonly [string, string]> = {
      "refund-2-one-approval": ["denied", "composition-requirement-not-met"],
      "refund-3-over-ceiling": ["not-entered", "gateway.policy.above-ceiling"],
      "refund-5-window": ["not-entered", "gateway.policy.window-exhausted"],
    };
    for (const [operation, [outcome, code]] of Object.entries(expectedRefusals)) {
      const got = results[operation]!;
      expect(got.outcome === outcome && got.code === code, `${operation}: ${JSON.stringify(got)}`);
    }
    if (!live) {
      const entries = journey.providerEntries();
      expect(entries.length === 2, `expected exactly 2 provider entries, saw ${entries.length}`);
      expect(entries.every((entry) => entry.authorized === true && entry.well_formed === true),
        "provider saw a malformed or unauthenticated request");
      expect(JSON.stringify(entries.map((entry) => entry.amount)) === JSON.stringify([1_500, 4_000]),
        `provider amounts ${JSON.stringify(entries)}`);
      for (const operation of Object.keys(expectedRefusals)) {
        expect(results[operation]!.provider_entries === 0, `${operation} reached the provider`);
      }
    }

    // README step 8: the audit bundle.
    const bundlePath = join(journey.work, "audit-bundle.json");
    await journey.step("export audit bundle", () => journey.run(process.execPath, [
      REFUNDS, "export", "--state", journey.state, "--out", bundlePath,
    ]));
    await journey.stop();

    // README step 9: the offline audit, with the gateway stopped.
    const audited = await journey.step("offline audit (gateway stopped)",
      () => journey.audit(bundlePath, facts.trusted_context_sha256, observer));
    expect(audited.status === 0, `audit failed: ${audited.stderr}`);
    const report = JSON.parse(audited.stdout) as {
      verified: number; refused: number; inconsistent: number;
      entries: { operation_id: string; status: string; code: string; approvals: string[] }[];
      approval_responses: { operation_id: string; approver: string; decision: string }[];
    };
    const verdicts = Object.fromEntries(report.entries.map((entry) =>
      [entry.operation_id, `${entry.status} ${entry.code}`]));
    expect(verdicts["refund-1"] === "verified audit.verified", `audit refund-1 ${JSON.stringify(verdicts)}`);
    expect(verdicts["refund-4"] === "verified audit.verified", `audit refund-4 ${JSON.stringify(verdicts)}`);
    for (const [operation, [, code]] of Object.entries(expectedRefusals)) {
      expect(verdicts[operation] === `refused ${code}`, `audit ${operation}: ${verdicts[operation]}`);
    }
    const verified = report.entries.find((entry) => entry.operation_id === "refund-1")!;
    expect(verified.approvals.length === 3, "refund-1 should carry the agent and two managers");
    expect(
      JSON.stringify([...verified.approvals].sort()) ===
        JSON.stringify(["agent", "manager-a", "manager-b"].map((name) => facts.principals[name]).sort()),
      "refund-1 approvers",
    );
    const recorded = new Set(report.approval_responses.map((item) =>
      `${item.operation_id} ${item.approver} ${item.decision}`));
    for (const [operation, name, decision] of [
      ["refund-declined", "manager-a", "approve"], ["refund-declined", "manager-b", "decline"],
      ["refund-1", "manager-a", "approve"], ["refund-1", "manager-b", "approve"],
    ] as const) {
      expect(recorded.has(`${operation} ${facts.principals[name]} ${decision}`),
        `audit approval responses ${JSON.stringify([...recorded])}`);
    }

    // Hostile: a tampered bundle is detected.
    const bundle = JSON.parse(readFileSync(bundlePath, "utf8")) as { entries: Json[] } & Json;
    const refund4 = bundle.entries.find((entry) => entry.operation_id === "refund-4")!;
    const tampered: Record<string, readonly [Json, string]> = {
      "proof byte flipped": [tamper(bundle, "refund-1", flipProofByte), "audit.entered-without-authority"],
      "action swapped": [
        tamper(bundle, "refund-1", (entry) => { entry.action_b64 = refund4.action_b64; }),
        "audit.outcome-commitment-mismatch",
      ],
      "outcome replayed": [
        tamper(bundle, "refund-1", (entry) => { entry.outcome_b64 = refund4.outcome_b64; }),
        "audit.outcome-invalid",
      ],
    };
    const detections: Record<string, string> = {};
    const tamperedPath = join(journey.work, "tampered.json");
    for (const [label, [value, code]] of Object.entries(tampered)) {
      writeFileSync(tamperedPath, JSON.stringify(value));
      const result = journey.audit(tamperedPath, facts.trusted_context_sha256, observer);
      const findings = (JSON.parse(result.stdout) as { entries: { status: string; code: string }[] }).entries
        .filter((entry) => entry.status === "inconsistent").map((entry) => entry.code);
      expect(result.status !== 0 && JSON.stringify(findings) === JSON.stringify([code]),
        `tamper '${label}' not detected: ${JSON.stringify(findings)} ${result.stderr}`);
      detections[label] = code;
    }
    writeFileSync(tamperedPath, JSON.stringify({
      ...bundle,
      trusted_context_b64: readFileSync(join(journey.state, "trust", "sdk.context.cbor")).toString("base64url"),
    }));
    const replaced = journey.audit(tamperedPath, facts.trusted_context_sha256, observer);
    expect(replaced.status !== 0 && replaced.stderr.includes("audit.trust-pin-mismatch"),
      "replaced trust not detected");
    detections["trust replaced"] = "audit.trust-pin-mismatch";
    journey.steps.push({ step: "tampered bundles detected", seconds: 0 });

    const summary = {
      journey: "stripe-refund-approval",
      sdk: "@auths-dev/sdk (packed npm)",
      provider: live ? "stripe-test-mode" : "counting-mock",
      wall_seconds: Math.round(performance.now() - journey.started) / 1000,
      steps: journey.steps,
      refunds: results,
      tampered_request: tamperedRun,
      provider_entries: live ? null : journey.providerEntries().length,
      audit: { verified: report.verified, refused: report.refused, inconsistent: report.inconsistent },
      tamper_detected: detections,
    };
    const text = JSON.stringify(summary, null, 2);
    process.stdout.write(`${text}\n`);
    if (values.summary !== undefined) writeFileSync(values.summary, `${text}\n`);
  } finally {
    await journey.stop();
    rmSync(work, { recursive: true, force: true });
  }
}

await main();
