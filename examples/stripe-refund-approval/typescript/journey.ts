/**
 * Run the whole README journey unattended from the npm package and check every
 * claim it makes, case for case with ../journey.py.
 *
 *   node build/journey.js --gateway PATH/TO/auths-gateway [--summary out.json]
 *
 * By default the gateway sends every request to ../mock_stripe.py, the
 * counting Stripe double on 127.0.0.1; that needs a gateway built with
 * `--features loopback-provider` and a `python3` (or `--python`). With
 * `--stripe-test-mode` the same journey calls Stripe's test mode instead,
 * using the developer's own restricted key STRIPE_TEST_RESTRICTED_KEY
 * (rk_test_ only), their platform and connected account IDs, a refundable
 * `--payment-intent` of at least 30.00 USD in the connected account, and a
 * `--rejected-payment-intent` of at least 80.00 USD whose charge is already
 * fully refunded. The key is piped to the gateway install and nowhere else.
 *
 * Refund 1 is read back: the gateway finds its echo token in the refund's
 * metadata and records `observed-by-provider`. Refund 4 names a PaymentIntent
 * whose charge is already refunded, so the provider rejects it with 400 after
 * the gateway entered it. The offline audit reports it `verified` (authorized
 * and entered) with its `http_status` of 400 beside the verdict, and it still
 * consumes the agent's second refund of the window.
 *
 * Each of the recipe's provider checks refuses one hostile refund with zero
 * writes, as in ../journey.py; the four refusals after the credential lease
 * consume a count slot each, so a second agent with its own grant makes them.
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
// The double's accounts and its already-refunded PaymentIntent.
const PLATFORM_ACCOUNT = "acct_1AuthsPlatform0";
const CONNECTED_ACCOUNT = "acct_1AuthsConnected";
const OTHER_ACCOUNT = "acct_1AuthsOtherAcct";
const REFUNDED_PAYMENT_INTENT = "pi_mock_refunded";
const STRIPE_VERSION = "2025-03-31.basil";
// The second agent, whose refunds the checks after the credential lease refuse.
const CHECKS_AGENT = "agent-checks";
// A clearly fake key without the recipe's `rk_test_` prefix.
const NON_TEST_KEY = "rk_live_not-a-real-key";
const KEY_VARIABLES = ["STRIPE_TEST_RESTRICTED_KEY", "STRIPE_TEST_SECRET_KEY"];
// The packaged approval CLI installed with @auths-dev/sdk.
const APPROVE_CLI = fileURLToPath(new URL("../node_modules/@auths-dev/sdk/tools/profile-cli.mjs", import.meta.url));

type Json = Record<string, unknown>;
type Step = { step: string; seconds: number };

class Journey {
  readonly state: string;
  readonly gatewayState: string;
  readonly socket: string;
  readonly ledger: string;
  readonly control: string;
  readonly env: NodeJS.ProcessEnv;
  readonly steps: Step[] = [];
  readonly started = performance.now();
  #processes: ChildProcess[] = [];

  constructor(readonly gateway: string, readonly python: string, readonly work: string) {
    this.state = join(work, "state");
    this.gatewayState = join(work, "gateway");
    this.socket = join(work, "app.sock");
    this.ledger = join(work, "ledger.jsonl");
    this.control = join(work, "control.json");
    // No child process inherits a Stripe key; the install reads it on stdin.
    this.env = { ...process.env };
    for (const name of KEY_VARIABLES) delete this.env[name];
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

  /**
   * The agent writes one request per manager (and its own response). `extra`
   * passes `currency`, `connect-account`, or `agent`.
   */
  request(operation: string, amount: number, approvers: string, paymentIntent: string,
    extra: Readonly<Record<string, string>> = {}): string {
    const folder = join(this.work, "approvals", operation);
    this.run(process.execPath, [
      REFUNDS, "request", "--state", this.state, "--operation-id", operation,
      "--payment-intent", paymentIntent, "--amount", String(amount), "--approvers", approvers,
      "--out", folder, ...Object.entries(extra).flatMap(([name, value]) => [`--${name}`, value]),
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
    declines: readonly string[] = [], extra: Readonly<Record<string, string>> = {}): Json {
    const folder = this.request(operation, amount, approvers, paymentIntent, extra);
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
      "rejected-payment-intent": { type: "string", default: REFUNDED_PAYMENT_INTENT },
      "platform-account": { type: "string", default: PLATFORM_ACCOUNT },
      "connect-account": { type: "string", default: CONNECTED_ACCOUNT },
    },
  });
  if (values.gateway === undefined) throw new Error("--gateway PATH/TO/auths-gateway is required");
  const live = values["stripe-test-mode"]!;
  const paymentIntent = values["payment-intent"]!;
  const rejectedPaymentIntent = values["rejected-payment-intent"]!;
  const platformAccount = values["platform-account"]!;
  const connectAccount = values["connect-account"]!;
  let secret: string;
  if (live) {
    secret = process.env.STRIPE_TEST_RESTRICTED_KEY ?? "";
    if (!secret.startsWith("rk_test_")) {
      throw new Error("--stripe-test-mode needs STRIPE_TEST_RESTRICTED_KEY=rk_test_...; other keys are refused");
    }
    for (const [option, value, fallback, prefix] of [
      ["--payment-intent", paymentIntent, "pi_mock_journey", "pi_"],
      ["--rejected-payment-intent", rejectedPaymentIntent, REFUNDED_PAYMENT_INTENT, "pi_"],
      ["--platform-account", platformAccount, PLATFORM_ACCOUNT, "acct_"],
      ["--connect-account", connectAccount, CONNECTED_ACCOUNT, "acct_"],
    ] as const) {
      if (!value.startsWith(prefix) || value === fallback) {
        throw new Error(`--stripe-test-mode needs ${option} ${prefix}... from your test account`);
      }
    }
  } else {
    secret = `rk_test_mock_${randomBytes(12).toString("hex")}`;
  }

  const work = realpathSync(mkdtempSync("/tmp/auths-refunds-"));
  const journey = new Journey(values.gateway, values.python!, work);
  try {
    // README step 3: principals, trust, and the agent's bounded grant.
    const facts = await journey.step("setup: root, three managers, agent, trust, bounded grant", () =>
      JSON.parse(journey.run(process.execPath, [
        REFUNDS, "setup", "--state", journey.state, "--gateway", journey.gateway,
        "--connect-account", connectAccount,
      ]).stdout) as SetupFacts);
    await journey.step(`second agent '${CHECKS_AGENT}' with its own grant (4 per window)`, () =>
      journey.run(process.execPath, [
        REFUNDS, "grant", "--state", journey.state, "--gateway", journey.gateway,
        "--agent", CHECKS_AGENT, "--max-count", "4",
      ]));
    // The double checks the bearer token by digest; the key itself stays
    // only in the gateway's credential store.
    const mockTokenSha256 = createHash("sha256").update(secret).digest("hex");
    const loopback: string[] = [];

    // README step 4: Stripe, here its local double.
    if (!live) {
      await journey.step("start the counting Stripe double", async () => {
        const mock = journey.background(journey.python, [
          "mock_stripe.py", "--ledger", journey.ledger, "--token-sha256", mockTokenSha256,
          "--control", journey.control, "--payment-intent", paymentIntent,
        ], "pipe");
        const port = await Promise.race([
          new Promise<string>((done) => createInterface({ input: mock.stdout! }).once("line", done)),
          sleep(10_000, "", { ref: false }),
        ]);
        expect(/^\d+$/.test(port.trim()), "mock Stripe did not start");
        loopback.push("--loopback-provider", port.trim());
      });
    }

    const install = (stateDir: string, key: string): SpawnSyncReturns<string> => {
      mkdirSync(stateDir, { mode: 0o700 });
      return journey.run(journey.gateway, [
        "install", "--state-dir", stateDir, "--recipe", "recipe.json",
        "--profile-lock", "profile.lock.json",
        "--trusted-context", join(journey.state, "trust", "gateway.context.cbor"),
        "--approve-digest", facts.recipe_digest, "--provider", "stripe", "--alias", "refunds",
        "--account-label", platformAccount, "--credential-stdin", ...loopback,
      ], `${key}\n`, false);
    };

    // Hostile: the credential guard refuses a key without the declared test
    // prefix before any provider read, and stores nothing.
    const guard = await journey.step("hostile: the guard refuses a key without rk_test_", () => {
      const before = journey.providerEntries().length;
      const refused = install(join(journey.work, "gateway-non-test-key"), NON_TEST_KEY);
      const words = refused.stderr.trim().split(/\s+/);
      return {
        exit: refused.status,
        code: words.length > 0 && words[0] !== "" ? words[words.length - 1]! : null,
        provider_requests: journey.providerEntries().length - before,
      };
    });
    expect(guard.exit !== 0 && guard.code === "gateway.install.credential-guard" && guard.provider_requests === 0,
      `non-test key: ${JSON.stringify(guard)}`);

    // README step 5: the gateway takes the key on stdin, checks it with the
    // provider, and starts.
    const onboardingFrom = journey.providerEntries().length;
    await journey.step("gateway install with the key on stdin", () => {
      const installed = install(journey.gatewayState, secret);
      expect(installed.status === 0, `install failed: ${installed.stderr.trim()}`);
    });
    const onboarding = journey.providerEntries().slice(onboardingFrom);
    const observer = await journey.step("gateway observer key", () =>
      ((JSON.parse(journey.run(journey.gateway, ["observer-init", "--state-dir", journey.gatewayState]).stdout) as
        { observer_anchor: { principal: string } }).observer_anchor.principal));
    await journey.step(`gateway serve${live ? "" : " (to the counting Stripe double)"}`, async () => {
      journey.background(journey.gateway, [
        "serve", "--state-dir", journey.gatewayState, "--app-socket", journey.socket, ...loopback,
      ], "ignore");
      const deadline = performance.now() + 10_000;
      while (!existsSync(journey.socket)) {
        expect(performance.now() < deadline, "gateway did not open its app socket");
        await sleep(50);
      }
    });

    const results: Record<string, Json> = {};
    const submit = (
      operation: string, amount: number, approvers: string, declines: readonly string[] = [],
      intent: string = paymentIntent, extra: Readonly<Record<string, string>> = {},
    ): void => {
      const before = journey.providerEntries().length;
      results[operation] = journey.refund(operation, amount, approvers, intent, declines, extra);
      const made = journey.providerEntries().slice(before);
      results[operation]!.provider_requests = made.length;
      results[operation]!.provider_writes = made.filter((entry) => entry.kind === "write").length;
    };

    // README steps 6 and 7: the agent writes a request per manager, each
    // manager answers with `auths approve`, the gateway submits; then a
    // decline, a tampered request, and the refusals before any lease.
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
    await journey.step("hostile: a connected account the grant does not list",
      () => submit("refund-other-account", 1_000, "manager-a,manager-c", [], paymentIntent,
        { "connect-account": OTHER_ACCOUNT }));
    await journey.step("hostile: 50.00 with 45.00 left of the day's 60.00 USD",
      () => submit("refund-over-sum", 5_000, "manager-a,manager-b"));
    await journey.step("refund 4: 40.00 of a PaymentIntent already refunded (rejected)",
      () => submit("refund-4", 4_000, "manager-b,manager-c", [], rejectedPaymentIntent));
    await journey.step("hostile: third refund in the window",
      () => submit("refund-5-window", 1_000, "manager-a,manager-c"));

    // The recipe's checks after the credential lease, each refusing one
    // refund of the second agent before any write.
    const checked = (operation: string, amount: number, control: Json,
      extra: Readonly<Record<string, string>> = {}): void => {
      writeFileSync(journey.control, JSON.stringify(control));
      try {
        submit(operation, amount, "manager-b,manager-c", [], paymentIntent, { agent: CHECKS_AGENT, ...extra });
      } finally {
        rmSync(journey.control, { force: true });
      }
    };
    await journey.step("hostile: 30.01, above half of the payment's 60.00",
      () => checked("refund-above-ratio", 3_001, {}));
    await journey.step("hostile: EUR against a USD PaymentIntent",
      () => checked("refund-currency-mismatch", 1_000, {}, { currency: "eur" }));
    if (!live) {
      await journey.step("hostile: the provider reports another account at the lease",
        () => checked("refund-account-substituted", 1_000, { account: OTHER_ACCOUNT }));
      await journey.step("hostile: the provider answers a denied read with 200",
        () => checked("refund-denied-read-answered", 1_000, { denied_status: 200 }));
    }

    const observed = results["refund-1"]! as Json & { evidence?: { channel: string; echo: string } };
    expect(observed.outcome === "observed-by-provider" && observed.status === 200 &&
      observed.evidence?.channel === "read-back", `refund-1: ${JSON.stringify(observed)}`);
    const rejected = results["refund-4"]!;
    expect(rejected.outcome === "response-recorded" && rejected.status === 400,
      `refund-4: ${JSON.stringify(rejected)}`);
    const declined = results["refund-declined"]!;
    expect(declined.outcome === "declined" && JSON.stringify(declined.declined) === JSON.stringify(["manager-b"]) &&
      declined.provider_requests === 0, `refund-declined: ${JSON.stringify(declined)}`);
    expect(JSON.stringify(tamperedRun) === JSON.stringify({ exit: 1, refused: true, signed: false }),
      `tampered request: ${JSON.stringify(tamperedRun)}`);
    // Refused before any credential lease: no provider request at all.
    const beforeLease: Record<string, readonly [string, string]> = {
      "refund-2-one-approval": ["denied", "composition-requirement-not-met"],
      "refund-3-over-ceiling": ["not-entered", "gateway.policy.above-ceiling"],
      "refund-other-account": ["not-entered", "gateway.policy.scope-denied"],
      "refund-over-sum": ["not-entered", "gateway.policy.sum-exhausted"],
      "refund-5-window": ["not-entered", "gateway.policy.window-exhausted"],
    };
    // Refused after the lease by a provider check: reads, never a write.
    const afterLease: Record<string, readonly [string, string]> = {
      "refund-above-ratio": ["not-entered", "gateway.relative-ceiling.above"],
      "refund-currency-mismatch": ["not-entered", "gateway.relative-ceiling.binding-mismatch"],
      ...(live ? {} : {
        "refund-account-substituted": ["not-entered", "gateway.credential.account-mismatch"],
        "refund-denied-read-answered": ["not-entered", "gateway.credential.capability-excess"],
      }),
    };
    const expectedRefusals = { ...beforeLease, ...afterLease };
    for (const [operation, [outcome, code]] of Object.entries(expectedRefusals)) {
      const got = results[operation]!;
      expect(got.outcome === outcome && got.code === code, `${operation}: ${JSON.stringify(got)}`);
    }
    if (!live) {
      for (const operation of Object.keys(beforeLease)) {
        expect(results[operation]!.provider_requests === 0, `${operation} reached the provider`);
      }
      for (const operation of Object.keys(afterLease)) {
        const got = results[operation]!;
        expect(got.provider_writes === 0 && (got.provider_requests as number) > 0,
          `${operation}: ${JSON.stringify(got)}`);
      }
      const entries = journey.providerEntries();
      expect(entries.every((entry) => entry.authorized === true && entry.stripe_version === STRIPE_VERSION),
        "provider saw an unauthenticated or unversioned request");
      const credentialReads = new Set(["/v1/balance", "/v1/account", "/v1/customers", "/v1/payouts"]);
      expect(entries.every((entry) => credentialReads.has(entry.path as string)
        ? entry.stripe_account === null
        : entry.stripe_account === connectAccount),
      "Stripe-Account went on a credential read or missed an action request");
      expect(JSON.stringify(onboarding.map((entry) => [entry.method, entry.path, entry.status])) === JSON.stringify([
        ["GET", "/v1/balance", 200], ["GET", "/v1/account", 200],
        ["GET", "/v1/customers", 403], ["GET", "/v1/payouts", 403],
      ]), `install onboarding reads ${JSON.stringify(onboarding)}`);
      const writes = entries.filter((entry) => entry.kind === "write");
      expect(writes.length === 2, `expected exactly 2 provider writes, saw ${writes.length}`);
      expect(writes.every((entry) => entry.well_formed === true), "provider saw a malformed refund");
      expect(JSON.stringify(writes.map((entry) => entry.amount)) === JSON.stringify([1_500, 4_000]),
        `provider writes ${JSON.stringify(writes)}`);
      expect(writes[0]!.echo === observed.evidence?.echo,
        `refund-1 echo ${String(writes[0]!.echo)} != ${String(observed.evidence?.echo)}`);
      const readBack = `/v1/refunds/${String(writes[0]!.refund)}`;
      expect(entries.some((entry) => entry.path === readBack && entry.status === 200),
        `refund-1 was not read back at ${readBack}`);
    }

    // README step 8: the audit bundle.
    const bundlePath = join(journey.work, "audit-bundle.json");
    await journey.step("export audit bundle", () => journey.run(process.execPath, [
      REFUNDS, "export", "--state", journey.state, "--out", bundlePath,
    ]));
    const providerRequests = journey.providerEntries();
    await journey.stop();

    // README step 9: the offline audit, with the gateway stopped.
    const audited = await journey.step("offline audit (gateway stopped)",
      () => journey.audit(bundlePath, facts.trusted_context_sha256, observer));
    expect(audited.status === 0, `audit failed: ${audited.stderr}`);
    const report = JSON.parse(audited.stdout) as {
      verified: number; refused: number; inconsistent: number;
      recovery: { class: string };
      entries: {
        operation_id: string; status: string; code: string; approvals: string[];
        provider_result: {
          stage: string; http_status: number | null; response_digest: string | null;
          refusal: string | null; recount: string | null;
        } | null;
      }[];
      approval_responses: { operation_id: string; approver: string; decision: string }[];
    };
    const verdicts = Object.fromEntries(report.entries.map((entry) =>
      [entry.operation_id, `${entry.status} ${entry.code}`]));
    expect(verdicts["refund-1"] === "verified audit.verified", `audit refund-1 ${JSON.stringify(verdicts)}`);
    expect(verdicts["refund-4"] === "verified audit.verified", `audit refund-4 ${JSON.stringify(verdicts)}`);
    for (const [operation, [, code]] of Object.entries(expectedRefusals)) {
      expect(verdicts[operation] === `refused ${code}`, `audit ${operation}: ${verdicts[operation]}`);
    }
    // Every entered refund shows the provider's result beside its verdict, the
    // one the provider rejected included.
    const providerResults = Object.fromEntries(report.entries.map((entry) =>
      [entry.operation_id, entry.provider_result]));
    const entered = report.entries.filter((entry) => entry.status === "verified").map((entry) => entry.operation_id);
    expect(JSON.stringify(entered) === JSON.stringify(["refund-1", "refund-4"]), `audit entered ${JSON.stringify(entered)}`);
    for (const [operation, stage, status] of [
      ["refund-1", "observed-by-provider", 200], ["refund-4", "response-recorded", 400],
    ] as const) {
      const result = providerResults[operation];
      expect(result !== null && result !== undefined && result.stage === stage &&
        result.http_status === status && result.response_digest !== null,
      `audit provider result ${operation}: ${JSON.stringify(result)}`);
    }
    const exhausted = providerResults["refund-5-window"];
    expect(exhausted !== null && exhausted !== undefined &&
      exhausted.refusal === "gateway.policy.window-exhausted" && exhausted.recount === null,
    `audit provider result refund-5-window: ${JSON.stringify(exhausted)}`);
    for (const [operation, [, code]] of Object.entries(afterLease)) {
      const result = providerResults[operation];
      expect(result !== null && result !== undefined && result.stage === "not-entered" &&
        result.refusal === code && result.http_status === null,
      `audit provider result ${operation}: ${JSON.stringify(result)}`);
    }
    expect(report.recovery.class === "linked-after-response", `audit recovery ${JSON.stringify(report.recovery)}`);
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

    const writes = providerRequests.filter((entry) => entry.kind === "write");
    const summary = {
      journey: "stripe-refund-approval",
      sdk: "@auths-dev/sdk (packed npm)",
      provider: live ? "stripe-test-mode" : "counting-mock",
      wall_seconds: Math.round(performance.now() - journey.started) / 1000,
      steps: journey.steps,
      refunds: results,
      tampered_request: tamperedRun,
      non_test_key: guard,
      provider_checks: Object.fromEntries(Object.keys(expectedRefusals).map((operation) => [operation, {
        code: results[operation]!.code,
        provider_writes: live ? null : results[operation]!.provider_writes,
      }])),
      provider_requests: live ? null : providerRequests.length,
      provider_writes: live ? null : writes.length,
      audit: {
        verified: report.verified, refused: report.refused, inconsistent: report.inconsistent,
        http_status: Object.fromEntries(entered.map((operation) => [operation, providerResults[operation]!.http_status])),
      },
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
