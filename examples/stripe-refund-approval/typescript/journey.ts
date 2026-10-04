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
 *
 * The trust installs any two of the three managers as the approval
 * requirement. The agent writes a request to every manager, whoever answers
 * first counts, and the agent signs its refund only once enough approved.
 *
 * Every refund is submitted through ../gateway_witness.py, a relay on the
 * application socket that runs as its own process (started with the same
 * Python as the double) and records each exchange; this journey's blocking
 * child processes cannot stall it. A hostile case passes only if it was
 * decided by the gateway: the command's record says `decided_by: "gateway"`
 * with the expected outcome and code, and the witness saw exactly one submit
 * frame during the case, whose response carries the same. A negative control
 * refused by `request --precheck` must fail that guard.
 *
 * Against the double it also checks the `Idempotency-Key` the gateway derives
 * for each refund, then restores the gateway's store from a backup taken
 * before the first refund, which forgets every claim but keeps the shared
 * connection record, and resubmits an approved refund: the double, like
 * Stripe, must return the first refund rather than create a second.
 */

import { type ChildProcess, spawn, spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync,
  writeFileSync,
} from "node:fs";
import { platform } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";

import { authorMcpProof, compileTrustedContext, proposeMcpApproval } from "@auths-dev/sdk/self-hosted";

import { CONTRACT, type CreateRefund } from "./generated.js";
import { ASSURANCE, EXAMPLE, anchor, developmentSigner, roleKey, type SetupFacts } from "./refunds.js";

const REFUNDS = fileURLToPath(new URL("./refunds.js", import.meta.url));
// The double's accounts and its already-refunded PaymentIntent.
const PLATFORM_ACCOUNT = "acct_1AuthsPlatform0";
const CONNECTED_ACCOUNT = "acct_1AuthsConnected";
const OTHER_ACCOUNT = "acct_1AuthsOtherAcct";
const REFUNDED_PAYMENT_INTENT = "pi_mock_refunded";
const STRIPE_VERSION = "2025-03-31.basil";
const MANAGERS = ["manager-a", "manager-b", "manager-c"] as const;
// The second agent, whose refunds the checks after the credential lease refuse.
const CHECKS_AGENT = "agent-checks";
// A clearly fake key without the recipe's `rk_test_` prefix.
const NON_TEST_KEY = "rk_live_not-a-real-key";
const KEY_VARIABLES = ["STRIPE_TEST_RESTRICTED_KEY", "STRIPE_TEST_SECRET_KEY"];
// The packaged approval CLI installed with @auths-dev/sdk.
const APPROVE_CLI = fileURLToPath(new URL("../node_modules/@auths-dev/sdk/tools/profile-cli.mjs", import.meta.url));
const IDEMPOTENCY_DOMAIN = "auths.gateway-idempotency-key/1\0";

/** The `Idempotency-Key` the gateway derives for one logical operation. */
function idempotencyKey(namespace: string, operation: string): string {
  return `auths-i1-${createHash("sha256").update(`${IDEMPOTENCY_DOMAIN}${namespace}\0${operation}`).digest("hex")}`;
}

type Json = Record<string, unknown>;
type Step = { step: string; seconds: number };

class Journey {
  readonly state: string;
  readonly gatewayState: string;
  readonly socket: string;
  readonly witnessSocket: string;
  readonly witnessLog: string;
  readonly ledger: string;
  readonly control: string;
  readonly env: NodeJS.ProcessEnv;
  readonly steps: Step[] = [];
  readonly started = performance.now();
  lastWarnings = "";
  #processes: ChildProcess[] = [];

  constructor(readonly gateway: string, readonly python: string, readonly work: string) {
    this.state = join(work, "state");
    this.gatewayState = join(work, "gateway");
    this.socket = join(work, "app.sock");
    // Every submission goes through the witness, which relays it to the
    // gateway and records the exchange from its own process.
    this.witnessSocket = join(work, "witness.sock");
    this.witnessLog = join(work, "witness.jsonl");
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

  async terminate(child: ChildProcess): Promise<void> {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise((done) => child.once("exit", done));
      child.kill("SIGTERM");
      if (await Promise.race([exited.then(() => true), sleep(5_000, false, { ref: false })]) === false) {
        child.kill("SIGKILL");
        await exited;
      }
    }
    this.#processes = this.#processes.filter((item) => item !== child);
  }

  async stop(): Promise<void> {
    for (const child of [...this.#processes]) await this.terminate(child);
  }

  providerEntries(): Json[] {
    if (!existsSync(this.ledger)) return [];
    return readFileSync(this.ledger, "utf8").split("\n").filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Json);
  }

  witnessLines(): Json[] {
    if (!existsSync(this.witnessLog)) return [];
    return readFileSync(this.witnessLog, "utf8").split("\n").filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as Json);
  }

  /**
   * The agent writes one request per manager into
   * `approvals/<out or operation>` and prints its record; its warnings are
   * kept in `lastWarnings`. `extra` passes `currency`, `connect-account`,
   * `agent`, or `required`.
   */
  request(operation: string, amount: number, paymentIntent: string,
    extra: Readonly<Record<string, string>> = {}, options: Readonly<{ out?: string; precheck?: boolean }> = {}):
    [string, Json] {
    const folder = join(this.work, "approvals", options.out ?? operation);
    const requested = this.run(process.execPath, [
      REFUNDS, "request", "--state", this.state, "--operation-id", operation,
      "--payment-intent", paymentIntent, "--amount", String(amount),
      "--out", folder, ...Object.entries(extra).flatMap(([name, value]) => [`--${name}`, value]),
      ...(options.precheck === true ? ["--precheck"] : []),
    ]);
    this.lastWarnings = requested.stderr;
    return [folder, JSON.parse(requested.stdout) as Json];
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

  submit(operation: string, folder: string): Json {
    return JSON.parse(this.run(process.execPath, [
      REFUNDS, "submit", "--state", this.state, "--socket", this.witnessSocket, "--operation-id", operation,
      "--responses", folder,
    ]).stdout) as Json;
  }

  /**
   * Requests, has each manager named in `answering` answer once (the others
   * never answer), and submits. Returns the request's record and the outcome
   * record; a pre-check refusal is the outcome, and nothing is asked or sent.
   */
  refund(operation: string, amount: number, answering: string, paymentIntent: string,
    declines: readonly string[] = [], extra: Readonly<Record<string, string>> = {},
    options: Readonly<{ out?: string; precheck?: boolean }> = {}): [Json, Json] {
    const [folder, requested] = this.request(operation, amount, paymentIntent, extra, options);
    if (requested.outcome === "not-submitted") return [requested, requested];
    for (const manager of new Set(answering.split(",").filter((name) => name.length > 0))) {
      const answered = this.answer(folder, manager, { decline: declines.includes(manager) });
      if (answered.status !== 0) throw new Error(`${manager} could not answer: ${answered.stderr.trim()}`);
    }
    return [requested, this.submit(operation, folder)];
  }

  audit(bundle: string, trust: string, observer: string, ...options: string[]): SpawnSyncReturns<string> {
    let command = this.gateway;
    let args = ["audit", "--bundle", bundle, "--trusted-context-sha256", trust, "--observer", observer, ...options];
    // Prove the audit needs no network where the platform allows it.
    if (platform() === "linux" && spawnSync("unshare", ["-rn", "true"]).status === 0) {
      args = ["-rn", command, ...args];
      command = "unshare";
    }
    return this.run(command, args, undefined, false);
  }
}

/**
 * Copies a directory tree keeping every entry's permission bits, as the
 * gateway's private store requires.
 */
function copyTree(source: string, target: string): void {
  cpSync(source, target, { recursive: true });
  const restore = (from: string, to: string): void => {
    chmodSync(to, statSync(from).mode & 0o7777);
    if (statSync(from).isDirectory()) {
      for (const name of readdirSync(from)) restore(join(from, name), join(to, name));
    }
  };
  restore(source, target);
}

function expect(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`journey check failed: ${message}`);
}

const SUBMIT_SCHEMA = "auths.gateway-submit/1";
// Words only the gateway's submit result may carry.
const GATEWAY_OUTCOMES = new Set([
  "denied", "not-entered", "indeterminate", "unknown", "response-recorded", "observed", "observed-by-provider",
]);

/** The witness's submit exchanges; observe frames are recorded but not counted. */
function submitFrames(frames: readonly Json[]): Json[] {
  return frames.filter((frame) => frame.schema === SUBMIT_SCHEMA);
}

/**
 * The case was decided by the gateway: the command's record says so, with the
 * expected result, and the witness process saw exactly one submit frame during
 * the case, whose response from the gateway is that result.
 */
function expectGatewayDecided(case_: string, record: Json, frames: readonly Json[], expected: Readonly<{
  outcome: string; code?: string; status?: number; actionB64?: string;
}>): void {
  const seen = submitFrames(frames);
  expect(record.decided_by === "gateway",
    `${case_}: the record says decided_by=${JSON.stringify(record.decided_by)}, not the gateway: ${JSON.stringify(record)}`);
  expect(seen.length > 0, `${case_}: the record says the gateway decided, but the witness saw no submit frame`);
  expect(seen.length === 1, `${case_}: the witness saw ${seen.length} submit frames, not one`);
  const response = (seen[0]!.response ?? {}) as Json;
  for (const key of ["outcome", "code", "status"]) {
    expect(response[key] === record[key],
      `${case_}: the gateway answered ${key}=${JSON.stringify(response[key])} on the socket, ` +
      `the record says ${JSON.stringify(record[key])}`);
  }
  expect(record.outcome === expected.outcome,
    `${case_}: outcome ${JSON.stringify(record.outcome)}, expected ${expected.outcome}`);
  if (expected.code !== undefined) {
    expect(record.code === expected.code, `${case_}: code ${JSON.stringify(record.code)}, expected ${expected.code}`);
  }
  if (expected.status !== undefined) {
    expect(record.status === expected.status,
      `${case_}: status ${JSON.stringify(record.status)}, expected ${expected.status}`);
  }
  if (expected.actionB64 !== undefined) {
    expect(seen[0]!.action_sha256 ===
      createHash("sha256").update(new Uint8Array(Buffer.from(expected.actionB64, "base64url"))).digest("hex"),
    `${case_}: the submit frame the witness saw carried another action`);
  }
}

/**
 * Nothing reached the gateway, and the record says who stopped it without
 * presenting the stop as a gateway refusal.
 */
function expectNotSubmitted(case_: string, record: Json, frames: readonly Json[], decidedBy: string,
  reason: string): void {
  expect(record.decided_by === decidedBy && record.outcome === "not-submitted" && record.reason === reason,
    `${case_}: ${JSON.stringify(record)}`);
  expect(!("code" in record), `${case_}: a record not decided by the gateway carries a code: ${JSON.stringify(record)}`);
  expect(!GATEWAY_OUTCOMES.has(record.outcome as string), `${case_}: ${JSON.stringify(record)}`);
  expect(submitFrames(frames).length === 0, `${case_}: the witness saw a submit frame: ${JSON.stringify(frames)}`);
}

/**
 * (major type, argument, offset after the head) of the definite-length CBOR
 * item at `at`; enough to read an approval response.
 */
function cborHead(data: Uint8Array, at: number): [number, number, number] {
  const initial = data[at]!;
  const major = initial >> 5;
  const info = initial & 0x1f;
  if (info < 24) return [major, info, at + 1];
  const width = ({ 24: 1, 25: 2, 26: 4, 27: 8 } as Record<number, number>)[info];
  expect(width !== undefined && width <= 4, "an approval response uses only short CBOR heads");
  let value = 0;
  for (let index = 1; index <= width; index += 1) value = value * 256 + data[at + index]!;
  return [major, value, at + 1 + width];
}

/**
 * The signed approval an `auths-as2-` approve response carries: the byte
 * string under key 4 of its five-key map.
 */
function signedApproval(responseText: string): Uint8Array {
  const data = new Uint8Array(Buffer.from(responseText.trim().slice("auths-as2-".length), "base64url"));
  let [major, count, at] = cborHead(data, 0);
  expect(major === 5 && count === 5, "an approval response is a five-key map");
  for (let entry = 0; entry < count; entry += 1) {
    let key: number;
    let length: number;
    [, key, at] = cborHead(data, at);
    [major, length, at] = cborHead(data, at);
    const value = data.slice(at, at + length);
    at += length;
    if (key === 4) {
      expect(major === 2, "an approval response's body is a byte string");
      return value;
    }
  }
  throw new Error("journey check failed: an approval response carries no body");
}

/**
 * `proof` with its empty approval list (bundle key 10, always last) replaced
 * by `approvals` in ascending digest order, as a hostile client that bypasses
 * the SDK would write it.
 */
function withApprovals(proof: Uint8Array, approvals: readonly Uint8Array[]): Uint8Array {
  expect(proof.length >= 2 && proof[proof.length - 2] === 0x0a && proof[proof.length - 1] === 0x80 &&
    approvals.length < 24, "a single-proof bundle ends with no approvals");
  const digest = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");
  const ordered = [...approvals].sort((left, right) => (digest(left) < digest(right) ? -1 : 1));
  return new Uint8Array(Buffer.concat([
    proof.slice(0, -1), Uint8Array.of(0x80 | ordered.length), ...ordered,
  ]));
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
    const facts = await journey.step("setup: root, three approving managers, agent, trust, bounded grant", () =>
      JSON.parse(journey.run(process.execPath, [
        REFUNDS, "setup", "--state", journey.state, "--gateway", journey.gateway,
        "--connect-account", connectAccount,
      ]).stdout) as SetupFacts);
    await journey.step("manager-a's own key given an agent grant (1 per window), for the self-approval case", () =>
      journey.run(process.execPath, [
        REFUNDS, "grant", "--state", journey.state, "--gateway", journey.gateway,
        "--agent", "manager-a", "--max-count", "1",
      ]));
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
    // The store as a backup taken now would hold it: the shared connection
    // record and no claim. The state-loss check restores it.
    const attemptsBackup = join(journey.work, "attempts-backup");
    copyTree(join(journey.gatewayState, "attempts"), attemptsBackup);
    const observer = await journey.step("gateway observer key", () =>
      ((JSON.parse(journey.run(journey.gateway, ["observer-init", "--state-dir", journey.gatewayState]).stdout) as
        { observer_anchor: { principal: string } }).observer_anchor.principal));
    let running: ChildProcess | undefined;
    const startGateway = async (): Promise<void> => {
      // A stopped gateway leaves its socket file behind; wait for a new one.
      rmSync(journey.socket, { force: true });
      running = journey.background(journey.gateway, [
        "serve", "--state-dir", journey.gatewayState, "--app-socket", journey.socket, ...loopback,
      ], "ignore");
      const deadline = performance.now() + 10_000;
      while (!existsSync(journey.socket)) {
        expect(performance.now() < deadline, "gateway did not open its app socket");
        await sleep(50);
      }
    };
    await journey.step(`gateway serve${live ? "" : " (to the counting Stripe double)"}`, startGateway);

    // The witness relays the application socket from its own process and
    // records every exchange; every `submit` below goes through it.
    await journey.step("gateway witness on the application socket", async () => {
      const witness = journey.background(journey.python, [
        "gateway_witness.py", "--listen", journey.witnessSocket, "--upstream", journey.socket,
        "--log", journey.witnessLog,
      ], "pipe");
      const ready = await Promise.race([
        new Promise<string>((done) => createInterface({ input: witness.stdout! }).once("line", done)),
        sleep(10_000, "", { ref: false }),
      ]);
      expect(ready.trim() === "ready", "the gateway witness did not start");
    });

    const results: Record<string, Json> = {};
    const requests: Record<string, Json> = {};
    const frames: Record<string, Json[]> = {};
    const warnings: Record<string, string> = {};
    /** Runs one case and keeps its record, its provider requests, and the witness's frames during it. */
    const watched = (case_: string, action: () => Json): void => {
      const before = journey.providerEntries().length;
      const seen = journey.witnessLines().length;
      results[case_] = action();
      const made = journey.providerEntries().slice(before);
      frames[case_] = journey.witnessLines().slice(seen);
      results[case_]!.provider_requests = made.length;
      results[case_]!.provider_writes = made.filter((entry) => entry.kind === "write").length;
    };
    const submit = (
      case_: string, amount: number, answering: string, declines: readonly string[] = [],
      intent: string = paymentIntent, extra: Readonly<Record<string, string>> = {},
      options: Readonly<{ operation?: string; out?: string; precheck?: boolean }> = {},
    ): void => watched(case_, () => {
      const [requested, record] = journey.refund(options.operation ?? case_, amount, answering, intent, declines,
        extra, options);
      requests[case_] = requested;
      warnings[case_] = journey.lastWarnings;
      return record;
    });
    const entriesLog = (): Json[] => readFileSync(join(journey.state, "audit", "entries.jsonl"), "utf8")
      .split("\n").filter((line) => line.length > 0).map((line) => JSON.parse(line) as Json);

    /** refund-1's approved proof, sent with another refund's action. */
    const reusedApprovals = (): Json => {
      const [, requested] = journey.request("refund-8-reuse", 1_000, paymentIntent);
      requests["refund-8-reuse"] = requested;
      const first = entriesLog().find((entry) => entry.operation_id === "refund-1")!;
      const proof = join(journey.work, "reuse.proof");
      const action = join(journey.work, "reuse.action");
      writeFileSync(proof, new Uint8Array(Buffer.from(first.proof_b64 as string, "base64url")));
      writeFileSync(action, new Uint8Array(Buffer.from(requested.action_b64 as string, "base64url")));
      // The witness is its own process, so this blocking call cannot stall it.
      const sent = journey.run(journey.gateway, [
        "submit", "--app-socket", journey.witnessSocket, "--proof", proof, "--action", action,
      ]);
      // The CLI prints the gateway's submit result unchanged.
      return { decided_by: "gateway", ...(JSON.parse(sent.stdout) as Json) };
    };

    /**
     * Manager A, given an agent grant, submits a refund as the actor, and
     * managers A and B approve it. The SDK refuses to author a proposal whose
     * actor is a listed approver, so this builds the proof as a hostile client
     * would: A signs its own action under its own grant, and the two
     * approvals, collected through `auths approve`, are added to the bundle by
     * hand. A is in the proof's authority chain, so only B's approval counts.
     */
    const selfApproval = async (): Promise<Json> => {
      const operation = "refund-self-approval";
      const [folder, requested] = journey.request(operation, 1_400, paymentIntent);
      requests[operation] = requested;
      for (const manager of ["manager-a", "manager-b"]) {
        const answered = journey.answer(folder, manager);
        expect(answered.status === 0, `${manager}: ${answered.stderr.trim()}`);
      }
      const state = journey.state;
      const principals = facts.principals;
      const pending = JSON.parse(readFileSync(join(state, "pending", `${operation}.json`), "utf8")) as {
        payment_intent: string; amount: number; currency: string; connect_account: string;
      };
      const command: CreateRefund = {
        operator_namespace: "stripe-refunds", operation_id: operation, recipe_digest: facts.recipe_digest,
        payment_intent: pending.payment_intent, amount: pending.amount,
        connect_account: pending.connect_account, currency: pending.currency,
      };
      const grantBytes = new Uint8Array(readFileSync(join(state, "manager-a.grant.cbor")));
      const challenge = new Uint8Array(Buffer.from(facts.challenge_hex, "hex"));
      const now = BigInt(Math.floor(Date.now() / 1000));
      let sdk: string;
      try {
        await proposeMcpApproval({
          contract: CONTRACT, command, required: facts.approvals_required,
          approvers: MANAGERS.map((name) => principals[name]!), actor: principals["manager-a"]!,
          actorGrant: grantBytes, challenge, evaluationTime: now,
        });
        sdk = "authored";
      } catch {
        sdk = "refused";
      }
      // A's own single-proof action, checked locally against a template of the
      // root anchor alone: the hostile client's view, with no approvals required.
      const extension = (JSON.parse(journey.run(journey.gateway, [
        "bound-extension", "--argument", "amount", "--ceiling", String(facts.limits.ceiling),
        "--window-seconds", String(facts.limits.window_seconds), "--max-count", "1",
        "--sum-limit", String(facts.limits.sum_limit),
        "--partition", `currency=${facts.limits.currencies.join(",")}`,
        "--scope", `connect_account=${facts.limits.connect_account}`,
      ]).stdout) as { extension_id: string }).extension_id;
      const template = await compileTrustedContext({
        anchors: [anchor("root", principals.root!, facts.audience, facts.tool, 1,
          BigInt(facts.not_before), BigInt(facts.expires_at))],
        assurance: ASSURANCE, channelPolicy: "none-v1", evidenceTypes: ["raw-key-v1"],
        criticalExtensions: [extension],
      });
      const root = await roleKey(state, "root");
      const authored = await authorMcpProof({
        contract: CONTRACT, command,
        grants: [{ signedGrant: grantBytes, evidence: [root.evidence] }],
        trustedContextTemplate: template,
        signer: developmentSigner("manager-a", await roleKey(state, "manager-a")),
        challenge, evaluationTime: now, validitySeconds: 300,
      });
      expect(Buffer.from(authored.action).toString("base64url") === requested.action_b64,
        "manager A signed another refund");
      const approvals = ["manager-a", "manager-b"].map((manager) =>
        signedApproval(readFileSync(join(folder, `${manager}.response`), "utf8")));
      const proofPath = join(journey.work, "self.proof");
      const actionPath = join(journey.work, "self.action");
      writeFileSync(proofPath, withApprovals(authored.proof, approvals));
      writeFileSync(actionPath, authored.action);
      const sent = journey.run(journey.gateway, [
        "submit", "--app-socket", journey.witnessSocket, "--proof", proofPath, "--action", actionPath,
      ]);
      return { decided_by: "gateway", sdk, ...(JSON.parse(sent.stdout) as Json) };
    };
    const watchedAsync = async (case_: string, action: () => Promise<Json>): Promise<void> => {
      const before = journey.providerEntries().length;
      const seen = journey.witnessLines().length;
      results[case_] = await action();
      const made = journey.providerEntries().slice(before);
      frames[case_] = journey.witnessLines().slice(seen);
      results[case_]!.provider_requests = made.length;
      results[case_]!.provider_writes = made.filter((entry) => entry.kind === "write").length;
    };

    // The hostile table: every case the gateway must decide, in order. Each is
    // checked by the guard: the record says the gateway decided, and the
    // witness saw exactly one submit frame with that answer.
    // Refused before any credential lease: no provider request at all.
    const beforeLease: Record<string, readonly [string, string]> = {
      "refund-2-lowered-threshold": ["denied", "approval-threshold-not-met"],
      "refund-6-lowered-two-approvals": ["denied", "approval-threshold-not-met"],
      "refund-self-approval": ["denied", "approval-threshold-not-met"],
      "refund-3-over-ceiling": ["not-entered", "gateway.policy.above-ceiling"],
      "refund-other-account": ["not-entered", "gateway.policy.scope-denied"],
      "refund-over-sum": ["not-entered", "gateway.policy.sum-exhausted"],
      "refund-5-window": ["not-entered", "gateway.policy.window-exhausted"],
      "refund-1-replay": ["not-entered", "gateway.attempt.replay"],
      "refund-8-reuse": ["denied", "action-body-mismatch"],
      "refund-2-retry": ["not-entered", "gateway.policy.window-exhausted"],
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

    // README step 6: the agent writes a request to every manager, any two
    // answer with `auths approve`, and the agent signs and submits.
    await journey.step("refund 1: 15.00, approved by manager-a and manager-b; manager-c never answers",
      () => submit("refund-1", 1_500, "manager-a,manager-b"));
    await journey.step("declined: manager-b and manager-c decline, nothing is submitted",
      () => submit("refund-two-declines", 2_000, "manager-a,manager-b,manager-c", ["manager-b", "manager-c"]));
    const tamperedRun: Json = {};
    await journey.step("tampered request: the manager's CLI refuses and signs nothing", () =>
      watched("refund-tampered", () => {
        const [folder] = journey.request("refund-tampered", 1_500, paymentIntent);
        const original = readFileSync(join(folder, "manager-a.request"), "utf8").trim();
        const raw = Buffer.from(original.slice("auths-ar2-".length), "base64url");
        const at = raw.indexOf('"amount":1500');
        expect(at >= 0, "the request does not carry the amount");
        raw.write('"amount":9500', at, "latin1");
        const edited = join(folder, "manager-a.edited");
        writeFileSync(edited, `auths-ar2-${raw.toString("base64url")}`);
        const answered = journey.answer(folder, "manager-a", { request: edited });
        Object.assign(tamperedRun, {
          exit: answered.status,
          refused: answered.stderr.includes("approval.action-mismatch"),
          signed: existsSync(join(folder, "manager-a.response")),
        });
        return { ...tamperedRun };
      }));
    await journey.step("hostile: the agent lowers the threshold to 1; only manager-a approves",
      () => submit("refund-2-lowered-threshold", 1_200, "manager-a", [], paymentIntent, { required: "1" }));
    await journey.step("hostile: the agent lowers the threshold to 1; manager-a and manager-b approve it",
      () => submit("refund-6-lowered-two-approvals", 1_100, "manager-a,manager-b", [], paymentIntent,
        { required: "1" }));
    await journey.step(
      "hostile: manager-a, given an agent grant, submits a refund it approves itself with manager-b",
      () => watchedAsync("refund-self-approval", selfApproval));
    await journey.step("repeated: manager-a's response twice counts for nobody, nothing is submitted", () =>
      watched("refund-7-repeated", () => {
        // manager-a's response arrives twice beside manager-b's.
        const [folder, requested] = journey.request("refund-7-repeated", 1_300, paymentIntent);
        requests["refund-7-repeated"] = requested;
        for (const manager of ["manager-a", "manager-b"]) {
          const answered = journey.answer(folder, manager);
          expect(answered.status === 0, `${manager}: ${answered.stderr.trim()}`);
        }
        copyFileSync(join(folder, "manager-a.response"), join(folder, "manager-a-again.response"));
        return journey.submit("refund-7-repeated", folder);
      }));
    await journey.step("hostile: over the 50.00 ceiling",
      () => submit("refund-3-over-ceiling", 9_000, "manager-a,manager-b"));
    await journey.step("hostile: a connected account the grant does not list",
      () => submit("refund-other-account", 1_000, "manager-a,manager-c", [], paymentIntent,
        { "connect-account": OTHER_ACCOUNT }));
    await journey.step("hostile: 50.00 with 45.00 left of the day's 60.00 USD",
      () => submit("refund-over-sum", 5_000, "manager-a,manager-b"));
    await journey.step("refund 4: 40.00 of a PaymentIntent already refunded; manager-a and manager-c " +
      "approve, manager-b declines (rejected by the provider)",
    () => submit("refund-4", 4_000, "manager-a,manager-b,manager-c", ["manager-b"], rejectedPaymentIntent));
    await journey.step("hostile: third refund in the window",
      () => submit("refund-5-window", 1_000, "manager-a,manager-c"));
    await journey.step("hostile: refund-1 requested again, with fresh approvals",
      () => submit("refund-1-replay", 1_500, "manager-b,manager-c", [], paymentIntent, {},
        { operation: "refund-1", out: "refund-1-replay" }));
    await journey.step("hostile: refund-1's proof sent for another refund",
      () => watched("refund-8-reuse", reusedApprovals));
    await journey.step("retry after denial: refund-2-lowered-threshold again, at the installed threshold",
      () => submit("refund-2-retry", 1_200, "manager-b,manager-c", [], paymentIntent, {},
        { operation: "refund-2-lowered-threshold", out: "refund-2-retry" }));
    // The negative control: a client-side pre-check refuses locally, and the
    // guard must reject it as not decided by the gateway.
    await journey.step("negative control: a lowered threshold refused by --precheck",
      () => submit("refund-9-precheck", 1_200, "manager-a", [], paymentIntent, { required: "1" },
        { precheck: true }));

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

    const same = (left: unknown, right: unknown): boolean => JSON.stringify(left) === JSON.stringify(right);
    const observed = results["refund-1"]! as Json & { evidence?: { channel: string; echo: string } };
    expectGatewayDecided("refund-1", observed, frames["refund-1"]!, {
      outcome: "observed-by-provider", status: 200, actionB64: requests["refund-1"]!.action_b64 as string,
    });
    expect(observed.evidence?.channel === "read-back" && observed.bundle === "appended",
      `refund-1: ${JSON.stringify(observed)}`);
    expect(same(observed.approved, ["manager-a", "manager-b"]) && same(observed.pending, ["manager-c"]) &&
      !("declined" in observed) &&
      same(Object.keys(requests["refund-1"]!.requests as Json).sort(), [...MANAGERS]),
    `refund-1: one request per manager, approved by two: ${JSON.stringify(observed)} ` +
      JSON.stringify(requests["refund-1"]));
    expectGatewayDecided("refund-4", results["refund-4"]!, frames["refund-4"]!, {
      outcome: "response-recorded", status: 400, actionB64: requests["refund-4"]!.action_b64 as string,
    });
    expect(same(results["refund-4"]!.approved, ["manager-a", "manager-c"]) &&
      same(results["refund-4"]!.declined, ["manager-b"]),
    `refund-4: one declined manager beside two approvals still submits: ${JSON.stringify(results["refund-4"])}`);
    const declined = results["refund-two-declines"]!;
    expectNotSubmitted("refund-two-declines", declined, frames["refund-two-declines"]!, "approver",
      "approvers-declined");
    expect(same(declined.declined, ["manager-b", "manager-c"]) && same(declined.approved, ["manager-a"]) &&
      declined.provider_requests === 0, `refund-two-declines: ${JSON.stringify(declined)}`);
    const repeated = results["refund-7-repeated"]!;
    expectNotSubmitted("refund-7-repeated", repeated, frames["refund-7-repeated"]!, "client",
      "approvals-incomplete");
    expect(same(repeated.approved, ["manager-b"]) &&
      same(Object.entries(repeated.waiting as Json).sort(),
        [["manager-a", "approval.duplicate-response"], ["manager-c", "pending"]]) &&
      repeated.provider_requests === 0, `refund-7-repeated: ${JSON.stringify(repeated)}`);
    expect(same(tamperedRun, { exit: 1, refused: true, signed: false }),
      `tampered request: ${JSON.stringify(tamperedRun)}`);
    expect(submitFrames(frames["refund-tampered"]!).length === 0 && results["refund-tampered"]!.provider_requests === 0,
      `tampered request reached the gateway: ${JSON.stringify(frames["refund-tampered"])}`);
    const hostile: Record<string, Json> = {};
    for (const [case_, [outcome, code]] of Object.entries(expectedRefusals)) {
      expectGatewayDecided(case_, results[case_]!, frames[case_]!, {
        outcome, code, actionB64: requests[case_]!.action_b64 as string,
      });
      hostile[case_] = {
        decided_by: results[case_]!.decided_by, outcome, code, submit_frames: submitFrames(frames[case_]!).length,
      };
    }
    // The reused-approvals and self-approval cases are sent by the journey
    // itself, which asks for no signed outcome.
    for (const case_ of ["refund-8-reuse", "refund-self-approval"]) {
      expect(frames[case_]!.length === 1, `${case_}: the witness saw ${JSON.stringify(frames[case_])}`);
    }
    expect(results["refund-self-approval"]!.sdk === "refused",
      `the SDK authored a proposal whose actor is a listed approver: ${JSON.stringify(results["refund-self-approval"])}`);
    for (const case_ of ["refund-2-lowered-threshold", "refund-6-lowered-two-approvals"]) {
      expect(requests[case_]!.required === 1 && warnings[case_]!.includes("not the 2 the trust installs"),
        `${case_}: request did not name the lowered threshold: ${warnings[case_]}`);
    }
    for (const case_ of ["refund-1-replay", "refund-2-retry"]) {
      expect(warnings[case_]!.includes("attempt store decides"),
        `${case_}: request did not warn that the operation ID was requested before`);
    }
    expect(results["refund-1-replay"]!.bundle === "unchanged", `replay: ${JSON.stringify(results["refund-1-replay"])}`);
    expect(results["refund-2-retry"]!.bundle === "replaced", `retry: ${JSON.stringify(results["refund-2-retry"])}`);

    const control = results["refund-9-precheck"]!;
    expectNotSubmitted("refund-9-precheck", control, frames["refund-9-precheck"]!, "client", "precheck");
    expect(control.precheck === "approvals-below-threshold", `negative control: ${JSON.stringify(control)}`);
    let negativeControl: Json;
    try {
      expectGatewayDecided("refund-9-precheck", control, frames["refund-9-precheck"]!, {
        outcome: "denied", code: "approval-threshold-not-met",
      });
      negativeControl = { guard_rejected: false };
    } catch (rejected) {
      negativeControl = { guard_rejected: true, reason: (rejected as Error).message };
    }
    expect(negativeControl.guard_rejected === true, "the guard accepted a request refused only locally");
    hostile["refund-9-precheck"] = {
      decided_by: control.decided_by, outcome: control.outcome, precheck: control.precheck,
      submit_frames: submitFrames(frames["refund-9-precheck"]!).length, guard_rejected: true,
    };
    for (const case_ of ["refund-1-replay", "refund-8-reuse", "refund-2-retry", "refund-9-precheck"]) {
      expect(results[case_]!.provider_requests === 0, `${case_} reached the provider`);
    }

    let stateLoss: Json | null = null;
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
      expect(same(onboarding.map((entry) => [entry.method, entry.path, entry.status]), [
        ["GET", "/v1/balance", 200], ["GET", "/v1/account", 200],
        ["GET", "/v1/customers", 403], ["GET", "/v1/payouts", 403],
      ]), `install onboarding reads ${JSON.stringify(onboarding)}`);
      let writes = entries.filter((entry) => entry.kind === "write");
      expect(writes.length === 2, `expected exactly 2 provider writes, saw ${writes.length}`);
      expect(writes.every((entry) => entry.well_formed === true), "provider saw a malformed refund");
      expect(same(writes.map((entry) => entry.amount), [1_500, 4_000]), `provider writes ${JSON.stringify(writes)}`);
      expect(writes[0]!.echo === observed.evidence?.echo,
        `refund-1 echo ${String(writes[0]!.echo)} != ${String(observed.evidence?.echo)}`);
      const readBack = `/v1/refunds/${String(writes[0]!.refund)}`;
      expect(entries.some((entry) => entry.path === readBack && entry.status === 200),
        `refund-1 was not read back at ${readBack}`);
      const keys = {
        "refund-1": idempotencyKey(facts.operator_namespace, "refund-1"),
        "refund-4": idempotencyKey(facts.operator_namespace, "refund-4"),
      };
      expect(same(writes.map((entry) => entry.idempotency_key), [keys["refund-1"], keys["refund-4"]]),
        `Idempotency-Key values ${JSON.stringify(writes.map((entry) => entry.idempotency_key))}`);
      expect(!writes.some((entry) => entry.replayed === true), `provider replays ${JSON.stringify(writes)}`);

      // State loss: the gateway's store is restored from the backup taken
      // before the first refund, which still holds the shared connection
      // record but no claim, and a client resubmits refund-1's approved proof
      // and action. No claim stops it now; only the repeated Idempotency-Key
      // keeps the double, like Stripe, from making a second refund. A wiped
      // store would lose the connection record too, and the gateway would
      // refuse every entry.
      stateLoss = await journey.step("state loss: store restored from an older backup, refund-1 resubmitted",
        async () => {
          await journey.terminate(running!);
          rmSync(join(journey.gatewayState, "attempts"), { recursive: true, force: true });
          copyTree(attemptsBackup, join(journey.gatewayState, "attempts"));
          await startGateway();
          const first = entriesLog().find((entry) => entry.operation_id === "refund-1")!;
          const proof = join(journey.work, "resubmit.proof");
          const action = join(journey.work, "resubmit.action");
          writeFileSync(proof, new Uint8Array(Buffer.from(first.proof_b64 as string, "base64url")));
          writeFileSync(action, new Uint8Array(Buffer.from(first.action_b64 as string, "base64url")));
          return JSON.parse(journey.run(journey.gateway, [
            "submit", "--app-socket", journey.socket, "--proof", proof, "--action", action,
          ]).stdout) as Json;
        });
      expect(stateLoss.outcome === "observed-by-provider" && stateLoss.status === 200,
        `resubmitted refund-1: ${JSON.stringify(stateLoss)}`);
      writes = journey.providerEntries().filter((entry) => entry.kind === "write");
      expect(writes.length === 3, `expected 3 provider writes, saw ${writes.length}`);
      expect(writes[2]!.idempotency_key === keys["refund-1"] && writes[2]!.replayed === true &&
        writes[2]!.refund === writes[0]!.refund,
      `resubmitted refund-1 was not de-duplicated: ${JSON.stringify(writes[2])}`);
      const created = new Set(writes.map((entry) => entry.refund).filter((refund) => refund));
      expect(created.size === 1, `expected 1 refund, saw ${JSON.stringify([...created])}`);
    }

    // README step 8: the audit bundle.
    const bundlePath = join(journey.work, "audit-bundle.json");
    await journey.step("export audit bundle", () => journey.run(process.execPath, [
      REFUNDS, "export", "--state", journey.state, "--out", bundlePath,
    ]));
    const providerRequests = journey.providerEntries();
    await journey.stop();

    // README step 9: the offline audit, with the gateway stopped. The gateway
    // recorded nothing for the refusals it made before the claim, so their
    // entries carry no outcome and the audit reports them unverified: the
    // default policy fails the bundle, and --allow-unverified-refusals passes
    // it because the audit itself refuses each of those proofs.
    const exported = JSON.parse(readFileSync(bundlePath, "utf8")) as { entries: Json[] };
    const unrecorded = new Set(exported.entries
      .filter((entry) => entry.outcome_b64 === null || entry.outcome_b64 === undefined)
      .map((entry) => entry.operation_id as string));
    // refund-2-lowered-threshold's unsigned entry was replaced by its signed retry.
    expect(same([...unrecorded].sort(), [
      "refund-3-over-ceiling", "refund-6-lowered-two-approvals", "refund-other-account",
    ]), `entries without a signed outcome: ${JSON.stringify([...unrecorded].sort())}`);
    const strict = await journey.step("offline audit (gateway stopped)",
      () => journey.audit(bundlePath, facts.trusted_context_sha256, observer));
    expect(strict.status !== 0 && strict.stderr.trim() === "audit.unverified",
      `audit without --allow-unverified-refusals: ${String(strict.status)} ${strict.stderr}`);
    const audited = await journey.step("offline audit accepting unverified refusals",
      () => journey.audit(bundlePath, facts.trusted_context_sha256, observer, "--allow-unverified-refusals"));
    expect(audited.status === 0, `audit failed: ${audited.stderr}`);
    expect(audited.stdout === strict.stdout, "the option changed the audit report");
    const report = JSON.parse(audited.stdout) as {
      verified: number; refused: number; unverified: number; inconsistent: number;
      recovery: { class: string };
      entries: {
        operation_id: string; status: string; code: string; admitted: boolean; approvals: string[];
        provider_result: {
          stage: string; http_status: number | null; response_digest: string | null;
          refusal: string | null; recount: string | null;
        } | null;
      }[];
      approval_responses: { operation_id: string; approver: string; decision: string }[];
    };
    const verdicts = Object.fromEntries(report.entries.map((entry) =>
      [entry.operation_id, `${entry.status} ${entry.code} ${String(entry.admitted)}`]));
    // One bundle entry per operation ID: the replay left refund-1's alone, the
    // retry replaced refund-2-lowered-threshold's unsigned one, and the
    // journey's own reused-approvals and self-approval submissions have none.
    const bundled = exported.entries.map((entry) => entry.operation_id as string);
    const auditedRefusals: Record<string, string> = Object.fromEntries(Object.entries(expectedRefusals)
      .filter(([operation]) =>
        !["refund-1-replay", "refund-8-reuse", "refund-self-approval", "refund-2-retry"].includes(operation))
      .map(([operation, [, code]]) => [operation, code]));
    auditedRefusals["refund-2-lowered-threshold"] = expectedRefusals["refund-2-retry"]![1];
    expect(new Set(bundled).size === bundled.length, `bundle repeats an operation ID: ${JSON.stringify(bundled)}`);
    expect(same([...bundled].sort(), ["refund-1", "refund-4", ...Object.keys(auditedRefusals)].sort()),
      `bundle entries ${JSON.stringify([...bundled].sort())}`);
    for (const operation of ["refund-1", "refund-4"]) {
      expect(verdicts[operation] === "verified audit.verified true", `audit ${operation}: ${verdicts[operation]}`);
    }
    for (const [operation, code] of Object.entries(auditedRefusals)) {
      const expected = unrecorded.has(operation) ? `unverified ${code} false` : `refused ${code} true`;
      expect(verdicts[operation] === expected, `audit ${operation}: ${verdicts[operation]}`);
    }
    // Every entered refund shows the provider's result beside its verdict, the
    // one the provider rejected included.
    const providerResults = Object.fromEntries(report.entries.map((entry) =>
      [entry.operation_id, entry.provider_result]));
    const entered = report.entries.filter((entry) => entry.status === "verified").map((entry) => entry.operation_id);
    expect(same(entered, ["refund-1", "refund-4"]), `audit entered ${JSON.stringify(entered)}`);
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
    expect(report.verified === 2 && report.refused === 7 && report.unverified === 3 && report.inconsistent === 0,
      `audit summary ${JSON.stringify([report.verified, report.refused, report.unverified, report.inconsistent])}`);
    expect(report.recovery.class === "linked-after-response", `audit recovery ${JSON.stringify(report.recovery)}`);
    // Only the managers whose approvals counted are listed; the agent, which
    // signed the action, never is.
    const principals = facts.principals;
    for (const [operation, names] of [
      ["refund-1", ["manager-a", "manager-b"]], ["refund-4", ["manager-a", "manager-c"]],
    ] as const) {
      const entry = report.entries.find((item) => item.operation_id === operation)!;
      expect(same([...entry.approvals].sort(), names.map((name) => principals[name]).sort()),
        `${operation} approvals: ${JSON.stringify(entry.approvals)}`);
    }
    const recorded = new Set(report.approval_responses.map((item) =>
      `${item.operation_id} ${item.approver} ${item.decision}`));
    for (const [operation, name, decision] of [
      ["refund-two-declines", "manager-a", "approve"], ["refund-two-declines", "manager-b", "decline"],
      ["refund-two-declines", "manager-c", "decline"],
      ["refund-1", "manager-a", "approve"], ["refund-1", "manager-b", "approve"],
      ["refund-4", "manager-b", "decline"],
    ] as const) {
      expect(recorded.has(`${operation} ${principals[name]} ${decision}`),
        `audit approval responses ${JSON.stringify([...recorded].sort())}`);
    }

    // Hostile: a tampered bundle is detected. Each case runs with
    // --allow-unverified-refusals, so that only the tampering can fail it.
    const bundle = JSON.parse(readFileSync(bundlePath, "utf8")) as { entries: Json[] } & Json;
    const refund4 = bundle.entries.find((entry) => entry.operation_id === "refund-4")!;
    type Audited = {
      inconsistent: number;
      entries: { operation_id: string; status: string; code: string; admitted: boolean }[];
    };
    const tamperedPath = join(journey.work, "tampered.json");
    const auditTampered = (value: Json): SpawnSyncReturns<string> => {
      writeFileSync(tamperedPath, JSON.stringify(value));
      return journey.audit(tamperedPath, facts.trusted_context_sha256, observer, "--allow-unverified-refusals");
    };
    const refund1 = (result: SpawnSyncReturns<string>) =>
      (JSON.parse(result.stdout) as Audited).entries.find((entry) => entry.operation_id === "refund-1")!;
    const dropOutcome = (entry: Json): void => { delete entry.outcome_b64; };
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
    for (const [label, [value, code]] of Object.entries(tampered)) {
      const result = auditTampered(value);
      const findings = (JSON.parse(result.stdout) as Audited).entries
        .filter((entry) => entry.status === "inconsistent").map((entry) => entry.code);
      expect(result.status !== 0 && same(findings, [code]),
        `tamper '${label}' not detected: ${JSON.stringify(findings)} ${result.stderr}`);
      detections[label] = code;
    }
    // An entered refund whose outcome was left out verifies, so it stays
    // unverified and fails the audit even with the option.
    const removed = auditTampered(tamper(bundle, "refund-1", dropOutcome));
    const removedEntry = refund1(removed);
    expect(removed.status !== 0 && removed.stderr.trim() === "audit.unverified" &&
      (JSON.parse(removed.stdout) as Audited).inconsistent === 0 &&
      `${removedEntry.status} ${removedEntry.code} ${String(removedEntry.admitted)}` ===
        "unverified audit.outcome-missing true",
    `tamper 'outcome removed' not detected: ${JSON.stringify(removedEntry)} ${removed.stderr}`);
    detections["outcome removed"] = "audit.unverified";
    const replaced = auditTampered({
      ...bundle,
      trusted_context_b64: readFileSync(join(journey.state, "trust", "sdk.context.cbor")).toString("base64url"),
    });
    expect(replaced.status !== 0 && replaced.stderr.includes("audit.trust-pin-mismatch"),
      "replaced trust not detected");
    detections["trust replaced"] = "audit.trust-pin-mismatch";
    // The documented limit of --allow-unverified-refusals: with its outcome
    // removed, an altered proof is refused by the audit and so accepted by the
    // option. It is reported unverified, never refused, and the default policy
    // still fails it. This is not a detection.
    const limited = auditTampered(tamper(bundle, "refund-1", (entry) => {
      dropOutcome(entry);
      flipProofByte(entry);
    }));
    const limitedEntry = refund1(limited);
    expect(limited.status === 0 && (JSON.parse(limited.stdout) as Audited).inconsistent === 0 &&
      limitedEntry.status === "unverified" && !limitedEntry.admitted,
    `known limit changed: ${JSON.stringify(limitedEntry)} ${String(limited.status)} ${limited.stderr}`);
    const knownLimits = {
      "outcome removed and proof byte flipped": { exit: limited.status, "refund-1": limitedEntry.status },
    };
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
      provider_refunds: live ? null : new Set(writes.map((entry) => entry.refund).filter((refund) => refund)).size,
      state_loss_resubmission: stateLoss,
      audit: {
        verified: report.verified, refused: report.refused, unverified: report.unverified,
        inconsistent: report.inconsistent,
        http_status: Object.fromEntries(entered.map((operation) => [operation, providerResults[operation]!.http_status])),
      },
      tamper_detected: detections,
      known_limits: knownLimits,
      hostile,
      negative_control: negativeControl,
      gateway_witness: journey.witnessLines(),
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
