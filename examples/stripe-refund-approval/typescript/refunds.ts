/**
 * Stripe refunds an AI agent may request only with two of three manager
 * approvals and inside a per-agent limit, submitted through the Auths gateway,
 * from the npm package. The commands and state directory match ../refunds.py:
 *
 *   node build/refunds.js setup   --state DIR --gateway auths-gateway
 *   node build/refunds.js request --state DIR --operation-id ID --payment-intent PI \
 *                                 --amount CENTS --approvers a,b --out REQUESTS
 *   npx auths approve REQUESTS/manager-a.request \
 *                                 --signer DIR/signers/manager-a.json --out REQUESTS/manager-a.response
 *   node build/refunds.js submit  --state DIR --socket SOCK --operation-id ID --responses REQUESTS
 *   node build/refunds.js export  --state DIR --out audit-bundle.json
 *
 * The agent writes one approval request per manager; each manager answers with
 * `auths approve` on their own machine, and the agent collects the
 * response files. Everything here uses development keys stored under DIR/keys
 * so one person can play every role; they are development custody. In
 * production the root and each manager sign through their own custody
 * adapters, and the agent never holds the managers' keys.
 * The Stripe secret key never enters this program: only the gateway holds it.
 */

import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import type {
  CustodyDescriptor, CustodySigner, CustodySignResult, SigningRequest,
} from "@auths-dev/sdk/adapters";
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";
import {
  approvalRequests, approve, authorRootGrant, collectApprovals, compileTrustedContext,
  openApprovalRequest, proposeMcpApproval,
  type ApprovalProposal, type AssurancePolicy, type GrantEvidence, type TrustAnchor,
} from "@auths-dev/sdk/self-hosted";
import { developmentEd25519Key, type DevelopmentEd25519Key } from "@auths-dev/sdk/testkit";

import { CONTRACT, type CreateRefund } from "./generated.js";

/** The example directory: recipe, profile lock, and the Python original. */
export const EXAMPLE = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const RECIPE = join(EXAMPLE, "recipe.json");
const PROFILE_LOCK = join(EXAMPLE, "profile.lock.json");
export const MANAGERS = ["manager-a", "manager-b", "manager-c"] as const;
const ROLES = ["root", "agent", ...MANAGERS] as const;
const DAY = 86_400n;
const MCP = { id: "auths.mcp", version: 2 };

/** Root and actor keys are self-certifying, and actors are verifiable offline. */
export const ASSURANCE: AssurancePolicy = {
  id: "raw-key-baseline",
  requirements: [
    { role: "root", quantifier: "every", claim: "self-certifying-identifier" },
    { role: "actor", quantifier: "every", claim: "self-certifying-identifier" },
    { role: "actor", quantifier: "every", claim: "offline-verifiable" },
  ],
};

export interface SetupFacts {
  readonly recipe_digest: string;
  readonly operator_namespace: string;
  readonly audience: string;
  readonly challenge_hex: string;
  readonly trusted_context_sha256: string;
  readonly principals: Readonly<Record<string, string>>;
  readonly bound: Readonly<Record<string, unknown>>;
}

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const hexBytes = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "hex"));
const unixNow = (): bigint => BigInt(Math.floor(Date.now() / 1000));

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function privateWrite(path: string, data: Uint8Array | string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, data);
  } finally {
    closeSync(descriptor);
  }
}

/** What `auths-gateway review` prints for the operator to approve and pin. */
interface RecipeReview {
  readonly service: string;
  readonly tool: string;
  readonly recipe_digest: string;
  readonly operator_namespace: string;
  readonly verifier_configuration: string;
}

/** What `auths-gateway bound-extension` prints: the grant extension it enforces. */
interface BoundExtension {
  readonly extension_id: string;
  readonly extension_body_hex: string;
  readonly argument: string;
  readonly ceiling: number;
  readonly window_seconds: number;
  readonly max_count: number;
}

function gatewayJson<T>(gateway: string, ...args: string[]): T {
  return JSON.parse(execFileSync(gateway, args, { encoding: "utf8" })) as T;
}

/**
 * A custody signer over a development key. Approvers see the review display
 * before signing; a production signer shows it on their own device.
 */
export function developmentSigner(name: string, key: DevelopmentEd25519Key): CustodySigner {
  const descriptor: CustodyDescriptor = {
    contract: "signer-custody/2",
    kind: "workload",
    adapterId: "example.development-key",
    principal: key.principal,
    signature: key.signature,
    keyVersion: "development-1",
    keyState: "active-current",
    lifecycle: "ephemeral",
  };
  return {
    descriptor,
    async sign(request: SigningRequest): Promise<CustodySignResult> {
      const shown = request.display.map((field) => `${field.label}=${field.value}`).join(", ");
      process.stderr.write(`  ${name} signs: ${shown.slice(0, 200)}\n`);
      return {
        kind: "signed",
        response: {
          requestId: request.requestId,
          objectId: request.objectId,
          principal: descriptor.principal,
          descriptor: descriptor.signature,
          providerKeyVersion: descriptor.keyVersion,
          transactionDigest: request.transactionDigest,
          signature: await key.sign(request.signingPreimage),
          evidence: [key.evidence],
        },
      };
    },
    async close() {},
    async [Symbol.asyncDispose]() {},
  };
}

async function roleKey(state: string, name: string): Promise<DevelopmentEd25519Key> {
  return developmentEd25519Key(new Uint8Array(readFileSync(join(state, "keys", `${name}.seed`))));
}

/**
 * `required` authorized approvals from as many distinct actors and distinct
 * roots under `anchors`, bound to one audience, challenge, and time.
 */
export function trustedContext(input: Readonly<{
  configuration?: Uint8Array;
  anchors: readonly TrustAnchor[];
  audience: string;
  challenge: Uint8Array;
  now: bigint;
  required: number;
  extension: string;
}>): Promise<Uint8Array> {
  return compileTrustedContext({
    ...(input.configuration === undefined ? {} : { configuration: input.configuration }),
    anchors: input.anchors,
    assurance: ASSURANCE,
    minimumAuthorizedBranches: input.required,
    minimumDistinctActors: input.required,
    minimumDistinctRoots: input.required,
    channelPolicy: "none-v1",
    evidenceTypes: ["raw-key-v1"],
    criticalExtensions: [input.extension],
    request: { audience: input.audience, challenge: input.challenge, evaluationTime: input.now },
  });
}

/** One trust anchor for `name`: the root may delegate once, managers approve directly. */
export function anchor(
  name: string, principal: string, audience: string, tool: string,
  depth: number, notBefore: bigint, expiresAt: bigint,
): TrustAnchor {
  return {
    id: name,
    principal,
    acceptedMethods: ["raw-key-v1"],
    profiles: [MCP],
    permissions: [{ capability: "tools/call", resource: `${audience}/tools/${tool}` }],
    resourceNamespaces: [audience],
    audiences: [audience],
    notBefore,
    expiresAt,
    maxDelegationDepth: depth,
    assurancePolicy: ASSURANCE.id,
  };
}

async function setup(options: Readonly<{
  state: string; gateway: string; ceiling: number; maxCount: number; windowSeconds: number; days: number;
}>): Promise<void> {
  const state = options.state;
  if (existsSync(join(state, "setup.json"))) fail(`${state} is already set up; use a fresh directory`);
  const review = gatewayJson<RecipeReview>(
    options.gateway, "review", "--recipe", RECIPE, "--profile-lock", PROFILE_LOCK,
  );
  const bound = gatewayJson<BoundExtension>(
    options.gateway, "bound-extension", "--argument", "amount",
    "--ceiling", String(options.ceiling), "--window-seconds", String(options.windowSeconds),
    "--max-count", String(options.maxCount),
  );
  for (const name of ROLES) privateWrite(join(state, "keys", `${name}.seed`), randomBytes(32));
  // What each manager passes to `auths approve --signer`.
  for (const name of MANAGERS) {
    privateWrite(join(state, "signers", `${name}.json`), JSON.stringify({
      schema: "auths.approval-signer/1", custody: "development-ed25519", seed_file: `../keys/${name}.seed`,
    }, null, 2));
  }
  const keys = new Map(await Promise.all(ROLES.map(async (name) => [name, await roleKey(state, name)] as const)));
  const principals = Object.fromEntries([...keys].map(([name, key]) => [name, key.principal]));

  const now = unixNow();
  const notBefore = now - 300n;
  const expiresAt = now + BigInt(options.days) * DAY;
  const tool = review.tool;
  const audience = `mcp://${review.service}`;
  const challenge = new Uint8Array(randomBytes(32));
  const anchors = [
    anchor("root", principals.root!, audience, tool, 1, notBefore, expiresAt),
    ...MANAGERS.map((name) => anchor(name, principals[name]!, audience, tool, 0, notBefore, expiresAt)),
  ];
  const extension = bound.extension_id;
  // Three authorized approvals from three distinct roots: the agent's
  // authority descends from the root and counts once, so two must be managers.
  const common = { anchors, audience, challenge, now, required: 3, extension };
  const gatewayContext = await trustedContext({
    ...common, configuration: hexBytes(review.verifier_configuration),
  });
  const sdkContext = await trustedContext(common);

  const grant = await authorRootGrant({
    signer: developmentSigner("root", keys.get("root")!),
    subject: principals.agent!,
    profile: MCP,
    permissions: [{ capability: "tools/call", resource: `${audience}/tools/${tool}` }],
    audiences: [audience],
    notBefore,
    expiresAt,
    remainingDepth: 0,
    assuranceFloor: ASSURANCE.id,
    criticalExtensions: [{ id: extension, bytes: hexBytes(bound.extension_body_hex) }],
    requestedAt: now,
  });

  privateWrite(join(state, "trust", "gateway.context.cbor"), gatewayContext);
  privateWrite(join(state, "trust", "sdk.context.cbor"), sdkContext);
  privateWrite(join(state, "agent.grant.cbor"), grant.signedGrant);
  const summary: SetupFacts = {
    recipe_digest: review.recipe_digest,
    operator_namespace: review.operator_namespace,
    audience,
    challenge_hex: Buffer.from(challenge).toString("hex"),
    trusted_context_sha256: createHash("sha256").update(gatewayContext).digest("hex"),
    principals,
    bound: {
      argument: bound.argument,
      ceiling: bound.ceiling,
      window_seconds: bound.window_seconds,
      max_count: bound.max_count,
    },
  };
  privateWrite(join(state, "setup.json"), JSON.stringify(summary, null, 2));
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

interface Pending {
  readonly managers: readonly string[];
  readonly payment_intent: string;
  readonly amount: number;
  readonly evaluation_time: number;
}

/**
 * Rebuilds the agent's proposal for `operation` from its saved inputs; the
 * same inputs always give the same envelopes and requests.
 */
async function proposal(state: string, operation: string): Promise<ApprovalProposal<CreateRefund>> {
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const pending = JSON.parse(readFileSync(join(state, "pending", `${operation}.json`), "utf8")) as Pending;
  return proposeMcpApproval({
    contract: CONTRACT,
    command: {
      operator_namespace: "stripe-refunds",
      operation_id: operation,
      recipe_digest: facts.recipe_digest,
      payment_intent: pending.payment_intent,
      amount: pending.amount,
    },
    // The agent and every listed manager approve the same exact refund.
    required: 1 + pending.managers.length,
    approvers: [
      {
        principal: facts.principals.agent!,
        terminalGrant: new Uint8Array(readFileSync(join(state, "agent.grant.cbor"))),
      },
      ...pending.managers.map((name) => ({ principal: facts.principals[name]! })),
    ],
    requester: facts.principals.agent!,
    challenge: hexBytes(facts.challenge_hex),
    evaluationTime: BigInt(pending.evaluation_time),
  });
}

async function agentGrants(state: string): Promise<GrantEvidence[]> {
  const root = await roleKey(state, "root");
  return [{ signedGrant: new Uint8Array(readFileSync(join(state, "agent.grant.cbor"))), evidence: [root.evidence] }];
}

async function request(options: Readonly<{
  state: string; operationId: string; paymentIntent: string; amount: number; approvers: string; out: string;
}>): Promise<Record<string, unknown>> {
  const state = options.state;
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const managers = options.approvers.split(",").filter((name) => name.length > 0);
  if (!managers.every((name) => (MANAGERS as readonly string[]).includes(name)) ||
      new Set(managers).size !== managers.length) {
    fail(`approvers must be distinct names from ${MANAGERS.join(", ")}`);
  }
  const pending: Pending = {
    managers, payment_intent: options.paymentIntent, amount: options.amount,
    evaluation_time: Math.floor(Date.now() / 1000),
  };
  privateWrite(join(state, "pending", `${options.operationId}.json`), JSON.stringify(pending));
  const names = new Map(Object.entries(facts.principals).map(([name, principal]) => [principal, name]));
  mkdirSync(options.out, { recursive: true, mode: 0o700 });
  const written: Record<string, string> = {};
  for (const item of await approvalRequests(await proposal(state, options.operationId))) {
    const name = names.get(item.approver)!;
    if (name === "agent") {
      // The agent approves its own request like any other approver.
      const review = await openApprovalRequest(item.data);
      const response = await approve(review, developmentSigner("agent", await roleKey(state, "agent")), {
        grants: await agentGrants(state),
      });
      writeFileSync(join(options.out, "agent.response"), `${response.text}\n`);
      continue;
    }
    const path = join(options.out, `${name}.request`);
    writeFileSync(path, `${item.text}\n`);
    written[name] = path;
  }
  return { operation_id: options.operationId, requests: written };
}

async function submit(options: Readonly<{
  state: string; socket: string; operationId: string; responses: string;
}>): Promise<Record<string, unknown>> {
  const state = options.state;
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const names = new Map(Object.entries(facts.principals).map(([name, principal]) => [principal, name]));
  const built = await proposal(state, options.operationId);
  const texts = readdirSync(options.responses).filter((name) => name.endsWith(".response")).sort()
    .map((name) => readFileSync(join(options.responses, name), "utf8").trim());
  const record: Record<string, unknown> = { operation_id: options.operationId, amount: built.command.amount };
  mkdirSync(join(state, "audit"), { recursive: true, mode: 0o700 });
  for (const text of texts) {
    appendFileSync(join(state, "audit", "approvals.jsonl"),
      `${JSON.stringify({ operation_id: options.operationId, response: text })}\n`, { mode: 0o600 });
  }
  const collection = await collectApprovals(built, texts);
  const declined = collection.statuses.filter((item) => item.status === "declined")
    .map((item) => names.get(item.approver) ?? item.approver).sort();
  if (declined.length > 0) return { ...record, stage: "collection", outcome: "declined", declined };
  const waiting = Object.fromEntries(collection.statuses.filter((item) => item.status !== "approved")
    .map((item) => [names.get(item.approver) ?? item.approver, item.code ?? item.status]));
  if (Object.keys(waiting).length > 0) return { ...record, stage: "collection", outcome: "incomplete", waiting };
  // Collection checks every envelope byte for byte; the gateway's verifier
  // checks the signatures and the threshold of its installed trust.
  const proof = collection.assemble();
  const gateway = new GatewayClient(new GatewayEndpoint(resolve(options.socket)));
  Object.assign(record, await gateway.submit({ proof, action: built.action }));
  const observation = await gateway.observeOutcome(options.operationId);
  const outcome = observation.outcome === "signed" ? observation.observation : null;
  const entry = {
    operation_id: options.operationId,
    proof_b64: b64(proof),
    action_b64: b64(built.action),
    outcome_b64: outcome === null ? null : b64(outcome),
  };
  appendFileSync(join(state, "audit", "entries.jsonl"), `${JSON.stringify(entry)}\n`, { mode: 0o600 });
  return record;
}

function exportBundle(options: Readonly<{ state: string; out: string }>): void {
  const log = join(options.state, "audit", "entries.jsonl");
  const entries = readFileSync(log, "utf8").split("\n").filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as unknown);
  const approvals = join(options.state, "audit", "approvals.jsonl");
  const responses = existsSync(approvals)
    ? readFileSync(approvals, "utf8").split("\n").filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as unknown)
    : [];
  const bundle = {
    schema: "auths.gateway-audit-bundle/1",
    recipe_b64: b64(readFileSync(RECIPE)),
    profile_lock_b64: b64(readFileSync(PROFILE_LOCK)),
    trusted_context_b64: b64(readFileSync(join(options.state, "trust", "gateway.context.cbor"))),
    entries,
    approval_responses: responses,
  };
  writeFileSync(options.out, `${JSON.stringify(bundle, null, 1)}\n`);
  process.stdout.write(`wrote ${options.out} with ${entries.length} submissions and ${responses.length} approval responses\n`);
}

function integer(value: string | undefined, name: string, fallback?: number): number {
  if (value === undefined && fallback !== undefined) return fallback;
  const parsed = Number(value);
  if (value === undefined || !Number.isSafeInteger(parsed) || parsed < 1) fail(`--${name} needs a positive integer`);
  return parsed;
}

function required(value: string | undefined, name: string): string {
  if (value === undefined || value.length === 0) fail(`--${name} is required`);
  return value;
}

async function main(): Promise<void> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      state: { type: "string" },
      gateway: { type: "string", default: "auths-gateway" },
      ceiling: { type: "string" },
      "max-count": { type: "string" },
      "window-seconds": { type: "string" },
      days: { type: "string" },
      socket: { type: "string" },
      "operation-id": { type: "string" },
      "payment-intent": { type: "string" },
      amount: { type: "string" },
      approvers: { type: "string" },
      responses: { type: "string" },
      out: { type: "string" },
    },
  });
  const state = resolve(required(values.state, "state"));
  switch (positionals[0]) {
    case "setup":
      await setup({
        state,
        gateway: values.gateway!,
        ceiling: integer(values.ceiling, "ceiling", 5_000),
        maxCount: integer(values["max-count"], "max-count", 2),
        windowSeconds: integer(values["window-seconds"], "window-seconds", 86_400),
        days: integer(values.days, "days", 30),
      });
      break;
    case "request":
      process.stdout.write(`${JSON.stringify(await request({
        state,
        operationId: required(values["operation-id"], "operation-id"),
        paymentIntent: required(values["payment-intent"], "payment-intent"),
        amount: integer(values.amount, "amount"),
        approvers: required(values.approvers, "approvers"),
        out: resolve(required(values.out, "out")),
      }))}\n`);
      break;
    case "submit":
      process.stdout.write(`${JSON.stringify(await submit({
        state,
        socket: required(values.socket, "socket"),
        operationId: required(values["operation-id"], "operation-id"),
        responses: resolve(required(values.responses, "responses")),
      }))}\n`);
      break;
    case "export":
      exportBundle({ state, out: resolve(required(values.out, "out")) });
      break;
    default:
      fail("usage: refunds.js setup|request|submit|export --state DIR ...");
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
