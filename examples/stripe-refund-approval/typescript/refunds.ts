/**
 * Stripe refunds an AI agent may make only once any two of three managers
 * approved them, inside a per-agent limit, submitted through the Auths gateway,
 * from the npm package. The commands and state directory match ../refunds.py:
 *
 *   node build/refunds.js setup   --state DIR --gateway auths-gateway
 *   node build/refunds.js request --state DIR --operation-id ID --payment-intent PI \
 *                                 --amount CENTS --out REQUESTS \
 *                                 [--currency usd] [--connect-account acct_...] [--precheck]
 *   npx auths approve REQUESTS/manager-a.request \
 *                                 --signer DIR/signers/manager-a.json --out REQUESTS/manager-a.response
 *   node build/refunds.js submit  --state DIR --socket SOCK --operation-id ID --responses REQUESTS
 *   node build/refunds.js export  --state DIR --out audit-bundle.json
 *
 * `submit` has the agent sign its refund and sends the assembled proof to the
 * gateway once two managers approved: only the gateway decides the approval
 * threshold, the ceiling, the per-window count, and whether an operation ID
 * may run again. `request --precheck` is an opt-in, client-side
 * pre-check and not an enforcement boundary. Every outcome record says who
 * decided it in `decided_by`: `gateway`, `approver`, or `client`.
 *
 * `node build/refunds.js grant --state DIR --agent NAME --max-count N` issues
 * one more agent its own grant with the same limits and another count; the
 * journey uses it for the refusals that consume a count slot. Naming a manager
 * gives that manager's key an agent grant, for the self-approval case.
 *
 * The agent writes one approval request per manager; any manager may answer
 * with `auths approve` on their own machine, and the agent collects whatever
 * response files exist. Whoever answers first counts: the third manager need
 * not answer. The agent's own approval never counts. `request --required N`
 * lowers the threshold the requests name; it is a hostile lever for the
 * journey, and the gateway refuses what it produces. Everything here uses development keys stored under DIR/keys
 * so one person can play every role; they are development custody. In
 * production the root and each manager sign through their own custody
 * adapters, and the agent never holds the managers' keys.
 * The Stripe secret key never enters this program: only the gateway holds it.
 */

import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import type {
  CustodyDescriptor, CustodySigner, CustodySignResult, SigningRequest,
} from "@auths-dev/sdk/adapters";
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";
import {
  approvalRequests, authorRootGrant, collectApprovals, compileTrustedContext, proposeMcpApproval,
  signApprovalAction,
  type ApprovalProposal, type ApprovalRequirement, type ApproverAnchor, type AssurancePolicy,
  type GrantEvidence, type TrustAnchor,
} from "@auths-dev/sdk/self-hosted";
import { developmentEd25519Key, type DevelopmentEd25519Key } from "@auths-dev/sdk/testkit";

import { CONTRACT, type CreateRefund } from "./generated.js";

/** The example directory: recipe, profile lock, and the Python original. */
export const EXAMPLE = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const RECIPE = join(EXAMPLE, "recipe.json");
const PROFILE_LOCK = join(EXAMPLE, "profile.lock.json");
export const MANAGERS = ["manager-a", "manager-b", "manager-c"] as const;
// The gateway's trusted context requires approvals from this many of the
// three managers, any of them.
const APPROVALS_REQUIRED = 2;
const ROLES = ["root", "agent", ...MANAGERS] as const;
const DAY = 86_400n;
// The test connected account the grant's scope lists; the gateway sends it as
// `Stripe-Account` on the refund and on every read of the refund's records.
const CONNECT_ACCOUNT = "acct_1AuthsConnected";
// The recipe declares a derived Idempotency-Key with 86 400 seconds of
// provider retention. The gateway refuses an action whose approval window plus
// its 60-second entry deadline exceeds that retention, so every entry of one
// approved refund falls within one retention period of the first.
const APPROVAL_WINDOW = 86_340;
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

/** The limits every agent grant carries; only the count differs per agent. */
interface Limits {
  readonly ceiling: number;
  readonly window_seconds: number;
  readonly sum_limit: number;
  readonly currencies: readonly string[];
  readonly connect_account: string;
}

export interface SetupFacts {
  readonly recipe_digest: string;
  readonly operator_namespace: string;
  readonly audience: string;
  readonly tool: string;
  readonly not_before: number;
  readonly expires_at: number;
  readonly challenge_hex: string;
  readonly trusted_context_sha256: string;
  readonly principals: Readonly<Record<string, string>>;
  readonly approvals_required: number;
  readonly approvers: readonly string[];
  readonly connect_account: string;
  readonly limits: Limits;
  readonly bound: Readonly<Record<string, unknown>> & { readonly ceiling: number };
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
  readonly sum_limit: number;
  readonly partition: unknown;
  readonly scope: unknown;
}

function gatewayJson<T>(gateway: string, ...args: string[]): T {
  return JSON.parse(execFileSync(gateway, args, { encoding: "utf8" })) as T;
}

/**
 * The grant extension for `limits` with `maxCount` refunds per window, as the
 * gateway's registered evaluator enforces it.
 */
function boundExtension(gateway: string, limits: Limits, maxCount: number): BoundExtension {
  return gatewayJson<BoundExtension>(
    gateway, "bound-extension", "--argument", "amount",
    "--ceiling", String(limits.ceiling), "--window-seconds", String(limits.window_seconds),
    "--max-count", String(maxCount), "--sum-limit", String(limits.sum_limit),
    "--partition", `currency=${limits.currencies.join(",")}`,
    "--scope", `connect_account=${limits.connect_account}`,
  );
}

/** Every principal by name: the roles setup created and each agent `grant` added. */
function principalsOf(state: string, facts: SetupFacts): Record<string, string> {
  const principals: Record<string, string> = { ...facts.principals };
  const agents = join(state, "agents");
  if (existsSync(agents)) {
    for (const file of readdirSync(agents).filter((name) => name.endsWith(".json")).sort()) {
      principals[file.slice(0, -".json".length)] =
        (JSON.parse(readFileSync(join(agents, file), "utf8")) as { principal: string }).principal;
    }
  }
  return principals;
}

/** A grant from the root to `subject` carrying `bound`, valid for the trust's lifetime. */
async function rootGrant(
  state: string, facts: Pick<SetupFacts, "audience" | "tool" | "not_before" | "expires_at">,
  subject: string, bound: BoundExtension,
): Promise<Uint8Array> {
  const grant = await authorRootGrant({
    signer: developmentSigner("root", await roleKey(state, "root")),
    subject,
    profile: MCP,
    permissions: [{ capability: "tools/call", resource: `${facts.audience}/tools/${facts.tool}` }],
    audiences: [facts.audience],
    notBefore: BigInt(facts.not_before),
    expiresAt: BigInt(facts.expires_at),
    remainingDepth: 0,
    assuranceFloor: ASSURANCE.id,
    criticalExtensions: [{ id: bound.extension_id, bytes: hexBytes(bound.extension_body_hex) }],
    requestedAt: unixNow(),
  });
  return grant.signedGrant;
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

export async function roleKey(state: string, name: string): Promise<DevelopmentEd25519Key> {
  return developmentEd25519Key(new Uint8Array(readFileSync(join(state, "keys", `${name}.seed`))));
}

/**
 * One authorized branch from one actor under one root, and approvals from any
 * `threshold` of the approvers `requirement` names, bound to one audience,
 * challenge, and time.
 */
export function trustedContext(input: Readonly<{
  configuration?: Uint8Array;
  anchors: readonly TrustAnchor[];
  approvers: readonly ApproverAnchor[];
  requirement: ApprovalRequirement;
  audience: string;
  challenge: Uint8Array;
  now: bigint;
  extension: string;
}>): Promise<Uint8Array> {
  return compileTrustedContext({
    ...(input.configuration === undefined ? {} : { configuration: input.configuration }),
    anchors: input.anchors,
    assurance: ASSURANCE,
    minimumAuthorizedBranches: 1,
    minimumDistinctActors: 1,
    minimumDistinctRoots: 1,
    approverAnchors: input.approvers,
    approvalRequirements: [input.requirement],
    channelPolicy: "none-v1",
    evidenceTypes: ["raw-key-v1"],
    criticalExtensions: [input.extension],
    request: { audience: input.audience, challenge: input.challenge, evaluationTime: input.now },
  });
}

/** One trust anchor for `name` that may delegate `depth` times. */
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
  sumLimit: number; currencies: string; connectAccount: string;
}>): Promise<void> {
  const state = options.state;
  if (existsSync(join(state, "setup.json"))) fail(`${state} is already set up; use a fresh directory`);
  const review = gatewayJson<RecipeReview>(
    options.gateway, "review", "--recipe", RECIPE, "--profile-lock", PROFILE_LOCK,
  );
  const limits: Limits = {
    ceiling: options.ceiling,
    window_seconds: options.windowSeconds,
    sum_limit: options.sumLimit,
    currencies: [...new Set(options.currencies.split(","))].sort(),
    connect_account: options.connectAccount,
  };
  const bound = boundExtension(options.gateway, limits, options.maxCount);
  for (const name of ROLES) {
    privateWrite(join(state, "keys", `${name}.seed`), new Uint8Array(randomBytes(32)));
  }
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
  // The root is the only trust anchor and may delegate once, to the agent.
  // The managers are approver anchors: they approve and hold no authority.
  const anchors = [anchor("root", principals.root!, audience, tool, 1, notBefore, expiresAt)];
  const approvers: ApproverAnchor[] = MANAGERS.map((name) => ({
    principal: principals[name]!, acceptedMethods: ["raw-key-v1"], notBefore, expiresAt,
  }));
  const requirement: ApprovalRequirement = {
    approvers: MANAGERS.map((name) => principals[name]!), threshold: APPROVALS_REQUIRED,
  };
  const extension = bound.extension_id;
  const common = { anchors, approvers, requirement, audience, challenge, now, extension };
  const gatewayContext = await trustedContext({
    ...common, configuration: hexBytes(review.verifier_configuration),
  });
  const sdkContext = await trustedContext(common);

  const lifetime = { audience, tool, not_before: Number(notBefore), expires_at: Number(expiresAt) };
  const agentGrant = await rootGrant(state, lifetime, principals.agent!, bound);

  privateWrite(join(state, "trust", "gateway.context.cbor"), gatewayContext);
  privateWrite(join(state, "trust", "sdk.context.cbor"), sdkContext);
  privateWrite(join(state, "agent.grant.cbor"), agentGrant);
  const summary: SetupFacts = {
    recipe_digest: review.recipe_digest,
    operator_namespace: review.operator_namespace,
    ...lifetime,
    challenge_hex: Buffer.from(challenge).toString("hex"),
    trusted_context_sha256: createHash("sha256").update(gatewayContext).digest("hex"),
    principals,
    approvals_required: APPROVALS_REQUIRED,
    approvers: [...MANAGERS],
    connect_account: options.connectAccount,
    limits,
    bound: {
      argument: bound.argument,
      ceiling: bound.ceiling,
      window_seconds: bound.window_seconds,
      max_count: bound.max_count,
      sum_limit: bound.sum_limit,
      partition: bound.partition,
      scope: bound.scope,
    },
  };
  privateWrite(join(state, "setup.json"), JSON.stringify(summary, null, 2));
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

/**
 * Issues one more agent its own grant: the setup's limits with `maxCount`
 * refunds per window, counted apart from every other agent's. Naming a manager
 * gives that manager's own key an agent grant, the operator error the
 * self-approval case exercises: the manager may then act, but its approval of
 * its own action never counts.
 */
async function grant(options: Readonly<{
  state: string; gateway: string; agent: string; maxCount: number;
}>): Promise<Record<string, unknown>> {
  const state = options.state;
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const name = options.agent;
  const manager = (MANAGERS as readonly string[]).includes(name);
  if (existsSync(join(state, "agents", `${name}.json`)) || (name in facts.principals && !manager)) {
    fail(`${name} already exists`);
  }
  const bound = boundExtension(options.gateway, facts.limits, options.maxCount);
  if (!manager) {
    privateWrite(join(state, "keys", `${name}.seed`), new Uint8Array(randomBytes(32)));
  }
  const principal = (await roleKey(state, name)).principal;
  privateWrite(join(state, `${name}.grant.cbor`), await rootGrant(state, facts, principal, bound));
  const record = { principal, max_count: bound.max_count };
  privateWrite(join(state, "agents", `${name}.json`), JSON.stringify(record));
  return { agent: name, ...record };
}

interface Pending {
  readonly agent: string;
  readonly required: number;
  readonly payment_intent: string;
  readonly amount: number;
  readonly currency: string;
  readonly connect_account: string;
  readonly evaluation_time: number;
}

/**
 * Rebuilds the agent's proposal for `operation` from its saved inputs; the
 * same inputs always give the same envelopes and requests.
 */
async function proposal(state: string, operation: string): Promise<ApprovalProposal<CreateRefund>> {
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const principals = principalsOf(state, facts);
  const pending = JSON.parse(readFileSync(join(state, "pending", `${operation}.json`), "utf8")) as Pending;
  return proposeMcpApproval({
    contract: CONTRACT,
    command: {
      operator_namespace: "stripe-refunds",
      operation_id: operation,
      recipe_digest: facts.recipe_digest,
      payment_intent: pending.payment_intent,
      amount: pending.amount,
      connect_account: pending.connect_account,
      currency: pending.currency,
    },
    // Any `required` of the three managers approve the agent's exact refund.
    required: pending.required,
    approvers: MANAGERS.map((name) => principals[name]!),
    actor: principals[pending.agent]!,
    actorGrant: new Uint8Array(readFileSync(join(state, `${pending.agent}.grant.cbor`))),
    challenge: hexBytes(facts.challenge_hex),
    evaluationTime: BigInt(pending.evaluation_time),
    validitySeconds: APPROVAL_WINDOW,
  });
}

async function agentGrants(state: string, agent: string): Promise<GrantEvidence[]> {
  const root = await roleKey(state, "root");
  return [{ signedGrant: new Uint8Array(readFileSync(join(state, `${agent}.grant.cbor`))), evidence: [root.evidence] }];
}

const PRECHECK_NOTE = "client-side pre-check; not an enforcement boundary. " +
  "The gateway enforces this rule whether or not the pre-check runs.";

/**
 * The rule a request breaks by what setup.json states, if any. It checks no
 * signature, window count, or operation ID: only the gateway decides those.
 */
function precheckRule(facts: SetupFacts, required: number, amount: number): string | null {
  if (required < facts.approvals_required) return "approvals-below-threshold";
  if (amount > facts.bound.ceiling) return "above-ceiling";
  return null;
}

/**
 * Writes the request's inputs. An earlier request for the same operation ID is
 * kept under the first free `<id>.json.N`: whether the ID may run again is the
 * gateway's decision, not this program's.
 */
function writePending(state: string, operation: string, data: string): void {
  const path = join(state, "pending", `${operation}.json`);
  if (existsSync(path)) {
    let number = 1;
    while (existsSync(`${path}.${number}`)) number += 1;
    renameSync(path, `${path}.${number}`);
    process.stderr.write(
      `${operation} was requested before; the earlier request is kept as ${operation}.json.${number}. ` +
      "The gateway's attempt store decides whether this operation ID may run again.\n",
    );
  }
  privateWrite(path, data);
}

async function request(options: Readonly<{
  state: string; operationId: string; paymentIntent: string; amount: number; required: number | undefined;
  out: string; currency: string; connectAccount: string | undefined; agent: string; precheck: boolean;
}>): Promise<Record<string, unknown>> {
  const state = options.state;
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const principals = principalsOf(state, facts);
  if ((MANAGERS as readonly string[]).includes(options.agent) || options.agent === "root" ||
      !(options.agent in principals)) {
    fail(`${options.agent} is not an agent of ${state}`);
  }
  const threshold = options.required ?? facts.approvals_required;
  if (options.precheck) {
    const rule = precheckRule(facts, threshold, options.amount);
    if (rule !== null) {
      return {
        operation_id: options.operationId, outcome: "not-submitted", decided_by: "client",
        reason: "precheck", precheck: rule, note: PRECHECK_NOTE,
      };
    }
  }
  if (threshold !== facts.approvals_required) {
    process.stderr.write(
      `the requests name a threshold of ${threshold}, not the ${facts.approvals_required} ` +
      "the trust installs; the gateway decides whether the approvals count\n",
    );
  }
  const pending: Pending = {
    agent: options.agent, required: threshold, payment_intent: options.paymentIntent, amount: options.amount,
    currency: options.currency, connect_account: options.connectAccount ?? facts.connect_account,
    evaluation_time: Math.floor(Date.now() / 1000),
  };
  writePending(state, options.operationId, JSON.stringify(pending));
  const built = await proposal(state, options.operationId);
  const names = new Map(Object.entries(principals).map(([name, principal]) => [principal, name]));
  mkdirSync(options.out, { recursive: true, mode: 0o700 });
  const written: Record<string, string> = {};
  for (const item of await approvalRequests(built)) {
    const name = names.get(item.approver)!;
    const path = join(options.out, `${name}.request`);
    writeFileSync(path, `${item.text}\n`);
    written[name] = path;
  }
  return {
    operation_id: options.operationId, required: built.requirement.required, requests: written,
    action_b64: b64(built.action),
  };
}

interface Entry {
  readonly operation_id: string;
  readonly proof_b64: string;
  readonly action_b64: string;
  readonly outcome_b64: string | null;
}

/**
 * Keeps at most one bundle entry per operation ID: the first submission, or a
 * later one that the gateway recorded in place of one it did not.
 */
function recordEntry(audit: string, entry: Entry): "appended" | "replaced" | "unchanged" {
  const log = join(audit, "entries.jsonl");
  const entries = existsSync(log)
    ? readFileSync(log, "utf8").split("\n").filter((line) => line.length > 0).map((line) => JSON.parse(line) as Entry)
    : [];
  const index = entries.findIndex((existing) => existing.operation_id === entry.operation_id);
  if (index < 0) {
    appendFileSync(log, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
    return "appended";
  }
  if (entries[index]!.outcome_b64 === null && entry.outcome_b64 !== null) {
    entries[index] = entry;
    const replacement = `${log}.new`;
    writeFileSync(replacement, entries.map((item) => `${JSON.stringify(item)}\n`).join(""), { mode: 0o600 });
    renameSync(replacement, log);
    return "replaced";
  }
  return "unchanged";
}

async function submit(options: Readonly<{
  state: string; socket: string; operationId: string; responses: string;
}>): Promise<Record<string, unknown>> {
  const state = options.state;
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const names = new Map(Object.entries(principalsOf(state, facts)).map(([name, principal]) => [principal, name]));
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
  const statuses = new Map(collection.statuses.map((item) => [names.get(item.approver) ?? item.approver, item]));
  const named = [...statuses.entries()];
  const approved = named.filter(([, item]) => item.status === "approved").map(([name]) => name).sort();
  const declined = named.filter(([, item]) => item.status === "declined").map(([name]) => name).sort();
  const silent = named.filter(([, item]) => item.status === "pending").map(([name]) => name).sort();
  const pendingCount = silent.length;
  Object.assign(record, { approved, pending: silent, required: collection.required });
  if (declined.length > 0) record.declined = declined;
  if (collection.approved < collection.required) {
    if (declined.length > 0 && collection.approved + pendingCount < collection.required) {
      // Too many managers declined for any later answer to make a quorum.
      return { ...record, outcome: "not-submitted", decided_by: "approver", reason: "approvers-declined" };
    }
    // No proof exists until `required` managers approved this exact request,
    // so nothing can be sent; this is not a policy refusal.
    return {
      ...record, outcome: "not-submitted", decided_by: "client", reason: "approvals-incomplete",
      waiting: Object.fromEntries(named.filter(([, item]) => item.status !== "approved")
        .map(([name, item]) => [name, item.code ?? item.status] as const)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))),
      unattributed: collection.unattributed.map(([index, code]) => [index, code]),
    };
  }
  // The agent signs its exact refund only now, and every assembled proof goes
  // to the gateway. Collection checks every approval statement byte for byte;
  // only the gateway decides the threshold, the ceiling, the count, and
  // whether the operation ID may run.
  const agent = (JSON.parse(readFileSync(join(state, "pending", `${options.operationId}.json`), "utf8")) as Pending)
    .agent;
  const action = await signApprovalAction(built, developmentSigner(agent, await roleKey(state, agent)), {
    grants: await agentGrants(state, agent),
  });
  const proof = collection.assemble(action);
  const gateway = new GatewayClient(new GatewayEndpoint(resolve(options.socket)));
  Object.assign(record, await gateway.submit({ proof, action: built.action }), { decided_by: "gateway" });
  const observation = await gateway.observeOutcome(options.operationId);
  const outcome = observation.outcome === "signed" ? observation.observation : null;
  record.bundle = recordEntry(join(state, "audit"), {
    operation_id: options.operationId,
    proof_b64: b64(proof),
    action_b64: b64(built.action),
    outcome_b64: outcome === null ? null : b64(outcome),
  });
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
    schema: "auths.gateway-audit-bundle/2",
    recipe_b64: b64(new Uint8Array(readFileSync(RECIPE))),
    profile_lock_b64: b64(new Uint8Array(readFileSync(PROFILE_LOCK))),
    trusted_context_b64: b64(new Uint8Array(readFileSync(join(options.state, "trust", "gateway.context.cbor")))),
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

const USAGE = [
  "usage: refunds.js setup|grant|request|submit|export --state DIR ...",
  "  request --required N: the threshold the requests name; defaults to the installed one. A lower value",
  "    is a hostile lever: approvals of it never count toward the installed threshold.",
  "  request --precheck: client-side pre-check, not an enforcement boundary: refuse before writing any",
  "    request when --required is below the threshold or the amount is above the ceiling that",
  "    setup.json records. The gateway enforces these rules whether or not the pre-check runs.",
].join("\n");

async function main(): Promise<void> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      state: { type: "string" },
      gateway: { type: "string", default: "auths-gateway" },
      ceiling: { type: "string" },
      "max-count": { type: "string" },
      "window-seconds": { type: "string" },
      "sum-limit": { type: "string" },
      currencies: { type: "string", default: "eur,usd" },
      "connect-account": { type: "string" },
      currency: { type: "string", default: "usd" },
      agent: { type: "string" },
      days: { type: "string" },
      socket: { type: "string" },
      "operation-id": { type: "string" },
      "payment-intent": { type: "string" },
      amount: { type: "string" },
      required: { type: "string" },
      responses: { type: "string" },
      out: { type: "string" },
      precheck: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });
  if (values.help === true) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }
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
        sumLimit: integer(values["sum-limit"], "sum-limit", 6_000),
        currencies: values.currencies!,
        connectAccount: values["connect-account"] ?? CONNECT_ACCOUNT,
      });
      break;
    case "grant":
      process.stdout.write(`${JSON.stringify(await grant({
        state,
        gateway: values.gateway!,
        agent: required(values.agent, "agent"),
        maxCount: integer(values["max-count"], "max-count"),
      }))}\n`);
      break;
    case "request":
      process.stdout.write(`${JSON.stringify(await request({
        state,
        operationId: required(values["operation-id"], "operation-id"),
        paymentIntent: required(values["payment-intent"], "payment-intent"),
        amount: integer(values.amount, "amount"),
        required: values.required === undefined ? undefined : integer(values.required, "required"),
        out: resolve(required(values.out, "out")),
        currency: values.currency!,
        connectAccount: values["connect-account"],
        agent: values.agent ?? "agent",
        precheck: values.precheck!,
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
      fail(USAGE);
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
