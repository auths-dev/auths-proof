/**
 * Stripe refunds an AI agent may request only with two of three manager
 * approvals and inside a per-agent limit, submitted through the Auths gateway,
 * from the npm package. The commands and state directory match ../refunds.py:
 *
 *   node build/refunds.js setup  --state DIR --gateway auths-gateway
 *   node build/refunds.js refund --state DIR --socket SOCK --operation-id ID \
 *                                           --payment-intent PI --amount CENTS --approvers a,b
 *   node build/refunds.js export --state DIR --out audit-bundle.json
 *
 * Everything here uses development keys stored under DIR/keys so one person
 * can play every role. In production the root and each manager sign through
 * their own custody adapters, and the agent never holds the managers' keys.
 * The Stripe secret key never enters this program: only the gateway holds it.
 */

import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import type {
  CustodyDescriptor, CustodySigner, CustodySignResult, SigningRequest,
} from "@auths-dev/sdk/adapters";
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";
import {
  AuthoringUnsuccessful, authorMcpQuorumProof, authorRootGrant, compileTrustedContext,
  type AssurancePolicy, type QuorumApprover, type TrustAnchor,
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

async function refund(options: Readonly<{
  state: string; socket: string; operationId: string; paymentIntent: string; amount: number;
  approvers: string; localTrust: string | undefined;
}>): Promise<Record<string, unknown>> {
  const state = options.state;
  const facts = JSON.parse(readFileSync(join(state, "setup.json"), "utf8")) as SetupFacts;
  const managers = options.approvers.split(",").filter((name) => name.length > 0);
  if (!managers.every((name) => (MANAGERS as readonly string[]).includes(name)) ||
      new Set(managers).size !== managers.length) {
    fail(`approvers must be distinct names from ${MANAGERS.join(", ")}`);
  }
  const command: CreateRefund = {
    operator_namespace: "stripe-refunds",
    operation_id: options.operationId,
    recipe_digest: facts.recipe_digest,
    payment_intent: options.paymentIntent,
    amount: options.amount,
  };
  const root = await roleKey(state, "root");
  const agent: QuorumApprover = {
    signer: developmentSigner("agent", await roleKey(state, "agent")),
    grants: [{
      signedGrant: new Uint8Array(readFileSync(join(state, "agent.grant.cbor"))),
      evidence: [root.evidence],
    }],
  };
  const approvers: QuorumApprover[] = [agent];
  for (const name of managers) approvers.push({ signer: developmentSigner(name, await roleKey(state, name)) });
  const localTrust = options.localTrust ?? join(state, "trust", "sdk.context.cbor");
  const record: Record<string, unknown> = { operation_id: options.operationId, amount: options.amount };
  let authored;
  try {
    // The agent and every listed manager sign the same exact refund.
    authored = await authorMcpQuorumProof({
      contract: CONTRACT,
      command,
      required: approvers.length,
      approvers,
      trustedContextTemplate: new Uint8Array(readFileSync(localTrust)),
      challenge: hexBytes(facts.challenge_hex),
      evaluationTime: unixNow(),
    });
  } catch (error) {
    if (!(error instanceof AuthoringUnsuccessful)) throw error;
    return { ...record, stage: "authoring", outcome: "refused-locally", code: error.code };
  }
  const gateway = new GatewayClient(new GatewayEndpoint(resolve(options.socket)));
  Object.assign(record, await gateway.submit({ proof: authored.proof, action: authored.action }));
  const observation = await gateway.observeOutcome(options.operationId);
  const outcome = observation.outcome === "signed" ? observation.observation : null;
  const entry = {
    operation_id: options.operationId,
    proof_b64: b64(authored.proof),
    action_b64: b64(authored.action),
    outcome_b64: outcome === null ? null : b64(outcome),
  };
  mkdirSync(join(state, "audit"), { recursive: true, mode: 0o700 });
  appendFileSync(join(state, "audit", "entries.jsonl"), `${JSON.stringify(entry)}\n`, { mode: 0o600 });
  return record;
}

function exportBundle(options: Readonly<{ state: string; out: string }>): void {
  const log = join(options.state, "audit", "entries.jsonl");
  const entries = readFileSync(log, "utf8").split("\n").filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as unknown);
  const bundle = {
    schema: "auths.gateway-audit-bundle/1",
    recipe_b64: b64(readFileSync(RECIPE)),
    profile_lock_b64: b64(readFileSync(PROFILE_LOCK)),
    trusted_context_b64: b64(readFileSync(join(options.state, "trust", "gateway.context.cbor"))),
    entries,
  };
  writeFileSync(options.out, `${JSON.stringify(bundle, null, 1)}\n`);
  process.stdout.write(`wrote ${options.out} with ${entries.length} submissions\n`);
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
      "local-trust": { type: "string" },
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
    case "refund":
      process.stdout.write(`${JSON.stringify(await refund({
        state,
        socket: required(values.socket, "socket"),
        operationId: required(values["operation-id"], "operation-id"),
        paymentIntent: required(values["payment-intent"], "payment-intent"),
        amount: integer(values.amount, "amount"),
        approvers: required(values.approvers, "approvers"),
        localTrust: values["local-trust"],
      }))}\n`);
      break;
    case "export":
      exportBundle({ state, out: resolve(required(values.out, "out")) });
      break;
    default:
      fail("usage: refunds.js setup|refund|export --state DIR ...");
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
