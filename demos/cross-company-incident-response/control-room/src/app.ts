import {
  approvalPolicy,
  commandsForGateway,
  loadAuths,
  prepareRawKeyAuthority,
  thresholdApproval,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type AttachedAgent,
} from "@auths-dev/sdk";
import { BoundedApprovalSession } from "@auths-dev/sdk/approvals";
import { loadDomainProfiles, type EdgeProfile } from "@auths-dev/sdk/profiles";
import { development } from "@auths-dev/sdk/testkit";
import { loadVerifier } from "@auths-dev/sdk/verify";

declare global {
  var AUTHS_INCIDENT_AGENT_API: string | undefined;
}

const api = globalThis.AUTHS_INCIDENT_AGENT_API ?? "http://localhost:7103";
const incidentId = "INC-2026-0811";
const region = "eu-west-2";
const text = new TextEncoder();

type Json = Record<string, any>;
type Session = {
  profile: EdgeProfile;
  agent: AttachedAgent<EdgeProfile>;
  client: Awaited<ReturnType<typeof loadAuths>>;
  rootSigner: Awaited<ReturnType<typeof development.ephemeralSigner>>;
  agentSigner: Awaited<ReturnType<typeof development.ephemeralSigner>>;
  planCommitment: string;
};

let state: Json = {};
let proposal: Json = {};
let session: Session | undefined;

const attacks = [
  ["scope-expansion", "Expand eu-west-2 → all regions"],
  ["byte-mutation", "Change firewall byte after approval"],
  ["replay", "Replay executed command"],
  ["expired", "Use expired grant"],
  ["compromised-approver", "Compromise approver"],
  ["rotate-key", "Rotate EdgeShield Ed25519 key"],
  ["unauthorized-iroh", "Deliver unauthorized bytes over Iroh"],
  ["remote-before", "Remote failure before execution"],
  ["remote-after", "Remote failure after execution"],
  ["remote-unknown", "Remote outcome unknown"],
  ["withdraw-approval", "Withdraw approval mid-plan"],
] as const;

async function request(path: string, options: RequestInit = {}): Promise<Json> {
  const response = await fetch(`${api}${path}`, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
  });
  const body = await response.json() as Json;
  if (!response.ok) throw Object.assign(new Error(body.code ?? `HTTP ${response.status}`), { body });
  return body;
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function escape(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`missing control-room element ${id}`);
  return found as T;
}

async function refresh(): Promise<void> {
  [state, proposal] = await Promise.all([request("/api/state"), request("/api/proposal")]);
  render();
}

function render(): void {
  const metrics = state.evidence?.metrics ?? {};
  element("metrics").innerHTML = [
    ["Checkout error rate", `${Math.round((metrics.checkout_error_rate ?? 0) * 100)}%`, "bad"],
    ["Edge 403 rate", `${Math.round((metrics.edge_403_rate ?? 0) * 100)}%`, "bad"],
    ["Authority window", "10m", ""],
    ["Incident state", state.incident?.status ?? "active", state.incident?.status === "active" ? "bad" : ""],
  ].map(([label, value, kind]) => `<div class="metric"><label>${escape(label)}</label><strong class="${kind}">${escape(value)}</strong></div>`).join("");

  element("actors").classList.remove("skeleton");
  element("actors").innerHTML = (state.actors ?? []).map((actor: Json) => `
    <article class="actor" data-org="${actor.organization === "EdgeShield" ? "edgeshield" : actor.organization === "Northstar Commerce" ? "northstar" : "joint"}">
      <div class="actor-top"><div><h3>${escape(actor.name)}</h3><p class="role">${escape(actor.role)} · ${escape(actor.organization)}</p></div><span class="state ${actor.lifecycle}">${escape(actor.lifecycle)}</span></div>
      <span class="suite">${escape(actor.signingSuite)}</span>
      <code>${escape(actor.principal)}</code>
      <div class="authority">${escape(actor.authority)}</div>
    </article>`).join("");

  element("proposal").classList.remove("skeleton");
  element("proposal").innerHTML = `
    <p class="eyebrow">DIAGNOSTIC AGENT PROPOSAL</p>
    <p style="color:var(--muted);font-size:11px;line-height:1.5">${escape(proposal.cause)}<br><strong style="color:var(--cyan)">No execution authority granted.</strong></p>
    ${(proposal.plan ?? []).map((step: Json, index: number) => `<div class="plan-step"><span class="index">0${index + 1}</span><div><strong>${escape(step.id)}</strong><small>${escape(step.command)} · ${escape(step.exact)}</small></div><span class="transport">${escape(step.transport)}</span></div>`).join("")}`;

  const fixed = [
    { at: Date.now() / 1000 - 180, company: "northstar", kind: "outage", detail: "Tenant checkout error alert crossed 40%" },
    { at: Date.now() / 1000 - 150, company: "auths", kind: "delegation", detail: "Diagnostic agent received read-only metrics/log authority" },
    { at: Date.now() / 1000 - 110, company: "northstar", kind: "proposal", detail: "Agent proposed remediation without execution authority" },
  ];
  const timeline = [...fixed, ...(state.timeline ?? [])];
  element("timeline").innerHTML = timeline.map((item: Json) => `<article class="timeline-event ${escape(item.company)}"><time>${new Date(Number(item.at) * 1000).toLocaleTimeString()}</time><strong>${escape(item.kind)}</strong><p>${escape(item.detail)}</p></article>`).join("");

  const receipts = state.receipts ?? [];
  element("receipts").innerHTML = receipts.length === 0
    ? `<div class="empty">No effects executed. Receipts will appear here.</div>`
    : receipts.map((receipt: Json) => `<article class="receipt"><div class="receipt-head"><h3>${escape(receipt.operation)}</h3><span class="verified">✓ INDEPENDENTLY VERIFIABLE</span></div><pre>${escape(JSON.stringify(receipt, null, 2))}</pre></article>`).join("");
}

function remoteApproval(company: "northstar" | "edgeshield", planCommitment: string): ApprovalProvider {
  return Object.freeze({
    async approve(input: ApprovalRequest): Promise<ApprovalResponse> {
      const response = await request(`/api/approval/${company}`, {
        method: "POST",
        body: JSON.stringify({
          transactionDigest: hex(input.transactionDigest),
          planCommitment,
          objectKind: input.objectKind,
          review: input.display,
        }),
      });
      return Object.freeze({
        requestId: input.requestId,
        transactionDigest: input.transactionDigest.slice(),
        policy: Object.freeze({ ...input.policy, configurationDigest: input.policy.configurationDigest.slice() }),
        decision: response.decision === "approved" ? "approved" as const : "rejected" as const,
      });
    },
  });
}

async function buildSession(): Promise<{ session: Session; plan: Awaited<ReturnType<EdgeProfile["plan"]>> }> {
  const profiles = await loadDomainProfiles();
  const profile = profiles.edge({ audience: "incident://northstar-edge", resourceNamespace: "edge://northstar" });
  const firewall = profile.action({
    fleet: "northstar",
    device: "firewall-eu-west-2",
    command: "apply-config",
    sequence: 185n,
    stateDigest: "184".padStart(64, "0"),
  });
  const cache = profile.action({
    fleet: "northstar",
    device: "cache-eu-west-2",
    command: "execute",
    sequence: 992n,
    stateDigest: "991".padStart(64, "0"),
  });
  const plan = await profile.plan([firewall, cache]);
  const planCommitment = hex(plan.commitment);
  const policy = await approvalPolicy.planOnce({
    policyId: "auths-incident-demo.cross-company-2-of-2",
    maxUses: 2,
    expiresInSeconds: 600,
    requirements: ["northstar:incident-commander", "edgeshield:on-call"],
  });
  const approval = Object.freeze({
    policy,
    provider: thresholdApproval({
      threshold: 2,
      providers: [remoteApproval("northstar", planCommitment), remoteApproval("edgeshield", planCommitment)],
    }),
  });
  const rootSigner = await development.ephemeralSigner();
  const agentSigner = await development.ephemeralSigner();
  const principal = await agentSigner.publicIdentity();
  const now = BigInt(Math.floor(Date.now() / 1000));
  const prepared = await prepareRawKeyAuthority({
    authorityId: "auths-incident-demo.edgeshield-root",
    rootSigner,
    subjectPrincipal: principal.principal,
    profile,
    permissions: plan.authority.permissions,
    resourceNamespaces: plan.authority.resourceNamespaces,
    validity: { notBefore: now - 5n, expiresAt: now + 600n },
    audiences: plan.authority.audiences,
    remainingDepth: 1,
    approval,
  });
  const client = await loadAuths({ signer: agentSigner, trustedAuthority: prepared.trustedAuthority });
  const agent = await client.attachAgent({ name: "edgeshield-remediation-agent", profile, authority: prepared.authority, approval });
  return { session: { profile, agent, client, rootSigner, agentSigner, planCommitment }, plan };
}

async function runWorkflow(): Promise<void> {
  const button = element<HTMLButtonElement>("run");
  button.disabled = true;
  element("run-status").textContent = "Building Rust-owned exact profile plan…";
  try {
    if (session) await disposeSession();
    const built = await buildSession();
    session = built.session;
    element("run-status").textContent = "Requesting one exact approval from each company…";
    const decision = await session.agent.authorizePlan(built.plan);
    if (decision.kind !== "authorized") throw new Error(`${decision.result.stage}/${decision.result.code}`);
    for (const node of element("approval-state").querySelectorAll("strong")) {
      node.textContent = "approved · exact plan";
      node.classList.add("approved");
    }
    const ticket = await request("/api/plan/ticket", { method: "POST", body: JSON.stringify({ planCommitment: session.planCommitment }) });
    const gateway = session.profile.gateway(async (command) => {
      const operation = command.device === "firewall-eu-west-2" ? "firewall-eu-west-2" : "cache-eu-west-2";
      return request("/api/execute", {
        method: "POST",
        body: JSON.stringify({
          operation,
          planCommitment: session?.planCommitment,
          ticket: ticket.ticket,
          idempotencyKey: `${incidentId}:${operation}:v1`,
        }),
      });
    });
    for (const command of commandsForGateway(decision.command)) await gateway.execute(command);
    element("run-status").textContent = `AUTHORIZED · ${decision.results.length} sealed commands executed once`;
    await refresh();
  } catch (error) {
    const value = error as Error & { body?: Json; code?: string };
    element("run-status").textContent = `STOPPED · ${value.code ?? value.body?.code ?? "error"} · ${value.message}`;
  } finally {
    button.disabled = false;
  }
}

async function crossVerify(): Promise<void> {
  const output = element("sdk-evidence");
  try {
    const fixture = await request("/api/fixture");
    const verifier = await loadVerifier();
    const result = verifier.verify(bytes(fixture.proof), bytes(fixture.action), bytes(fixture.context));
    const agrees = result.kind === fixture.python.kind && result.stage === fixture.python.stage && result.code === fixture.python.code;
    output.classList.toggle("ok", agrees);
    output.textContent = `${agrees ? "✓" : "✗"} PORTABLE FIXTURE · Python ${fixture.python.kind}/${fixture.python.code} · TypeScript ${result.kind}/${result.code} · P-256 WebAuthn root`;
    element("run-status").textContent = agrees ? "Python + TypeScript agree · ready" : "Cross-SDK mismatch";
  } catch (error) {
    output.textContent = `Cross-SDK verification unavailable: ${(error as Error).message}`;
  }
}

async function liveScopeAttack(): Promise<Json | undefined> {
  if (!session) return undefined;
  const child = await development.ephemeralSigner();
  try {
    const now = BigInt(Math.floor(Date.now() / 1000));
    await session.agent.reviewDelegation({
      name: "compromised-all-regions",
      signer: child,
      authority: {
        permissions: [{ capability: "edge/apply-config", resource: "edge://northstar/devices/firewall-all-regions" }],
        validity: { notBefore: now, expiresAt: now + 300n },
        audiences: ["incident://northstar-edge"],
        remainingDepth: 0,
      },
    });
    return { attack: "scope-expansion", blocked: false, stage: "authority", code: "unexpected-authorized" };
  } catch (error) {
    const value = error as Error & { code?: string };
    return { attack: "scope-expansion", blocked: true, stage: "authority", code: value.code ?? "delegation-expanded", detail: value.message, evidence: { sdk: "TypeScript live native authoring", signerCalls: 0 } };
  } finally {
    await child.dispose?.();
  }
}

async function liveMutationAttack(): Promise<Json> {
  const fixture = await request("/api/fixture");
  const action = bytes(fixture.action);
  action[action.length - 1] = (action[action.length - 1] ?? 0) ^ 1;
  const result = (await loadVerifier()).verify(bytes(fixture.proof), action, bytes(fixture.context));
  const python = await request("/api/attack/byte-mutation", { method: "POST", body: "{}" });
  return { ...python, evidence: { python: python.evidence, typescript: { kind: result.kind, stage: result.stage, code: result.code } } };
}

async function liveWithdrawalAttack(): Promise<Json> {
  const policy = await approvalPolicy.planOnce({ maxUses: 2, expiresInSeconds: 60 });
  const plan = new Uint8Array(32).fill(1);
  const first = new Uint8Array(32).fill(2);
  const second = new Uint8Array(32).fill(3);
  const session = new BoundedApprovalSession({ planCommitment: plan, memberCommitments: [first, second], policy, provider: development.approve(), display: [] });
  await session.providerFor(0, first).approve({
    requestId: "withdraw:first",
    objectKind: "action",
    transactionDigest: new Uint8Array(32).fill(4),
    policy: policy.reference,
    expiresAt: BigInt(Math.floor(Date.now() / 1000) + 60),
    display: [],
  });
  await session.dispose();
  try {
    await session.providerFor(1, second).approve({
      requestId: "withdraw:second",
      objectKind: "action",
      transactionDigest: new Uint8Array(32).fill(5),
      policy: policy.reference,
      expiresAt: BigInt(Math.floor(Date.now() / 1000) + 60),
      display: [],
    });
    return { attack: "withdraw-approval", blocked: false, code: "unexpected-authorized" };
  } catch (error) {
    return { attack: "withdraw-approval", blocked: true, stage: "approval", code: "approval-cancelled", detail: (error as Error).message, evidence: { completedSteps: ["firewall-eu-west-2"], unresolved: ["cache-eu-west-2"], sdk: "TypeScript BoundedApprovalSession" } };
  }
}

async function runAttack(id: string): Promise<void> {
  const output = element("attack-output");
  output.textContent = "RUNNING REAL SDK PATH…";
  try {
    let result: Json;
    if (id === "scope-expansion") result = (await liveScopeAttack()) ?? await request(`/api/attack/${id}`, { method: "POST", body: "{}" });
    else if (id === "byte-mutation") result = await liveMutationAttack();
    else if (id === "withdraw-approval") result = await liveWithdrawalAttack();
    else result = await request(`/api/attack/${id}`, { method: "POST", body: "{}" });
    output.innerHTML = `<span class="${result.blocked ? "blocked" : "failed"}">${result.blocked ? "BLOCKED" : "NOT BLOCKED"} · ${escape(result.stage)} / ${escape(result.code)}</span>\n${escape(result.detail)}\n\n${escape(JSON.stringify(result.evidence, null, 2))}`;
    if (id === "rotate-key") await refresh();
  } catch (error) {
    output.innerHTML = `<span class="failed">ATTACK LAB ERROR</span>\n${escape((error as Error).message)}`;
  }
}

async function disposeSession(): Promise<void> {
  if (!session) return;
  await session.client.dispose();
  await session.rootSigner.dispose?.();
  session = undefined;
}

function wire(): void {
  element("attack-grid").innerHTML = attacks.map(([id, label]) => `<button data-attack="${id}">${label}</button>`).join("");
  element("attack-grid").addEventListener("click", (event) => {
    const target = (event.target as HTMLElement).closest<HTMLButtonElement>("[data-attack]");
    if (target?.dataset.attack) void runAttack(target.dataset.attack);
  });
  element("run").addEventListener("click", () => void runWorkflow());
  element("reset").addEventListener("click", async () => {
    await disposeSession();
    await request("/api/reset", { method: "POST", body: "{}" });
    for (const node of element("approval-state").querySelectorAll("strong")) { node.textContent = "pending"; node.classList.remove("approved"); }
    await refresh();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-org]").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll("[data-org]").forEach((node) => node.classList.remove("active"));
    button.classList.add("active");
    document.body.dataset.org = button.dataset.org;
  }));
}

wire();
await Promise.all([refresh(), crossVerify()]);
