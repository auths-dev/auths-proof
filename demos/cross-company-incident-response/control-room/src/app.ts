import type { CustodyDescriptor, CustodySigner } from "@auths-dev/sdk/adapters";
import {
  ApprovalRefused, approvalRequests, approve, collectApprovals, compileTrustedContext,
  decline, exactMcpTool, openApprovalRequest, proposeMcpApproval, signApprovalAction, stringField,
} from "@auths-dev/sdk/self-hosted";
import { developmentEd25519Key } from "@auths-dev/sdk/testkit";
import { createVerifier } from "@auths-dev/sdk/verify";

declare global {
  var AUTHS_INCIDENT_AGENT_API: string | undefined;
}

const api = globalThis.AUTHS_INCIDENT_AGENT_API ?? "http://localhost:7103";
const incidentId = "INC-2026-0811";

type Json = Record<string, any>;
let state: Json = {};
let proposal: Json = {};
let viewerToken = sessionStorage.getItem("auths.incident.viewer-token") ?? "";
let viewerGeneration = 0;
let refreshGeneration = 0;

const attacks = [
  ["byte-mutation", "Change firewall byte after approval"],
  ["replay", "Replay executed command"],
  ["expired", "Use expired grant"],
  ["rotate-key", "Rotate EdgeShield Ed25519 key"],
  ["unauthorized-iroh", "Deliver unauthorized bytes over Iroh"],
  ["remote-before", "Remote failure before execution"],
  ["remote-after", "Remote failure after execution"],
  ["remote-unknown", "Remote outcome unknown"],
  ["withdraw-approval", "Withdraw approval mid-plan"],
] as const;

async function request(path: string, options: RequestInit = {}, token = viewerToken): Promise<Json> {
  const response = await fetch(`${api}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(options.headers ?? {}),
    },
  });
  const body = await response.json() as Json;
  if (!response.ok) throw Object.assign(new Error(body.code ?? `HTTP ${response.status}`), { body });
  return body;
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
  const scope = viewerGeneration;
  const generation = ++refreshGeneration;
  const token = viewerToken;
  const current = () => scope === viewerGeneration && generation === refreshGeneration;
  try {
    const [nextState, nextProposal] = await Promise.all([
      request("/api/state", {}, token), request("/api/proposal", {}, token),
    ]);
    if (!current()) return;
    state = nextState;
    proposal = nextProposal;
    render();
  } catch (error) {
    if (!current()) return;
    clearReceiptView();
    element("receipt-access-status").textContent = "Receipt access unavailable.";
    throw error;
  }
}

function clearReceiptView(): void {
  // Remove retained disclosure as well as rendered evidence: another render
  // during login/failure must not revive the previous viewer's receipts.
  state = { ...state, receipts: [], receiptView: "opaque" };
  element("receipts").replaceChildren();
  element("receipt-access-status").textContent = "Receipt view changing…";
  document.querySelectorAll<HTMLButtonElement>("[data-receipt-role]").forEach((button) => button.classList.remove("active"));
}

function changeViewerScope(token: string): void {
  ++viewerGeneration;
  viewerToken = token;
  if (token) sessionStorage.setItem("auths.incident.viewer-token", token);
  else sessionStorage.removeItem("auths.incident.viewer-token");
  clearReceiptView();
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
  const receiptMode = String(state.receiptView ?? "opaque");
  element("receipt-access-status").textContent = {
    opaque: "Unauthenticated viewer · signatures and commitments verified · action and result withheld.",
    summary: "Northstar operator · profile-owned summary · exact command and result bytes remain protected.",
    full: "Northstar security auditor · verified summary plus explicit canonical evidence.",
  }[receiptMode] ?? "Receipt access unavailable.";
  document.querySelectorAll<HTMLButtonElement>("[data-receipt-role]").forEach((button) => {
    const expected = button.dataset.receiptRole === "public"
      ? "opaque"
      : button.dataset.receiptRole === "northstar-security" ? "full" : "summary";
    button.classList.toggle("active", expected === receiptMode);
  });
  element("receipts").innerHTML = receipts.length === 0
    ? `<div class="empty">No effects executed. Receipts will appear here.</div>`
    : receipts.map((receipt: Json, index: number) => renderReceipt(receipt, index)).join("");
}

function renderReceipt(receipt: Json, index: number): string {
  if (!receipt.receipt) {
    return `<article class="receipt"><div class="receipt-head"><h3>Plan member ${index + 1}</h3><span class="verified">RECEIPT PENDING</span></div><p class="receipt-meta">${escape(receipt.state)} · ${escape(receipt.outcome)}</p></article>`;
  }
  const metadata = receipt.receipt;
  const fields = receipt.summary?.fields ?? [];
  const summary = receipt.kind === "verified-opaque"
    ? `<div class="receipt-summary">
        <div class="receipt-field"><span>Profile</span><strong>${escape(metadata.profile?.id)} v${escape(metadata.profile?.version)}</strong></div>
        <div class="receipt-field"><span>Outcome</span><strong>${escape(metadata.outcome)}</strong></div>
        <div class="receipt-field"><span>Action</span><strong>withheld · commitment ${escape(String(metadata.commitments?.command ?? "").slice(0, 16))}…</strong></div>
        <div class="receipt-field"><span>Result</span><strong>withheld · digest only</strong></div>
      </div>`
    : `<div class="receipt-summary">${fields.map((field: Json) => `<div class="receipt-field"><span>${escape(field.label)}</span><strong>${escape(field.value)}</strong></div>`).join("")}</div>`;
  const evidence = receipt.mode === "full" && receipt.disclosure
    ? `<details><summary>Show exact canonical material and signed evidence</summary>
        <pre>${escape(JSON.stringify({
          command: canonicalMaterial(receipt.disclosure.command),
          result: canonicalMaterial(receipt.disclosure.result),
          signedReceipts: receipt.evidence,
        }, null, 2))}</pre>
      </details>`
    : "";
  return `<article class="receipt">
    <div class="receipt-head"><h3>Plan member ${index + 1}</h3><span class="verified">✓ RUST VERIFIED</span></div>
    <span class="receipt-mode">${escape(receipt.mode)} view</span>
    ${summary}
    <p class="receipt-meta">${escape(metadata.outcome)} · ${escape(new Date(Number(metadata.completedAt) * 1000).toISOString())}<br>
      signer <code>${escape(String(metadata.executionSigner?.principal ?? "").slice(0, 30))}…</code><br>
      receipt <code>${escape(String(metadata.executionReceiptId ?? "").slice(0, 24))}…</code></p>
    ${evidence}
  </article>`;
}

function canonicalMaterial(value: unknown): unknown {
  if (typeof value !== "string") return null;
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes(value));
  try { return JSON.parse(decoded); } catch { return decoded; }
}

async function runWorkflow(): Promise<void> {
  const button = element<HTMLButtonElement>("run");
  button.disabled = true;
  element("run-status").textContent = "Preparing a fresh deterministic incident…";
  try {
    await request("/api/reset", { method: "POST", body: "{}" });
    element("run-status").textContent = "Trusted backend is authorizing the exact plan…";
    const result = await request("/api/workflow/execute", {
      method: "POST",
      body: JSON.stringify({ incidentId, transport: "https" }),
    });
    for (const node of element("approval-state").querySelectorAll("strong")) {
      node.textContent = "approved · exact plan";
      node.classList.add("approved");
    }
    await refresh();
    element("run-status").textContent = `AUTHORIZED · ${result.authorization.length} opaque commands executed once at the trusted boundary`;
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
    const verifier = await createVerifier();
    const result = verifier.verify({ proof: bytes(fixture.proof), action: bytes(fixture.action), trustedContext: bytes(fixture.context) });
    const agrees = result.kind === fixture.python.kind && result.stage === fixture.python.stage && result.code === fixture.python.code;
    output.classList.toggle("ok", agrees);
    output.textContent = `${agrees ? "✓" : "✗"} PORTABLE FIXTURE · Python ${fixture.python.kind}/${fixture.python.code} · TypeScript ${result.kind}/${result.code} · P-256 WebAuthn root`;
    element("run-status").textContent = agrees ? "Python + TypeScript agree · ready" : "Cross-SDK mismatch";
  } catch (error) {
    output.textContent = `Cross-SDK verification unavailable: ${(error as Error).message}`;
  }
}

async function liveMutationAttack(): Promise<Json> {
  const fixture = await request("/api/fixture");
  const action = bytes(fixture.action);
  action[action.length - 1] = (action[action.length - 1] ?? 0) ^ 1;
  const result = (await createVerifier()).verify({ proof: bytes(fixture.proof), action, trustedContext: bytes(fixture.context) });
  const python = await request("/api/attack/byte-mutation", { method: "POST", body: "{}" });
  return { ...python, evidence: { python: python.evidence, typescript: { kind: result.kind, stage: result.stage, code: result.code } } };
}

async function withdrawalSigner(): Promise<CustodySigner> {
  const key = await developmentEd25519Key();
  const descriptor: CustodyDescriptor = Object.freeze({
    contract: "signer-custody/2", kind: "workload", adapterId: "incident.browser.development",
    principal: key.principal, signature: key.signature, keyVersion: "development-1",
    keyState: "active-current", lifecycle: "ephemeral",
  });
  let phase: "open" | "closed" = "open";
  const close = async () => { phase = "closed"; };
  return {
    descriptor,
    async sign(request) {
      if (phase === "closed" || request.signal.aborted) return { kind: "rejected", failure: "cancelled" };
      const signature = await key.sign(request.signingPreimage);
      if (phase !== "open" || request.signal.aborted) return { kind: "rejected", failure: "cancelled" };
      return { kind: "signed", response: {
        requestId: request.requestId, objectId: request.objectId.slice(), principal: key.principal,
        descriptor: key.signature, providerKeyVersion: descriptor.keyVersion,
        transactionDigest: request.transactionDigest.slice(), signature, evidence: [key.evidence],
      } };
    },
    close,
    [Symbol.asyncDispose]: close,
  };
}

async function liveWithdrawalAttack(): Promise<Json> {
  const actor = await withdrawalSigner();
  const approver = await withdrawalSigner();
  try {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const contract = exactMcpTool({ service: "incident-withdrawal", name: "review_step",
      fields: { step: stringField({ minBytes: 1, maxBytes: 64 }) } });
    const approvers = [approver.descriptor.principal];
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const build = (step: string) => proposeMcpApproval({ contract, command: { step }, required: 1,
      approvers, actor: actor.descriptor.principal, challenge, evaluationTime: now, validitySeconds: 60 });
    const first = await build("firewall-eu-west-2");
    const firstRequest = (await approvalRequests(first))[0];
    if (!firstRequest) throw new Error("Native approval request missing");
    const firstReview = await openApprovalRequest(firstRequest.data, { now });
    const firstApproval = await approve(firstReview, approver);
    const firstCollection = await collectApprovals(first, [firstApproval.data]);
    const firstProof = firstCollection.assemble(await signApprovalAction(first, actor));
    const audience = "mcp://incident-withdrawal";
    const trustedContext = await compileTrustedContext({
      anchors: [{ id: "browser-demo-actor", principal: actor.descriptor.principal,
        acceptedMethods: ["raw-key-v1"], profiles: [{ id: "auths.mcp", version: 2 }],
        permissions: [{ capability: "tools/call", resource: `${audience}/tools/review_step` }],
        resourceNamespaces: [audience], audiences: [audience], notBefore: now, expiresAt: now + 60n,
        maxDelegationDepth: 0, assurancePolicy: "browser-withdrawal" }],
      assurance: { id: "browser-withdrawal", requirements: [
        { role: "root", quantifier: "every", claim: "self-certifying-identifier" },
        { role: "actor", quantifier: "every", claim: "self-certifying-identifier" },
        { role: "actor", quantifier: "every", claim: "offline-verifiable" },
      ] },
      evidenceTypes: ["raw-key-v1"],
      approverAnchors: approvers.map((principal) => ({ principal, acceptedMethods: ["raw-key-v1"], notBefore: now, expiresAt: now + 60n })),
      approvalRequirements: [{ approvers, threshold: 1 }],
      request: { audience, challenge, evaluationTime: now },
    });
    const verifier = await createVerifier();
    const firstDecision = verifier.verify({ proof: firstProof, action: first.action, trustedContext });
    if (firstDecision.kind !== "authorized") throw new Error(`First approval did not verify: ${firstDecision.code}`);

    const second = await build("cache-eu-west-2");
    const secondRequest = (await approvalRequests(second))[0];
    if (!secondRequest) throw new Error("Native approval request missing");
    const secondReview = await openApprovalRequest(secondRequest.data, { now });
    const refusal = await decline(secondReview, approver, { now });
    const secondCollection = await collectApprovals(second, [refusal.data]);
    const secondAction = await signApprovalAction(second, actor);
    try {
      secondCollection.assemble(secondAction);
      return { attack: "withdraw-approval", blocked: false, code: "unexpected-authorized" };
    } catch (error) {
      if (!(error instanceof ApprovalRefused) || error.code !== "approval.incomplete") throw error;
      // Rechecking the original exact proof demonstrates that refusing a later
      // action neither erases its earlier approval nor claims a provider effect.
      const retained = verifier.verify({ proof: firstProof, action: first.action, trustedContext });
      return { attack: "withdraw-approval", blocked: retained.kind === "authorized" && !secondCollection.isComplete,
        stage: "approval", code: error.code,
        detail: "The first exact action remains approved; a signed decline prevents a proof for the second. No provider calls were made by this browser check.",
        evidence: { approvedSteps: ["firewall-eu-west-2"], unresolved: ["cache-eu-west-2"], providerCalls: 0,
          firstDecision: retained.kind, secondApproved: secondCollection.approved,
          secondStatuses: secondCollection.statuses.map(({ approver, status }) => ({ approver, status })),
          firstProof: base64Url(firstProof), decline: refusal.text, sdk: "TypeScript native remote approval" } };
    }
  } finally {
    await approver.close();
    await actor.close();
  }
}

async function runAttack(id: string): Promise<void> {
  const output = element("attack-output");
  output.textContent = "RUNNING REAL SDK PATH…";
  try {
    let result: Json;
    if (id === "byte-mutation") result = await liveMutationAttack();
    else if (id === "withdraw-approval") result = await liveWithdrawalAttack();
    else result = await request(`/api/attack/${id}`, { method: "POST", body: "{}" });
    output.innerHTML = `<span class="${result.blocked ? "blocked" : "failed"}">${result.blocked ? "BLOCKED" : "NOT BLOCKED"} · ${escape(result.stage)} / ${escape(result.code)}</span>\n${escape(result.detail)}\n\n${escape(JSON.stringify(result.evidence, null, 2))}`;
    if (id === "rotate-key") await refresh();
  } catch (error) {
    output.innerHTML = `<span class="failed">ATTACK LAB ERROR</span>\n${escape((error as Error).message)}`;
  }
}

function wire(): void {
  element("attack-grid").innerHTML = attacks.map(([id, label]) => `<button data-attack="${id}">${label}</button>`).join("");
  element("attack-grid").addEventListener("click", (event) => {
    const target = (event.target as HTMLElement).closest<HTMLButtonElement>("[data-attack]");
    if (target?.dataset.attack) void runAttack(target.dataset.attack);
  });
  element("run").addEventListener("click", () => void runWorkflow());
  element("reset").addEventListener("click", async () => {
    await request("/api/reset", { method: "POST", body: "{}" });
    for (const node of element("approval-state").querySelectorAll("strong")) { node.textContent = "pending"; node.classList.remove("approved"); }
    await refresh();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-org]").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll("[data-org]").forEach((node) => node.classList.remove("active"));
    button.classList.add("active");
    document.body.dataset.org = button.dataset.org;
  }));
  document.querySelectorAll<HTMLButtonElement>("[data-receipt-role]").forEach((button) => button.addEventListener("click", () => {
    const role = button.dataset.receiptRole;
    if (role === "public") {
      changeViewerScope("");
      sessionStorage.removeItem("auths.incident.viewer-role");
      void refresh().catch(() => { /* the matching refresh owns its error view */ });
      return;
    }
    if (role) void beginViewerLogin(role);
  }));
}

async function beginViewerLogin(subject: string): Promise<void> {
  changeViewerScope("");
  const scope = viewerGeneration;
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  if (scope !== viewerGeneration) return;
  const oauthState = base64Url(crypto.getRandomValues(new Uint8Array(24)));
  sessionStorage.setItem("auths.incident.pkce-verifier", verifier);
  sessionStorage.setItem("auths.incident.oauth-state", oauthState);
  sessionStorage.setItem("auths.incident.viewer-role", subject);
  const redirectUri = `${location.origin}${location.pathname}`;
  const authorize = new URL("/authorize", String(state.identityProvider));
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: "auths-incident-control-room",
    redirect_uri: redirectUri,
    scope: "openid profile",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: oauthState,
    login_hint: subject,
  }).toString();
  location.assign(authorize);
}

async function completeViewerLogin(): Promise<void> {
  const scope = viewerGeneration;
  const query = new URLSearchParams(location.search);
  const code = query.get("code");
  if (!code) return;
  const expectedState = sessionStorage.getItem("auths.incident.oauth-state");
  const verifier = sessionStorage.getItem("auths.incident.pkce-verifier");
  if (!expectedState || query.get("state") !== expectedState || !verifier) {
    throw new Error("Northstar OIDC callback did not match this browser session");
  }
  let response: Response;
  let token: Json;
  try {
    response = await fetch(new URL("/token", String(state.identityProvider)), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "auths-incident-control-room",
        redirect_uri: `${location.origin}${location.pathname}`,
        code,
        code_verifier: verifier,
      }),
    });
    token = await response.json() as Json;
  } catch (error) {
    if (scope !== viewerGeneration) return;
    throw error;
  }
  if (scope !== viewerGeneration) return;
  if (!response.ok || typeof token.access_token !== "string") throw new Error("Northstar OIDC login failed");
  changeViewerScope(token.access_token);
  sessionStorage.removeItem("auths.incident.pkce-verifier");
  sessionStorage.removeItem("auths.incident.oauth-state");
  history.replaceState({}, "", location.pathname);
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function bootstrap(): Promise<void> {
  await refresh();
  await completeViewerLogin();
  if (viewerToken) await refresh();
  await crossVerify();
}

wire();
await bootstrap();
