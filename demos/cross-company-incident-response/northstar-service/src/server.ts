import http from "node:http";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const port = Number(process.env.PORT ?? 7101);
const publicUrl = process.env.NORTHSTAR_PUBLIC_URL ?? `http://localhost:${port}`;
const statePath = process.env.NORTHSTAR_STATE_PATH ?? "/tmp/auths-incident-demo/northstar.json";
const allowOrigin = process.env.AUTHS_INCIDENT_ALLOWED_ORIGIN ?? "http://localhost:7100";
const serviceToken = process.env.AUTHS_INCIDENT_SERVICE_TOKEN ?? "";
const insecureLocal = process.env.AUTHS_INCIDENT_ALLOW_INSECURE_LOCAL === "1";

type CodeRecord = {
  sub: string;
  challenge: string;
  redirectUri: string;
  clientId: string;
  expiresAt: number;
};

type State = {
  outage: boolean;
  firewallApplied: boolean;
  approvals: number;
  providerCalls: number;
  codes: Record<string, CodeRecord>;
  timeline: Array<Record<string, unknown>>;
  oidcPrivateJwk: Record<string, unknown>;
  oidcPublicJwk: Record<string, unknown>;
};

function initialState(): State {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const privateJwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  return {
    outage: true,
    firewallApplied: false,
    approvals: 0,
    providerCalls: 0,
    codes: {},
    timeline: [],
    oidcPrivateJwk: { ...privateJwk, kid: "northstar-local-p256", alg: "ES256", use: "sig" },
    oidcPublicJwk: { ...publicJwk, kid: "northstar-local-p256", alg: "ES256", use: "sig" }
  };
}

function load(): State {
  if (!existsSync(statePath)) return persist(initialState());
  return JSON.parse(readFileSync(statePath, "utf8")) as State;
}

function persist(state: State): State {
  mkdirSync(dirname(statePath), { recursive: true });
  writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  return state;
}

function event(state: State, type: string, detail: string): void {
  state.timeline.push({ id: randomBytes(8).toString("hex"), at: new Date().toISOString(), company: "northstar", type, detail });
}

function base64url(value: any): string {
  return Buffer.from(value).toString("base64url");
}

function jwt(state: State, claims: Record<string, unknown>): string {
  const header = base64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "northstar-local-p256" }));
  const body = base64url(JSON.stringify(claims));
  const signature = sign("sha256", Buffer.from(`${header}.${body}`), {
    key: createPrivateKey({ key: state.oidcPrivateJwk, format: "jwk" }),
    dsaEncoding: "ieee-p1363"
  });
  return `${header}.${body}.${base64url(signature)}`;
}

function authenticateOidc(state: State, request: any): Record<string, unknown> | undefined {
  const authorization = String(request.headers.authorization ?? "");
  if (!authorization.startsWith("Bearer ")) return undefined;
  const token = authorization.slice(7);
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as Record<string, unknown>;
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
    const valid = header.alg === "ES256" && header.kid === "northstar-local-p256" && verify(
      "sha256",
      Buffer.from(`${parts[0]}.${parts[1]}`),
      { key: createPublicKey({ key: state.oidcPublicJwk, format: "jwk" }), dsaEncoding: "ieee-p1363" },
      Buffer.from(parts[2], "base64url")
    );
    const now = Math.floor(Date.now() / 1000);
    return valid && claims.iss === publicUrl && claims.aud === "auths-incident-agent" &&
      claims.sub === "northstar-commander" && typeof claims.exp === "number" && claims.exp >= now
      ? claims
      : undefined;
  } catch {
    return undefined;
  }
}

function json(response: any, status: number, body: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-headers": "content-type, authorization",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "cache-control": "no-store"
  });
  response.end(JSON.stringify(body));
}

async function body(request: any): Promise<Record<string, any>> {
  const chunks: any[] = [];
  for await (const chunk of request) chunks.push(chunk);
  if (chunks.length === 0) return {};
  const raw = Buffer.concat(chunks).toString("utf8");
  if ((request.headers["content-type"] ?? "").includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  return JSON.parse(raw) as Record<string, any>;
}

function internal(request: any): boolean {
  if (insecureLocal && request.socket.remoteAddress?.includes("127.0.0.1")) return true;
  return serviceToken.length >= 24 && request.headers.authorization === `Bearer ${serviceToken}`;
}

const actors = [
  {
    id: "northstar-commander",
    name: "Maya Chen",
    role: "Incident commander",
    organization: "Northstar Commerce",
    authentication: "OIDC authorization code + PKCE",
    principal: "webauthn:Hx8fHx8fHx8fHx8fHx8fHw",
    signingSuite: "p256-sha256-v1",
    lifecycle: "active",
    authority: "review and approve incident plan; no provider credential"
  },
  {
    id: "northstar-security",
    name: "Jon Bell",
    role: "Security engineer",
    organization: "Northstar Commerce",
    authentication: "OIDC authorization code + PKCE",
    principal: "webauthn:IyMjIyMjIyMjIyMjIyMjIw",
    signingSuite: "p256-sha256-v1",
    lifecycle: "active",
    authority: "inspect evidence and review exact firewall bytes"
  },
  {
    id: "northstar-diagnostic-agent",
    name: "Northstar Diagnostic",
    role: "Diagnostic agent",
    organization: "Northstar Commerce",
    authentication: "distinct agent principal",
    principal: "key:sha256:northstar-diagnostic-demo",
    signingSuite: "p256-sha256-v1",
    lifecycle: "active",
    authority: "read metrics/logs for northstar-fashion in eu-west-2; no execute"
  }
];

const server = http.createServer(async (request: any, response: any) => {
  try {
    if (request.method === "OPTIONS") return json(response, 204, {});
    const url = new URL(request.url ?? "/", publicUrl);
    let state = load();

    if (url.pathname === "/healthz") return json(response, 200, { status: "ok", service: "northstar", schema: "auths-incident-demo/1" });
    if (url.pathname === "/.well-known/openid-configuration") {
      return json(response, 200, {
        issuer: publicUrl,
        authorization_endpoint: `${publicUrl}/authorize`,
        token_endpoint: `${publicUrl}/token`,
        jwks_uri: `${publicUrl}/jwks.json`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["openid", "profile"]
      });
    }
    if (url.pathname === "/jwks.json") return json(response, 200, { keys: [state.oidcPublicJwk] });
    if (url.pathname === "/authorize" && request.method === "GET") {
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";
      const clientId = url.searchParams.get("client_id") ?? "";
      const challenge = url.searchParams.get("code_challenge") ?? "";
      if (url.searchParams.get("response_type") !== "code" || !redirectUri || !clientId || !challenge) {
        return json(response, 400, { error: "invalid_request" });
      }
      const loginHint = url.searchParams.get("login_hint") ?? "northstar-commander";
      if (loginHint !== "northstar-commander" && loginHint !== "northstar-security") {
        return json(response, 400, { error: "access_denied" });
      }
      const code = randomBytes(24).toString("base64url");
      state.codes[code] = { sub: loginHint, challenge, redirectUri, clientId, expiresAt: Date.now() + 120_000 };
      persist(state);
      const redirect = new URL(redirectUri);
      redirect.searchParams.set("code", code);
      redirect.searchParams.set("state", url.searchParams.get("state") ?? "");
      response.writeHead(302, { location: redirect.toString(), "cache-control": "no-store" });
      return response.end();
    }
    if (url.pathname === "/token" && request.method === "POST") {
      const input = await body(request);
      const record = state.codes[String(input.code ?? "")];
      const verifier = String(input.code_verifier ?? "");
      const actual = createHash("sha256").update(verifier).digest("base64url");
      if (!record || record.expiresAt < Date.now() || record.challenge !== actual || record.redirectUri !== input.redirect_uri) {
        return json(response, 400, { error: "invalid_grant" });
      }
      delete state.codes[String(input.code)];
      persist(state);
      const now = Math.floor(Date.now() / 1000);
      return json(response, 200, {
        token_type: "Bearer",
        expires_in: 300,
        access_token: jwt(state, { iss: publicUrl, sub: record.sub, aud: record.clientId, iat: now, exp: now + 300, scope: "openid profile" }),
        id_token: jwt(state, { iss: publicUrl, sub: record.sub, aud: record.clientId, iat: now, exp: now + 300, name: "Maya Chen" })
      });
    }
    if (url.pathname === "/api/actors") return json(response, 200, { actors });
    if (url.pathname === "/api/evidence") {
      return json(response, 200, {
        tenant: "northstar-fashion",
        region: "eu-west-2",
        metrics: { checkout_error_rate: state.outage ? 0.47 : 0.008, edge_403_rate: state.outage ? 0.39 : 0.003, origin_saturation: 0.31 },
        logs: ["edge policy v184 rejects signed checkout assets", "cache generation 991 retains stale deny metadata"],
        authority: "read-only: metrics/* and logs/edge for one tenant/region"
      });
    }
    if (url.pathname === "/api/approve" && request.method === "POST") {
      if (!authenticateOidc(state, request)) return json(response, 401, { code: "oidc-approval-authentication-required" });
      const input = await body(request);
      if (!input.requestId || !input.transactionDigest || !input.planCommitment) return json(response, 400, { code: "invalid-approval-request" });
      state.approvals += 1;
      event(state, "approval", "Northstar incident commander approved the exact plan commitment");
      persist(state);
      return json(response, 200, { decision: "approved", actor: actors[0], requestId: input.requestId, transactionDigest: input.transactionDigest });
    }
    if (url.pathname === "/api/firewall/apply" && request.method === "POST") {
      if (!internal(request)) return json(response, 401, { code: "northstar-service-auth-required" });
      const input = await body(request);
      if (input.incidentId !== "INC-2026-0811" || input.region !== "eu-west-2" || input.operation !== "apply-config") {
        return json(response, 403, { code: "closed-operation-mismatch" });
      }
      state.providerCalls += 1;
      if (state.firewallApplied) return json(response, 409, { code: "already-applied", providerCalls: state.providerCalls });
      state.firewallApplied = true;
      event(state, "effect", "Exact eu-west-2 firewall exception applied over HTTPS");
      persist(state);
      return json(response, 200, { outcome: "executed", revision: "fw-185", providerCalls: state.providerCalls, observed: true });
    }
    if (url.pathname === "/api/reset" && request.method === "POST") {
      if (!internal(request)) return json(response, 401, { code: "northstar-service-auth-required" });
      const fresh = initialState();
      fresh.oidcPrivateJwk = state.oidcPrivateJwk;
      fresh.oidcPublicJwk = state.oidcPublicJwk;
      state = persist(fresh);
      return json(response, 200, { reset: true });
    }
    return json(response, 404, { code: "not-found" });
  } catch {
    return json(response, 500, { code: "northstar-internal" });
  }
});

server.listen(port, "0.0.0.0", () => {
  process.stdout.write(`auths-incident-demo northstar listening on ${publicUrl}\n`);
});
