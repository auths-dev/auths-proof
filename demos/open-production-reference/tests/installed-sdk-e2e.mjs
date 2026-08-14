import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuths } from "@auths-dev/sdk";
import {
  githubIssueAddress,
  opentofuSavedPlanApply,
  postgresqlBoundedUpdate,
} from "@auths-dev/sdk/profiles";

const directory = mkdtempSync(join(tmpdir(), "auths-reference-"));
const decode = (value) => Uint8Array.from(Buffer.from(value, "base64url"));
const endpoint = process.env.AUTHS_REFERENCE_ENDPOINT ?? "https://localhost:8443";
const profiles = [
  ["opentofu", opentofuSavedPlanApply()],
  ["postgresql", postgresqlBoundedUpdate()],
  ["github", githubIssueAddress()],
];
for (const [name, profile] of profiles) {
  const actionPath = join(directory, `${name}.bin`);
  writeFileSync(actionPath, `exact ${name} operation`);
  const generated = JSON.parse(execFileSync("auths-sandbox-request", [actionPath], {encoding: "utf8"}));
  const identity = new TextEncoder().encode(`reference-${name}-human`);
  const agent = new TextEncoder().encode(`reference-${name}-agent`);
  const issuer = createAuths({endpoint, identity, profile});
  const authority = await issuer.create(decode(generated.request));
  assert.equal(authority.kind, "authority");
  const delegator = createAuths({endpoint, identity, profile});
  const delegated = await delegator.delegate(authority, agent, decode(generated.attenuation));
  assert.equal(delegated.kind, "authority");
  const agentClient = createAuths({endpoint, identity: agent, profile});
  const completed = await agentClient.execute(delegated, decode(generated.action));
  assert.equal(completed.kind, "completed");
  const verifier = createAuths({endpoint, identity: agent, profile});
  assert.equal((await verifier.verify(completed.receipt)).kind, "verified");
  assert.equal((await verifier.execute(delegated, decode(generated.action))).kind, "denied");
}

const recoverPath = join(directory, "recover.bin");
writeFileSync(recoverPath, "AUTHS-SANDBOX-RECOVER issue 104");
const recovery = JSON.parse(execFileSync("auths-sandbox-request", [recoverPath], {encoding: "utf8"}));
const recoveryProfile = githubIssueAddress();
const recoveryIdentity = new TextEncoder().encode("reference-recovery-human");
const recoveryAgent = new TextEncoder().encode("reference-recovery-agent");
const issuer = createAuths({endpoint, identity: recoveryIdentity, profile: recoveryProfile});
const delegator = createAuths({endpoint, identity: recoveryIdentity, profile: recoveryProfile});
const recoveryAuthority = await issuer.create(decode(recovery.request));
const recoveryDelegated = await delegator.delegate(
  recoveryAuthority,
  recoveryAgent,
  decode(recovery.attenuation),
);
const agentClient = createAuths({endpoint, identity: recoveryAgent, profile: recoveryProfile});
const unknown = await agentClient.execute(recoveryDelegated, decode(recovery.action));
assert.equal(unknown.kind, "recoverable");
const verifier = createAuths({endpoint, identity: recoveryAgent, profile: recoveryProfile});
const resumed = await verifier.resume(unknown.reference);
assert.equal(resumed.kind, "completed");
