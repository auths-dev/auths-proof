// Exercises the packed TypeScript SDK against the reference stack.
//
// The previous version called `auths-sandbox-request` and asserted
// `issuer.create(...)` returned an authority. Both are gone, and deliberately:
// the node answers `create` and `delegate` with `core.unauthenticated-principal`
// because `ProductionRequest.identity` is unauthenticated bytes and there is no
// client authentication at that call site to require instead. That test
// asserted the fail-open the kernel rebuild removed.
//
// Authority originates from a trust anchor's signature and arrives inside the
// proof. `auths-local-authority` authors one offline against the same anchor
// the trusted context carries; the client imports it and calls `execute`, the
// only verb the node answers.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServiceClient, importAuthority } from "@auths-dev/sdk/service";
import {
  githubIssueAddress,
  opentofuSavedPlanApply,
  postgresqlBoundedUpdate,
} from "@auths-dev/sdk/profiles";

const directory = mkdtempSync(join(tmpdir(), "auths-reference-"));
const encode = (value) => new TextEncoder().encode(value);
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
  const authored = JSON.parse(
    execFileSync("auths-local-authority", [profile.id, actionPath, `reference-${name}-agent`], {
      encoding: "utf8",
    }),
  );

  const authority = importAuthority(decode(authored.proof));
  assert.equal(authority.kind, "authority");

  const client = createServiceClient({
    endpoint,
    identity: encode(`reference-${name}-agent`),
    profile,
  });
  const completed = await client.execute(authority, decode(authored.action));
  // Report WHY on refusal. A bare `expected completed, got denied` sends the
  // reader back to CI for another round trip; the code names the dimension.
  assert.equal(
    completed.kind,
    "completed",
    `${name}: ${completed.kind}${completed.code ? ` (${completed.code})` : ""}`,
  );

  const verified = await client.verify(completed.receipt);
  assert.equal(verified.kind, "verified");

  // The claim is keyed on (proof digest, action digest) and allows one effect,
  // so replaying the identical pair is refused rather than repeated.
  const replayed = await client.execute(authority, decode(authored.action));
  assert.equal(replayed.kind, "denied");
}

// A body marked recoverable leaves the effect outcome unknown, and resuming
// resolves it. `Indeterminate` exists precisely so a receipt can say so instead
// of asserting a failure that may have applied.
const recoverPath = join(directory, "recover.bin");
writeFileSync(recoverPath, "AUTHS-SANDBOX-RECOVER issue 104");
const recoveryProfile = githubIssueAddress();
const recovery = JSON.parse(
  execFileSync("auths-local-authority", [recoveryProfile.id, recoverPath, "reference-recovery-agent"], {
    encoding: "utf8",
  }),
);
const recoveryClient = createServiceClient({
  endpoint,
  identity: encode("reference-recovery-agent"),
  profile: recoveryProfile,
});
const unknown = await recoveryClient.execute(
  importAuthority(decode(recovery.proof)),
  decode(recovery.action),
);
assert.equal(
  unknown.kind,
  "recoverable",
  `recovery: ${unknown.kind}${unknown.code ? ` (${unknown.code})` : ""}`,
);
const resumed = await recoveryClient.resume(unknown.reference);
assert.equal(resumed.kind, "completed");

console.log("installed TypeScript SDK: reference stack contract satisfied");
