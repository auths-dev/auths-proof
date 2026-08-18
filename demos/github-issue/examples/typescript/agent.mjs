import assert from "node:assert/strict";
import { createGitHubAgentClient } from "@auths-dev/sdk/service";

const endpoint = required("AUTHS_GITHUB_AGENT_ENDPOINT");
const client = createGitHubAgentClient({ endpoint });
const boundary = await client.boundary();
const session = await client.delegate({
  repository: boundary.repository,
  issueNumber: boundary.issueNumber,
  baseRef: boundary.baseRef,
  baseRevision: boundary.baseRevision,
  allowedPaths: boundary.allowedPaths,
  protectedPaths: boundary.protectedPaths,
  expiresInSeconds: boundary.maximumExpirySeconds,
  branchBudget: 1,
  draftPullRequestBudget: 1,
  agentLabel: process.env.AUTHS_AGENT_LABEL ?? "launch-agent",
});

const fixture = process.env.AUTHS_GITHUB_FIXTURE;
const inspection = fixture
  ? await client.inspectFixture(session, fixture)
  : await client.inspectCandidate(session, {
      path: required("AUTHS_GITHUB_CANDIDATE_BUNDLE"),
      baseRevision: boundary.baseRevision,
      candidateRevision: required("AUTHS_GITHUB_CANDIDATE_REVISION"),
    });

console.log("candidate", inspection);
if (fixture) {
  const denied = await client.execute(session);
  assert.equal(denied.kind, "denied");
  assert.equal(denied.credentialRequests, 0);
  assert.equal(denied.mutations, 0);
  console.log("denied safely", denied.code);
  process.exit(0);
}
if (process.env.AUTHS_GITHUB_LIVE !== "1") {
  throw new Error("set AUTHS_GITHUB_LIVE=1 to permit the isolated draft-PR effect");
}
assert.equal(inspection.kind, "inspected");
let outcome = await client.execute(session);
if (outcome.next === "reconcile") outcome = await client.reconcile(session);
assert.ok(outcome.kind === "completed" || outcome.kind === "reconciled");
const verified = await client.verifyReceipts(session);
assert.equal(verified.kind, "verified");
const replay = await client.replay(session);
assert.equal(replay.kind, "replayed");
assert.equal(replay.credentialRequests, 0);
assert.equal(replay.mutations, 0);
console.log("completed", outcome.pullRequestUrl, verified);

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
