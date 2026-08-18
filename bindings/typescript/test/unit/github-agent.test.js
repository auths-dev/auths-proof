import assert from "node:assert/strict";
import { test } from "node:test";

import { createGitHubAgentClient } from "../../dist/service.js";

const schema = "auths-github-agent/v1";

test("typed GitHub task projects to the closed launch API", async () => {
  const calls = [];
  const responses = [
    {
      schema,
      repository: "auths-dev/example",
      issue_number: 123,
      base_ref: "main",
      base_revision: "a".repeat(40),
      allowed_paths: ["src/**", "tests/**"],
      denied_paths: [".github/**"],
      budgets: { branches: 1, draft_pull_requests: 1 },
      expiry: { minimum_seconds: 60, maximum_seconds: 900 },
      agent_credential_present: false,
    },
    {
      schema,
      session_id: "1".repeat(32),
      workflow_id: "demo-" + "1".repeat(32),
      expires_at: 1000,
      target_ref: "auths/issue-123-abcdef123456",
      agent_principal: "urn:auths:raw-key:agent",
      required_configuration: "2".repeat(64),
      executed_configuration: "2".repeat(64),
    },
    {
      schema,
      candidate: {
        status: "denied",
        changed_paths: [],
        direct_push: { result: "not-attempted" },
        preview: {
          code: "path-explicitly-denied",
          credential_would_be_requested: false,
        },
      },
    },
    {
      schema,
      decision: { class: "denied", code: "path-explicitly-denied" },
      execution: { branch: "not-attempted", pull_request: "not-attempted" },
      credential_requests: 0,
      mutations: 0,
    },
  ];
  const client = createGitHubAgentClient({
    endpoint: "https://operator.example",
    fetch: async (url, init) => {
      calls.push({ url: String(url), body: init?.body });
      return new Response(JSON.stringify(responses.shift()), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const boundary = await client.boundary();
  const task = {
    repository: boundary.repository,
    issueNumber: boundary.issueNumber,
    baseRef: boundary.baseRef,
    baseRevision: boundary.baseRevision,
    allowedPaths: boundary.allowedPaths,
    protectedPaths: boundary.protectedPaths,
    expiresInSeconds: boundary.maximumExpirySeconds,
    branchBudget: 1,
    draftPullRequestBudget: 1,
    agentLabel: "review-agent",
  };
  const session = await client.delegate(task);
  const inspection = await client.inspectFixture(session, "prohibited-path");
  const denied = await client.execute(session);

  assert.equal(inspection.kind, "denied");
  assert.equal(inspection.credentialWouldBeRequested, false);
  assert.equal(denied.kind, "denied");
  assert.equal(denied.credentialRequests, 0);
  assert.equal(denied.mutations, 0);
  assert.deepEqual(JSON.parse(calls[1].body), {
    repository: "auths-dev/example",
    issueNumber: 123,
    baseRef: "main",
    baseRevision: "a".repeat(40),
    allowedPaths: ["src/**", "tests/**"],
    protectedPaths: [".github/**"],
    expiresInSeconds: 900,
    branchBudget: 1,
    draftPullRequestBudget: 1,
    agentLabel: "review-agent",
  });
});

test("GitHub sessions cannot be forged", async () => {
  const client = createGitHubAgentClient({
    endpoint: "https://operator.example",
    fetch: async () => { throw new Error("transport must not be reached"); },
  });
  await assert.rejects(
    client.execute({ kind: "github-agent-session" }),
    /forged Auths GitHub agent session/,
  );
});

test("a lost execute response requires reconciliation and never claims zero effects", async () => {
  let calls = 0;
  const client = createGitHubAgentClient({
    endpoint: "https://operator.example",
    fetch: async () => {
      calls += 1;
      if (calls > 1) throw new Error("connection lost after request left the process");
      return new Response(JSON.stringify({
        schema,
        session_id: "1".repeat(32),
        workflow_id: "demo-" + "1".repeat(32),
        expires_at: 1_000,
        target_ref: "auths/issue-123-abcdef123456",
        agent_principal: "urn:auths:raw-key:agent",
        required_configuration: "2".repeat(64),
        executed_configuration: "2".repeat(64),
      }), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  const session = await client.delegate({
    repository: "auths-dev/example",
    issueNumber: 123,
    baseRef: "main",
    baseRevision: "a".repeat(40),
    allowedPaths: ["src/**"],
    protectedPaths: [".github/**"],
    expiresInSeconds: 900,
    branchBudget: 1,
    draftPullRequestBudget: 1,
    agentLabel: "review-agent",
  });
  const outcome = await client.execute(session);
  assert.deepEqual(outcome, {
    kind: "indeterminate",
    code: "transport-uncertain",
    credentialRequests: "unknown",
    mutations: "unknown",
    next: "reconcile",
  });
});
