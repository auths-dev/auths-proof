import assert from "node:assert/strict";
import test from "node:test";

import { loadDomainProfiles } from "../../dist/profiles.js";
import { development, InMemoryApplicationExecutionStore } from "../../dist/testkit/index.js";

const digest = "ab".repeat(32);

test("maintained Rust domain profiles own canonicalization and authority projections", async () => {
  const domains = await loadDomainProfiles();
  const profiles = [
    [domains.http({ audience: "auths://domain" }), {
      method: "POST",
      scheme: "https",
      authority: "api.example.com",
      path: "/v1/items",
      headers: { "content-type": "application/json" },
      contentType: "application/json",
      bodyDigest: digest,
    }],
    [domains.git({ audience: "auths://domain" }), {
      repository: "auths-proof",
      operation: "push",
      reference: "heads/main",
      objectId: digest,
    }],
    [domains.deployment({ audience: "auths://domain" }), {
      environment: "production",
      region: "eu-west-1",
      operation: "deploy",
      artifactDigest: digest,
      provenanceDigest: digest,
      configurationDigest: digest,
      strategy: "canary",
      rolloutNotBefore: 1n,
      rolloutExpiresAt: 100n,
      blastRadius: 5n,
    }],
    [domains.supplyChain({ audience: "auths://domain" }), {
      operation: "release",
      subjectDigest: digest,
      predicateType: "slsa-v1",
      builder: "github-actions",
    }],
    [domains.edge({ audience: "auths://domain" }), {
      fleet: "london",
      device: "device-1",
      command: "restart",
      sequence: 1n,
      stateDigest: digest,
    }],
  ];

  for (const [profile, input] of profiles) {
    const action = profile.action(input);
    const canonical = profile.inspectAction(action);
    const authority = profile.authorityFor(action);
    assert.ok(canonical.body.length > 0);
    assert.equal(authority.permission.capability, canonical.permission.capability);
    assert.equal((await profile.plan([action])).length, 1);
  }
});

test("domain gateways reject forged and cross-profile command substitution before effects", async () => {
  const domains = await loadDomainProfiles();
  const http = domains.http({ audience: "auths://domain" });
  const git = domains.git({ audience: "auths://domain" });
  let calls = 0;
  const options = async (execute) => ({
    state: new InMemoryApplicationExecutionStore(),
    credentials: { async acquire() { return undefined; } },
    receipts: await development.receiptAttestor(),
    canonicalizeResult: () => new Uint8Array([1]),
    execute,
  });
  const gateway = http.gateway(await options(async () => { calls += 1; }));

  assert.throws(() => gateway.parse({}), /forged/);
  const gitGateway = git.gateway(await options(async () => undefined));
  assert.throws(() => gateway.parse(gitGateway.parse.bind(gitGateway)), /forged/);
  assert.equal(calls, 0);
});
