import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationPlan,
  loadAuthorizationPlanBuilder,
  proofReference,
} from "../../dist/authorization-plans.js";

test("general authorization plans are composed and summarized by Rust", async () => {
  const builder = await loadAuthorizationPlanBuilder();
  const first = builder.proof(proofReference("01".repeat(32)));
  const second = builder.proof(proofReference("02".repeat(32)));
  const third = builder.proof(proofReference("03".repeat(32)));
  const fourth = builder.proof(proofReference("04".repeat(32)));
  const any = builder.anyOf([first, second]);
  const threshold = builder.threshold(2, [third, fourth]);
  const plan = builder.allOf([any, threshold]);
  const summary = builder.summarize(plan);

  assert.equal(summary.leafCount, 4);
  assert.equal(summary.maximumDepth, 3);
  assert.equal(summary.planId.length, 32);
  assert.ok(summary.canonicalPlan.length > 0);
  assert.equal(Object.isFrozen(plan), true);
  assert.throws(() => Reflect.construct(AuthorizationPlan, [Symbol(), "proof", builder, 0]));
  builder.dispose();
  assert.throws(() => builder.summarize(plan), /disposed/);
});

test("general authorization plans reject malformed composition", async () => {
  const builder = await loadAuthorizationPlanBuilder();
  const proof = builder.proof(proofReference("03".repeat(32)));
  assert.throws(() => builder.allOf([]));
  assert.throws(() => builder.anyOf([proof, proof]));
  assert.throws(() => builder.threshold(2, [proof]));
  assert.throws(() => proofReference("03".repeat(31)));

  const other = await loadAuthorizationPlanBuilder();
  const foreign = other.proof(proofReference("04".repeat(32)));
  assert.throws(() => builder.allOf([proof, foreign]), /another builder/);

  let nested = proof;
  let depthRejected = false;
  for (let index = 5; index < 100; index += 1) {
    try {
      nested = builder.allOf([nested, builder.proof(proofReference(
        index.toString(16).padStart(2, "0").repeat(32),
      ))]);
    } catch {
      depthRejected = true;
      break;
    }
  }
  assert.equal(depthRejected, true);
  builder.dispose();
  other.dispose();
});
