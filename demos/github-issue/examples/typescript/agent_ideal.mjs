/**
 * Ideal AP-SPEC-040 GitHub agent workflow.
 *
 * This is a target-API example, not an example of the currently implemented
 * package. It deliberately keeps candidate inspection, effects,
 * reconciliation, receipts, and replay separate while making proof creation
 * and verification the two-call center of the workflow.
 */
import { connect } from "@auths-dev/sdk/service";
import { githubIssueAddress } from "@auths-dev/sdk/profiles";

const auths = connect({
  endpoint: required("AUTHS_GITHUB_AGENT_ENDPOINT"),
  profile: githubIssueAddress(),
});

// The deployment owns the repository, issue, base revision, path policy, and
// effect budgets. The caller can narrow expiry and choose a label, but cannot
// copy, edit, or widen the configured boundary.
const agent = await auths.delegate({
  agentLabel: process.env.AUTHS_AGENT_LABEL ?? "launch-agent",
  expiresInSeconds: 15 * 60,
});

try {
  await run(agent);
} finally {
  await agent.close();
}

async function run(scopedAgent) {
  console.log("bounded task", scopedAgent.boundary);

  // Inspection remains explicit: it parses a hostile Git bundle without
  // running candidate code. The scoped agent supplies the bound base revision.
  const fixture = process.env.AUTHS_GITHUB_FIXTURE;
  const inspection = fixture
    ? await scopedAgent.inspect({ fixture })
    : await scopedAgent.inspect({
        bundle: required("AUTHS_GITHUB_CANDIDATE_BUNDLE"),
        candidateRevision: required("AUTHS_GITHUB_CANDIDATE_REVISION"),
      });

  // The ordinary Auths proof workflow: create, then verify.
  const proof = await scopedAgent.create(inspection);
  const verification = await scopedAgent.verify(proof);

  if (!verification.passed) {
    if (verification.kind === "indeterminate") {
      throw new Error(
        `verification needs trusted input: ${verification.code} (${verification.requestId})`,
      );
    }
    if (!fixture) {
      throw new Error(`unexpected denial: ${verification.code}`);
    }
    console.log("denied safely", verification.code);
    return;
  }

  if (fixture) {
    throw new Error("a denial fixture unexpectedly produced a verified proof");
  }
  if (process.env.AUTHS_GITHUB_LIVE !== "1") {
    throw new Error(
      "set AUTHS_GITHUB_LIVE=1 to permit the isolated draft-PR effect",
    );
  }

  // Verification never performs an effect. Only the sealed verified value can
  // cross the executor boundary.
  let outcome = await scopedAgent.execute(verification.verified);
  if (outcome.kind === "indeterminate" && outcome.next === "reconcile") {
    outcome = await scopedAgent.reconcile(outcome.reference);
  }
  if (outcome.kind !== "completed" && outcome.kind !== "reconciled") {
    throw new Error(`workflow did not complete: ${outcome.code}`);
  }

  // Receipt authenticity and effect replay are separate from proof
  // authorization, so they keep distinct operations.
  const receipts = await scopedAgent.verifyReceipts();
  const replay = await scopedAgent.replay();
  if (replay.kind !== "replayed" || replay.mutations !== 0) {
    throw new Error("replay attempted another GitHub mutation");
  }

  console.log("completed", outcome.pullRequestUrl, receipts);
}

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
