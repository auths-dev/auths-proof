"use strict";

const {mkdir, writeFile} = require("node:fs/promises");
const {dirname} = require("node:path");

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

module.exports = async function verifyQualificationAttesterToolsMetadata({github, context}) {
  const decimal = /^(0|[1-9][0-9]{0,31})$/;
  const revision = process.env.TOOL_ATTESTER_REVISION || "";
  const runId = process.env.TOOL_RUN_ID || "";
  const runAttempt = process.env.TOOL_RUN_ATTEMPT || "";
  const artifactId = process.env.TOOL_ARTIFACT_ID || "";
  const digest = (process.env.TOOL_ARTIFACT_DIGEST || "").replace(/^sha256:/, "");
  const retentionDays = Number(process.env.TOOL_RETENTION_DAYS || "");
  const repositoryId = process.env.TOOL_REPOSITORY_ID || "";
  const manifestSha256 = process.env.TOOL_MANIFEST_SHA256 || "";
  const output = process.env.TOOL_VERIFICATION_OUTPUT || "";
  if (!/^[0-9a-f]{40}$/.test(revision) || !decimal.test(runId) || !/^[1-9][0-9]{0,9}$/.test(runAttempt) || !decimal.test(artifactId) || !/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error("invalid protected tool locator");
  }
  if (!decimal.test(repositoryId) || !/^[0-9a-f]{64}$/.test(manifestSha256)) {
    throw new Error("invalid protected tool repository or manifest binding");
  }
  const runNumber = Number(runId);
  const artifactNumber = Number(artifactId);
  if (!Number.isSafeInteger(runNumber) || !Number.isSafeInteger(artifactNumber)) {
    throw new Error("protected tool locator exceeds the GitHub API integer range");
  }
  const {data: artifact} = await github.rest.actions.getArtifact({
    owner: context.repo.owner,
    repo: context.repo.repo,
    artifact_id: artifactNumber,
  });
  const {data: run} = await github.rest.actions.getWorkflowRun({
    owner: context.repo.owner,
    repo: context.repo.repo,
    run_id: runNumber,
  });
  const created = Date.parse(artifact.created_at);
  const expires = Date.parse(artifact.expires_at);
  if (
    String(artifact.id) !== artifactId ||
    artifact.name !== `auths-qualification-attester-tools-${revision}-attempt-${runAttempt}` ||
    artifact.digest !== `sha256:${digest}` ||
    artifact.expired ||
    String(artifact.workflow_run.id) !== runId ||
    !Number.isSafeInteger(artifact.size_in_bytes) ||
    artifact.size_in_bytes < 1 ||
    artifact.size_in_bytes > 536870912 ||
    !Number.isFinite(created) ||
    !Number.isFinite(expires) ||
    created >= expires ||
    !Number.isSafeInteger(retentionDays) ||
    retentionDays !== 90 ||
    expires - created < retentionDays * 86400000 ||
    run.path !== ".github/workflows/qualification-attester-tools.yml" ||
    run.head_sha !== revision ||
    run.head_branch !== "main" ||
    run.event !== "workflow_dispatch" ||
    run.status !== "completed" ||
    run.conclusion !== "success" ||
    String(run.run_attempt) !== runAttempt
  ) {
    throw new Error("protected tool run or artifact metadata drifted");
  }
  if (output !== "") {
    const checkedAt = Math.floor(Date.now() / 1000);
    const record = canonical({
      artifactId,
      artifactName: artifact.name,
      createdAtUnixSeconds: Math.floor(created / 1000),
      expiresAtUnixSeconds: Math.floor(expires / 1000),
      manifestSha256,
      repositoryId,
      retentionDays,
      runAttempt: Number(runAttempt),
      runId,
      schema: "auths.qualification-attester-tools-verification/1",
      uploadedArchiveBytes: artifact.size_in_bytes,
      uploadedArchiveSha256: digest,
      verifiedAtUnixSeconds: checkedAt,
      workflowPath: ".github/workflows/qualification-attester-tools.yml",
      workflowRevision: revision,
    });
    await mkdir(dirname(output), {recursive: true, mode: 0o700});
    await writeFile(output, JSON.stringify(record), {encoding: "utf8", flag: "wx", mode: 0o600});
  }
};
