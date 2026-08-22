import { access, readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const metadata = JSON.parse(await readFile(new URL("sdk-capability.json", root), "utf8"));
const readme = await readFile(new URL("README.md", root), "utf8");

const tiers = new Set(["verifier-binding", "authoring-sdk", "full-workflow-sdk"]);
const evidenceStates = new Set([
  "specified",
  "repository-local-in-progress",
  "repository-local-complete",
  "independently-reviewed",
]);
const scorecardStates = new Set(["verified", "external-review-required", "python-follow-up"]);

if (metadata.schema !== "auths.sdk-capability/2") {
  throw new Error("unsupported TypeScript capability metadata schema");
}
for (const field of ["implementationTier", "promotedTier", "targetTier"]) {
  if (!tiers.has(metadata[field])) throw new Error(`invalid ${field}`);
}
if (!evidenceStates.has(metadata.evidenceStatus)) {
  throw new Error("invalid evidenceStatus");
}
if (
  metadata.promotedTier === "full-workflow-sdk" &&
  metadata.evidenceStatus !== "independently-reviewed"
) {
  throw new Error("Full Workflow promotion requires independent review evidence");
}
const requiredScorecard = [
  "timeToValue", "progressiveAdoption", "semanticSafety", "typeSafety",
  "productionIntegration", "operationalCompleteness", "debuggability", "extensibility",
  "portability", "runtimeContract", "securityEvidence", "documentation", "crossSdkParity",
];
for (const dimension of requiredScorecard) {
  const entry = metadata.eliteScorecard?.[dimension];
  if (!scorecardStates.has(entry?.status) || !Array.isArray(entry?.evidence) || entry.evidence.length === 0) {
    throw new Error(`invalid elite scorecard entry: ${dimension}`);
  }
  for (const evidence of entry.evidence) {
    if (typeof evidence !== "string" || evidence.length === 0) {
      throw new Error(`invalid elite scorecard evidence: ${dimension}`);
    }
    await access(new URL(evidence, root));
  }
}
if (
  metadata.publicationStatus !== "blocked" &&
  metadata.blockingIssues.length > 0
) {
  throw new Error("publication status contradicts unresolved blockers");
}
for (const statement of [
  "closed product workflow",
  "There is no Auths application token",
  "profile-runtime",
  "Publication, promotion, and independent-review status",
]) {
  if (!readme.includes(statement)) {
    throw new Error(`README is missing capability boundary: ${statement}`);
  }
}
for (const [label, field] of [
  ["Implementation tier", "implementationTier"],
  ["Evidence status", "evidenceStatus"],
  ["Promoted tier", "promotedTier"],
  ["Publication status", "publicationStatus"],
  ["Promotion status", "promotionStatus"],
]) {
  if (!readme.includes(`${label}: \`${metadata[field]}\``)) {
    throw new Error(`README contradicts capability field ${field}`);
  }
}
