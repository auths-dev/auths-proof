import {
  approvalPolicy,
  loadAuths,
  prepareRawKeyAuthority,
  type ApprovalProvider,
  type ReviewField,
} from "@auths-dev/sdk";
import { mcp } from "@auths-dev/sdk/mcp";
import { development } from "@auths-dev/sdk/testkit";

/**
 * Complete local quickstart. The MCP profile owns tool-call meaning; Auths
 * owns grants, attenuation, signing transactions, verification, and the
 * sealed command accepted by the gateway.
 */
export async function runQuickstart(
  review: (fields: readonly ReviewField[]) => Promise<boolean>,
): Promise<string> {
  const policy = await approvalPolicy.everyAction({
    expiresInSeconds: 300,
    maxUses: 1,
    requirements: ["visible-human-review"],
  });
  const approvalProvider: ApprovalProvider = {
    async approve(request) {
      return {
        requestId: request.requestId,
        transactionDigest: request.transactionDigest.slice(),
        policy: request.policy,
        decision: await review(request.display) ? "approved" : "rejected",
      };
    },
  };
  const approval = Object.freeze({ policy, provider: approvalProvider });
  const profile = mcp.profile({ service: "records" });
  const rootSigner = await development.ephemeralSigner();
  const parentSigner = await development.ephemeralSigner();
  const childSigner = await development.ephemeralSigner();
  const parentPrincipal = await parentSigner.publicIdentity();
  const now = BigInt(Math.floor(Date.now() / 1000));

  const prepared = await prepareRawKeyAuthority({
    authorityId: "quickstart.local-owner",
    rootSigner,
    subjectPrincipal: parentPrincipal.principal,
    profile,
    permissions: [{
      capability: "tools/call",
      resource: "mcp://records/tools/update_record",
    }],
    resourceNamespaces: ["mcp://records"],
    validity: { notBefore: now - 30n, expiresAt: now + 3_600n },
    audiences: ["mcp://records"],
    budget: { algebra: "numeric-ceiling-v1", value: 2n },
    remainingDepth: 1,
    approval,
  });

  const auths = await loadAuths({
    signer: parentSigner,
    trustedAuthority: prepared.trustedAuthority,
  });
  try {
    const parent = await auths.attachAgent({
      name: "records-parent",
      profile,
      authority: prepared.authority,
      approval,
    });
    const child = await parent.delegate({
      name: "records-child",
      signer: childSigner,
      authority: {
        permissions: [{
          capability: "tools/call",
          resource: "mcp://records/tools/update_record",
        }],
        validity: { notBefore: now - 10n, expiresAt: now + 900n },
        audiences: ["mcp://records"],
        actionConstraint: { kind: "inherit" },
        budget: { kind: "ceiling", algebra: "numeric-ceiling-v1", value: 1n },
        remainingDepth: 0,
        status: { kind: "inherit" },
      },
    });
    const decision = await child.authorize(
      profile.call("update_record", { recordId: "demo", value: "reviewed" }),
    );
    if (decision.kind !== "authorized") {
      return `${decision.kind}:${decision.code}`;
    }
    const gateway = profile.gateway(async (call) => {
      // A real application performs the MCP effect here and nowhere else.
      return `${call.service}/${call.name}`;
    });
    return gateway.execute(decision.command);
  } finally {
    await auths.dispose();
    await rootSigner.dispose?.();
  }
}
