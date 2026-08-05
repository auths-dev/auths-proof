import { VerifiedAction, type Signer } from "../../src/index.js";
import { ApplicationCommand } from "../../src/profile-kit.js";
import { defineProfile } from "../../src/profile-kit.js";
import { McpCommand } from "../../src/mcp.js";
import { ProfilePlan, VerifiedPlanCommand } from "../../src/plans.js";

// @ts-expect-error verified actions are package-minted
new VerifiedAction(Symbol(), new Uint8Array());

// @ts-expect-error application commands are profile/verifier-minted
new ApplicationCommand(Symbol(), {}, {});

const applicationProfile = defineProfile({
  id: "example.contract/1",
  version: 1,
  canonicalize() {
    return {
      mediaType: "application/octet-stream",
      body: new Uint8Array([1]),
      permission: { capability: "example/use", resource: "example://one" },
      resourceNamespace: "example://",
      audience: "example://one",
      display: [{ label: "Action", value: "one" }],
    };
  },
});

// @ts-expect-error applications cannot produce the private command-factory token
applicationProfile.createVerifiedCommand(Symbol(), applicationProfile.inspectAction(applicationProfile.action({})));

// @ts-expect-error MCP commands are profile/verifier-minted
new McpCommand(Symbol(), {});

// @ts-expect-error plans require a package-owned profile token
new ProfilePlan(Symbol(), {}, [], {});

// @ts-expect-error verified plans are created only after every member authorizes
new VerifiedPlanCommand(Symbol(), []);

// @ts-expect-error a signer without an exact sign operation is not a Signer
const invalidSigner: Signer = {
  kind: "invalid",
  lifecycle: "durable",
  async publicIdentity() {
    return {
      principal: "did:web:invalid.example",
      principalMethod: "did-web-v1",
      verificationMethod: "did:web:invalid.example#key-1",
      suite: "ed25519-v1",
    };
  },
};

void invalidSigner;
