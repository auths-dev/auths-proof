import { type Signer } from "../../src/index.js";
import { Auths, VerifiedAction } from "../../src/advanced.js";
import { ApplicationCommand } from "../../src/profile-kit.js";
import { defineProfile } from "../../src/profile-kit.js";
import { McpCommand } from "../../src/mcp.js";
import { ProfilePlan, VerifiedPlanCommand } from "../../src/plans.js";
import * as publicRoot from "../../src/index.js";
import * as advanced from "../../src/advanced.js";

// @ts-expect-error package coordination is not part of the public root
publicRoot.registerProfileRuntime;

// @ts-expect-error attached-agent resources are package-private
publicRoot.resourcesForAttachedAgent;

// @ts-expect-error the advanced verifier surface does not expose workflow internals
advanced.engineForClient;

// @ts-expect-error verified actions are package-minted
new VerifiedAction(Symbol(), new Uint8Array());

// @ts-expect-error the capability-minting verifier is package-minted
new Auths({ verifyV1: () => new Uint8Array() });

// @ts-expect-error raw verification is not on the supported root entry point
publicRoot.loadPortableAuths;

// @ts-expect-error the raw verifier type is not on the supported root entry point
publicRoot.Auths;

// @ts-expect-error decision inspection is an advanced surface
publicRoot.inspectDecision;

// @ts-expect-error canonical commitment is an advanced surface
publicRoot.commitCanonical;

// @ts-expect-error diagnostic verification never reaches the root entry point
publicRoot.createDiagnosticVerifier;

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

declare const inspection: advanced.DecisionInspection;
declare const diagnostic: advanced.DiagnosticResult;

// @ts-expect-error inspection evidence is not a gateway-accepted command
const promotedCommand: McpCommand = inspection;
void promotedCommand;

// @ts-expect-error diagnostic results are never gateway-accepted commands
const promotedDiagnostic: McpCommand = diagnostic;
void promotedDiagnostic;

// @ts-expect-error diagnostic results carry no verified action
diagnostic.action;

// @ts-expect-error inspection evidence carries no verified action
inspection.action;

// @ts-expect-error a caller-supplied engine cannot produce an authorized SDK result
const promotedResult: advanced.AuthorizedResult = diagnostic;
void promotedResult;

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
