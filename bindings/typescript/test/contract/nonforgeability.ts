import { type Signer } from "../../src/index.js";
import { Auths, VerifiedAction } from "../../src/advanced.js";
import { ApplicationCommand } from "../../src/profile-kit.js";
import { defineProfile } from "../../src/profile-kit.js";
import { McpCommand } from "../../src/mcp.js";
import { ProfilePlan, VerifiedPlanCommand } from "../../src/plans.js";
import * as publicRoot from "../../src/index.js";
import * as advanced from "../../src/advanced.js";
import type {
  AuthenticatedIdentityMessage,
  DecodedIdentity,
  ValidatedIdentity,
} from "../../src/identity.js";
import { AuthorizationPlan, type ProofReference } from "../../src/authorization-plans.js";
import type {
  GitCommand,
  GitGateway,
  HttpCommand,
  HttpGateway,
} from "../../src/profiles/domains/index.js";
import type { TrustedContextConfiguration } from "../../src/trust.js";

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

// @ts-expect-error decoded identities require package-owned parsing
const forgedDecodedIdentity: DecodedIdentity = {
  validation: "decoded",
  methodId: "raw-key-v2",
  identityId: "raw-key-v2:forged",
  suiteId: "ed25519-v1",
  publicKey: new Uint8Array(32),
  packet: new Uint8Array(),
};

// @ts-expect-error validated identities cannot be promoted structurally
const forgedValidatedIdentity: ValidatedIdentity = {
  validation: "validated",
  methodId: forgedDecodedIdentity.methodId,
  identityId: forgedDecodedIdentity.identityId,
  suiteId: forgedDecodedIdentity.suiteId,
  publicKey: forgedDecodedIdentity.publicKey,
  packet: forgedDecodedIdentity.packet,
};

// @ts-expect-error authenticated messages require a suite parse transition
const forgedAuthenticatedMessage: AuthenticatedIdentityMessage = {
  identity: forgedValidatedIdentity,
  message: new Uint8Array(),
};

void forgedAuthenticatedMessage;

// @ts-expect-error authorization plans require a native builder token
new AuthorizationPlan(Symbol(), "proof", {}, 0);

// @ts-expect-error proof references are parsed nominal values, not raw bytes
const rawProofReference: ProofReference = new Uint8Array(32);
void rawProofReference;

declare const httpCommand: HttpCommand;
declare const gitCommand: GitCommand;
declare const httpGateway: HttpGateway<void>;
declare const gitGateway: GitGateway<void>;

// @ts-expect-error domain command types are profile-specific
const substitutedGitCommand: GitCommand = httpCommand;
void substitutedGitCommand;

// @ts-expect-error an HTTP gateway cannot parse a Git command
httpGateway.parse(gitCommand);

// @ts-expect-error a Git gateway cannot parse an HTTP command
gitGateway.parse(httpCommand);

declare const trustWithoutPrincipalStatus: Omit<
  TrustedContextConfiguration,
  "principalStatus"
>;

const rawTrustConfiguration: TrustedContextConfiguration = {
  ...trustWithoutPrincipalStatus,
  // @ts-expect-error typed trust configuration does not accept raw snapshot bytes
  principalStatus: new Uint8Array(),
};
void rawTrustConfiguration;
