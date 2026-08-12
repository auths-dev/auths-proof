import * as publicRoot from "../../src/index.js";
import type { Signer } from "../../src/framework.js";
import { McpCommand, type McpClosedProvider } from "../../src/profiles/mcp/index.js";
import { Verifier, VerifiedAction, type AuthorizedResult } from "../../src/verify.js";
import { ProfilePlan, VerifiedPlanCommand } from "../../src/plans.js";
import {
  createDiagnosticVerifier,
  type DiagnosticResult,
} from "../../src/testkit/index.js";
import type {
  AuthenticatedIdentityMessage,
  DecodedIdentity,
  ValidatedIdentity,
} from "../../src/identity.js";

// @ts-expect-error package coordination is not part of the public root
publicRoot.registerProfileRuntime;

// @ts-expect-error effect-free verification is not re-exported from root
publicRoot.loadVerifier;

// @ts-expect-error framework ports are absent from the product root
publicRoot.AtomicReservationStore;

// @ts-expect-error conformance machinery is confined to testkit
publicRoot.certifyAtomicStore;

// @ts-expect-error verified actions are package-minted
new VerifiedAction(Symbol(), new Uint8Array());

// @ts-expect-error the capability-minting verifier is package-minted
new Verifier({ verifyV1: () => new Uint8Array() });

// @ts-expect-error MCP commands are profile-minted
new McpCommand(Symbol(), {});

// @ts-expect-error plans require a package-owned profile token
new ProfilePlan(Symbol(), {}, [], {});

// @ts-expect-error verified plans are released only after every member authorizes
new VerifiedPlanCommand(Symbol(), []);

const diagnostic = createDiagnosticVerifier({ verifyV1: () => new Uint8Array() });
type DiagnosticDecision = ReturnType<typeof diagnostic.verify>;
declare const diagnosticDecision: DiagnosticDecision;
declare const diagnosticResult: DiagnosticResult;

// @ts-expect-error diagnostic evidence is not a gateway command
const diagnosticCommand: McpCommand = diagnosticDecision;
void diagnosticCommand;

// @ts-expect-error diagnostic results carry no verified action
diagnosticResult.action;

// @ts-expect-error caller-supplied engines cannot produce effect-capable authorization
const promotedResult: AuthorizedResult = diagnosticResult;
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

// @ts-expect-error authenticated messages require a suite transition
const forgedAuthenticatedMessage: AuthenticatedIdentityMessage = {
  identity: forgedValidatedIdentity,
  message: new Uint8Array(),
};
void forgedAuthenticatedMessage;

declare const provider: McpClosedProvider;
declare const raw: Uint8Array;

// @ts-expect-error provider invocation requires a profile-owned command session
provider.invoke(raw);
