import { connect, DeniedError, type ClientOptions } from "../../src/index.js";
import {
  PROFILE_CLIENT_RUNTIME,
  bindProfile,
  type ProfileDescriptor,
  type ProfileOutcome,
} from "../../src/profile-runtime.js";

const options: ClientOptions = { agentSocket: "/run/auths/agent.sock" };
void connect(options);

// The application launch API has no bearer token or remote executor URL.
// @ts-expect-error Auths application tokens are not part of ClientOptions
void connect({ accessToken: "secret" });
// @ts-expect-error remote executor endpoints are not part of ClientOptions
void connect({ endpoint: "https://executor.example" });

declare const outcome: ProfileOutcome<{ readonly id: string }>;
switch (outcome.kind) {
  case "completed": void outcome.value.id; break;
  case "denied": void outcome.issue; break;
  case "unavailable": void outcome.operationId; break;
  case "conflict": void outcome.recovery; break;
  case "not-applied": void outcome.completion; break;
  case "partial": void outcome.details; break;
  case "recovery-required": void outcome.progress; break;
  case "receipt-integrity-failed": void outcome.terminal; break;
  default: outcome satisfies never;
}

void PROFILE_CLIENT_RUNTIME;
void bindProfile;

const descriptor: ProfileDescriptor = {
  profileClientRuntime: PROFILE_CLIENT_RUNTIME,
  profileId: "auths.example.double",
  version: 1,
  collectionRoute: "/v1/profiles/example/double/1/operations",
  runtimeContractDigest: "00".repeat(32),
  errorProjectionDigest: "00".repeat(32),
  preparationEvidence: null,
  requestBytes: 4096,
  responseBytes: 4096,
  executionMilliseconds: 30_000,
  receiptCount: 4,
  receiptBytes: 1024,
  profileApi: {},
  inputType: "Input",
  successType: "Result",
};
void descriptor;

// @ts-expect-error operational error claims can only be minted by the SDK
new DeniedError({});
