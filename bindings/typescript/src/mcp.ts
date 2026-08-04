import { type VerificationResult } from "./index.js";
import {
  AuthsWorkflowError,
  type AttachedAgent,
  type Profile,
  engineForClient,
  registerProfileRuntime,
  resourcesForAttachedAgent,
} from "./workflow.js";
import { authorizePreparedAction } from "./internal/authorization.js";

const PROFILE_ID = "auths.mcp";
const PROFILE_VERSION = 1;
const MAX_ARGUMENT_JSON_BYTES = 256 * 1024;
const MCP_PROFILE_TOKEN: unique symbol = Symbol("auths-mcp-profile");
const MCP_ACTION_TOKEN: unique symbol = Symbol("auths-mcp-action");

interface McpActionResources {
  readonly profile: McpProfile;
  readonly name: string;
  readonly argumentsJson: Uint8Array;
}

const actionResources = new WeakMap<McpAction, McpActionResources>();

/** Closed MCP tool-call action constructible only by this profile facade. */
export class McpAction {
  readonly name: string;

  private constructor(
    token: typeof MCP_ACTION_TOKEN,
    profile: McpProfile,
    name: string,
    argumentsJson: Uint8Array,
  ) {
    if (token !== MCP_ACTION_TOKEN) throw new TypeError("sealed Auths MCP action");
    this.name = name;
    actionResources.set(this, {
      profile,
      name,
      argumentsJson: argumentsJson.slice(),
    });
    Object.freeze(this);
  }

  static create(
    token: typeof MCP_ACTION_TOKEN,
    profile: McpProfile,
    name: string,
    argumentsJson: Uint8Array,
  ): McpAction {
    if (token !== MCP_ACTION_TOKEN) throw new TypeError("sealed Auths MCP action");
    return new McpAction(token, profile, name, argumentsJson);
  }
}

/** Package-owned `auths.mcp/1` profile bound to one logical MCP service. */
export class McpProfile implements Profile<McpAction, never> {
  readonly id = PROFILE_ID;
  readonly version = PROFILE_VERSION;
  readonly service: string;
  declare readonly __action?: McpAction;
  declare readonly __command?: never;

  private constructor(token: typeof MCP_PROFILE_TOKEN, service: string) {
    if (token !== MCP_PROFILE_TOKEN) throw new TypeError("sealed Auths MCP profile");
    this.service = service;
  }

  static create(token: typeof MCP_PROFILE_TOKEN, service: string): McpProfile {
    if (token !== MCP_PROFILE_TOKEN) throw new TypeError("sealed Auths MCP profile");
    const profile = new McpProfile(token, service);
    registerProfileRuntime(profile, {
      authorize: (agent, action) => authorizeMcp(agent, profile, action),
    });
    return Object.freeze(profile);
  }

  call(name: string, argumentsValue: Readonly<Record<string, unknown>>): McpAction {
    const argumentsJson = encodeArguments(argumentsValue);
    return McpAction.create(
      MCP_ACTION_TOKEN,
      this,
      boundedToolName(name),
      argumentsJson,
    );
  }
}

export interface McpProfileOptions {
  readonly service: string;
}

export const mcp = Object.freeze({
  profile(options: McpProfileOptions): McpProfile {
    if (options === null || typeof options !== "object") {
      throw new AuthsWorkflowError("invalid-profile", "MCP profile options are missing");
    }
    return McpProfile.create(
      MCP_PROFILE_TOKEN,
      boundedService(options.service),
    );
  },
});

async function authorizeMcp(
  agent: AttachedAgent<Profile>,
  profile: McpProfile,
  candidate: unknown,
): Promise<VerificationResult> {
  agent.assertActive();
  const action = candidate instanceof McpAction ? actionResources.get(candidate) : undefined;
  if (action === undefined || action.profile !== profile) {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "action was not created by the attached MCP profile",
    );
  }
  const resources = resourcesForAttachedAgent(agent);
  const engine = engineForClient(resources.client);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const evaluationTime = BigInt(Math.floor(Date.now() / 1000));
  let preparation;
  try {
    preparation = engine.prepareMcpActionV1(
      profile.service,
      action.name,
      action.argumentsJson.slice(),
      agent.identity.principal.principal,
      resources.signedGrant.slice(),
      challenge,
      evaluationTime,
    );
  } catch {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "native MCP profile rejected the proposed tool call",
    );
  }
  return authorizePreparedAction(
    agent,
    preparation,
    Object.freeze([
      Object.freeze({ label: "Service", value: profile.service }),
      Object.freeze({ label: "Tool", value: action.name }),
      Object.freeze({ label: "Resource", value: preparation.resource }),
      Object.freeze({ label: "Canonical digest", value: preparation.displayDigestHex }),
    ]),
  );
}

function encodeArguments(value: Readonly<Record<string, unknown>>): Uint8Array {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AuthsWorkflowError("invalid-profile", "MCP arguments must be an object");
  }
  let encoded: Uint8Array;
  try {
    const json = JSON.stringify(value);
    if (json === undefined) throw new TypeError("missing JSON");
    encoded = new TextEncoder().encode(json);
  } catch {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "MCP arguments must have one finite JSON representation",
    );
  }
  if (encoded.length === 0 || encoded.length > MAX_ARGUMENT_JSON_BYTES) {
    throw new AuthsWorkflowError("invalid-profile", "MCP arguments exceed profile limits");
  }
  return encoded;
}

function boundedService(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > 64 ||
    !/^[a-z0-9._-]+$/.test(value)
  ) {
    throw new AuthsWorkflowError("invalid-profile", "MCP service is outside profile limits");
  }
  return value;
}

function boundedToolName(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > 128 ||
    !/^[a-zA-Z0-9._-]+$/.test(value)
  ) {
    throw new AuthsWorkflowError("invalid-profile", "MCP tool name is outside profile limits");
  }
  return value;
}
