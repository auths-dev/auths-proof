import {
  AuthsWorkflowError,
  type AuthorizationResult,
  type ApprovalConfiguration,
  type AttachedAgent,
  type Profile,
  engineForClient,
  registerProfileRuntime,
  resourcesForAttachedAgent,
} from "../../workflow.js";
import { authorizePreparedAction } from "../../internal/authorization.js";
import { createProfilePlan, type ProfilePlan } from "../../plans.js";

const PROFILE_ID = "auths.mcp";
const PROFILE_VERSION = 1;
const MAX_ARGUMENT_JSON_BYTES = 256 * 1024;
const MCP_PROFILE_TOKEN: unique symbol = Symbol("auths-mcp-profile");
const MCP_ACTION_TOKEN: unique symbol = Symbol("auths-mcp-action");
const MCP_COMMAND_TOKEN: unique symbol = Symbol("auths-mcp-command");

let mintMcpCommand: (resources: McpActionResources) => McpCommand;
let mintMcpAction: (
  profile: McpProfile,
  name: string,
  argumentsJson: Uint8Array,
) => McpAction;
let mintMcpProfile: (service: string) => McpProfile;

interface McpActionResources {
  readonly profile: McpProfile;
  readonly name: string;
  readonly argumentsJson: Uint8Array;
}

const actionResources = new WeakMap<McpAction, McpActionResources>();
const commandResources = new WeakMap<McpCommand, McpActionResources>();

/** Verifier-minted MCP tool call accepted only by its matching gateway. */
export class McpCommand {
  readonly service: string;
  readonly name: string;

  private constructor(token: typeof MCP_COMMAND_TOKEN, resources: McpActionResources) {
    if (token !== MCP_COMMAND_TOKEN) throw new TypeError("sealed Auths MCP command");
    this.service = resources.profile.service;
    this.name = resources.name;
    commandResources.set(this, {
      ...resources,
      argumentsJson: resources.argumentsJson.slice(),
    });
    Object.freeze(this);
  }

  private static create(token: typeof MCP_COMMAND_TOKEN, resources: McpActionResources): McpCommand {
    return new McpCommand(token, resources);
  }

  static {
    mintMcpCommand = (resources) => McpCommand.create(MCP_COMMAND_TOKEN, resources);
  }

  toJSON(): never {
    throw new TypeError("verified Auths commands are not serializable");
  }
}

export interface McpGatewayCall {
  readonly service: string;
  readonly name: string;
  readonly argumentsJson: Uint8Array;
}

export interface McpGateway<Result> {
  execute(command: McpCommand): Promise<Result>;
}

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

  private static create(
    token: typeof MCP_ACTION_TOKEN,
    profile: McpProfile,
    name: string,
    argumentsJson: Uint8Array,
  ): McpAction {
    if (token !== MCP_ACTION_TOKEN) throw new TypeError("sealed Auths MCP action");
    return new McpAction(token, profile, name, argumentsJson);
  }

  static {
    mintMcpAction = (profile, name, argumentsJson) =>
      McpAction.create(MCP_ACTION_TOKEN, profile, name, argumentsJson);
  }
}

/** Package-owned `auths.mcp/1` profile bound to one logical MCP service. */
export class McpProfile implements Profile<McpAction, McpCommand> {
  readonly id = PROFILE_ID;
  readonly version = PROFILE_VERSION;
  readonly service: string;
  declare readonly __action?: McpAction;
  declare readonly __command?: McpCommand;

  private constructor(token: typeof MCP_PROFILE_TOKEN, service: string) {
    if (token !== MCP_PROFILE_TOKEN) throw new TypeError("sealed Auths MCP profile");
    this.service = service;
  }

  private static create(token: typeof MCP_PROFILE_TOKEN, service: string): McpProfile {
    if (token !== MCP_PROFILE_TOKEN) throw new TypeError("sealed Auths MCP profile");
    const profile = new McpProfile(token, service);
    registerProfileRuntime(profile, {
      authorize: (agent, action, approvalOverride) => authorizeMcp(
        agent,
        profile,
        action,
        approvalOverride,
      ),
    });
    return Object.freeze(profile);
  }

  static {
    mintMcpProfile = (service) => McpProfile.create(MCP_PROFILE_TOKEN, service);
  }

  call(name: string, argumentsValue: Readonly<Record<string, unknown>>): McpAction {
    const argumentsJson = encodeArguments(argumentsValue);
    return mintMcpAction(
      this,
      boundedToolName(name),
      argumentsJson,
    );
  }

  async plan(actions: readonly McpAction[]): Promise<ProfilePlan<McpAction>> {
    const resources = actions.map((action) => {
      const item = actionResources.get(action);
      if (item === undefined || item.profile !== this) {
        throw new AuthsWorkflowError("invalid-profile", "MCP plan contains an action from another profile");
      }
      return item;
    });
    return createProfilePlan(this, actions, (action) => {
      const resources = actionResources.get(action);
      if (resources === undefined || resources.profile !== this) {
        throw new AuthsWorkflowError("invalid-profile", "MCP plan contains an action from another profile");
      }
      const service = new TextEncoder().encode(this.service);
      const name = new TextEncoder().encode(resources.name);
      const output = new Uint8Array(8 + service.length + name.length + resources.argumentsJson.length);
      const view = new DataView(output.buffer);
      view.setUint16(0, service.length, false);
      output.set(service, 2);
      view.setUint16(2 + service.length, name.length, false);
      output.set(name, 4 + service.length);
      view.setUint32(4 + service.length + name.length, resources.argumentsJson.length, false);
      output.set(resources.argumentsJson, 8 + service.length + name.length);
      return output;
    }, {
      permissions: resources.map((item) => Object.freeze({
        capability: "tools/call",
        resource: `mcp://${this.service}/tools/${item.name}`,
      })),
      resourceNamespaces: [ `mcp://${this.service}` ],
      audiences: [ `mcp://${this.service}` ],
    });
  }

  gateway<Result>(execute: (call: McpGatewayCall) => Promise<Result>): McpGateway<Result> {
    if (typeof execute !== "function") {
      throw new AuthsWorkflowError("invalid-profile", "MCP gateway executor is missing");
    }
    const profile = this;
    return Object.freeze({
      async execute(command: McpCommand): Promise<Result> {
        const resources = commandResources.get(command);
        if (resources === undefined || resources.profile !== profile) {
          throw new AuthsWorkflowError("invalid-profile", "MCP command is forged or belongs to another profile");
        }
        return execute(Object.freeze({
          service: profile.service,
          name: resources.name,
          argumentsJson: resources.argumentsJson.slice(),
        }));
      },
    });
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
    return mintMcpProfile(boundedService(options.service));
  },
});

async function authorizeMcp(
  agent: AttachedAgent<Profile>,
  profile: McpProfile,
  candidate: unknown,
  approvalOverride?: ApprovalConfiguration,
): Promise<AuthorizationResult<McpCommand>> {
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
  const result = await authorizePreparedAction(
    agent,
    preparation,
    Object.freeze([
      Object.freeze({ label: "Service", value: profile.service }),
      Object.freeze({ label: "Tool", value: action.name }),
      Object.freeze({ label: "Resource", value: preparation.resource }),
      Object.freeze({ label: "Canonical digest", value: preparation.displayDigestHex }),
    ]),
    approvalOverride,
  );
  if (result.kind !== "authorized") return result;
  return Object.freeze({
    ...result,
    command: mintMcpCommand(action),
  });
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
