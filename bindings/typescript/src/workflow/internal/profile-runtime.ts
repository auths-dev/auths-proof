import type {
  ApprovalConfiguration,
  AuthorizationResult,
  Profile,
} from "../contracts.js";
import type { AttachedAgent } from "./orchestrator.js";

export interface ProfileRuntime {
  authorize(
    agent: AttachedAgent<Profile>,
    action: unknown,
    approvalOverride?: ApprovalConfiguration,
  ): Promise<AuthorizationResult<unknown>>;
}

const profileRuntimes = new WeakMap<object, ProfileRuntime>();

export function registerProfileRuntime(profile: Profile, runtime: ProfileRuntime): void {
  if (profileRuntimes.has(profile as object)) {
    throw new TypeError("Auths profile runtime is already registered");
  }
  profileRuntimes.set(profile as object, runtime);
}

export function profileRuntimeFor(profile: Profile): ProfileRuntime | undefined {
  return profileRuntimes.get(profile as object);
}

export function bindProfileRuntimeCopy(source: Profile, target: Profile): void {
  const runtime = profileRuntimeFor(source);
  if (runtime !== undefined) profileRuntimes.set(target as object, runtime);
}
