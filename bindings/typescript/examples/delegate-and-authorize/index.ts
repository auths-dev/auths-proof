import type { AttachedAgent, Profile } from "@auths-dev/sdk";

export async function authorizeOne<P extends Profile>(
  agent: AttachedAgent<P>,
  action: NonNullable<P["__action"]>,
) {
  return agent.authorize(action);
}
