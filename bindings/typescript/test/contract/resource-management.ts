import type { Auths } from "../../src/index.js";

declare function configuredAuths(): Promise<Auths>;

async function managed(): Promise<void> {
  await using auths = await configuredAuths();
  void auths.actor;
}

void managed;
