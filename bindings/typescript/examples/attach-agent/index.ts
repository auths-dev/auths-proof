import { loadAuths, type LoadAuthsOptions } from "@auths-dev/sdk";

export async function openAuths(options: LoadAuthsOptions) {
  return loadAuths(options);
}
