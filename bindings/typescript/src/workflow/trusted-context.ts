import { AuthsWorkflowError } from "./errors.js";
import { boundedIdentifier } from "./internal/orchestrator.js";
import type { TrustedContextProvider, TrustedContextSourceOptions } from "./contracts.js";

interface TrustedContextSourceResources {
  readonly provider: TrustedContextProvider;
}

const trustedContextSourceResources = new WeakMap<
  TrustedContextSource,
  TrustedContextSourceResources
>();
const TRUSTED_CONTEXT_SOURCE_TOKEN: unique symbol = Symbol(
  "auths-trusted-context-source",
);
let mintTrustedContextSource: (
  sourceId: string,
  provider: TrustedContextProvider,
) => TrustedContextSource;

export class TrustedContextSource {
  readonly sourceId: string;

  private constructor(
    token: typeof TRUSTED_CONTEXT_SOURCE_TOKEN,
    sourceId: string,
    provider: TrustedContextProvider,
  ) {
    if (token !== TRUSTED_CONTEXT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths trusted-context source");
    }
    this.sourceId = sourceId;
    trustedContextSourceResources.set(this, { provider });
    Object.freeze(this);
  }

  private static create(
    token: typeof TRUSTED_CONTEXT_SOURCE_TOKEN,
    sourceId: string,
    provider: TrustedContextProvider,
  ): TrustedContextSource {
    if (token !== TRUSTED_CONTEXT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths trusted-context source");
    }
    return new TrustedContextSource(token, sourceId, provider);
  }

  static {
    mintTrustedContextSource = (sourceId, provider) =>
      TrustedContextSource.create(TRUSTED_CONTEXT_SOURCE_TOKEN, sourceId, provider);
  }
}

export function trustedContextSource(
  options: TrustedContextSourceOptions,
): TrustedContextSource {
  if (
    options === null ||
    typeof options !== "object" ||
    options.provider === null ||
    typeof options.provider !== "object" ||
    typeof options.provider.loadTrustedContext !== "function"
  ) {
    throw new AuthsWorkflowError(
      "invalid-trusted-context",
      "trusted-context provider does not implement the Auths source port",
    );
  }
  return mintTrustedContextSource(
    boundedIdentifier(options.sourceId, "trusted-context source"),
    options.provider,
  );
}


export function trustedContextProviderFor(source: TrustedContextSource): TrustedContextProvider | undefined {
  return trustedContextSourceResources.get(source)?.provider;
}
