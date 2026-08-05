import { AuthsWorkflowError } from "./errors.js";
import { boundedIdentifier } from "./internal/orchestrator.js";
import type { SignedGrantProvider, SignedGrantSourceOptions } from "./contracts.js";

interface SignedGrantSourceResources {
  readonly provider: SignedGrantProvider;
}

const signedGrantSourceResources = new WeakMap<
  SignedGrantSource,
  SignedGrantSourceResources
>();
const SIGNED_GRANT_SOURCE_TOKEN: unique symbol = Symbol(
  "auths-signed-grant-source",
);
let mintSignedGrantSource: (sourceId: string, provider: SignedGrantProvider) => SignedGrantSource;

export class SignedGrantSource {
  readonly sourceId: string;

  private constructor(
    token: typeof SIGNED_GRANT_SOURCE_TOKEN,
    sourceId: string,
    provider: SignedGrantProvider,
  ) {
    if (token !== SIGNED_GRANT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths signed-grant source");
    }
    this.sourceId = sourceId;
    signedGrantSourceResources.set(this, { provider });
    Object.freeze(this);
  }

  private static create(
    token: typeof SIGNED_GRANT_SOURCE_TOKEN,
    sourceId: string,
    provider: SignedGrantProvider,
  ): SignedGrantSource {
    if (token !== SIGNED_GRANT_SOURCE_TOKEN) {
      throw new TypeError("sealed Auths signed-grant source");
    }
    return new SignedGrantSource(token, sourceId, provider);
  }

  static {
    mintSignedGrantSource = (sourceId, provider) =>
      SignedGrantSource.create(SIGNED_GRANT_SOURCE_TOKEN, sourceId, provider);
  }
}

export function signedGrantSource(
  options: SignedGrantSourceOptions,
): SignedGrantSource {
  if (
    options === null ||
    typeof options !== "object" ||
    options.provider === null ||
    typeof options.provider !== "object" ||
    typeof options.provider.loadSignedGrant !== "function"
  ) {
    throw new AuthsWorkflowError(
      "invalid-authority-source",
      "signed-grant provider does not implement the Auths source port",
    );
  }
  return mintSignedGrantSource(
    boundedIdentifier(options.sourceId, "signed-grant source"),
    options.provider,
  );
}


export function signedGrantProviderFor(source: SignedGrantSource): SignedGrantProvider | undefined {
  return signedGrantSourceResources.get(source)?.provider;
}
