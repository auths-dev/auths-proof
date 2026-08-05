import { SigningCoordinator, WasmSigningAdapter } from "../internal/signing.js";
import {
  AuthsWorkflowError,
  type ApprovalConfiguration,
  type PermissionSummary,
  type Profile,
  type SignedGrantSource,
  type Signer,
  type TrustedAuthority,
  boundedIdentifier,
  copyPolicy,
  copyPrincipal,
  signedGrantSource,
  trustedContextSource,
} from "../workflow.js";
import { loadPackagedWorkflowEngine } from "./wasm.js";

export interface RawKeyAuthorityRequest<P extends Profile> {
  readonly authorityId: string;
  readonly rootSigner: Signer;
  readonly subjectPrincipal: string;
  readonly profile: P;
  readonly permissions: readonly PermissionSummary[];
  readonly resourceNamespaces: readonly string[];
  readonly validity: Readonly<{ notBefore: bigint; expiresAt: bigint }>;
  readonly audiences: readonly string[];
  readonly budget?: Readonly<{ algebra: string; value: bigint }>;
  readonly remainingDepth: number;
  readonly approval: ApprovalConfiguration;
}

export interface PreparedRawKeyAuthority {
  readonly trustedAuthority: TrustedAuthority;
  readonly authority: SignedGrantSource;
}

export async function prepareRawKeyAuthority<P extends Profile>(
  options: RawKeyAuthorityRequest<P>,
): Promise<PreparedRawKeyAuthority> {
  const engine = await loadPackagedWorkflowEngine();
  const authorityId = boundedIdentifier(options.authorityId, "authority id");
  const requiredApproval = copyPolicy(options.approval.policy.reference);
  let root;
  try {
    root = copyPrincipal(await options.rootSigner.publicIdentity());
  } catch {
    throw new AuthsWorkflowError("invalid-principal", "root signer returned an invalid principal descriptor");
  }
  if (root.principalMethod !== "raw-key-v1" || root.suite !== "ed25519-v1") {
    throw new AuthsWorkflowError("invalid-principal", "raw-key bootstrap requires an Ed25519 raw-key root signer");
  }
  let preparation;
  try {
    preparation = engine.prepareRawKeyAuthorityV1(
      root.principal,
      options.subjectPrincipal,
      options.profile.id,
      options.profile.version,
      options.permissions.map((permission) => permission.capability),
      options.permissions.map((permission) => permission.resource),
      [...options.resourceNamespaces],
      options.validity.notBefore,
      options.validity.expiresAt,
      [...options.audiences],
      options.budget !== undefined,
      options.budget?.algebra ?? "",
      options.budget?.value ?? 0n,
      options.remainingDepth,
    );
    const signed = await new SigningCoordinator(new WasmSigningAdapter(engine)).execute({
      objectKind: "grant",
      unsignedObject: preparation.statementCbor,
      principal: root,
      signer: options.rootSigner,
      approval: options.approval,
      requiredApproval,
      expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 300n,
      display: [
        { label: "Authority", value: authorityId },
        { label: "Subject", value: options.subjectPrincipal },
        { label: "Profile", value: `${options.profile.id}/${options.profile.version}` },
        { label: "Permissions", value: String(options.permissions.length) },
        { label: "Delegation depth", value: String(options.remainingDepth) },
      ],
    });
    if (!signed.evidence.some((item) => item.evidenceType === "raw-key-v1")) {
      throw new AuthsWorkflowError("invalid-provider", "raw-key root signer omitted public control evidence");
    }
    const signedGrant = signed.signedObject.slice();
    const evidence = signed.evidence.map((item) => Object.freeze({
      evidenceType: item.evidenceType,
      mediaType: item.mediaType,
      bytes: item.bytes.slice(),
    }));
    const trustedContext = preparation.trustedContextCbor.slice();
    const verifierConfiguration = preparation.verifierConfiguration.slice();
    return Object.freeze({
      trustedAuthority: Object.freeze({
        authorityId,
        rootPrincipal: root.principal,
        verifierConfiguration,
        context: trustedContextSource({
          sourceId: `${authorityId}.context`,
          provider: { async loadTrustedContext() { return trustedContext.slice(); } },
        }),
        requiredApproval,
      }),
      authority: signedGrantSource({
        sourceId: `${authorityId}.root-grant`,
        provider: { async loadSignedGrant() { return { signedGrant: signedGrant.slice(), evidence }; } },
      }),
    });
  } catch (error) {
    if (error instanceof AuthsWorkflowError) throw error;
    throw new AuthsWorkflowError("invalid-authority", "native raw-key authority preparation rejected the request");
  } finally {
    preparation?.free?.();
  }
}
