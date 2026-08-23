import * as publicRoot from "../../src/index.js";
import type { Receipt } from "../../src/index.js";
import type { AuthenticatedIdentityMessage, DecodedIdentity, ResolvedIdentity, ValidatedIdentity } from "../../src/identity.js";

// @ts-expect-error profile coordination is not a root export
publicRoot.registerProfileRuntime;
// @ts-expect-error adapters are not root exports
publicRoot.ReservationStore;
// @ts-expect-error conformance is confined to testkit
publicRoot.conformance;

// @ts-expect-error receipts cannot be forged structurally
const receipt: Receipt = { id: "forged", toBytes: () => new Uint8Array(), toJSON: () => { throw new Error(); } };
// @ts-expect-error decoded identities are package-minted
const decoded: DecodedIdentity = { validation: "decoded", methodId: "x", identityId: "y", methodMaterial: new Uint8Array(), relationships: [], toBytes: () => new Uint8Array() };
// @ts-expect-error resolved identities are package-minted
const resolved: ResolvedIdentity = { validation: "resolved", methodId: "x", identityId: "y", evidence: { source: "x", observedAtUnixSeconds: 0n, expiresAtUnixSeconds: 1n, provenance: [] } };
// @ts-expect-error validated identities are package-minted
const validated: ValidatedIdentity = { validation: "validated", methodId: "x", identityId: "y", relationships: [], toBytes: () => new Uint8Array() };
// @ts-expect-error authenticated messages are package-minted
const authenticated: AuthenticatedIdentityMessage = { identity: validated, relationshipId: "x", message: new Uint8Array() };

void receipt; void decoded; void resolved; void validated; void authenticated;
