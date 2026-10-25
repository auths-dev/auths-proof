import Auths.Crypto.BundleObjects

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Crypto.SnapshotObjects
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolArrayWriters
open Auths.Codec.ProtocolTextWriters

/- Independent snapshot/trust bytes. Primary constructor order, trusted issuer
meaning and statement authentication are separate from this wire grammar.
The wire statements use stable derived-ID order, retaining all signed payloads
and tie order. No source encoder/decoder/hash result defines this model. -/
def scope : auths_model.StatusScope → List Nat
  | .OwnAnchor => UnsignedWire.map [(0, UnsignedWire.uint 0)]
  | .Anchors anchors => UnsignedWire.map [(0, UnsignedWire.uint 1),
      (1, UnsignedWire.array (anchors.val.map UnsignedObjects.identifier))]
  | .AnyAnchor => UnsignedWire.map [(0, UnsignedWire.uint 2)]

def scopeCost : auths_model.StatusScope → Nat
  | .OwnAnchor => 27
  | .Anchors anchors => 45 + allocation textCost anchors.val
  | .AnyAnchor => 27

def trustRule (value : auths_model.StatusTrustRule) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.method),
    (1, UnsignedObjects.identifier value.issuer), (2, UnsignedWire.uint value.sequence_floor.val),
    (3, scope value.scope)]

def trustRuleCost (value : auths_model.StatusTrustRule) : Nat :=
  72 + value.method.toByteArray.size + value.issuer.toByteArray.size + scopeCost value.scope

def trust (values : List auths_model.StatusTrustRule) : List Nat :=
  UnsignedWire.array (values.map trustRule)

def trustCost (values : List auths_model.StatusTrustRule) : Nat := 9 + allocation trustRuleCost values

def principalStatements (sha256 : List Nat → auths_model.Digest)
    (value : auths_model.PrincipalStatusSnapshot) :=
  StableNormalization.sort (BundleObjects.principalStatusKey sha256) value.statements.val

def grantStatements (sha256 : List Nat → auths_model.Digest)
    (value : auths_model.GrantStatusSnapshot) :=
  StableNormalization.sort (BundleObjects.grantStatusKey sha256) value.statements.val

def principalSnapshot (sha256 : List Nat → auths_model.Digest)
    (value : auths_model.PrincipalStatusSnapshot) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.digest value.id),
    (1, UnsignedWire.uint value.observed_at.val), (2, UnsignedWire.uint value.valid_until.val),
    (3, UnsignedWire.array ((principalStatements sha256 value).map UnsignedObjects.signedPrincipalStatus)),
    (4, UnsignedWire.array (value.checkpoints.val.map UnsignedObjects.digest)),
    (5, trust value.trust.val)]

def grantSnapshot (sha256 : List Nat → auths_model.Digest)
    (value : auths_model.GrantStatusSnapshot) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.digest value.id),
    (1, UnsignedWire.uint value.observed_at.val), (2, UnsignedWire.uint value.valid_until.val),
    (3, UnsignedWire.array ((grantStatements sha256 value).map UnsignedObjects.signedGrantStatus)),
    (4, UnsignedWire.array (value.checkpoints.val.map UnsignedObjects.digest)),
    (5, trust value.trust.val)]

def principalCost (value : auths_model.PrincipalStatusSnapshot) : Nat :=
  149 + allocation SignedObjectWriters.principal_statusCost value.statements.val +
    41 * value.checkpoints.val.length + allocation trustRuleCost value.trust.val

def grantCost (value : auths_model.GrantStatusSnapshot) : Nat :=
  149 + allocation SignedObjectWriters.grant_statusCost value.statements.val +
    41 * value.checkpoints.val.length + allocation trustRuleCost value.trust.val

end Auths.Crypto.SnapshotObjects
