import Auths.Crypto.UnsignedObjects
import Auths.Crypto.UnsignedLeaves

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Crypto.BoundedPolicyObjects
open Auths.Codec.Refinement

/- Complete independent bounded-policy bytes. A syntactically encoded policy
does not establish its semantics or that its declared digest opens correctly.
Those constructor/opening/evaluator obligations are separate from this schema. -/
def commitment (value : auths_model.bounded_policy.PolicyCommitment) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.policy_type),
    (1, UnsignedWire.uint value.policy_version.val),
    (2, UnsignedObjects.identifier value.canonicalization_id),
    (3, UnsignedObjects.digest value.policy_digest),
    (4, UnsignedObjects.identifier value.evaluator_semantic_id)]

def commitmentCost (value : auths_model.bounded_policy.PolicyCommitment) : Nat :=
  131 + value.policy_type.toByteArray.size + value.canonicalization_id.toByteArray.size +
    value.evaluator_semantic_id.toByteArray.size

def body (value : auths_model.bounded_policy.BoundedPolicyCommitment) : List Nat :=
  UnsignedWire.map [(0, commitment value.commitment),
    (1, UnsignedWire.bytes (byteList value.policy.val)),
    (2, UnsignedObjects.optionalDigest value.parent)]

def bodyCost (value : auths_model.bounded_policy.BoundedPolicyCommitment) : Nat :=
  86 + commitmentCost value.commitment + value.policy.val.length

def policyDomain : String := "auths.bounded-policy.v1"
def linkDomain : String := "auths.bounded-policy-commitment.v1"

end Auths.Crypto.BoundedPolicyObjects
