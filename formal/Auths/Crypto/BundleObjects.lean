import Auths.Crypto.SignedObjectWriters
import Auths.Crypto.PlanWriters
import Auths.Crypto.CommitmentFrames
import Auths.Codec.StableNormalization

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Crypto.BundleObjects
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolArrayWriters

/- Independent bundle bytes, including the wire writer's stable normalization.
Keys use field projections and a named mathematical SHA function over independent
unsigned schemas. No Rust encoder, parser, hash result or successful-normalizer
predicate is invoked. Equal keys retain complete records and their multiplicity.
Approval order is the stored order, matching the source contract. -/
def header (value : auths_model.BundleHeader) : List Nat :=
  UnsignedWire.map [(0, UnsignedWire.uint value.version.val), (1, UnsignedWire.uint value.flags.val)]

def statementParts : auths_model.StatementRef → Nat × auths_model.Digest
  | .Grant identifier => (0, identifier)
  | .Action identifier => (1, identifier)
  | .PrincipalStatus identifier => (2, identifier)
  | .GrantStatus identifier => (3, identifier)

def statementKey (value : auths_model.StatementRef) : List Nat :=
  (statementParts value).1 :: byteList (statementParts value).2.val

def statementRef (value : auths_model.StatementRef) : List Nat :=
  UnsignedWire.map [(0, UnsignedWire.uint (statementParts value).1),
    (1, UnsignedObjects.digest (statementParts value).2)]

def binding (value : auths_model.ControlBinding) : List Nat :=
  UnsignedWire.map [(0, statementRef value.statement),
    (1, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest))]

def optionalBytes : Option (alloc.vec.Vec Std.U8) → List Nat
  | none => UnsignedWire.null
  | some value => UnsignedWire.bytes (byteList value.val)

def optionalBytesCost : Option (alloc.vec.Vec Std.U8) → Nat
  | none => 1
  | some value => 9 + value.val.length

def bodySlices : Option (alloc.vec.Vec Std.U8) → Option (Slice Std.U8)
  | none => none
  | some value => some (alloc.vec.Vec.deref value)

def optionalSliceBytes : Option (Slice Std.U8) → List Nat
  | none => UnsignedWire.null
  | some value => UnsignedWire.bytes (byteList value.val)

def optionalSliceCost : Option (Slice Std.U8) → Nat
  | none => 1
  | some value => 9 + value.val.length

theorem body_slice_bytes (value : Option (alloc.vec.Vec Std.U8)) :
    optionalSliceBytes (bodySlices value) = optionalBytes value := by cases value <;> rfl

theorem body_slice_cost (value : Option (alloc.vec.Vec Std.U8)) :
    optionalSliceCost (bodySlices value) = optionalBytesCost value := by cases value <;> rfl

def bindingCost (value : auths_model.ControlBinding) : Nat :=
  113 + 41 * value.evidence.val.length

def digestKey (value : auths_model.Digest) : List Nat := byteList value.val

def grantKey (sha256 : List Nat → auths_model.Digest) (value : auths_model.SignedGrant) : List Nat :=
  digestKey (sha256 (CommitmentFrames.identifier ⟨1, UnsignedObjects.grant value.statement⟩))

def principalStatusKey (sha256 : List Nat → auths_model.Digest)
    (value : auths_model.SignedPrincipalStatus) : List Nat :=
  digestKey (sha256 (CommitmentFrames.identifier ⟨5, UnsignedObjects.principalStatus value.statement⟩))

def grantStatusKey (sha256 : List Nat → auths_model.Digest)
    (value : auths_model.SignedGrantStatus) : List Nat :=
  digestKey (sha256 (CommitmentFrames.identifier ⟨6, UnsignedObjects.grantStatus value.statement⟩))

def actionKey (value : auths_model.SignedAction) : List Nat := digestKey value.envelope.proof_ref
def evidenceKey (value : auths_model.EvidenceObject) : List Nat := digestKey value.id
def bindingKey (value : auths_model.ControlBinding) : List Nat := statementKey value.statement
def attachmentKey (value : auths_model.AttachmentDescriptor) : List Nat := digestKey value.digest

def grants (sha256 : List Nat → auths_model.Digest) (value : auths_model.ProofBundle) :=
  StableNormalization.sort (grantKey sha256) value.grants.val

def actions (value : auths_model.ProofBundle) :=
  StableNormalization.sort actionKey value.actions.val

def evidence (value : auths_model.ProofBundle) :=
  StableNormalization.sort evidenceKey value.evidence.val

def bindings (value : auths_model.ProofBundle) :=
  StableNormalization.sort bindingKey value.bindings.val

def principalStatus (sha256 : List Nat → auths_model.Digest) (value : auths_model.ProofBundle) :=
  StableNormalization.sort (principalStatusKey sha256) value.principal_status.val

def grantStatus (sha256 : List Nat → auths_model.Digest) (value : auths_model.ProofBundle) :=
  StableNormalization.sort (grantStatusKey sha256) value.grant_status.val

def attachments (value : auths_model.ProofBundle) :=
  StableNormalization.sort attachmentKey value.attachments.val

def bundle (sha256 : List Nat → auths_model.Digest) (value : auths_model.ProofBundle) : List Nat :=
  UnsignedWire.map [
    (0, header value.header),
    (1, UnsignedWire.array ((grants sha256 value).map UnsignedObjects.signedGrant)),
    (2, UnsignedWire.array ((actions value).map UnsignedObjects.signedAction)),
    (3, PlanWire.encode (PlanWriters.viewPlan value.plan)),
    (4, UnsignedWire.array ((evidence value).map UnsignedObjects.evidence)),
    (5, UnsignedWire.array ((bindings value).map binding)),
    (6, UnsignedWire.array ((principalStatus sha256 value).map UnsignedObjects.signedPrincipalStatus)),
    (7, UnsignedWire.array ((grantStatus sha256 value).map UnsignedObjects.signedGrantStatus)),
    (8, UnsignedWire.array ((attachments value).map UnsignedObjects.attachment)),
    (9, optionalBytes value.canonical_body),
    (10, UnsignedWire.array (value.approvals.val.map UnsignedObjects.signedApproval))]

/-- Stable normalization changes no payload-dependent allocation sum. This
includes collisions and repeated records, without an injectivity hypothesis. -/
theorem allocation_normalized {Value Key : Type} [LinearOrder Key]
    (key : Value → Key) (cost : Value → Nat) (values : List Value) :
    allocation cost (StableNormalization.sort key values) = allocation cost values := by
  exact ((StableNormalization.permutation key values).map cost).sum_eq

def cost (value : auths_model.ProofBundle) : Nat :=
  108 + ([45,
    9 + allocation SignedObjectWriters.grantCost value.grants.val,
    9 + allocation SignedObjectWriters.actionCost value.actions.val,
    PlanWriters.cost value.plan,
    9 + allocation EvidenceWriters.recordCost value.evidence.val,
    9 + allocation bindingCost value.bindings.val,
    9 + allocation SignedObjectWriters.principal_statusCost value.principal_status.val,
    9 + allocation SignedObjectWriters.grant_statusCost value.grant_status.val,
    9 + allocation UnsignedLeaves.attachmentCost value.attachments.val,
    optionalBytesCost value.canonical_body,
    9 + allocation SignedObjectWriters.approvalCost value.approvals.val] : List Nat).sum

end Auths.Crypto.BundleObjects
