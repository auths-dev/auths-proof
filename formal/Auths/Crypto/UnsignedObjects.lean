import qualification.aeneas.generated.protocol_codec.Types
import Auths.Crypto.UnsignedWire

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Crypto.UnsignedObjects
open UnsignedWire

/- Independent field schemas for every signed core object. The definitions
project values into the byte grammar; they invoke no source encoder, decoder,
successful-result predicate or content hash. Collection order and multiplicity
are explicit. Source refinements and validated-domain inverse proofs must be
earned separately before these schemas qualify the complete protocol path. -/

def utf8 (value : String) : List Nat :=
  value.toByteArray.toList.map UInt8.toNat

def digest (value : auths_model.Digest) : List Nat := bytes (value.val.map UScalar.val)

def identifier (value : String) : List Nat := text (utf8 value)

def profile (value : auths_model.ProfileRef) : List Nat :=
  map [(0, identifier value.id), (1, uint value.version.val)]

def permission (value : auths_model.Permission) : List Nat :=
  map [(0, identifier value.capability), (1, identifier value.resource)]

def budget (value : auths_model.BudgetCeiling) : List Nat :=
  map [(0, identifier value.algebra), (1, uint value.value.val)]

def optionalBudget (value : Option auths_model.BudgetCeiling) : List Nat :=
  match value with | none => null | some value => budget value

def optionalDigest (value : Option auths_model.Digest) : List Nat :=
  match value with | none => null | some value => digest value

def statusPolicy : auths_model.StatusPolicy → List Nat
  | .ExpiryOnly => map [(0, uint 0)]
  | .SnapshotRequired method maximum =>
      map [(0, uint 1), (1, identifier method), (2, uint maximum.val)]

def constraint : auths_model.ActionConstraint → List Nat
  | .AnyBody => map [(0, uint 0)]
  | .ExactBodyDigest value => map [(0, uint 1), (1, digest value)]
  | .AllowedBodyDigests values => map [(0, uint 2), (1, array (values.val.map digest))]

def extension (value : auths_model.CriticalExtension) : List Nat :=
  map [(0, identifier value.id), (1, bytes (value.bytes.val.map UScalar.val))]

def extensions (value : auths_model.CriticalExtensions) : List Nat :=
  array (value.val.map extension)

def descriptorFields (value : auths_model.SignatureDescriptor) : UnsignedWire.Descriptor :=
  ⟨utf8 value.principal_method, utf8 value.verification_method, utf8 value.suite⟩

def signatureDescriptor (value : auths_model.SignatureDescriptor) : List Nat :=
  descriptor (descriptorFields value)

def signature (value : auths_model.SignatureEnvelope) : List Nat :=
  map [(0, signatureDescriptor value.descriptor), (1, bytes (value.signature.val.map UScalar.val))]

def attachment (value : auths_model.AttachmentDescriptor) : List Nat :=
  map [(0, digest value.digest), (1, identifier value.media_type),
    (2, uint value.byte_length.val), (3, identifier value.disposition),
    (4, boolean (match value.confidentiality with | .Encrypted => true | .Plain => false)),
    (5, boolean (match value.presence with | .Required => true | .Optional => false)),
    (6, boolean (match value.opacity with | .OpaqueAllowed => true | .MustBeInspectable => false))]

def grant (value : auths_model.GrantStatement) : List Nat :=
  map [(0, uint value.version.val), (1, identifier value.issuer),
    (2, identifier value.subject), (3, identifier value.profile.id),
    (4, uint value.profile.version.val), (5, array (value.permissions.val.map permission)),
    (6, uint value.validity.not_before.val), (7, uint value.validity.expires_at.val),
    (8, array (value.audiences.val.map identifier)), (9, constraint value.action_constraint),
    (10, optionalBudget value.budget_ceiling), (11, uint value.remaining_depth.val),
    (12, optionalDigest value.parent), (13, statusPolicy value.status_policy),
    (14, identifier value.assurance_floor), (15, extensions value.extensions)]

def action (value : auths_model.ActionEnvelope) : List Nat :=
  map [(0, uint value.version.val), (1, identifier value.profile.id),
    (2, uint value.profile.version.val), (3, identifier value.body_media_type),
    (4, digest value.canonical_body_digest), (5, identifier value.permission.capability),
    (6, identifier value.permission.resource), (7, optionalBudget value.requested_budget),
    (8, identifier value.audience), (9, digest value.challenge),
    (10, uint value.validity.not_before.val), (11, uint value.validity.expires_at.val),
    (12, identifier value.actor), (13, optionalDigest value.terminal_grant),
    (14, digest value.authorization_plan), (15, identifier value.channel_binding),
    (16, digest value.proof_ref), (17, array (value.attachments.val.map attachment)),
    (18, extensions value.extensions)]

def principalState : auths_model.PrincipalState → Nat
  | .Active => 0 | .Revoked => 1 | .Superseded => 2

def grantState : auths_model.GrantState → Nat
  | .Active => 0 | .Revoked => 1 | .Superseded => 2

def principalStatus (value : auths_model.PrincipalStatusStatement) : List Nat :=
  map [(0, uint value.version.val), (1, identifier value.method),
    (2, identifier value.principal), (3, uint (principalState value.state)),
    (4, uint value.sequence.val), (5, uint value.observed_at.val),
    (6, uint value.valid_until.val), (7, identifier value.issuer),
    (8, extensions value.extensions)]

def grantStatus (value : auths_model.GrantStatusStatement) : List Nat :=
  map [(0, uint value.version.val), (1, identifier value.method),
    (2, digest value.grant_id), (3, uint (grantState value.state)),
    (4, uint value.sequence.val), (5, uint value.observed_at.val),
    (6, uint value.valid_until.val), (7, identifier value.issuer),
    (8, extensions value.extensions)]

def approval (value : auths_model.approval.ApprovalStatement) : List Nat :=
  map [(0, uint value.version.val), (1, identifier value.approver),
    (2, digest value.requirement), (3, identifier value.media_type),
    (4, digest value.body_digest), (5, identifier value.permission.capability),
    (6, identifier value.permission.resource), (7, optionalBudget value.requested_budget),
    (8, optionalDigest value.attributes), (9, identifier value.audience),
    (10, digest value.challenge), (11, uint value.validity.not_before.val),
    (12, uint value.validity.expires_at.val)]

def factValue : auths_model.observation.FactValue → List Nat
  | .Uint value => uint value.val
  | .Bytes value => bytes (value.val.map UScalar.val)
  | .Text value => identifier value

def fact (value : auths_model.observation.ObservationFact) : List Nat :=
  map [(0, identifier value.name), (1, factValue value.value)]

def observation (value : auths_model.observation.ObservationStatement) : List Nat :=
  map [(0, uint value.version.val), (1, identifier value.observer),
    (2, identifier value.schema), (3, identifier value.subject),
    (4, uint value.observed_at.val), (5, array (value.facts.val.map fact))]

def approvalRequirement (value : auths_model.approval.ApprovalRequirement) : List Nat :=
  map [(0, array (value.approvers.val.map identifier)), (1, uint value.threshold.val)]

def observationSubject : auths_model.observation.ObservationSubject → List Nat
  | .Resource value => map [(0, uint 0), (1, identifier value)]
  | .ActionFact name => map [(0, uint 1), (1, identifier name)]

def observationCondition (value : auths_model.observation.ObservationCondition) : List Nat :=
  match value.test with
  | .EqLiteral literal =>
    map [(0, uint 0), (1, identifier value.name), (2, factValue literal)]
  | .EqAction name =>
    map [(0, uint 1), (1, identifier value.name), (2, identifier name)]
  | .UintRange range =>
    map [(0, uint 2), (1, identifier value.name), (2, uint range.lo.val), (3, uint range.hi.val)]
  | .Member values =>
    map [(0, uint 3), (1, identifier value.name), (2, array (values.val.map factValue))]

def observationRequirement (value : auths_model.observation.ObservationRequirement) : List Nat :=
  map [(0, identifier value.observer_anchor), (1, identifier value.schema),
    (2, observationSubject value.subject), (3, uint value.max_age_seconds.val),
    (4, array (value.conditions.val.map observationCondition))]

def evidenceContent (value : auths_model.EvidenceObject) : List Nat :=
  map [(0, identifier value.evidence_type), (1, identifier value.media_type),
    (2, bytes (value.bytes.val.map UScalar.val))]

def evidence (value : auths_model.EvidenceObject) : List Nat :=
  map [(0, digest value.id), (1, identifier value.evidence_type),
    (2, identifier value.media_type), (3, bytes (value.bytes.val.map UScalar.val))]

def signedGrant (value : auths_model.SignedGrant) : List Nat :=
  map [(0, grant value.statement), (1, signature value.signature)]

def signedAction (value : auths_model.SignedAction) : List Nat :=
  map [(0, action value.envelope), (1, signature value.signature)]

def signedPrincipalStatus (value : auths_model.SignedPrincipalStatus) : List Nat :=
  map [(0, principalStatus value.statement), (1, signature value.signature)]

def signedGrantStatus (value : auths_model.SignedGrantStatus) : List Nat :=
  map [(0, grantStatus value.statement), (1, signature value.signature)]

def signedApproval (value : auths_model.approval.SignedApproval) : List Nat :=
  map [(0, approval value.statement), (1, signature value.signature),
    (2, array (value.evidence.val.map evidence))]

def signedObservation (value : auths_model.observation.SignedObservation) : List Nat :=
  map [(0, observation value.statement), (1, signature value.signature),
    (2, array (value.evidence.val.map evidence))]

def grantSigningObject (value : auths_model.GrantStatement)
    (selected : auths_model.SignatureDescriptor) : List Nat :=
  signingObject (grant value) (descriptorFields selected)

def actionSigningObject (value : auths_model.ActionEnvelope)
    (selected : auths_model.SignatureDescriptor) : List Nat :=
  signingObject (action value) (descriptorFields selected)

def principalStatusSigningObject (value : auths_model.PrincipalStatusStatement)
    (selected : auths_model.SignatureDescriptor) : List Nat :=
  signingObject (principalStatus value) (descriptorFields selected)

def grantStatusSigningObject (value : auths_model.GrantStatusStatement)
    (selected : auths_model.SignatureDescriptor) : List Nat :=
  signingObject (grantStatus value) (descriptorFields selected)

def approvalSigningObject (value : auths_model.approval.ApprovalStatement)
    (selected : auths_model.SignatureDescriptor) : List Nat :=
  signingObject (approval value) (descriptorFields selected)

def observationSigningObject (value : auths_model.observation.ObservationStatement)
    (selected : auths_model.SignatureDescriptor) : List Nat :=
  signingObject (observation value) (descriptorFields selected)

end Auths.Crypto.UnsignedObjects
