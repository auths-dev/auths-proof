import Auths.Codec.ProtocolReencoding
import Auths.Codec.ProtocolConstructors
import Auths.Codec.ProtocolIdentifiers
import Auths.Codec.ProtocolCollectionScans
import Auths.Codec.ProtocolKeyScans
import Auths.Codec.ProtocolSets
import Auths.Codec.RequirementConstructors
import Auths.Codec.CanonicalValues
import Auths.Codec.CanonicalEncoding
import Auths.Codec.CanonicalIntegrity
import Auths.Codec.StableNormalization
import Auths.Codec.OwnedRecords
import Auths.Codec.KeyDerivation
import Auths.Codec.SnapshotOrdering
import Auths.Codec.RecordNormalization
import Auths.Crypto.ProtocolFramingTotality
import Auths.Crypto.SigningCallers
import Auths.Crypto.UnsignedObjects
import Auths.Crypto.DescriptorWriter
import Auths.Crypto.SigningPreimages
import Auths.Crypto.FramedHash
import Auths.Crypto.IdentifierCallers
import Auths.Crypto.EvidenceWriters
import Auths.Crypto.RequirementIdentifiers
import Auths.Crypto.PlanIdentifier
import Auths.Crypto.SignedCommitments
import Auths.Crypto.BundleLeaves
import Auths.Crypto.BundleSelectors
import Auths.Crypto.BundleSorting
import Auths.Crypto.BundleCommitments
import Auths.Crypto.SigningPreimageResults
import Auths.Crypto.SnapshotWriters
import Auths.Crypto.ContextLimits
import Auths.Crypto.ContextAnchorArrays
import Auths.Crypto.ContextAssurance
import Auths.Crypto.ContextCommitments
import Auths.Crypto.BoundedPolicyWriters
import Auths.Crypto.BoundedPolicyCommitments
import Auths.Crypto.ResultCommitments
import Auths.Codec.PolicyCanonical
import Auths.Crypto.ResultCost
import Auths.Codec.ResultIntegrity
import Auths.Codec.PolicyInverse
import Auths.Codec.PolicyAccepted
import Auths.Codec.PolicyReadTotal
import Auths.Codec.PolicyCursor
import Auths.Codec.PolicyAssurance

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace qualification.aeneas.cases.protocolCodec

-- Typed result specifications obtain source success/refusal; none supplies
-- a successful public caller as a premise.
example (payload : Slice Std.U8) :
    hash.identifier_preimage .Grant payload ⦃ result =>
      Auths.Crypto.FramedHash.PreimageResult
        (Auths.Crypto.FramedHash.IdentifierAdmissible
          (Auths.Crypto.ProtocolFraming.identifierFrame .Grant payload).payload)
        (Auths.Crypto.CommitmentFrames.identifier
          (Auths.Crypto.ProtocolFraming.identifierFrame .Grant payload)) result ⦄ :=
  Auths.Crypto.FramedHash.identifier_preimage_total .Grant payload

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256) (payload : Slice Std.U8) :
    hash.domain_commitment ⟨[], by scalar_tac⟩ payload = ok (.Err .LimitExceeded) := by
  apply Auths.Crypto.FramedHash.application_hash_refuses sha256 contract
  simp [Auths.Crypto.FramedHash.ApplicationAdmissible, Auths.Crypto.ProtocolFraming.applicationFrame]

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256) :
    hash.body_digest ⟨[], by scalar_tac⟩ = ok (sha256 []) := by
  simpa only [Auths.Codec.Refinement.byteList, List.map_nil] using
    Auths.Crypto.IdentifierCallers.body_digest_exact sha256 contract ⟨[], by scalar_tac⟩

example : Auths.Crypto.CommitmentFrames.identifier ⟨1, [0, 255]⟩ ≠
    Auths.Crypto.CommitmentFrames.identifier ⟨2, [0, 255]⟩ := by decide

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256) (value : auths_model.GrantStatement)
    (valid : Auths.Codec.ProtocolValidity.Grant value)
    (space : Auths.Crypto.StatementWriters.grantCost value ≤ Usize.max)
    (fits : Auths.Crypto.FramedHash.IdentifierAdmissible (Auths.Crypto.UnsignedObjects.grant value)) :
    hash.grant_id value = ok (.Ok (sha256 (Auths.Crypto.CommitmentFrames.identifier
      (Auths.Crypto.IdentifierCallers.grantFrame value)))) :=
  Auths.Crypto.IdentifierCallers.grant_exact sha256 contract value valid space fits

example (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : Auths.Codec.ProtocolValidity.Grant value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (space : Auths.Crypto.SigningObjectWriters.grantSigningCost value descriptor ≤ Usize.max) :
    hash.grant_signing_preimage value descriptor ⦃ result =>
      Auths.Crypto.FramedHash.PreimageResult
        (Auths.Crypto.FramedHash.SigningAdmissible (Auths.Crypto.SigningPreimages.grantFrame value descriptor))
        (Auths.Crypto.Framing.encode (Auths.Crypto.SigningPreimages.grantFrame value descriptor)) result ⦄ :=
  Auths.Crypto.SigningPreimageResults.grant_total value descriptor valid descriptorValid space

example (value : auths_model.ActionEnvelope) (descriptor : auths_model.SignatureDescriptor)
    (valid : Auths.Codec.ProtocolValidity.Action value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (space : Auths.Crypto.SigningObjectWriters.actionSigningCost value descriptor ≤ Usize.max) :
    hash.action_signing_preimage value descriptor ⦃ result =>
      Auths.Crypto.FramedHash.PreimageResult
        (Auths.Crypto.FramedHash.SigningAdmissible (Auths.Crypto.SigningPreimages.actionFrame value descriptor))
        (Auths.Crypto.Framing.encode (Auths.Crypto.SigningPreimages.actionFrame value descriptor)) result ⦄ :=
  Auths.Crypto.SigningPreimageResults.action_total value descriptor valid descriptorValid space

example (value : auths_model.PrincipalStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : Auths.Codec.ProtocolValidity.PrincipalStatus value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (space : Auths.Crypto.SigningObjectWriters.principal_statusSigningCost value descriptor ≤ Usize.max) :
    hash.principal_status_signing_preimage value descriptor ⦃ result =>
      Auths.Crypto.FramedHash.PreimageResult
        (Auths.Crypto.FramedHash.SigningAdmissible (Auths.Crypto.SigningPreimages.principal_statusFrame value descriptor))
        (Auths.Crypto.Framing.encode (Auths.Crypto.SigningPreimages.principal_statusFrame value descriptor)) result ⦄ :=
  Auths.Crypto.SigningPreimageResults.principal_status_total value descriptor valid descriptorValid space

example (value : auths_model.GrantStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : Auths.Codec.ProtocolValidity.GrantStatus value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (space : Auths.Crypto.SigningObjectWriters.grant_statusSigningCost value descriptor ≤ Usize.max) :
    hash.grant_status_signing_preimage value descriptor ⦃ result =>
      Auths.Crypto.FramedHash.PreimageResult
        (Auths.Crypto.FramedHash.SigningAdmissible (Auths.Crypto.SigningPreimages.grant_statusFrame value descriptor))
        (Auths.Crypto.Framing.encode (Auths.Crypto.SigningPreimages.grant_statusFrame value descriptor)) result ⦄ :=
  Auths.Crypto.SigningPreimageResults.grant_status_total value descriptor valid descriptorValid space

example (value : auths_model.approval.ApprovalStatement) (descriptor : auths_model.SignatureDescriptor) (profileValue : auths_model.ProfileRef)
    (valid : Auths.Codec.ProtocolValidity.Approval value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (profileValid : Auths.Codec.ProtocolValidity.Profile profileValue)
    (space : Auths.Crypto.SigningObjectWriters.approvalSigningCost value descriptor ≤ Usize.max) :
    hash.approval_signing_preimage value descriptor profileValue ⦃ result =>
      Auths.Crypto.FramedHash.PreimageResult
        (Auths.Crypto.FramedHash.SigningAdmissible (Auths.Crypto.SigningPreimages.approvalFrame value descriptor profileValue))
        (Auths.Crypto.Framing.encode (Auths.Crypto.SigningPreimages.approvalFrame value descriptor profileValue)) result ⦄ :=
  Auths.Crypto.SigningPreimageResults.approval_total value descriptor profileValue valid descriptorValid profileValid space

example (value : auths_model.observation.ObservationStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : Auths.Codec.ProtocolValidity.Observation value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (space : Auths.Crypto.SigningObjectWriters.observationSigningCost value descriptor ≤ Usize.max) :
    hash.observation_signing_preimage value descriptor ⦃ result =>
      Auths.Crypto.FramedHash.PreimageResult
        (Auths.Crypto.FramedHash.SigningAdmissible (Auths.Crypto.SigningPreimages.observationFrame value descriptor))
        (Auths.Crypto.Framing.encode (Auths.Crypto.SigningPreimages.observationFrame value descriptor)) result ⦄ :=
  Auths.Crypto.SigningPreimageResults.observation_total value descriptor valid descriptorValid space

-- Bounded evidence fields earn native writer/framing space; this useful
-- source equation has no allocation-fit or successful-call premise.
example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256) (value : auths_model.EvidenceObject)
    (valid : Auths.Codec.ProtocolValidity.Evidence value) :
    hash.evidence_id value = ok (.Ok (sha256 (Auths.Crypto.CommitmentFrames.identifier
      (Auths.Crypto.IdentifierCallers.evidenceFrame value)))) :=
  Auths.Crypto.IdentifierCallers.evidence_valid_exact sha256 contract value valid

example (value : auths_model.EvidenceObject) (identifier : auths_model.EvidenceId) :
    Auths.Crypto.UnsignedObjects.evidenceContent { value with id := identifier } =
      Auths.Crypto.UnsignedObjects.evidenceContent value :=
  Auths.Crypto.EvidenceWriters.content_ignores_declared_id value identifier

-- Complete requirement IDs earn resource room from independent constructor
-- bounds. The SHA functional contract is explicit; source success is absent.
example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.approval.ApprovalRequirement)
    (valid : Auths.Codec.ProtocolValidity.ApprovalRequirement value) :
    hash.approval_requirement_id value = ok (.Ok (sha256 (Auths.Crypto.CommitmentFrames.identifier
      (Auths.Crypto.RequirementIdentifiers.approvalFrame value)))) :=
  Auths.Crypto.RequirementIdentifiers.approval_valid_exact sha256 contract value valid

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.observation.ObservationRequirement)
    (valid : Auths.Codec.ProtocolValidity.ObservationRequirement value) :
    hash.observation_requirement_id value = ok (.Ok (sha256 (Auths.Crypto.CommitmentFrames.identifier
      (Auths.Crypto.RequirementIdentifiers.observationFrame value)))) :=
  Auths.Crypto.RequirementIdentifiers.observation_valid_exact sha256 contract value valid

example (self : cbor.Encoder) (value : auths_model.observation.ObservationCondition)
    (strings : Auths.Crypto.RequirementLeaves.ConditionStrings value)
    (space : self.output.val.length + Auths.Crypto.RequirementLeaves.conditionCost value ≤ Usize.max) :
    observation.encode_condition self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.UnsignedObjects.observationCondition value ⦄ :=
  Auths.Crypto.RequirementLeaves.condition_exact self value strings space

example (value : auths_model.AuthorizationPlan)
    (space : Auths.Crypto.PlanWriters.cost value ≤ Usize.max) :
    encode.encode_authorization_plan value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes
        (Auths.Crypto.PlanWire.encode (Auths.Crypto.PlanWriters.viewPlan value)) result ⦄ :=
  Auths.Crypto.PlanWriters.plan_encoder value space

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.AuthorizationPlan)
    (space : Auths.Crypto.PlanWriters.cost value ≤ Usize.max)
    (fits : Auths.Crypto.FramedHash.IdentifierAdmissible
      (Auths.Crypto.PlanWire.encode (Auths.Crypto.PlanWriters.viewPlan value))) :
    hash.plan_id value = ok (.Ok (sha256 (Auths.Crypto.CommitmentFrames.identifier
      (Auths.Crypto.PlanIdentifier.planFrame value)))) :=
  Auths.Crypto.PlanIdentifier.plan_exact sha256 contract value space fits

-- Independent grammar witnesses preserve tags and thresholds with real-size
-- reference fields; these byte facts make no hash-injectivity claim.
example : Auths.Crypto.PlanWire.cost (.proof (List.replicate 32 0)) = 77 := by decide

example : Auths.Crypto.PlanWire.encode (.allOf [.proof (List.replicate 32 0)]) ≠
    Auths.Crypto.PlanWire.encode (.anyOf [.proof (List.replicate 32 0)]) := by decide

example : Auths.Crypto.PlanWire.encode (.kOfN 1
      [.proof (List.replicate 32 0), .proof (List.replicate 32 1)]) ≠
    Auths.Crypto.PlanWire.encode (.kOfN 2
      [.proof (List.replicate 32 0), .proof (List.replicate 32 1)]) := by decide

-- Complete signed data is preserved independently of whether its signature
-- or evidence authenticates authority. No successful encoder is a premise.
example (value : auths_model.SignedGrant)
    (valid : Auths.Codec.ProtocolValidity.SignedGrant value)
    (space : Auths.Crypto.SignedObjectWriters.grantCost value ≤ Usize.max) :
    encode.encode_signed_grant value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.UnsignedObjects.signedGrant value) result ⦄ :=
  Auths.Crypto.SignedObjectWriters.grant_encoder_valid value valid space

example (value : auths_model.SignedAction)
    (valid : Auths.Codec.ProtocolValidity.SignedAction value)
    (space : Auths.Crypto.SignedObjectWriters.actionCost value ≤ Usize.max) :
    encode.encode_signed_action value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.UnsignedObjects.signedAction value) result ⦄ :=
  Auths.Crypto.SignedObjectWriters.action_encoder_valid value valid space

example (value : auths_model.SignedPrincipalStatus)
    (valid : Auths.Codec.ProtocolValidity.SignedPrincipalStatus value)
    (space : Auths.Crypto.SignedObjectWriters.principal_statusCost value ≤ Usize.max) :
    encode.encode_signed_principal_status value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.UnsignedObjects.signedPrincipalStatus value) result ⦄ :=
  Auths.Crypto.SignedObjectWriters.principal_status_encoder_valid value valid space

example (value : auths_model.SignedGrantStatus)
    (valid : Auths.Codec.ProtocolValidity.SignedGrantStatus value)
    (space : Auths.Crypto.SignedObjectWriters.grant_statusCost value ≤ Usize.max) :
    encode.encode_signed_grant_status value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.UnsignedObjects.signedGrantStatus value) result ⦄ :=
  Auths.Crypto.SignedObjectWriters.grant_status_encoder_valid value valid space

example (value : auths_model.approval.SignedApproval)
    (valid : Auths.Codec.ProtocolValidity.SignedApproval value)
    (space : Auths.Crypto.SignedObjectWriters.approvalCost value ≤ Usize.max) :
    approval.encode_signed_approval_value value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.UnsignedObjects.signedApproval value) result ⦄ :=
  Auths.Crypto.SignedObjectWriters.approval_encoder_valid value valid space

example (value : auths_model.observation.SignedObservation)
    (valid : Auths.Codec.ProtocolValidity.SignedObservation value)
    (space : Auths.Crypto.SignedObjectWriters.observationCost value ≤ Usize.max) :
    observation.encode_signed_observation_value value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.UnsignedObjects.signedObservation value) result ⦄ :=
  Auths.Crypto.SignedObjectWriters.observation_encoder_valid value valid space

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest)
    (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.approval.SignedApproval)
    (valid : Auths.Codec.ProtocolValidity.SignedApproval value)
    (space : Auths.Crypto.SignedObjectWriters.approvalCost value ≤ Usize.max) :
    hash.approval_digest value = ok (.Ok (sha256 (Auths.Crypto.UnsignedObjects.signedApproval value))) :=
  Auths.Crypto.SignedCommitments.approval_digest_exact sha256 contract value valid space

example (self : cbor.Encoder) (value : auths_model.ControlBinding)
    (space : self.output.val.length + Auths.Crypto.BundleObjects.bindingCost value ≤ Usize.max) :
    encode.encode_binding self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.BundleObjects.binding value ⦄ :=
  Auths.Crypto.BundleLeaves.binding_exact self value space

example (value : auths_model.SignedAction) :
    encode.action_ref_sort_key value = ok value.envelope.proof_ref :=
  Auths.Crypto.BundleSelectors.action_key value

example (value : auths_model.EvidenceObject) :
    encode.evidence_ref_sort_key value = ok value.id :=
  Auths.Crypto.BundleSelectors.evidence_key value

-- Sorting cannot discard or change a payload-dependent allocation sum, even
-- when all keys collide; full record order within that class is retained.
example (values : List auths_model.SignedGrant) :
    Auths.Codec.ProtocolArrayWriters.allocation Auths.Crypto.SignedObjectWriters.grantCost
      (Auths.Codec.StableNormalization.sort (fun _ => (0 : Nat)) values) =
        Auths.Codec.ProtocolArrayWriters.allocation Auths.Crypto.SignedObjectWriters.grantCost values :=
  Auths.Crypto.BundleObjects.allocation_normalized _ _ values

-- These are real concrete sorts with source selector/comparison laws,
-- rather than assumed successful sorting outcomes.
example (values : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant)) :
    encode.sort_grant_ref_keys values = ok (Auths.Codec.SnapshotOrdering.sortedByKey
      Auths.Codec.RecordNormalization.grantKey values) :=
  Auths.Crypto.BundleSorting.grant_keys_exact values

example (values : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus)) :
    encode.sort_principal_status_ref_keys values = ok (Auths.Codec.SnapshotOrdering.sortedByKey
      Auths.Codec.RecordNormalization.principalStatusKey values) :=
  Auths.Crypto.BundleSorting.principal_status_keys_exact values

example (values : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus)) :
    encode.sort_grant_status_ref_keys values = ok (Auths.Codec.SnapshotOrdering.sortedByKey
      Auths.Codec.RecordNormalization.grantStatusKey values) :=
  Auths.Crypto.BundleSorting.grant_status_keys_exact values

-- The complete stored model is earned from the actual accessor. Validity
-- and capacity remain explicit rather than inferred from a nominal carrier.
example (carrier : canonical_value.Canonical auths_model.observation.SignedObservation) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      ∀ (valid : Auths.Codec.ProtocolValidity.SignedObservation value)
        (space : Auths.Crypto.SignedObjectWriters.observationCost value ≤ Usize.max),
        observation.encode_signed_observation carrier ⦃ result =>
          Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.UnsignedObjects.signedObservation value) result ⦄ :=
  Auths.Crypto.SignedObjectWriters.observation_canonical_projection carrier

-- Complete borrowed key derivation earns both every actual ID and its
-- record association from independent input/native domains.
example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (records : Slice auths_model.SignedGrant)
    (domains : ∀ record ∈ records.val, Auths.Crypto.BorrowedKeys.GrantDomain record)
    (capacity : Auths.Crypto.BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.derive_grant_ref_keys records ⦃ result => match result with
      | .Err _ => False
      | .Ok output => output.val = Auths.Crypto.BorrowedKeys.grantEntries sha256 records.val ⦄ :=
  Auths.Crypto.BorrowedKeys.grant_derive_exact sha256 contract records domains capacity

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.ProofBundle)
    (domains : ∀ record ∈ value.grants.val, Auths.Crypto.BorrowedKeys.GrantDomain record)
    (capacity : Auths.Crypto.BorrowedKeys.ReferenceCapacity value.grants.val.length) :
    encode.sorted_grants value ⦃ result => match result with
      | .Err _ => False
      | .Ok output => output.val = Auths.Crypto.BundleObjects.grants sha256 value ⦄ :=
  Auths.Crypto.BundleNormalization.grant_exact sha256 contract value domains capacity

example (records : Slice auths_model.ControlBinding)
    (capacity : Auths.Crypto.BorrowedKeys.ReferenceCapacity records.val.length) :
    encode.sorted_binding_refs records ⦃ output => output.val =
      Auths.Codec.StableNormalization.sort Auths.Crypto.BundleObjects.bindingKey records.val ⦄ :=
  Auths.Crypto.BorrowedFields.binding_exact records capacity

example (self : cbor.Encoder) (body : Option (Slice Std.U8))
    (space : self.output.val.length + Auths.Crypto.BundleObjects.optionalSliceCost body ≤ Usize.max) :
    encode.encode_optional_body self body ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.BundleObjects.optionalSliceBytes body ⦄ :=
  Auths.Crypto.BundleLeaves.optional_body_exact self body space

example : Auths.Crypto.BundleObjects.optionalBytes none = [246] := rfl

example : Auths.Crypto.BundleObjects.optionalBytes (some (alloc.vec.Vec.new Std.U8)) = [64] := by
  simp [Auths.Crypto.BundleObjects.optionalBytes, alloc.vec.new_contents,
    Auths.Codec.Refinement.byteList, Auths.Crypto.UnsignedWire.bytes,
    Auths.Codec.encodeHead, Auths.Codec.argumentWidth, Auths.Codec.additionalTag]

-- Full eleven-field source composition. No successful source encoder or
-- desired intermediate bytes occur among these explicit input conditions.
example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.ProofBundle) (fields : Auths.Crypto.BundleWriters.Fields value)
    (dimensions : Auths.Crypto.BundleWriters.Dimensions value)
    (domains : Auths.Crypto.BundleWriters.IdentifierDomains value)
    (space : Auths.Crypto.BundleObjects.cost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.BundleObjects.cost value : Int) ≤ Isize.max) :
    encode.encode_bundle_value value ⦃ result => Auths.Crypto.SigningObjectWriters.Encodes
      (Auths.Crypto.BundleObjects.bundle sha256 value) result ⦄ :=
  Auths.Crypto.BundleWriters.bundle_encoder sha256 contract value fields dimensions domains space native

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.ProofBundle) (fields : Auths.Crypto.BundleWriters.Fields value)
    (dimensions : Auths.Crypto.BundleWriters.Dimensions value)
    (domains : Auths.Crypto.BundleWriters.IdentifierDomains value)
    (space : Auths.Crypto.BundleObjects.cost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.BundleObjects.cost value : Int) ≤ Isize.max) :
    hash.proof_digest value = ok (.Ok (sha256 (Auths.Crypto.BundleObjects.bundle sha256 value))) :=
  Auths.Crypto.BundleCommitments.proof_digest_exact sha256 contract value fields dimensions domains space native

-- These call actual complete writers, not a desired-result oracle.
example (self : cbor.Encoder) (value : auths_model.GrantStatement)
    (strings : Auths.Crypto.StatementWriters.GrantStrings value)
    (space : self.output.val.length + Auths.Crypto.StatementWriters.grantCost value ≤ Usize.max) :
    encode.encode_grant_statement_to self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++ Auths.Crypto.UnsignedObjects.grant value ⦄ :=
  Auths.Crypto.StatementWriters.grant_exact self value strings space

example (self : cbor.Encoder) (values : Slice auths_model.AttachmentDescriptor)
    (fields : ∀ value ∈ values.val, Auths.Codec.ProtocolArrayWriters.AttachmentStrings value)
    (space : self.output.val.length + 9 + Auths.Codec.ProtocolArrayWriters.allocation
      Auths.Crypto.UnsignedLeaves.attachmentCost values.val ≤ Usize.max) :
    encode.encode_attachments self values ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++
          Auths.Crypto.UnsignedWire.array (values.val.map Auths.Crypto.UnsignedObjects.attachment) ⦄ :=
  Auths.Codec.ProtocolArrayWriters.attachments_exact self values fields space

example (self : cbor.Encoder) (values : Slice String)
    (fields : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + 9 + Auths.Codec.ProtocolArrayWriters.allocation
      Auths.Codec.ProtocolTextWriters.textCost values.val ≤ Usize.max) :
    text_list.encode_audiences self values ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++
          Auths.Crypto.UnsignedWire.array (values.val.map Auths.Crypto.UnsignedObjects.identifier) ⦄ :=
  Auths.Codec.ProtocolTextWriters.audiences_exact self values fields space

example (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : Auths.Codec.ProtocolValidity.Grant value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (space : Auths.Crypto.SigningObjectWriters.grantSigningCost value descriptor ≤ Usize.max) :
    encode.encode_grant_signing_input value descriptor ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes
        (Auths.Crypto.UnsignedObjects.grantSigningObject value descriptor) result ⦄ :=
  Auths.Crypto.ValidatedWriters.grant_signing_valid value descriptor valid descriptorValid space

example (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : Auths.Codec.ProtocolValidity.Grant value)
    (descriptorValid : Auths.Codec.ProtocolValidity.SignatureDescriptor descriptor)
    (space : Auths.Crypto.SigningObjectWriters.grantSigningCost value descriptor ≤ Usize.max)
    (output : alloc.vec.Vec Std.U8)
    (accepted : hash.grant_signing_preimage value descriptor = ok (.Ok output)) :
    Auths.Codec.Refinement.byteList output.val = Auths.Crypto.Framing.encode
      (Auths.Crypto.SigningPreimages.grantFrame value descriptor) :=
  Auths.Crypto.SigningPreimages.grant_exact value descriptor valid descriptorValid space output accepted


example (major : Std.U8) (argument : Std.U64) :
    cbor.encode_head major argument ⦃ result =>
      Auths.Codec.ProtocolHeadEncoder.EncodingRefines major argument result ⦄ :=
  Auths.Codec.ProtocolHeadEncoder.encode_head_refines major argument

example (self : cbor.Encoder) (value : auths_model.SignatureDescriptor)
    (principalBound : value.principal_method.toByteArray.size ≤ U32.max)
    (verificationBound : value.verification_method.toByteArray.size ≤ U32.max)
    (suiteBound : value.suite.toByteArray.size ≤ U32.max)
    (space : self.output.val.length + Auths.Crypto.DescriptorWriter.cost value ≤ Usize.max) :
    encode.encode_signature_descriptor self value ⦃ actual =>
      actual.1 = .Ok () ∧ Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++
          Auths.Crypto.UnsignedObjects.signatureDescriptor value ⦄ :=
  Auths.Crypto.DescriptorWriter.descriptor_exact self value
    principalBound verificationBound suiteBound space

example : Auths.Crypto.UnsignedObjects.factValue (.Uint 0#u64) ≠
    Auths.Crypto.UnsignedObjects.factValue (.Text "0") := by decide

-- These are independent framing bytes, not outputs of a Rust writer.
example : Auths.Crypto.UnsignedWire.descriptor ⟨[112, 109], [118, 109], [115, 105, 103]⟩ =
    [163, 0, 98, 112, 109, 1, 98, 118, 109, 2, 99, 115, 105, 103] := by decide

example (left right : Auths.Crypto.UnsignedWire.Descriptor)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (same : Auths.Crypto.UnsignedWire.descriptor left = Auths.Crypto.UnsignedWire.descriptor right) :
    left.principalMethod = right.principalMethod ∧
      left.verificationMethod = right.verificationMethod ∧ left.suite = right.suite :=
  Auths.Crypto.UnsignedWire.descriptor_binds_fields left right leftValid rightValid same

example (value : Auths.Crypto.UnsignedWire.Descriptor) (valid : value.Valid) (tail : List Nat) :
    Auths.Crypto.UnsignedWire.readDescriptor (Auths.Crypto.UnsignedWire.descriptor value ++ tail) =
      some (value, tail) :=
  Auths.Crypto.UnsignedWire.descriptor_roundtrip value valid tail

example [Auths.Crypto.Sha256Primitives]
    (sha256 : List Std.U8 → Array Std.U8 32#usize)
    (contract : Auths.Crypto.Sha256Native.Contract sha256) (bytes : Slice Std.U8) :
    hash.raw_sha256 bytes = ok (sha256 bytes.val) :=
  AuthsProtocolCodec.raw_sha256_refines sha256 contract bytes

example (kind : hash.IdentifierType) (payload : Slice Std.U8) :
    hash.identifier_preimage kind payload ⦃ result =>
      Auths.Crypto.ProtocolFramingTotality.IdentifierResult payload result ⦄ :=
  Auths.Crypto.ProtocolFramingTotality.identifier_total kind payload

example (domain : Str) (payload : Slice Std.U8) :
    hash.commitment_preimage domain payload ⦃ result =>
      Auths.Crypto.ProtocolFramingTotality.ApplicationResult domain payload result ⦄ :=
  Auths.Crypto.ProtocolFramingTotality.application_total domain payload

example (kind : hash.ObjectType) (profile : Str) (version : Std.U16) (payload : Slice Std.U8) :
    hash.signing_preimage kind profile version payload ⦃ result =>
      Auths.Crypto.ProtocolFramingTotality.SigningResult profile payload result ⦄ :=
  Auths.Crypto.ProtocolFramingTotality.signing_total kind profile version payload

example (leftKind rightKind : hash.ObjectType) (leftProfile rightProfile : Str)
    (leftVersion rightVersion : Std.U16) (leftPayload rightPayload : Slice Std.U8)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftAccepted : hash.signing_preimage leftKind leftProfile leftVersion leftPayload = ok (.Ok leftOutput))
    (rightAccepted : hash.signing_preimage rightKind rightProfile rightVersion rightPayload = ok (.Ok rightOutput))
    (same : leftOutput.val = rightOutput.val) :
    leftKind = rightKind ∧ leftProfile = rightProfile ∧
      leftVersion = rightVersion ∧ leftPayload = rightPayload :=
  Auths.Crypto.ProtocolFraming.accepted_preimages_bind_inputs
    leftKind rightKind leftProfile rightProfile leftVersion rightVersion
    leftPayload rightPayload leftOutput rightOutput leftAccepted rightAccepted same

-- Actual comparator source must agree with the independent partial keys.
example (left right : auths_model.SignedPrincipalStatus) :
    auths_model.status_snapshot.principal_order left right =
      ok (compare (Auths.Codec.SnapshotOrdering.principalKey left)
        (Auths.Codec.SnapshotOrdering.principalKey right)) :=
  Auths.Codec.SnapshotOrdering.principal_source_compare left right

example (left right : auths_model.SignedGrantStatus) :
    auths_model.status_snapshot.grant_order left right =
      ok (compare (Auths.Codec.SnapshotOrdering.grantKey left)
        (Auths.Codec.SnapshotOrdering.grantKey right)) :=
  Auths.Codec.SnapshotOrdering.grant_source_compare left right

example (values : alloc.vec.Vec auths_model.SignedPrincipalStatus) :
    auths_model.status_snapshot.sort_principal values =
      ok (Auths.Codec.SnapshotOrdering.sortedByKey Auths.Codec.SnapshotOrdering.principalKey values) :=
  Auths.Codec.SnapshotOrdering.principal_sort_exact values

example (values : alloc.vec.Vec auths_model.SignedGrantStatus) :
    auths_model.status_snapshot.sort_grant values =
      ok (Auths.Codec.SnapshotOrdering.sortedByKey Auths.Codec.SnapshotOrdering.grantKey values) :=
  Auths.Codec.SnapshotOrdering.grant_sort_exact values

-- The full source constructor, rather than a caller-supplied ordering flag,
-- earns the premise needed by the independent wire-preservation theorem.
example (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.PrincipalStatusSnapshot)
    (accepted : auths_model.PrincipalStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    output.statements.val.Pairwise
      (Auths.Codec.StableNormalization.before Auths.Codec.SnapshotOrdering.principalKey) :=
  Auths.Codec.SnapshotOrdering.principal_constructor_ordered
    id observed validUntil statements checkpoints trust output accepted

example (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedGrantStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.GrantStatusSnapshot)
    (accepted : auths_model.GrantStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    output.statements.val.Pairwise
      (Auths.Codec.StableNormalization.before Auths.Codec.SnapshotOrdering.grantKey) :=
  Auths.Codec.SnapshotOrdering.grant_constructor_ordered
    id observed validUntil statements checkpoints trust output accepted

private def separated : Slice Std.U8 := ⟨[1#u8, 2#u8, 1#u8], by scalar_tac⟩
private def distinct : Slice Std.U8 := ⟨[3#u8, 1#u8, 2#u8], by scalar_tac⟩

-- No successful second invocation is assumed in these actual-source cases.
example [Auths.Crypto.Sha256Primitives]
    (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    canonical_value.normalize_grants output = ok (.Ok output) :=
  Auths.Codec.RecordNormalization.grants_idempotent input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    canonical_value.normalize_principal_status output = ok (.Ok output) :=
  Auths.Codec.RecordNormalization.principal_status_idempotent input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    canonical_value.normalize_grant_status output = ok (.Ok output) :=
  Auths.Codec.RecordNormalization.grant_status_idempotent input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input output : alloc.vec.Vec auths_model.SignedGrant)
    (id : Option (List Nat))
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    Auths.Codec.StableNormalization.bucket Auths.Codec.RecordNormalization.grantSourceKey id output.val =
      Auths.Codec.StableNormalization.bucket Auths.Codec.RecordNormalization.grantSourceKey id input.val :=
  Auths.Codec.RecordNormalization.grants_ties input output id accepted

-- These compose actual source derivation, actual stable ID sorting and
-- actual consuming projection; ID collisions do not erase signed payloads.
example [Auths.Crypto.Sha256Primitives]
    (input output : alloc.vec.Vec auths_model.SignedGrant)
    (accepted : canonical_value.normalize_grants input = ok (.Ok output)) :
    output.val.Perm input.val :=
  Auths.Codec.RecordNormalization.grants_permutation input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input output : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (accepted : canonical_value.normalize_principal_status input = ok (.Ok output)) :
    output.val.Perm input.val :=
  Auths.Codec.RecordNormalization.principal_status_permutation input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input output : alloc.vec.Vec auths_model.SignedGrantStatus)
    (accepted : canonical_value.normalize_grant_status input = ok (.Ok output)) :
    output.val.Perm input.val :=
  Auths.Codec.RecordNormalization.grant_status_permutation input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input : alloc.vec.Vec auths_model.SignedGrant)
    (output : alloc.vec.Vec (auths_model.GrantId × auths_model.SignedGrant))
    (accepted : canonical_value.derive_grant_keys input = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.grant_id entry.2.statement = ok (.Ok entry.1) :=
  Auths.Codec.KeyDerivation.grant_keys_consistent input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (output : alloc.vec.Vec (auths_model.PrincipalStatusId × auths_model.SignedPrincipalStatus))
    (accepted : canonical_value.derive_principal_status_keys input = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.principal_status_id entry.2.statement = ok (.Ok entry.1) :=
  Auths.Codec.KeyDerivation.principal_status_keys_consistent input output accepted

example [Auths.Crypto.Sha256Primitives]
    (input : alloc.vec.Vec auths_model.SignedGrantStatus)
    (output : alloc.vec.Vec (auths_model.GrantStatusId × auths_model.SignedGrantStatus))
    (accepted : canonical_value.derive_grant_status_keys input = ok (.Ok output)) :
    ∀ entry ∈ output.val, hash.grant_status_id entry.2.statement = ok (.Ok entry.1) :=
  Auths.Codec.KeyDerivation.grant_status_keys_consistent input output accepted

-- Independent two-pass normal forms retain complete equal-key payloads.
example : Auths.Codec.StableNormalization.storage
    (fun value : Nat × Nat × Nat => value.1) (fun value => value.2.1)
    [(1, 2, 20), (0, 2, 10), (1, 1, 30), (1, 2, 40)] =
      [(0, 2, 10), (1, 1, 30), (1, 2, 20), (1, 2, 40)] := by decide

example {Value Primary Secondary : Type} [LinearOrder Primary] [LinearOrder Secondary]
    (primary : Value → Primary) (secondary : Value → Secondary) (values : List Value) :
    Auths.Codec.StableNormalization.storage primary secondary values = values ↔
      values.Pairwise (Auths.Codec.StableNormalization.before
        (Auths.Codec.StableNormalization.jointKey primary secondary)) :=
  Auths.Codec.StableNormalization.storage_normal_form_iff primary secondary values

example {Value Primary Secondary : Type} [LinearOrder Primary] [LinearOrder Secondary]
    (primary : Value → Primary) (secondary : Value → Secondary) (values : List Value)
    (primaryOrdered : values.Pairwise (Auths.Codec.StableNormalization.before primary)) :
    Auths.Codec.StableNormalization.sort secondary
      (Auths.Codec.StableNormalization.storage primary secondary values) =
        Auths.Codec.StableNormalization.sort secondary values :=
  Auths.Codec.StableNormalization.wire_preserved primary secondary values primaryOrdered

example {Key Value : Type} (input : alloc.vec.Vec (Key × Value)) :
    @canonical_value.unkey_records Key Value input
      ⦃ output => output.val = input.val.map Prod.snd ⦄ :=
  Auths.Codec.OwnedRecords.unkey_exact input

example (left right : auths_model.GrantId) :
    auths_model.GrantId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (Auths.Codec.ProtocolOrdering.grantIdKey left)
        (Auths.Codec.ProtocolOrdering.grantIdKey right)) :=
  Auths.Codec.ProtocolOrdering.grant_id_compare left right

example (left right : auths_model.PrincipalStatusId) :
    auths_model.PrincipalStatusId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (Auths.Codec.ProtocolOrdering.principalStatusIdKey left)
        (Auths.Codec.ProtocolOrdering.principalStatusIdKey right)) :=
  Auths.Codec.ProtocolOrdering.principal_status_id_compare left right

example (left right : auths_model.GrantStatusId) :
    auths_model.GrantStatusId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (Auths.Codec.ProtocolOrdering.grantStatusIdKey left)
        (Auths.Codec.ProtocolOrdering.grantStatusIdKey right)) :=
  Auths.Codec.ProtocolOrdering.grant_status_id_compare left right

example (left right : auths_model.ApprovalRequirementId) :
    auths_model.ApprovalRequirementId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (Auths.Codec.ProtocolOrdering.approvalRequirementIdKey left)
        (Auths.Codec.ProtocolOrdering.approvalRequirementIdKey right)) :=
  Auths.Codec.ProtocolOrdering.approval_requirement_id_compare left right
private theorem byte_equality (left right : Std.U8) :
    core.cmp.PartialEqU8.eq left right = ok (decide (left.val = right.val)) := by
  simp [core.cmp.PartialEqU8, UScalar.eq_equiv]

-- These call the actual production scans. A/B/A is intentionally not
-- adjacent, but the order-preserving collection scan must reject it.
example : @auths_model.collection_scan.adjacent_equal Std.U8 core.cmp.PartialEqU8 separated = ok false := by
  rw [Auths.Codec.ProtocolCollectionScans.adjacent_exact core.cmp.PartialEqU8
    (fun value => value.val) byte_equality separated]
  rfl

example : @auths_model.collection_scan.has_duplicates Std.U8 core.cmp.PartialEqU8 separated = ok true := by
  rw [Auths.Codec.ProtocolCollectionScans.duplicates_exact core.cmp.PartialEqU8
    (fun value => value.val) byte_equality separated]
  decide

example : @auths_model.collection_scan.has_duplicates Std.U8 core.cmp.PartialEqU8 distinct = ok false := by
  rw [Auths.Codec.ProtocolCollectionScans.duplicates_exact core.cmp.PartialEqU8
    (fun value => value.val) byte_equality distinct]
  decide

example : @auths_model.collection_scan.prefix_contains Std.U8 core.cmp.PartialEqU8 separated 2#u8 0#usize = ok false := by
  rw [Auths.Codec.ProtocolCollectionScans.prefix_exact core.cmp.PartialEqU8
    (fun value => value.val) byte_equality separated 2#u8 0#usize]
  decide

example : @auths_model.collection_scan.prefix_contains Std.U8 core.cmp.PartialEqU8 separated 2#u8 99#usize = ok true := by
  rw [Auths.Codec.ProtocolCollectionScans.prefix_exact core.cmp.PartialEqU8
    (fun value => value.val) byte_equality separated 2#u8 99#usize]
  decide

-- Constructor boundaries, including equality at the inclusive time boundary.
-- These cases assert no signature verification or grant authority.
example : auths_model.ProtocolVersion.new 1#u16 = ok (.Ok 1#u16) := by
  simpa using Auths.Codec.ProtocolConstructors.protocol_version_exact 1#u16

example : auths_model.ProtocolVersion.new 2#u16 = ok (.Err .UnsupportedProtocol) := by
  simpa using Auths.Codec.ProtocolConstructors.protocol_version_exact 2#u16

example : auths_model.FreshnessLimit.new 0#u64 = ok (.Err .InvalidStatus) := by
  simpa using Auths.Codec.ProtocolConstructors.freshness_exact 0#u64

example : auths_model.FreshnessLimit.new 1#u64 = ok (.Ok 1#u64) := by
  simpa using Auths.Codec.ProtocolConstructors.freshness_exact 1#u64

example : auths_model.ValidityWindow.new 7#u64 7#u64 = ok (.Ok ⟨7#u64, 7#u64⟩) := by
  simpa using Auths.Codec.ProtocolConstructors.window_exact 7#u64 7#u64

example : auths_model.ValidityWindow.new 8#u64 7#u64 = ok (.Err .InvalidValidity) := by
  simpa using Auths.Codec.ProtocolConstructors.window_exact 8#u64 7#u64

example : auths_model.PrincipalId.parse (toStr "raw:key" (by decide)) = ok (.Ok "raw:key") := by
  simpa [Auths.Codec.ProtocolIdentifiers.valid, Auths.Codec.Constructors.identifierDecision,
    Auths.PrincipalScheme.Model.evaluate, Auths.PrincipalScheme.Model.tailValid,
    Auths.PrincipalScheme.Model.lower, Auths.PrincipalScheme.Model.allowed,
    Auths.Model.Identifier.excluded] using
    Auths.Codec.ProtocolIdentifiers.parse_exact "raw:key" (by decide)

example : auths_model.PrincipalId.parse (toStr "Raw:key" (by decide)) = ok (.Err .InvalidPrincipal) := by
  simpa [Auths.Codec.ProtocolIdentifiers.valid, Auths.Codec.Constructors.identifierDecision,
    Auths.PrincipalScheme.Model.evaluate, Auths.PrincipalScheme.Model.tailValid,
    Auths.PrincipalScheme.Model.lower, Auths.Model.Identifier.excluded] using
    Auths.Codec.ProtocolIdentifiers.parse_exact "Raw:key" (by decide)

-- Fact text permits empty/whitespace values, whereas identifiers do not.
-- No stronger identifier policy is imported into the fact-text constructor.
example : auths_model.observation.FactText.new (toStr "" (by decide)) = ok (.Ok "") := by
  simpa using Auths.Codec.ProtocolIdentifiers.fact_text_exact "" (by decide)

example : auths_model.observation.FactText.new (toStr " " (by decide)) = ok (.Ok " ") := by
  simpa using Auths.Codec.ProtocolIdentifiers.fact_text_exact " " (by decide)

example (bytes : alloc.vec.Vec Std.U8) (empty : bytes.val = []) :
    auths_model.SignatureBytes.new bytes = ok (.Err .InvalidSignature) := by
  rw [Auths.Codec.ProtocolConstructors.signature_bytes_exact]
  simp [empty]

private def first : Slice Std.U8 := ⟨[1#u8], by scalar_tac⟩
private def same : alloc.vec.Vec Std.U8 := alloc.vec.Vec.ofBase ⟨[1#u8], by scalar_tac⟩
private def other : alloc.vec.Vec Std.U8 := alloc.vec.Vec.ofBase ⟨[2#u8], by scalar_tac⟩

-- These are actual-source byte-gate witnesses. They do not replace the
-- required useful whole-object decoder/encoder round trips.
example : canonical.accept first same ([7, 8] : List Nat)
    ⦃ result => result = .Ok [7, 8] ⦄ := by
  simpa [first, same, alloc.vec.Vec.val, alloc.vec.Vec.ofBase,
    auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
    auths_composition.alloc.vec.SizedList.toList_ofList] using
    Auths.Codec.ProtocolCanonical.accept_exact first same ([7, 8] : List Nat)

example : canonical.accept first other ([7, 8] : List Nat)
    ⦃ result => result = .Err .NonCanonical ⦄ := by
  simpa [first, other, alloc.vec.Vec.val, alloc.vec.Vec.ofBase,
    auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
    auths_composition.alloc.vec.SizedList.toList_ofList] using
    Auths.Codec.ProtocolCanonical.accept_exact first other ([7, 8] : List Nat)

example : canonical.accept_with_error first other ([7, 8] : List Nat) .DigestMismatch
    ⦃ result => result = .Err .DigestMismatch ⦄ := by
  simpa [first, other, alloc.vec.Vec.val, alloc.vec.Vec.ofBase,
    auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.ofBase,
    auths_composition.alloc.vec.SizedList.toList_ofList] using
    Auths.Codec.ProtocolCanonical.with_error_exact first other ([7, 8] : List Nat) .DigestMismatch

variable [primitive : Auths.Crypto.Sha256Primitives]

-- These use arbitrary carriers and the complete actual Result behavior.
-- No expected writer result or successful-encoding premise is supplied.
example (value : canonical_value.Canonical auths_model.ProofBundle) :
    encode.encode_bundle value = (do
      let raw ← canonical_value.Canonical.as_value value
      encode.encode_bundle_value raw) :=
  Auths.Codec.CanonicalEncoding.bundle_exact value

example (value : canonical_value.Canonical auths_model.TrustedContext) :
    encode.encode_verifier_context value = (do
      let raw ← canonical_value.Canonical.as_value value
      encode.encode_verifier_context_value raw) :=
  Auths.Codec.CanonicalEncoding.context_exact value

example (value : canonical_value.Canonical auths_model.approval.SignedApproval) :
    approval.encode_signed_approval value = (do
      let raw ← canonical_value.Canonical.as_value value
      approval.encode_signed_approval_value raw) :=
  Auths.Codec.CanonicalEncoding.signed_approval_exact value

example (value : canonical_value.Canonical auths_model.PortableVerificationResult) :
    encode.encode_verification_result value = (do
      let raw ← canonical_value.Canonical.as_value value
      encode.encode_verification_result_value raw) :=
  Auths.Codec.CanonicalEncoding.result_exact value

example (value : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment) :
    bounded_policy.encode_bounded_policy_commitment value = (do
      let raw ← canonical_value.Canonical.as_value value
      bounded_policy.encode_bounded_policy_commitment_value raw) :=
  Auths.Codec.CanonicalEncoding.bounded_policy_exact value

example (input : auths_model.approval.SignedApproval)
    (output : canonical_value.Canonical auths_model.approval.SignedApproval)
    (accepted : canonical_value.checked_signed_approval input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input :=
  Auths.Codec.CanonicalIntegrity.signed_approval_retains input output accepted

example (input : auths_model.observation.SignedObservation)
    (output : canonical_value.Canonical auths_model.observation.SignedObservation)
    (accepted : canonical_value.checked_signed_observation input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input :=
  Auths.Codec.CanonicalIntegrity.signed_observation_retains input output accepted

example (input : auths_model.bounded_policy.BoundedPolicyCommitment)
    (output : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : canonical_value.checked_bounded_policy input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input :=
  Auths.Codec.CanonicalIntegrity.bounded_policy_retains input output accepted

example (input : auths_model.PortableVerificationResult)
    (output : canonical_value.Canonical auths_model.PortableVerificationResult)
    (accepted : canonical_value.checked_verification_result input = ok (.Ok output)) :
    canonical_value.Canonical.as_value output = ok input :=
  Auths.Codec.CanonicalIntegrity.verification_result_retains input output accepted

example (input : Slice Std.U8) : hash.raw_sha256 input =
    AuthsNativeSha256.hash.raw_sha256 (primitive := primitive) input :=
  AuthsProtocolCodec.raw_sha256_delegates input

-- Actual public-wrapper consequences, including a recursive bundle, signed
-- approval and digest-bearing output. The antecedent is real acceptance,
-- not the desired encoding, and the conclusion names the real encoder.
example (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : canonical_value.Canonical auths_model.ProofBundle)
    (accepted : decode.decode_bundle input limits = ok (.Ok value)) :
    ∃ encoded, encode.encode_bundle value = ok (.Ok encoded) ∧ encoded.val = input.val :=
  Auths.Codec.ProtocolReencoding.decode_bundle_reencodes input limits value accepted

example (input : Slice Std.U8) (limits : auths_model.VerifierLimits)
    (value : canonical_value.Canonical auths_model.approval.SignedApproval)
    (accepted : approval.decode_signed_approval input limits = ok (.Ok value)) :
    ∃ encoded, approval.encode_signed_approval value = ok (.Ok encoded) ∧ encoded.val = input.val :=
  Auths.Codec.ProtocolReencoding.decode_signed_approval_reencodes input limits value accepted

example (input : Slice Std.U8)
    (value : canonical_value.Canonical auths_model.PortableVerificationResult)
    (accepted : decode.decode_verification_result input = ok (.Ok value)) :
    ∃ encoded, encode.encode_verification_result value = ok (.Ok encoded) ∧ encoded.val = input.val :=
  Auths.Codec.ProtocolReencoding.decode_verification_result_reencodes input value accepted

-- Duplicate keys with different payloads are still duplicates. No signature,
-- body digest or payload bytes are used as a substitute for the signed key.
example : auths_model.collection_scan.extension_ids_repeat
    (⟨[⟨"test-extension", same⟩, ⟨"test-extension", other⟩], by scalar_tac⟩ : Slice auths_model.CriticalExtension) =
      ok true := by
  rw [Auths.Codec.ProtocolKeyScans.extension_exact]
  decide

example : auths_model.collection_scan.fact_names_repeat
    (⟨[⟨"amount", .Uint 1#u64⟩, ⟨"amount", .Uint 2#u64⟩], by scalar_tac⟩ : Slice auths_model.observation.ObservationFact) =
      ok true := by
  rw [Auths.Codec.ProtocolKeyScans.fact_exact]
  decide

example (identifier : auths_model.EvidenceId) : auths_model.collection_scan.evidence_ids_repeat
    (⟨[⟨identifier, "type-a", "application/octet-stream", same⟩,
      ⟨identifier, "type-b", "application/octet-stream", other⟩], by scalar_tac⟩ : Slice auths_model.EvidenceObject) =
      ok true := by
  rw [Auths.Codec.ProtocolKeyScans.evidence_exact]
  simp [CollectionInvariants.adjacent]

private def unsortedAudience : alloc.vec.Vec auths_model.Audience :=
  alloc.vec.Vec.ofBase ⟨["é", "z", "a"], by scalar_tac⟩
private def sortedAudience : alloc.vec.Vec auths_model.Audience :=
  alloc.vec.Vec.ofBase ⟨["a", "z", "é"], by scalar_tac⟩
private def repeatedAudience : alloc.vec.Vec auths_model.Audience :=
  alloc.vec.Vec.ofBase ⟨["é", "a", "é"], by scalar_tac⟩
private def oversizedAudience : alloc.vec.Vec auths_model.Audience :=
  alloc.vec.Vec.ofBase ⟨List.replicate 257 "same", by scalar_tac⟩

example : auths_model.AudienceSet.new unsortedAudience = ok (.Ok sortedAudience) := by
  rw [Auths.Codec.ProtocolSets.audiences_exact]
  rfl

example : auths_model.AudienceSet.new repeatedAudience = ok (.Err .DuplicateAudience) := by
  rw [Auths.Codec.ProtocolSets.audiences_exact]
  rfl

example : auths_model.AudienceSet.new oversizedAudience = ok (.Err .InvalidAudienceSet) := by
  rw [Auths.Codec.ProtocolSets.audiences_exact]
  rfl

example (input : alloc.vec.Vec auths_model.Permission) (output : auths_model.PermissionSet)
    (fields : ∀ value ∈ input.val, Auths.Codec.ProtocolValidity.Permission value)
    (accepted : auths_model.PermissionSet.new input = ok (.Ok output)) :
    Auths.Codec.ProtocolValidity.Permissions output :=
  Auths.Codec.ProtocolSets.permissions_valid input output fields accepted

example (input : alloc.vec.Vec auths_model.Digest) (output : auths_model.BodyDigestSet)
    (accepted : auths_model.BodyDigestSet.new input = ok (.Ok output)) :
    Auths.Codec.ProtocolValidity.BodyDigests output :=
  Auths.Codec.ProtocolSets.body_digests_valid input output accepted

example : auths_model.observation.UintRange.new 5#u64 5#u64 = ok (.Ok ⟨5#u64, 5#u64⟩) := by
  simpa using Auths.Codec.RequirementConstructors.range_exact 5#u64 5#u64

example : auths_model.observation.UintRange.new 6#u64 5#u64 = ok (.Err .InvalidObservationRequirement) := by
  simpa using Auths.Codec.RequirementConstructors.range_exact 6#u64 5#u64

example : auths_model.observation.FactValue.Insts.CoreCmpPartialEqFactValue.eq
    (.Uint 0#u64) (.Text "0") = ok false := by
  rw [Auths.Codec.RequirementEquality.fact]
  decide

example (observer : auths_model.observation.ObserverAnchorId) (schema : auths_model.observation.ObservationSchemaId)
    (subject : auths_model.observation.ObservationSubject)
    (conditions : alloc.vec.Vec auths_model.observation.ObservationCondition) :
    auths_model.observation.ObservationRequirement.Insts.CoreCmpPartialEqObservationRequirement.eq
      ⟨observer, schema, subject, 1#u32, conditions⟩
      ⟨observer, schema, subject, 2#u32, conditions⟩ = ok false := by
  rw [Auths.Codec.RequirementEquality.observation]
  simp [Auths.Codec.RequirementKeys.observation]

example (input : alloc.vec.Vec auths_model.approval.ApprovalRequirement)
    (output : auths_model.approval.ApprovalRequirements)
    (fields : ∀ value ∈ input.val, Auths.Codec.ProtocolValidity.ApprovalRequirement value)
    (accepted : auths_model.approval.ApprovalRequirements.new input = ok (.Ok output)) :
    Auths.Codec.ProtocolValidity.ApprovalRequirements output :=
  Auths.Codec.RequirementConstructors.approvals_valid input output fields accepted

example (input : alloc.vec.Vec auths_model.observation.ObservationRequirement)
    (output : auths_model.observation.ObservationRequirements)
    (fields : ∀ value ∈ input.val, Auths.Codec.ProtocolValidity.ObservationRequirement value)
    (accepted : auths_model.observation.ObservationRequirements.new input = ok (.Ok output)) :
    Auths.Codec.ProtocolValidity.ObservationRequirements output :=
  Auths.Codec.RequirementConstructors.observations_valid input output fields accepted

example {Value : Type} (value : canonical_value.Canonical Value) :
    @canonical_value.Canonical.as_value Value value =
      @canonical_value.Canonical.into_value Value value :=
  Auths.Codec.CanonicalValues.projections_agree value

example : Auths.Codec.CanonicalValues.normalize (fun value : Nat => [value]) [3, 1, 2] = [1, 2, 3] := by decide

-- Equal identifier keys retain both distinct values in their original order.
-- Canonical normalization never assumes that a hash key is injective.
example : Auths.Codec.CanonicalValues.normalize (fun _ : Nat => [0]) [2, 1] = [2, 1] := by decide

example (identifier : Nat → List Nat) (values : List Nat) :
    Auths.Codec.CanonicalValues.normalize identifier
      (Auths.Codec.CanonicalValues.normalize identifier values) =
        Auths.Codec.CanonicalValues.normalize identifier values :=
  Auths.Codec.CanonicalValues.normalize_idempotent identifier values


-- Distinct status scopes have distinct wire tags; an empty explicit anchor
-- set remains a different syntax from OwnAnchor or AnyAnchor. Constructor
-- validity of the explicit set is not assumed by this wire discriminator.
example : Auths.Crypto.SnapshotObjects.scope .OwnAnchor = [161, 0, 0] := by decide
example : Auths.Crypto.SnapshotObjects.scope .AnyAnchor = [161, 0, 2] := by decide

example (self : cbor.Encoder) (scope : auths_model.StatusScope)
    (fields : Auths.Crypto.SnapshotLeaves.ScopeStrings scope)
    (space : self.output.val.length + Auths.Crypto.SnapshotObjects.scopeCost scope ≤ Usize.max) :
    encode.encode_status_scope self scope ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++ Auths.Crypto.SnapshotObjects.scope scope ⦄ :=
  Auths.Crypto.SnapshotLeaves.scope_exact self scope fields space

example (self : cbor.Encoder) (rule : auths_model.StatusTrustRule)
    (fields : Auths.Crypto.SnapshotLeaves.TrustStrings rule)
    (space : self.output.val.length + Auths.Crypto.SnapshotObjects.trustRuleCost rule ≤ Usize.max) :
    encode.encode_status_trust_rule self rule ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++ Auths.Crypto.SnapshotObjects.trustRule rule ⦄ :=
  Auths.Crypto.SnapshotLeaves.trust_rule_exact self rule fields space

-- Maximum u64 floors are retained as integers rather than narrowed to a
-- platform counter. This independent grammar case covers the 8-byte head.
example : Auths.Crypto.UnsignedWire.uint 18446744073709551615 =
    [27, 255, 255, 255, 255, 255, 255, 255, 255] := by decide

example (self : cbor.Encoder) (value : auths_model.VerifierLimits)
    (space : self.output.val.length + 549 ≤ Usize.max) :
    encode.encode_limits self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++ Auths.Crypto.ContextObjects.limits value ⦄ :=
  Auths.Crypto.ContextLimits.limits_exact self value space

example (self : cbor.Encoder) (value : auths_model.CompositionRequirement)
    (space : self.output.val.length + 113 ≤ Usize.max) :
    encode.encode_composition_requirement self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val =
        Auths.Codec.Refinement.byteList self.output.val ++ Auths.Crypto.ContextObjects.composition value ⦄ :=
  Auths.Crypto.ContextLimits.composition_exact self value space

example (self : cbor.Encoder) (values : Slice auths_model.ProfileRef)
    (fields : ∀ value ∈ values.val, Auths.Crypto.ContextProfiles.Strings value)
    (space : self.output.val.length + 9 + Auths.Codec.ProtocolArrayWriters.allocation
      Auths.Crypto.ContextObjects.profileCost values.val ≤ Usize.max) :
    encode.encode_profiles self values ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.UnsignedWire.array (values.val.map Auths.Crypto.UnsignedObjects.profile) ⦄ :=
  Auths.Crypto.ContextProfiles.profiles_exact self values fields space

example (self : cbor.Encoder) (value : auths_model.TrustAnchor)
    (fields : Auths.Crypto.ContextAnchors.AnchorStrings value)
    (space : self.output.val.length + Auths.Crypto.ContextObjects.anchorCost value ≤ Usize.max) :
    encode.encode_anchor self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ContextObjects.anchor value ⦄ :=
  Auths.Crypto.ContextAnchors.anchor_exact self value fields space

example (self : cbor.Encoder) (value : auths_model.AcceptedRegistries)
    (fields : Auths.Crypto.ContextAnchors.RegistriesStrings value)
    (space : self.output.val.length + Auths.Crypto.ContextObjects.registriesCost value ≤ Usize.max) :
    encode.encode_registries self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ContextObjects.registries value ⦄ :=
  Auths.Crypto.ContextAnchors.registries_exact self value fields space

example (self : cbor.Encoder) (value : auths_model.observation.ObserverAnchor)
    (fields : Auths.Crypto.ContextAnchors.ObserverStrings value)
    (space : self.output.val.length + Auths.Crypto.ContextObjects.observerCost value ≤ Usize.max) :
    observation.encode_observer_anchor self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ContextObjects.observer value ⦄ :=
  Auths.Crypto.ContextAnchors.observer_exact self value fields space

example (self : cbor.Encoder) (value : auths_model.approval.ApproverAnchor)
    (fields : Auths.Crypto.ContextAnchors.ApproverStrings value)
    (space : self.output.val.length + Auths.Crypto.ContextObjects.approverCost value ≤ Usize.max) :
    approval.encode_approver_anchor self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ContextObjects.approver value ⦄ :=
  Auths.Crypto.ContextAnchors.approver_exact self value fields space

example (self : cbor.Encoder) (values : Slice auths_model.TrustAnchor)
    (fields : ∀ value ∈ values.val, Auths.Crypto.ContextAnchors.AnchorStrings value)
    (space : self.output.val.length + 9 + Auths.Codec.ProtocolArrayWriters.allocation
      Auths.Crypto.ContextObjects.anchorCost values.val ≤ Usize.max) :
    encode.encode_trust_anchors self values ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.UnsignedWire.array (values.val.map Auths.Crypto.ContextObjects.anchor) ⦄ :=
  Auths.Crypto.ContextAnchorArrays.anchors_exact self values fields space

example (self : cbor.Encoder) (values : Slice auths_model.observation.ObserverAnchor)
    (fields : ∀ value ∈ values.val, Auths.Crypto.ContextAnchors.ObserverStrings value)
    (space : self.output.val.length + 9 + Auths.Codec.ProtocolArrayWriters.allocation
      Auths.Crypto.ContextObjects.observerCost values.val ≤ Usize.max) :
    observation.encode_observer_anchors self values ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.UnsignedWire.array (values.val.map Auths.Crypto.ContextObjects.observer) ⦄ :=
  Auths.Crypto.ContextAnchorArrays.observers_exact self values fields space

example (self : cbor.Encoder) (values : Slice auths_model.approval.ApproverAnchor)
    (fields : ∀ value ∈ values.val, Auths.Crypto.ContextAnchors.ApproverStrings value)
    (space : self.output.val.length + 9 + Auths.Codec.ProtocolArrayWriters.allocation
      Auths.Crypto.ContextObjects.approverCost values.val ≤ Usize.max) :
    approval.encode_approver_anchors self values ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.UnsignedWire.array (values.val.map Auths.Crypto.ContextObjects.approver) ⦄ :=
  Auths.Crypto.ContextAnchorArrays.approvers_exact self values fields space

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.PrincipalStatusSnapshot) (fields : Auths.Crypto.SnapshotWriters.PrincipalFields value)
    (domains : ∀ record ∈ value.statements.val, Auths.Crypto.BorrowedKeys.PrincipalStatusDomain record)
    (capacity : Auths.Crypto.BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : Auths.Crypto.SnapshotObjects.principalCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.SnapshotObjects.principalCost value : Int) ≤ Isize.max) :
    encode.encode_principal_status_snapshot_value value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes
        (Auths.Crypto.SnapshotObjects.principalSnapshot sha256 value) result ⦄ :=
  Auths.Crypto.SnapshotWriters.principal_encoder sha256 contract value fields domains capacity space native

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.GrantStatusSnapshot) (fields : Auths.Crypto.SnapshotWriters.GrantFields value)
    (domains : ∀ record ∈ value.statements.val, Auths.Crypto.BorrowedKeys.GrantStatusDomain record)
    (capacity : Auths.Crypto.BorrowedKeys.ReferenceCapacity value.statements.val.length)
    (space : Auths.Crypto.SnapshotObjects.grantCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.SnapshotObjects.grantCost value : Int) ≤ Isize.max) :
    encode.encode_grant_status_snapshot_value value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes
        (Auths.Crypto.SnapshotObjects.grantSnapshot sha256 value) result ⦄ :=
  Auths.Crypto.SnapshotWriters.grant_encoder sha256 contract value fields domains capacity space native


-- Every role and quantifier is a closed source variant, independent of any
-- accepted-registry membership or successful assurance-verification flag.
example : encode.assurance_role_tag .Root = ok 0#u8 := by rfl
example : encode.assurance_role_tag .Intermediate = ok 1#u8 := by rfl
example : encode.assurance_role_tag .Actor = ok 2#u8 := by rfl
example : encode.assurance_role_tag .ExternalIssuer = ok 3#u8 := by rfl
example : encode.assurance_quantifier_tag .Any = ok 0#u8 := by rfl
example : encode.assurance_quantifier_tag .Every = ok 1#u8 := by rfl

-- Absent and present zero are different raw syntax. This is not a claim that
-- the actual constructor accepts a zero version or freshness window.
example : Auths.Crypto.ContextObjects.optionalU16 none ≠
    Auths.Crypto.ContextObjects.optionalU16 (some 0#u16) := by decide
example : Auths.Crypto.ContextObjects.optionalAge none ≠
    Auths.Crypto.ContextObjects.optionalAge (some 0#u64) := by decide

example (self : cbor.Encoder) (value : auths_model.AssuranceRequirement)
    (fields : Auths.Crypto.ContextAssurance.RequirementStrings value)
    (space : self.output.val.length + Auths.Crypto.ContextObjects.assuranceRequirementCost value ≤ Usize.max) :
    encode.encode_assurance_requirement self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ContextObjects.assuranceRequirement value ⦄ :=
  Auths.Crypto.ContextAssurance.requirement_exact self value fields space

example (self : cbor.Encoder) (value : auths_model.AssurancePolicy)
    (fields : Auths.Crypto.ContextAssurance.PolicyStrings value)
    (space : self.output.val.length + Auths.Crypto.ContextObjects.assurancePolicyCost value ≤ Usize.max) :
    encode.encode_assurance_policy self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ContextObjects.assurancePolicy value ⦄ :=
  Auths.Crypto.ContextAssurance.policy_exact self value fields space


example [primitive : Auths.Crypto.Sha256Primitives] (self : cbor.Encoder)
    (values : Slice auths_model.approval.ApprovalRequirement) (count : 64 < values.val.length) :
    approval.encode_context_requirements self values ⦃ actual =>
      actual.1 = .Err .LimitExceeded ∧ actual.2 = self ⦄ :=
  Auths.Crypto.ContextApproval.context_refuses self values count

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (self : cbor.Encoder) (values : Slice auths_model.approval.ApprovalRequirement)
    (domains : ∀ requirement ∈ values.val, Auths.Crypto.ContextApproval.Domain requirement)
    (count : values.val.length ≤ 64)
    (space : self.output.val.length + 9 + Auths.Codec.ProtocolArrayWriters.allocation
      Auths.Crypto.RequirementWriters.approvalCost values.val ≤ Usize.max) :
    approval.encode_context_requirements self values ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ContextObjects.approvalRequirements sha256 values.val ⦄ :=
  Auths.Crypto.ContextApproval.context_exact sha256 contract self values domains count space

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.TrustedContext) (fields : Auths.Crypto.ContextWriters.Fields value)
    (domains : Auths.Crypto.ContextWriters.Domains value) (dimensions : Auths.Crypto.ContextWriters.Dimensions value)
    (space : Auths.Crypto.ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.ContextObjects.contextCost value : Int) ≤ Isize.max) :
    encode.encode_verifier_context_value value ⦃ result => Auths.Crypto.SigningObjectWriters.Encodes
      (Auths.Crypto.ContextObjects.context sha256 value) result ⦄ :=
  Auths.Crypto.ContextWriters.context_encoder sha256 contract value fields domains dimensions space native

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.TrustedContext) (fields : Auths.Crypto.ContextWriters.Fields value)
    (domains : Auths.Crypto.ContextWriters.Domains value) (dimensions : Auths.Crypto.ContextWriters.Dimensions value)
    (space : Auths.Crypto.ContextObjects.contextCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.ContextObjects.contextCost value : Int) ≤ Isize.max)
    (fits : Auths.Crypto.FramedHash.IdentifierAdmissible (Auths.Crypto.ContextObjects.context sha256 value)) :
    ∃ measured, hash.context_digest_and_size value = ok (.Ok
      (sha256 (Auths.Crypto.CommitmentFrames.identifier (Auths.Crypto.ContextCommitments.frame sha256 value)), measured)) ∧
      measured.val = (Auths.Crypto.ContextObjects.context sha256 value).length :=
  Auths.Crypto.ContextCommitments.digest_and_size_exact sha256 contract value fields domains dimensions space native fits

example (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (fields : Auths.Crypto.BoundedPolicyWriters.Fields value.commitment)
    (space : Auths.Crypto.BoundedPolicyObjects.bodyCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.BoundedPolicyObjects.bodyCost value : Int) ≤ Isize.max) :
    bounded_policy.encode_bounded_policy_commitment_value value ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.BoundedPolicyObjects.body value) result ⦄ :=
  Auths.Crypto.BoundedPolicyWriters.body_encoder value fields space native

example : Auths.Crypto.CommitmentFrames.application (Auths.Crypto.BoundedPolicyCommitments.policyFrame []) ≠
    Auths.Crypto.CommitmentFrames.application (Auths.Crypto.BoundedPolicyCommitments.linkFrame []) := by decide

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (payload : Slice Std.U8) (bounded : payload.val.length ≤ 4096) :
    bounded_policy.bounded_policy_digest payload = ok (.Ok (sha256
      (Auths.Crypto.CommitmentFrames.application (Auths.Crypto.BoundedPolicyCommitments.policyFrame
        (Auths.Codec.Refinement.byteList payload.val))))) :=
  Auths.Crypto.BoundedPolicyCommitments.policy_bounded_exact sha256 contract payload bounded


example : encode.verification_decision_tag .Authorized = ok 0#u8 := by rfl
example : encode.verification_decision_tag .Denied = ok 1#u8 := by rfl
example : encode.verification_decision_tag .Indeterminate = ok 2#u8 := by rfl
example : encode.verification_stage_tag .Complete = ok 4#u8 := by rfl

example (value : auths_model.VerificationCode) :
    auths_model.VerificationCode.code value ⦃ actual =>
      Auths.Codec.Refinement.byteList actual.val =
        Auths.Crypto.UnsignedObjects.utf8 (Auths.Crypto.ResultObjects.codeLabel value) ⦄ :=
  Auths.Crypto.ResultLeaves.code_label_exact value

example : Auths.Crypto.ResultObjects.codeLabel (.Denied .VerifierConfigurationMismatch) =
    "verifier-configuration-mismatch" := by rfl
example : Auths.Crypto.ResultObjects.codeLabel (.Indeterminate .UnsupportedProtocol) =
    "unsupported-protocol" := by rfl

example (self : cbor.Encoder) (value : auths_model.VerificationResources)
    (space : self.output.val.length + 135 ≤ Usize.max) :
    encode.encode_verification_resources self value ⦃ actual => actual.1 = .Ok () ∧
      Auths.Codec.Refinement.byteList actual.2.output.val = Auths.Codec.Refinement.byteList self.output.val ++
        Auths.Crypto.ResultObjects.resources value ⦄ :=
  Auths.Crypto.ResultLeaves.resources_exact self value space

example (value : auths_model.PortableVerificationResult) (include : Bool)
    (fields : Auths.Crypto.ResultWriters.Fields value)
    (space : Auths.Crypto.ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.ResultObjects.resultCost value : Int) ≤ Isize.max) :
    encode.encode_verification_result_projection value include ⦃ result =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.ResultObjects.result include value) result ⦄ :=
  Auths.Crypto.ResultWriters.projection_encoder value include fields space native

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.PortableVerificationResult) (fields : Auths.Crypto.ResultWriters.Fields value)
    (space : Auths.Crypto.ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.ResultObjects.resultCost value : Int) ≤ Isize.max) :
    hash.verification_result_digest value = ok (.Ok (sha256 (Auths.Crypto.ResultObjects.result false value))) :=
  Auths.Crypto.ResultCommitments.digest_exact sha256 contract value fields space native

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.PortableVerificationResult) (digest : auths_model.VerificationResultDigest)
    (fields : Auths.Crypto.ResultWriters.Fields value)
    (space : Auths.Crypto.ResultObjects.resultCost value ≤ Usize.max)
    (native : (2 * Auths.Crypto.ResultObjects.resultCost value : Int) ≤ Isize.max) :
    (do let changed ← auths_model.PortableVerificationResult.impl.with_result_digest value digest
        hash.verification_result_digest changed) = ok (.Ok (sha256 (Auths.Crypto.ResultObjects.result false value))) :=
  Auths.Crypto.ResultCommitments.rebinding_digest_exact sha256 contract value digest fields space native


example : Auths.Codec.PolicyValidity.accepts "AZaz09./:_-" 128 = true := by decide
example : Auths.Codec.PolicyValidity.accepts "λ" 128 = false := by decide
example : Auths.Codec.PolicyValidity.accepts "a b" 128 = false := by decide
example : Auths.Codec.PolicyValidity.accepts "" 128 = false := by decide

example : auths_model.bounded_policy.PolicyIdentifier.parse
    (Auths.Codec.toStr "λ" (by change 2 ≤ U32.max; scalar_tac)) 128#usize = ok (.Err .InvalidBoundedPolicy) := by
  rw [Auths.Codec.PolicyIdentifiers.parse_exact]
  decide

example (input : Slice Std.U8) :
    auths_model.bounded_policy.policy_identifier_has_invalid input ⦃ actual =>
      actual = Auths.Codec.PolicyValidity.invalid (Auths.Codec.Refinement.byteList input.val) ⦄ :=
  Auths.Codec.PolicyIdentifiers.scan_exact input

example (value : auths_model.bounded_policy.PolicyCommitment)
    (fields : Auths.Crypto.BoundedPolicyWriters.Fields value) :
    auths_model.bounded_policy.PolicyCommitment.new value.policy_type 0#u16
      value.canonicalization_id value.policy_digest value.evaluator_semantic_id = ok (.Err .InvalidBoundedPolicy) := by
  simpa [Auths.Codec.PolicyValidity.CommitmentDimensions] using
    Auths.Codec.PolicyConstructors.commitment_exact { value with policy_version := 0#u16 } fields

example (value : auths_model.bounded_policy.BoundedPolicyCommitment) :
    auths_model.bounded_policy.BoundedPolicyCommitment.new value.commitment (alloc.vec.Vec.new Std.U8) value.parent =
      ok (.Err .InvalidBoundedPolicy) := by
  simpa only [alloc.vec.new_contents, ↓reduceIte] using
    Auths.Codec.PolicyConstructors.body_exact { value with policy := alloc.vec.Vec.new Std.U8 }

example (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : Auths.Codec.PolicyValidity.Body value) :
    bounded_policy.encode_bounded_policy_commitment_value value ⦃ encoded =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.BoundedPolicyObjects.body value) encoded ⦄ :=
  Auths.Codec.PolicyConstructors.body_encoder_valid value valid

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : Auths.Codec.PolicyValidity.Body value) (unopened : ¬ Auths.Codec.PolicyValidity.Opening sha256 value) :
    canonical_value.checked_bounded_policy value = ok (.Err .DigestMismatch) :=
  Auths.Codec.PolicyCanonical.checked_refuses sha256 contract value valid unopened


example (value : auths_model.PortableVerificationResult) (include : Bool)
    (fits : (Auths.Crypto.ResultObjects.result include value).length ≤ 8388608) :
    encode.encode_verification_result_projection value include ⦃ encoded =>
      Auths.Crypto.SigningObjectWriters.Encodes (Auths.Crypto.ResultObjects.result include value) encoded ⦄ :=
  Auths.Crypto.ResultCost.projection_encoder_bounded value include fits

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.PortableVerificationResult)
    (fits : (Auths.Crypto.ResultObjects.result false value).length ≤ 8388608) :
    hash.verification_result_digest value = ok (.Ok (sha256 (Auths.Crypto.ResultObjects.result false value))) :=
  Auths.Crypto.ResultCost.digest_bounded_exact sha256 contract value fits


example [primitive : Auths.Crypto.Sha256Primitives]
    (value : auths_model.PortableVerificationResult)
    (inconsistent : ¬ Auths.Codec.ResultIntegrity.Consistent value) :
    canonical_value.checked_verification_result value = ok (.Err .Malformed) :=
  Auths.Codec.ResultIntegrity.rejects_inconsistent value inconsistent

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (value : auths_model.PortableVerificationResult)
    (fits : (Auths.Crypto.ResultObjects.result true value).length ≤ 8388608)
    (consistent : Auths.Codec.ResultIntegrity.Consistent value)
    (unopened : ¬ Auths.Codec.ResultIntegrity.Opening sha256 value) :
    canonical_value.checked_verification_result value = ok (.Err .DigestMismatch) :=
  Auths.Codec.ResultIntegrity.checked_refuses_opening sha256 contract value fits consistent unopened


example (self : cbor.Decoder) (value : Std.U32) (leading trailing : List Nat)
    (wire : Auths.Codec.Refinement.byteList self.input.val = leading ++
      Auths.Codec.encodeHead ⟨0, value.val⟩ ++ trailing)
    (start : self.position.val = leading.length) :
    cbor.Decoder.u32 self ⦃ actual => actual.1 = .Ok value ∧
      actual.2.position.val = leading.length + (Auths.Codec.encodeHead ⟨0, value.val⟩).length ∧
      actual.2.input = self.input ⦄ :=
  Auths.Codec.ProtocolPrimitiveInverse.u32_inverse self value leading trailing wire start

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (input : Slice Std.U8) (value : auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : Auths.Codec.PolicyValidity.Body value)
    (wire : Auths.Codec.Refinement.byteList input.val = Auths.Crypto.BoundedPolicyObjects.body value) :
    bounded_policy.decode_bounded_policy_commitment input ⦃ result =>
      result = if Auths.Codec.PolicyValidity.Opening sha256 value then .Ok ⟨value⟩ else .Err .DigestMismatch ⦄ :=
  Auths.Codec.PolicyInverse.decode_encoding sha256 contract input value valid wire

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (valid : Auths.Codec.PolicyValidity.Body carrier.value)
    (opened : Auths.Codec.PolicyValidity.Opening sha256 carrier.value) :
    bounded_policy.encode_bounded_policy_commitment carrier ⦃ encoded =>
      match encoded with
      | .Err _ => False
      | .Ok bytes => bounded_policy.decode_bounded_policy_commitment (alloc.vec.Vec.deref bytes)
          ⦃ decoded => decoded = .Ok carrier ⦄ ⦄ :=
  Auths.Codec.PolicyInverse.public_roundtrip sha256 contract carrier valid opened

-- Arbitrary represented bytes: no successful parser/constructor or expected
-- intermediate output is supplied as a premise.
example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (input : Slice Std.U8) :
    bounded_policy.decode_bounded_policy_commitment input ⦃ result =>
      match result with
      | .Err _ => True
      | .Ok carrier => ∃ value encoded, canonical_value.Canonical.as_value carrier = ok value ∧
          Auths.Codec.PolicyValidity.Body value ∧ Auths.Codec.PolicyValidity.Opening sha256 value ∧
          bounded_policy.encode_bounded_policy_commitment carrier = ok (.Ok encoded) ∧
          encoded.val = input.val ∧
          Auths.Codec.Refinement.byteList input.val = Auths.Crypto.BoundedPolicyObjects.body value ⦄ :=
  Auths.Codec.PolicyReadTotal.decoder_total sha256 contract input

example [primitive : Auths.Crypto.Sha256Primitives] (input : Slice Std.U8)
    (oversize : 65536 < input.val.length) :
    bounded_policy.decode_bounded_policy_commitment input = ok (.Err .LimitExceeded) :=
  Auths.Codec.PolicyReadTotal.decoder_oversize input oversize

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (input : Slice Std.U8)
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : bounded_policy.decode_bounded_policy_commitment input = ok (.Ok carrier)) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      Auths.Codec.PolicyValidity.Body value ∧ Auths.Codec.PolicyValidity.Opening sha256 value :=
  Auths.Codec.PolicyAccepted.decoder_valid sha256 contract input carrier accepted

-- These statements retain the failure cursor and the whole borrowed input;
-- the initial confinement premise is what public Decoder::new earns.
example (self : cbor.Decoder) (within : self.position.val ≤ self.input.val.length) :
    cbor.Decoder.str self ⦃ actual => Auths.Codec.ProtocolReaderBounds.Frame self actual.2 ∧
      ∃ payload, cbor.Decoder.payload self 3#u8 = ok (payload, actual.2) ∧
        actual.1 = Auths.Codec.ProtocolReaderBounds.utf8Outcome payload ∧
        Auths.Codec.ProtocolReaderBounds.utf8Bytes payload ≤ actual.2.position.val - self.position.val ∧
        Auths.Codec.ProtocolReaderBounds.utf8Bytes payload ≤ self.input.val.length ⦄ :=
  Auths.Codec.ProtocolReaderBounds.source_str_trace self within

example (self : cbor.Decoder) (within : self.position.val ≤ self.input.val.length) :
    decode.text self ⦃ actual => Auths.Codec.ProtocolReaderBounds.Frame self actual.2 ∧
      ∀ text, actual.1 = .Ok text →
        text.val.length ≤ actual.2.position.val - self.position.val ∧
        text.val.length ≤ self.input.val.length ∧
        (Auths.Codec.StdModel.bytes text).IsValidUTF8 ⦄ :=
  Auths.Codec.ProtocolReaderBounds.source_text_span self within

example (self : cbor.Decoder) (within : self.position.val ≤ self.input.val.length) :
    bounded_policy.commitment self ⦃ actual =>
      Auths.Codec.ProtocolReaderBounds.Frame self actual.2 ∧
      match actual.1 with | .Err _ => True | .Ok value => Auths.Codec.PolicyValidity.Commitment value ⦄ :=
  Auths.Codec.PolicyCursor.commitment_bounded self within

example (self : cbor.Decoder) (maximum : Std.Usize) :
    decode.array self maximum ⦃ actual =>
      match actual.1 with | .Err _ => True | .Ok count => count.val ≤ maximum.val ⦄ :=
  Auths.Codec.ProtocolReaderBounds.source_array_limit self maximum

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (input : Slice Std.U8)
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment) :
    bounded_policy.decode_bounded_policy_commitment input = ok (.Ok carrier) ↔
      Auths.Codec.PolicyAssurance.Accepts sha256 input carrier.value :=
  Auths.Codec.PolicyAssurance.accepted_iff sha256 contract input carrier

example [primitive : Auths.Crypto.Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : Auths.Crypto.FramedHash.Contract sha256)
    (input : Slice Std.U8) :
    bounded_policy.decode_bounded_policy_commitment input ⦃ result =>
      match result with
      | .Err _ => ∀ carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment,
          ¬ Auths.Codec.PolicyAssurance.Accepts sha256 input carrier.value
      | .Ok carrier => Auths.Codec.PolicyAssurance.Accepts sha256 input carrier.value ∧
          ∃ encoded, bounded_policy.encode_bounded_policy_commitment carrier = ok (.Ok encoded) ∧
            encoded.val = input.val ⦄ :=
  Auths.Codec.PolicyAssurance.decoder_refines sha256 contract input

end qualification.aeneas.cases.protocolCodec
