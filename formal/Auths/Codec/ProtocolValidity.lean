import qualification.aeneas.generated.protocol_codec.Types
import Auths.Codec.Constructors
import Auths.Codec.PrincipalSchemeModel

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolValidity

/- Representation validity is independent of successful decoding, signatures,
registry lookup, graph resolution and authorization. Aeneas exposes Rust private
fields, so nominal Rust types alone cannot supply these premises in Lean.

These predicates describe constructor invariants. In particular an action's
attachment Vec has no collection check in ActionEnvelope::new. Decoder limits,
wire ordering and whole-input consumption must be proved separately; they must
not be silently attributed to that constructor. -/

abbrev Identifier (value : String) (maximum : Nat) : Prop :=
  Constructors.IdentifierValid value maximum

def textBytes (value : String) : List Nat :=
  value.toByteArray.toList.map UInt8.toNat

def textLT (left right : String) : Prop :=
  List.Lex (fun a b : Nat => a < b) (textBytes left) (textBytes right)

def Principal (value : auths_model.PrincipalId) : Prop :=
  Identifier value 512 ∧ Auths.PrincipalScheme.Model.grammar (textBytes value)

def Profile (value : auths_model.ProfileRef) : Prop :=
  Identifier value.id 128 ∧ 0 < value.version.val

def Permission (value : auths_model.Permission) : Prop :=
  Identifier value.capability 128 ∧ Identifier value.resource 1024

def permissionLT (left right : auths_model.Permission) : Prop :=
  textLT left.capability right.capability ∨
    (left.capability = right.capability ∧ textLT left.resource right.resource)

def Permissions (value : auths_model.PermissionSet) : Prop :=
  value.val ≠ [] ∧ value.val.length ≤ 1024 ∧
    (∀ item ∈ value.val, Permission item) ∧
    value.val.Pairwise permissionLT ∧ value.val.Nodup

def Audiences (value : auths_model.AudienceSet) : Prop :=
  value.val ≠ [] ∧ value.val.length ≤ 256 ∧
    (∀ item ∈ value.val, Identifier item 512) ∧
    value.val.Pairwise textLT ∧ value.val.Nodup

def Budget (value : auths_model.BudgetCeiling) : Prop :=
  Identifier value.algebra 128

def OptionalBudget (value : Option auths_model.BudgetCeiling) : Prop :=
  ∀ budget ∈ value, Budget budget

def Window (value : auths_model.ValidityWindow) : Prop :=
  value.not_before.val ≤ value.expires_at.val

def StatusPolicy : auths_model.StatusPolicy → Prop
  | .ExpiryOnly => True
  | .SnapshotRequired method maximum => Identifier method 128 ∧ 0 < maximum.val

def digestLT (left right : auths_model.Digest) : Prop :=
  List.Lex (fun a b : Nat => a < b)
    (left.val.map (·.val)) (right.val.map (·.val))

def BodyDigests (values : auths_model.BodyDigestSet) : Prop :=
  values.val ≠ [] ∧ values.val.length ≤ 256 ∧
    values.val.Pairwise digestLT ∧ values.val.Nodup

def BodyConstraint : auths_model.ActionConstraint → Prop
  | .AnyBody => True
  | .ExactBodyDigest _ => True
  | .AllowedBodyDigests values => BodyDigests values

def Extension (value : auths_model.CriticalExtension) : Prop :=
  Identifier value.id 128 ∧ value.bytes.val.length ≤ 65536

def Extensions (value : auths_model.CriticalExtensions) : Prop :=
  value.val.length ≤ 32 ∧ (∀ item ∈ value.val, Extension item) ∧
    value.val.Pairwise (fun left right => textLT left.id right.id) ∧
    (value.val.map (fun item => item.id)).Nodup

def SignatureDescriptor (value : auths_model.SignatureDescriptor) : Prop :=
  Identifier value.principal_method 128 ∧
    Identifier value.verification_method 512 ∧ Identifier value.suite 128

/-- A bounded representation of a signature. Cryptographic verification is a
separate statement, including suite/key/principal binding. -/
def Signature (value : auths_model.SignatureEnvelope) : Prop :=
  SignatureDescriptor value.descriptor ∧
    value.signature.val ≠ [] ∧ value.signature.val.length ≤ 4096

def GrantFields (value : auths_model.GrantStatement) : Prop :=
  Principal value.issuer ∧ Principal value.subject ∧ Profile value.profile ∧
    Permissions value.permissions ∧ Window value.validity ∧ Audiences value.audiences ∧
    BodyConstraint value.action_constraint ∧ OptionalBudget value.budget_ceiling ∧
    StatusPolicy value.status_policy ∧ Identifier value.assurance_floor 128 ∧
    Extensions value.extensions

def Grant (value : auths_model.GrantStatement) : Prop :=
  value.version.val = 1 ∧ GrantFields value

def SignedGrant (value : auths_model.SignedGrant) : Prop :=
  Grant value.statement ∧ Signature value.signature

def AttachmentDescriptor (value : auths_model.AttachmentDescriptor) : Prop :=
  Identifier value.media_type 128 ∧ Identifier value.disposition 128

def ActionFields (value : auths_model.ActionEnvelope) : Prop :=
  Profile value.profile ∧ Identifier value.body_media_type 128 ∧
    Permission value.permission ∧ OptionalBudget value.requested_budget ∧
    Identifier value.audience 512 ∧ Window value.validity ∧ Principal value.actor ∧
    Identifier value.channel_binding 128 ∧
    (∀ attachment ∈ value.attachments.val, AttachmentDescriptor attachment) ∧
    Extensions value.extensions

def Action (value : auths_model.ActionEnvelope) : Prop :=
  value.version.val = 1 ∧ ActionFields value

def SignedAction (value : auths_model.SignedAction) : Prop :=
  Action value.envelope ∧ Signature value.signature

def PrincipalStatusFields (value : auths_model.PrincipalStatusStatement) : Prop :=
  Identifier value.method 128 ∧ Principal value.principal ∧
    Principal value.issuer ∧ Extensions value.extensions

def PrincipalStatus (value : auths_model.PrincipalStatusStatement) : Prop :=
  value.version.val = 1 ∧ PrincipalStatusFields value ∧
    value.observed_at.val ≤ value.valid_until.val

def GrantStatusFields (value : auths_model.GrantStatusStatement) : Prop :=
  Identifier value.method 128 ∧ Principal value.issuer ∧ Extensions value.extensions

def GrantStatus (value : auths_model.GrantStatusStatement) : Prop :=
  value.version.val = 1 ∧ GrantStatusFields value ∧
    value.observed_at.val ≤ value.valid_until.val

def SignedPrincipalStatus (value : auths_model.SignedPrincipalStatus) : Prop :=
  PrincipalStatus value.statement ∧ Signature value.signature

def SignedGrantStatus (value : auths_model.SignedGrantStatus) : Prop :=
  GrantStatus value.statement ∧ Signature value.signature

def ApprovalRequirement (value : auths_model.approval.ApprovalRequirement) : Prop :=
  value.approvers.val ≠ [] ∧ value.approvers.val.length ≤ 16 ∧
    0 < value.threshold.val ∧ value.threshold.val ≤ value.approvers.val.length ∧
    (∀ principal ∈ value.approvers.val, Principal principal) ∧
    value.approvers.val.Pairwise textLT ∧ value.approvers.val.Nodup

def ApprovalRequirements (values : auths_model.approval.ApprovalRequirements) : Prop :=
  values.val ≠ [] ∧ values.val.length ≤ 4 ∧ values.val.Nodup ∧
    ∀ value ∈ values.val, ApprovalRequirement value

def ApprovalFields (value : auths_model.approval.ApprovalStatement) : Prop :=
  Principal value.approver ∧ Identifier value.media_type 128 ∧
    Permission value.permission ∧ OptionalBudget value.requested_budget ∧
    Identifier value.audience 512 ∧ Window value.validity

def Approval (value : auths_model.approval.ApprovalStatement) : Prop :=
  value.version.val = 1 ∧ ApprovalFields value

def FactValue : auths_model.observation.FactValue → Prop
  | .Uint _ => True
  | .Bytes bytes => bytes.val.length ≤ 64
  | .Text text => text.toByteArray.size ≤ 256

def MemberValues (values : auths_model.observation.MemberValues) : Prop :=
  values.val ≠ [] ∧ values.val.length ≤ 16 ∧ values.val.Nodup ∧
    ∀ value ∈ values.val, FactValue value

def ConditionTest : auths_model.observation.ConditionTest → Prop
  | .EqLiteral value => FactValue value
  | .EqAction name => Identifier name 128
  | .UintRange value => value.lo.val ≤ value.hi.val
  | .Member values => MemberValues values

def Condition (value : auths_model.observation.ObservationCondition) : Prop :=
  Identifier value.name 128 ∧ ConditionTest value.test

def ObservationSubject : auths_model.observation.ObservationSubject → Prop
  | .Resource value => Identifier value 1024
  | .ActionFact name => Identifier name 128

def ObservationRequirementFields (value : auths_model.observation.ObservationRequirement) : Prop :=
  Identifier value.observer_anchor 128 ∧ Identifier value.schema 128 ∧
    ObservationSubject value.subject ∧ ∀ condition ∈ value.conditions.val, Condition condition

def ObservationRequirement (value : auths_model.observation.ObservationRequirement) : Prop :=
  ObservationRequirementFields value ∧ 0 < value.max_age_seconds.val ∧
    value.max_age_seconds.val ≤ 86400 ∧ value.conditions.val ≠ [] ∧ value.conditions.val.length ≤ 16

def ObservationRequirements (values : auths_model.observation.ObservationRequirements) : Prop :=
  values.val ≠ [] ∧ values.val.length ≤ 8 ∧ values.val.Nodup ∧
    ∀ value ∈ values.val, ObservationRequirement value

def Fact (value : auths_model.observation.ObservationFact) : Prop :=
  Identifier value.name 128 ∧ FactValue value.value

def Facts (value : auths_model.observation.ObservationFacts) : Prop :=
  value.val ≠ [] ∧ value.val.length ≤ 16 ∧
    (∀ item ∈ value.val, Fact item) ∧
    value.val.Pairwise (fun left right => textLT left.name right.name) ∧
    (value.val.map (fun item => item.name)).Nodup

def ObservationFields (value : auths_model.observation.ObservationStatement) : Prop :=
  Principal value.observer ∧ Identifier value.schema 128 ∧
    Identifier value.subject 1024 ∧ Facts value.facts

def Observation (value : auths_model.observation.ObservationStatement) : Prop :=
  value.version.val = 1 ∧ ObservationFields value

def Evidence (value : auths_model.EvidenceObject) : Prop :=
  Identifier value.evidence_type 128 ∧ Identifier value.media_type 128 ∧
    value.bytes.val ≠ [] ∧ value.bytes.val.length ≤ 2097152

/-- Signed approval/observation constructors allow an empty control-evidence
list, but require at most four uniquely identified records in digest order. -/
def ControlEvidence (values : List auths_model.EvidenceObject) : Prop :=
  values.length ≤ 4 ∧ (∀ value ∈ values, Evidence value) ∧
    values.Pairwise (fun left right => digestLT left.id right.id) ∧
    (values.map (fun value => value.id)).Nodup

def SignedApproval (value : auths_model.approval.SignedApproval) : Prop :=
  Approval value.statement ∧ Signature value.signature ∧ ControlEvidence value.evidence.val

def SignedObservation (value : auths_model.observation.SignedObservation) : Prop :=
  Observation value.statement ∧ Signature value.signature ∧ ControlEvidence value.evidence.val

theorem principal_nonempty (value : auths_model.PrincipalId) (valid : Principal value) :
    value.toByteArray.size ≠ 0 := valid.1.1

theorem principal_scheme_has_separator (value : auths_model.PrincipalId)
    (valid : Principal value) : 3 ≤ (textBytes value).length :=
  Auths.PrincipalScheme.Model.grammar_minimum _ valid.2

theorem grant_permissions_nonempty (value : auths_model.GrantStatement)
    (valid : Grant value) : value.permissions.val ≠ [] := valid.2.2.2.2.1.1

theorem signature_nonempty (value : auths_model.SignatureEnvelope) (valid : Signature value) :
    value.signature.val ≠ [] := valid.2.1

theorem observation_fact_names_unique (value : auths_model.observation.ObservationStatement)
    (valid : Observation value) : (value.facts.val.map (fun item => item.name)).Nodup :=
  valid.2.2.2.2.2.2.2.2

end Auths.Codec.ProtocolValidity
