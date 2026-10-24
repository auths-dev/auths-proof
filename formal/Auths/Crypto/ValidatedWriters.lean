import Auths.Crypto.SigningObjectWriters
import Auths.Codec.ProtocolValidity

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Crypto.ValidatedWriters
open Auths.Codec Auths.Codec.ProtocolArrayWriters
open Auths.Crypto.UnsignedLeaves Auths.Crypto.StatementWriters Auths.Crypto.SigningObjectWriters

/- Writer conditions are earned from independent constructor invariants.
These predicates contain no decoder/encoder result or trusted flag. The source
constructor and public-decoder validity closure must still establish them at
actual byte-to-authority callers. Space is an independent allocation envelope. -/

theorem identifier_bound (value : String) (maximum : Nat)
    (valid : ProtocolValidity.Identifier value maximum) (within : maximum ≤ U32.max) :
    value.toByteArray.size ≤ U32.max := Nat.le_trans valid.2.1 within

theorem principal_bound (value : auths_model.PrincipalId) (valid : ProtocolValidity.Principal value) :
    value.toByteArray.size ≤ U32.max := identifier_bound value 512 valid.1 (by scalar_tac)

theorem permission_strings (value : auths_model.Permission) (valid : ProtocolValidity.Permission value) :
    PermissionStrings value :=
  ⟨identifier_bound _ 128 valid.1 (by scalar_tac), identifier_bound _ 1024 valid.2 (by scalar_tac)⟩

theorem budget_strings (value : Option auths_model.BudgetCeiling)
    (valid : ProtocolValidity.OptionalBudget value) :
    ∀ budget ∈ value, budget.algebra.toByteArray.size ≤ U32.max := by
  intro budget member
  exact identifier_bound _ 128 (valid budget member) (by scalar_tac)

theorem policy_strings (value : auths_model.StatusPolicy) (valid : ProtocolValidity.StatusPolicy value) :
    PolicyStrings value := by
  cases value with
  | ExpiryOnly => trivial
  | SnapshotRequired method maximum =>
    exact identifier_bound _ 128 valid.1 (by scalar_tac)

theorem extension_strings (value : auths_model.CriticalExtensions) (valid : ProtocolValidity.Extensions value) :
    ∀ item ∈ value.val, ExtensionStrings item := by
  intro item member
  exact identifier_bound _ 128 (valid.2.1 item member).1 (by scalar_tac)

theorem attachment_strings (value : auths_model.AttachmentDescriptor)
    (valid : ProtocolValidity.AttachmentDescriptor value) : AttachmentStrings value :=
  ⟨identifier_bound _ 128 valid.1 (by scalar_tac), identifier_bound _ 128 valid.2 (by scalar_tac)⟩

theorem fact_value_strings (value : auths_model.observation.FactValue)
    (valid : ProtocolValidity.FactValue value) : FactValueStrings value := by
  cases value with
  | Uint value => trivial
  | Bytes value => trivial
  | Text value =>
    change value.toByteArray.size ≤ U32.max
    have bound : value.toByteArray.size ≤ 256 := valid
    scalar_tac

theorem fact_strings (value : auths_model.observation.ObservationFact) (valid : ProtocolValidity.Fact value) :
    FactStrings value :=
  ⟨identifier_bound _ 128 valid.1 (by scalar_tac), fact_value_strings value.value valid.2⟩

theorem descriptor_bounds (value : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.SignatureDescriptor value) :
    value.principal_method.toByteArray.size ≤ U32.max ∧
      value.verification_method.toByteArray.size ≤ U32.max ∧ value.suite.toByteArray.size ≤ U32.max :=
  ⟨identifier_bound _ 128 valid.1 (by scalar_tac),
    identifier_bound _ 512 valid.2.1 (by scalar_tac),
    identifier_bound _ 128 valid.2.2 (by scalar_tac)⟩

theorem grant_strings (value : auths_model.GrantStatement) (valid : ProtocolValidity.Grant value) :
    GrantStrings value := by
  rcases valid.2 with ⟨issuer, subject, profile, permissions, window, audiences,
    constraint, budget, policy, assurance, extensions⟩
  exact {
    issuer := principal_bound _ issuer
    subject := principal_bound _ subject
    profile := identifier_bound _ 128 profile.1 (by scalar_tac)
    permissions := fun item member => permission_strings item (permissions.2.2.1 item member)
    audiences := fun item member => identifier_bound _ 512 (audiences.2.2.1 item member) (by scalar_tac)
    budget := budget_strings _ budget
    policy := policy_strings _ policy
    assurance := identifier_bound _ 128 assurance (by scalar_tac)
    extensions := extension_strings _ extensions
  }

theorem action_strings (value : auths_model.ActionEnvelope) (valid : ProtocolValidity.Action value) :
    ActionStrings value := by
  rcases valid.2 with ⟨profile, media, permission, budget, audience, window, actor, channel,
    attachments, extensions⟩
  exact {
    profile := identifier_bound _ 128 profile.1 (by scalar_tac)
    media := identifier_bound _ 128 media (by scalar_tac)
    capability := identifier_bound _ 128 permission.1 (by scalar_tac)
    resource := identifier_bound _ 1024 permission.2 (by scalar_tac)
    budget := budget_strings _ budget
    audience := identifier_bound _ 512 audience (by scalar_tac)
    actor := principal_bound _ actor
    channel := identifier_bound _ 128 channel (by scalar_tac)
    attachments := fun item member => attachment_strings item (attachments item member)
    extensions := extension_strings _ extensions
  }

theorem principal_status_strings (value : auths_model.PrincipalStatusStatement)
    (valid : ProtocolValidity.PrincipalStatus value) : PrincipalStatusStrings value := by
  rcases valid.2.1 with ⟨method, principal, issuer, extensions⟩
  exact {
    method := identifier_bound _ 128 method (by scalar_tac)
    principal := principal_bound _ principal
    issuer := principal_bound _ issuer
    extensions := extension_strings _ extensions
  }

theorem grant_status_strings (value : auths_model.GrantStatusStatement)
    (valid : ProtocolValidity.GrantStatus value) : GrantStatusStrings value := by
  rcases valid.2.1 with ⟨method, issuer, extensions⟩
  exact {
    method := identifier_bound _ 128 method (by scalar_tac)
    issuer := principal_bound _ issuer
    extensions := extension_strings _ extensions
  }

theorem approval_strings (value : auths_model.approval.ApprovalStatement)
    (valid : ProtocolValidity.Approval value) : ApprovalStrings value := by
  rcases valid.2 with ⟨approver, media, permission, budget, audience, window⟩
  exact {
    approver := principal_bound _ approver
    media := identifier_bound _ 128 media (by scalar_tac)
    capability := identifier_bound _ 128 permission.1 (by scalar_tac)
    resource := identifier_bound _ 1024 permission.2 (by scalar_tac)
    budget := budget_strings _ budget
    audience := identifier_bound _ 512 audience (by scalar_tac)
  }

theorem observation_strings (value : auths_model.observation.ObservationStatement)
    (valid : ProtocolValidity.Observation value) : ObservationStrings value := by
  rcases valid.2 with ⟨observer, schema, subject, facts⟩
  exact {
    observer := principal_bound _ observer
    schema := identifier_bound _ 128 schema (by scalar_tac)
    subject := identifier_bound _ 1024 subject (by scalar_tac)
    facts := fun item member => fact_strings item (facts.2.2.1 item member)
  }

@[step] theorem grant_encoder_valid (value : auths_model.GrantStatement)
    (valid : ProtocolValidity.Grant value) (space : grantCost value ≤ Usize.max) :
    encode.encode_grant_statement value ⦃ result => Encodes (UnsignedObjects.grant value) result ⦄ :=
  SigningObjectWriters.grant_statement_exact value (grant_strings value valid) space

@[step] theorem grant_signing_valid (value : auths_model.GrantStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Grant value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grantSigningCost value descriptor ≤ Usize.max) :
    encode.encode_grant_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.grantSigningObject value descriptor) result ⦄ := by
  obtain ⟨principal, verification, suite⟩ := descriptor_bounds descriptor descriptorValid
  exact SigningObjectWriters.grant_signing_exact value descriptor (grant_strings value valid)
    principal verification suite space

@[step] theorem action_encoder_valid (value : auths_model.ActionEnvelope)
    (valid : ProtocolValidity.Action value) (space : actionCost value ≤ Usize.max) :
    encode.encode_action_envelope value ⦃ result => Encodes (UnsignedObjects.action value) result ⦄ :=
  SigningObjectWriters.action_statement_exact value (action_strings value valid) space

@[step] theorem action_signing_valid (value : auths_model.ActionEnvelope) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Action value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : actionSigningCost value descriptor ≤ Usize.max) :
    encode.encode_action_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.actionSigningObject value descriptor) result ⦄ := by
  obtain ⟨principal, verification, suite⟩ := descriptor_bounds descriptor descriptorValid
  exact SigningObjectWriters.action_signing_exact value descriptor (action_strings value valid)
    principal verification suite space

@[step] theorem principal_status_encoder_valid (value : auths_model.PrincipalStatusStatement)
    (valid : ProtocolValidity.PrincipalStatus value) (space : principal_statusCost value ≤ Usize.max) :
    encode.encode_principal_status_statement value ⦃ result => Encodes (UnsignedObjects.principalStatus value) result ⦄ :=
  SigningObjectWriters.principal_status_statement_exact value (principal_status_strings value valid) space

@[step] theorem principal_status_signing_valid (value : auths_model.PrincipalStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.PrincipalStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : principal_statusSigningCost value descriptor ≤ Usize.max) :
    encode.encode_principal_status_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.principalStatusSigningObject value descriptor) result ⦄ := by
  obtain ⟨principal, verification, suite⟩ := descriptor_bounds descriptor descriptorValid
  exact SigningObjectWriters.principal_status_signing_exact value descriptor (principal_status_strings value valid)
    principal verification suite space

@[step] theorem grant_status_encoder_valid (value : auths_model.GrantStatusStatement)
    (valid : ProtocolValidity.GrantStatus value) (space : grant_statusCost value ≤ Usize.max) :
    encode.encode_grant_status_statement value ⦃ result => Encodes (UnsignedObjects.grantStatus value) result ⦄ :=
  SigningObjectWriters.grant_status_statement_exact value (grant_status_strings value valid) space

@[step] theorem grant_status_signing_valid (value : auths_model.GrantStatusStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.GrantStatus value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : grant_statusSigningCost value descriptor ≤ Usize.max) :
    encode.encode_grant_status_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.grantStatusSigningObject value descriptor) result ⦄ := by
  obtain ⟨principal, verification, suite⟩ := descriptor_bounds descriptor descriptorValid
  exact SigningObjectWriters.grant_status_signing_exact value descriptor (grant_status_strings value valid)
    principal verification suite space

@[step] theorem approval_encoder_valid (value : auths_model.approval.ApprovalStatement)
    (valid : ProtocolValidity.Approval value) (space : approvalCost value ≤ Usize.max) :
    approval.encode_approval_statement value ⦃ result => Encodes (UnsignedObjects.approval value) result ⦄ :=
  SigningObjectWriters.approval_statement_exact value (approval_strings value valid) space

@[step] theorem approval_signing_valid (value : auths_model.approval.ApprovalStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Approval value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : approvalSigningCost value descriptor ≤ Usize.max) :
    approval.encode_approval_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.approvalSigningObject value descriptor) result ⦄ := by
  obtain ⟨principal, verification, suite⟩ := descriptor_bounds descriptor descriptorValid
  exact SigningObjectWriters.approval_signing_exact value descriptor (approval_strings value valid)
    principal verification suite space

@[step] theorem observation_encoder_valid (value : auths_model.observation.ObservationStatement)
    (valid : ProtocolValidity.Observation value) (space : observationCost value ≤ Usize.max) :
    observation.encode_observation_statement value ⦃ result => Encodes (UnsignedObjects.observation value) result ⦄ :=
  SigningObjectWriters.observation_statement_exact value (observation_strings value valid) space

@[step] theorem observation_signing_valid (value : auths_model.observation.ObservationStatement) (descriptor : auths_model.SignatureDescriptor)
    (valid : ProtocolValidity.Observation value) (descriptorValid : ProtocolValidity.SignatureDescriptor descriptor)
    (space : observationSigningCost value descriptor ≤ Usize.max) :
    observation.encode_observation_signing_input value descriptor ⦃ result => Encodes (UnsignedObjects.observationSigningObject value descriptor) result ⦄ := by
  obtain ⟨principal, verification, suite⟩ := descriptor_bounds descriptor descriptorValid
  exact SigningObjectWriters.observation_signing_exact value descriptor (observation_strings value valid)
    principal verification suite space

end Auths.Crypto.ValidatedWriters
