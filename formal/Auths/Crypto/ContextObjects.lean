import Auths.Crypto.SnapshotObjects
import Auths.Crypto.RequirementWriters
import Auths.Crypto.CommitmentFrames

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Crypto.ContextObjects
open Auths.Codec Auths.Codec.Refinement Auths.Codec.ProtocolArrayWriters
open Auths.Codec.ProtocolTextWriters

/- Independent complete trusted-context fields. Registries, trust/assurance
policies, observer/approver anchors and every deployment limit are byte-bound
configuration data here; membership/primitive dispatch/authority require their
own actual verifier proofs. No source encoder/decoder/hash result or accepted
configuration flag is used to define these schemas. -/
def numbered (index : Nat) : List Nat → List (Nat × List Nat)
  | [] => []
  | first :: rest => (index, UnsignedWire.uint first) :: numbered (index + 1) rest

def limitValues (value : auths_model.VerifierLimits) : List Nat :=
  [value.bundle_bytes.val, value.action_bytes.val, value.context_bytes.val, value.grants.val, value.actions.val, value.plan_leaves.val, value.plan_depth.val, value.plan_branching.val, value.evidence.val, value.evidence_bytes.val, value.bindings.val, value.principal_status.val, value.grant_status.val, value.attachments.val, value.attachment_bytes.val, value.signatures.val, value.signature_bytes.val, value.permissions.val, value.audiences.val, value.extensions.val, value.extension_bytes.val, value.body_digests.val, value.binding_evidence.val, value.canonical_body_bytes.val, value.registry_entries.val, value.trust_anchors.val, value.work_units.val, value.approvals.val, value.approver_anchors.val, value.approval_requirements.val]

def limitValue (value : auths_model.VerifierLimits) : auths_model.LimitKind → Nat
  | .BundleBytes => value.bundle_bytes.val
  | .ActionBytes => value.action_bytes.val
  | .ContextBytes => value.context_bytes.val
  | .Grants => value.grants.val
  | .Actions => value.actions.val
  | .PlanLeaves => value.plan_leaves.val
  | .PlanDepth => value.plan_depth.val
  | .PlanBranching => value.plan_branching.val
  | .EvidenceObjects => value.evidence.val
  | .EvidenceBytes => value.evidence_bytes.val
  | .ControlBindings => value.bindings.val
  | .PrincipalStatusStatements => value.principal_status.val
  | .GrantStatusStatements => value.grant_status.val
  | .Attachments => value.attachments.val
  | .AttachmentBytes => value.attachment_bytes.val
  | .Signatures => value.signatures.val
  | .SignatureBytes => value.signature_bytes.val
  | .Permissions => value.permissions.val
  | .Audiences => value.audiences.val
  | .CriticalExtensions => value.extensions.val
  | .CriticalExtensionBytes => value.extension_bytes.val
  | .AllowedBodyDigests => value.body_digests.val
  | .BindingEvidence => value.binding_evidence.val
  | .CanonicalBodyBytes => value.canonical_body_bytes.val
  | .RegistryEntries => value.registry_entries.val
  | .TrustAnchors => value.trust_anchors.val
  | .Approvals => value.approvals.val
  | .ApproverAnchors => value.approver_anchors.val
  | .ApprovalRequirements => value.approval_requirements.val

def limits (value : auths_model.VerifierLimits) : List Nat := UnsignedWire.map (numbered 0 (limitValues value))

def composition (value : auths_model.CompositionRequirement) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.optionalDigest value.expected_plan),
    (1, UnsignedWire.uint value.minimum_authorized_branches.val),
    (2, UnsignedWire.uint value.minimum_distinct_actors.val),
    (3, UnsignedWire.uint value.minimum_distinct_roots.val)]

def optionalText : Option String → List Nat
  | none => UnsignedWire.null
  | some value => UnsignedObjects.identifier value

def optionalTextCost : Option String → Nat
  | none => 1
  | some value => 9 + value.toByteArray.size

def optionalU16 : Option Std.U16 → List Nat
  | none => UnsignedWire.null
  | some value => UnsignedWire.uint value.val

def optionalAge : Option auths_model.FreshnessLimit → List Nat
  | none => UnsignedWire.null
  | some value => UnsignedWire.uint value.val

def role : auths_model.ParticipantRole → Nat
  | .Root => 0 | .Intermediate => 1 | .Actor => 2 | .ExternalIssuer => 3

def quantifier : auths_model.AssuranceQuantifier → Nat
  | .Any => 0 | .Every => 1

def parameter (value : auths_model.ClaimParameterId × auths_model.ClaimParameterId) : List Nat :=
  UnsignedWire.array [UnsignedObjects.identifier value.1, UnsignedObjects.identifier value.2]

def parameterCost (value : auths_model.ClaimParameterId × auths_model.ClaimParameterId) : Nat :=
  27 + value.1.toByteArray.size + value.2.toByteArray.size

def assuranceRequirement (value : auths_model.AssuranceRequirement) : List Nat :=
  UnsignedWire.map [(0, UnsignedWire.uint (role value.role)), (1, UnsignedObjects.identifier value.claim_kind),
    (2, UnsignedWire.array (value.parameters.val.map parameter)), (3, optionalText value.source),
    (4, optionalText value.adapter), (5, optionalU16 value.adapter_version),
    (6, optionalAge value.maximum_age), (7, UnsignedWire.uint (quantifier value.quantifier))]

def assuranceRequirementCost (value : auths_model.AssuranceRequirement) : Nat :=
  135 + value.claim_kind.toByteArray.size + allocation parameterCost value.parameters.val +
    optionalTextCost value.source + optionalTextCost value.adapter

def assurancePolicy (value : auths_model.AssurancePolicy) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.id),
    (1, UnsignedWire.array (value.requirements.val.map assuranceRequirement))]

def assurancePolicyCost (value : auths_model.AssurancePolicy) : Nat :=
  45 + value.id.toByteArray.size + allocation assuranceRequirementCost value.requirements.val

def profiles (values : List auths_model.ProfileRef) : List Nat := UnsignedWire.array (values.map UnsignedObjects.profile)
def profileCost (value : auths_model.ProfileRef) : Nat := 45 + value.id.toByteArray.size

def textArrayCost (values : List String) : Nat := 9 + allocation textCost values

def profilesCost (values : List auths_model.ProfileRef) : Nat := 9 + allocation profileCost values

def anchor (value : auths_model.TrustAnchor) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.id), (1, UnsignedObjects.identifier value.principal),
    (2, UnsignedWire.array (value.accepted_methods.val.map UnsignedObjects.identifier)),
    (3, profiles value.profiles.val), (4, UnsignedWire.array (value.permissions.val.map UnsignedObjects.permission)),
    (5, UnsignedWire.array (value.resource_namespaces.val.map UnsignedObjects.identifier)),
    (6, UnsignedWire.array (value.audiences.val.map UnsignedObjects.identifier)),
    (7, UnsignedWire.uint value.validity.not_before.val), (8, UnsignedWire.uint value.validity.expires_at.val),
    (9, UnsignedObjects.optionalBudget value.budget_ceiling), (10, UnsignedWire.uint value.max_delegation_depth.val),
    (11, UnsignedObjects.identifier value.assurance_policy), (12, UnsignedObjects.statusPolicy value.status_policy)]

def anchorCost (value : auths_model.TrustAnchor) : Nat :=
  126 + ([9 + value.id.toByteArray.size, 9 + value.principal.toByteArray.size,
    textArrayCost value.accepted_methods.val, profilesCost value.profiles.val,
    UnsignedCollections.permissionsCost value.permissions, textArrayCost value.resource_namespaces.val,
    textArrayCost value.audiences.val, 9, 9, UnsignedLeaves.budgetOptionCost value.budget_ceiling,
    9, 9 + value.assurance_policy.toByteArray.size, UnsignedLeaves.statusPolicyCost value.status_policy] : List Nat).sum

def registries (value : auths_model.AcceptedRegistries) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.digest value.manifest_id),
    (1, UnsignedWire.array (value.principal_methods.val.map UnsignedObjects.identifier)),
    (2, UnsignedWire.array (value.signature_suites.val.map UnsignedObjects.identifier)),
    (3, UnsignedWire.array (value.evidence_types.val.map UnsignedObjects.identifier)),
    (4, UnsignedWire.array (value.principal_status_methods.val.map UnsignedObjects.identifier)),
    (5, UnsignedWire.array (value.grant_status_methods.val.map UnsignedObjects.identifier)),
    (6, UnsignedWire.array (value.assurance_claims.val.map UnsignedObjects.identifier)),
    (7, UnsignedWire.array (value.assurance_implications.val.map UnsignedObjects.identifier)),
    (8, UnsignedWire.array (value.resource_matchers.val.map UnsignedObjects.identifier)),
    (9, UnsignedWire.array (value.budget_algebras.val.map UnsignedObjects.identifier)),
    (10, UnsignedWire.array (value.critical_extensions.val.map UnsignedObjects.identifier)),
    (11, profiles value.profiles.val), (12, UnsignedWire.array (value.profile_policies.val.map UnsignedObjects.identifier)),
    (13, profiles value.budget_free_profiles.val)]

def registriesCost (value : auths_model.AcceptedRegistries) : Nat :=
  135 + ([41, textArrayCost value.principal_methods.val, textArrayCost value.signature_suites.val,
    textArrayCost value.evidence_types.val, textArrayCost value.principal_status_methods.val,
    textArrayCost value.grant_status_methods.val, textArrayCost value.assurance_claims.val,
    textArrayCost value.assurance_implications.val, textArrayCost value.resource_matchers.val,
    textArrayCost value.budget_algebras.val, textArrayCost value.critical_extensions.val,
    profilesCost value.profiles.val, textArrayCost value.profile_policies.val,
    profilesCost value.budget_free_profiles.val] : List Nat).sum

def observer (value : auths_model.observation.ObserverAnchor) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.id), (1, UnsignedObjects.identifier value.principal),
    (2, UnsignedWire.array (value.accepted_methods.val.map UnsignedObjects.identifier)),
    (3, UnsignedWire.array (value.schemas.val.map UnsignedObjects.identifier)),
    (4, UnsignedWire.array (value.subject_namespaces.val.map UnsignedObjects.identifier)),
    (5, UnsignedWire.uint value.validity.not_before.val), (6, UnsignedWire.uint value.validity.expires_at.val)]

def observerCost (value : auths_model.observation.ObserverAnchor) : Nat :=
  135 + value.id.toByteArray.size + value.principal.toByteArray.size +
    allocation textCost value.accepted_methods.val + allocation textCost value.schemas.val +
    allocation textCost value.subject_namespaces.val

def approver (value : auths_model.approval.ApproverAnchor) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.principal),
    (1, UnsignedWire.array (value.accepted_methods.val.map UnsignedObjects.identifier)),
    (2, UnsignedWire.uint value.validity.not_before.val), (3, UnsignedWire.uint value.validity.expires_at.val),
    (4, UnsignedObjects.statusPolicy value.status_policy)]

def approverCost (value : auths_model.approval.ApproverAnchor) : Nat :=
  90 + value.principal.toByteArray.size + allocation textCost value.accepted_methods.val +
    UnsignedLeaves.statusPolicyCost value.status_policy

def approvalKey (sha256 : List Nat → auths_model.Digest) (value : auths_model.approval.ApprovalRequirement) : List Nat :=
  byteList (sha256 (CommitmentFrames.identifier ⟨12, UnsignedObjects.approvalRequirement value⟩)).val

def approvalRequirements (sha256 : List Nat → auths_model.Digest)
    (values : List auths_model.approval.ApprovalRequirement) : List Nat :=
  UnsignedWire.array ((StableNormalization.sort (approvalKey sha256) values).map UnsignedObjects.approvalRequirement)

def context (sha256 : List Nat → auths_model.Digest) (value : auths_model.TrustedContext) : List Nat :=
  UnsignedWire.map [(0, limits value.limits), (1, UnsignedObjects.digest value.configuration),
    (2, composition value.composition), (3, UnsignedWire.array (value.trust_anchors.val.map anchor)),
    (4, registries value.accepted_registries), (5, UnsignedObjects.identifier value.expected_audience),
    (6, UnsignedObjects.digest value.expected_challenge), (7, UnsignedWire.uint value.evaluation_time.val),
    (8, assurancePolicy value.assurance_policy),
    (9, SnapshotObjects.principalSnapshot sha256 value.principal_status_snapshot),
    (10, SnapshotObjects.grantSnapshot sha256 value.grant_status_snapshot),
    (11, UnsignedObjects.identifier value.resource_matcher), (12, UnsignedObjects.identifier value.profile_policy),
    (13, UnsignedObjects.identifier value.channel_policy),
    (14, UnsignedWire.array (value.observer_anchors.val.map observer)),
    (15, UnsignedWire.array (value.approver_anchors.val.map approver)),
    (16, approvalRequirements sha256 value.approval_requirements.val)]

def contextCost (value : auths_model.TrustedContext) : Nat :=
  162 + ([549, 41, 113, 9 + allocation anchorCost value.trust_anchors.val,
    registriesCost value.accepted_registries, 9 + value.expected_audience.toByteArray.size,
    41, 9, assurancePolicyCost value.assurance_policy, SnapshotObjects.principalCost value.principal_status_snapshot,
    SnapshotObjects.grantCost value.grant_status_snapshot, 9 + value.resource_matcher.toByteArray.size,
    9 + value.profile_policy.toByteArray.size, 9 + value.channel_policy.toByteArray.size,
    9 + allocation observerCost value.observer_anchors.val, 9 + allocation approverCost value.approver_anchors.val,
    9 + allocation RequirementWriters.approvalCost value.approval_requirements.val] : List Nat).sum

end Auths.Crypto.ContextObjects
