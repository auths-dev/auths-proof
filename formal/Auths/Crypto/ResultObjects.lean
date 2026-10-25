import Auths.Crypto.ContextObjects

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Crypto.ResultObjects
open Auths.Codec.Refinement Auths.Codec.ProtocolArrayWriters

/- Independent complete result grammar. Stable labels and ABI version are
literal wire data, not calls to source code/encoder methods. Result consistency,
self-digest opening, verifier origin and authority are separate obligations. -/
def decision : auths_model.VerificationDecision → Nat
  | .Authorized => 0 | .Denied => 1 | .Indeterminate => 2

def stage : auths_model.VerificationStage → Nat
  | .Decode => 0 | .Resolve => 1 | .PrincipalControl => 2 | .Authority => 3 | .Complete => 4

def codeClass : auths_model.VerificationCode → Nat
  | .Authorized => 0 | .Denied _ => 1 | .Indeterminate _ => 2

def denialLabel : auths_model.DenialReason → String
  | .ActionBodyMismatch => "action-body-mismatch"
  | .ActionConstraintMismatch => "action-constraint-mismatch"
  | .ActionOutsideValidity => "action-outside-validity"
  | .AmbiguousTerminalGrant => "ambiguous-terminal-grant"
  | .ApprovalThresholdNotMet => "approval-threshold-not-met"
  | .AttachmentDigestMismatch => "attachment-digest-mismatch"
  | .AttachmentLengthMismatch => "attachment-length-mismatch"
  | .AttachmentMissing => "attachment-missing"
  | .AudienceMismatch => "audience-mismatch"
  | .AuthorizationPlanInvalid => "authorization-plan-invalid"
  | .BrokenGrantChain => "broken-grant-chain"
  | .BudgetCeilingExceeded => "budget-ceiling-exceeded"
  | .ChallengeMismatch => "challenge-mismatch"
  | .CompositionRequirementNotMet => "composition-requirement-not-met"
  | .CriticalExtensionUnknown => "critical-extension-unknown"
  | .DelegationExpanded => "delegation-expanded"
  | .DigestMismatch => "digest-mismatch"
  | .DuplicateAttachment => "duplicate-attachment"
  | .DuplicateObject => "duplicate-object"
  | .GrantRevoked => "grant-revoked"
  | .InvalidSignature => "invalid-signature"
  | .LocalPolicyDenied => "local-policy-denied"
  | .MalformedProof => "malformed-proof"
  | .MissingReference => "missing-reference"
  | .NonCanonicalProof => "non-canonical-proof"
  | .ObservationConditionFalse => "observation-condition-false"
  | .ObservationRequirementDropped => "observation-requirement-dropped"
  | .ObserverInAuthorityChain => "observer-in-authority-chain"
  | .OpaqueAttachmentNotAllowed => "opaque-attachment-not-allowed"
  | .PermissionNotGranted => "permission-not-granted"
  | .PlanActionMismatch => "plan-action-mismatch"
  | .PrincipalMethodMismatch => "principal-method-mismatch"
  | .PrincipalRevoked => "principal-revoked"
  | .ReferenceCycle => "reference-cycle"
  | .RegistryManifestMismatch => "registry-manifest-mismatch"
  | .ResourceLimitExceeded => "resource-limit-exceeded"
  | .ResourceNamespaceMismatch => "resource-namespace-mismatch"
  | .SignatureSuiteMismatch => "signature-suite-mismatch"
  | .StatusIssuerUntrusted => "status-issuer-untrusted"
  | .StatusMethodMismatch => "status-method-mismatch"
  | .StatusSequenceRollback => "status-sequence-rollback"
  | .UntrustedRoot => "untrusted-root"
  | .UnusedCriticalAttachment => "unused-critical-attachment"
  | .UnusedCriticalEvidence => "unused-critical-evidence"
  | .VerificationMethodMismatch => "verification-method-mismatch"
  | .VerifierConfigurationMismatch => "verifier-configuration-mismatch"

def requirementLabel : auths_model.Requirement → String
  | .ApprovalUnavailable => "approval-unavailable"
  | .AssuranceRequirementNotMet => "assurance-requirement-not-met"
  | .ExternalFactUnavailable => "external-fact-unavailable"
  | .HistoricalStateUnavailable => "historical-state-unavailable"
  | .MissingGrantStatus => "missing-grant-status"
  | .MissingPrincipalEvidence => "missing-principal-evidence"
  | .MissingPrincipalStatus => "missing-principal-status"
  | .ObservationActionFactUnavailable => "observation-action-fact-unavailable"
  | .ObservationMissing => "observation-missing"
  | .StaleStatus => "stale-status"
  | .UnsupportedAssuranceClaim => "unsupported-assurance-claim"
  | .UnsupportedBudgetAlgebra => "unsupported-budget-algebra"
  | .UnsupportedCriticalExtension => "unsupported-critical-extension"
  | .UnsupportedEvidenceType => "unsupported-evidence-type"
  | .UnsupportedPrincipalMethod => "unsupported-principal-method"
  | .UnsupportedProfile => "unsupported-profile"
  | .UnsupportedProfilePolicy => "unsupported-profile-policy"
  | .UnsupportedProtocol => "unsupported-protocol"
  | .UnsupportedResourceMatcher => "unsupported-resource-matcher"
  | .UnsupportedSignatureSuite => "unsupported-signature-suite"
  | .UnsupportedStatusMethod => "unsupported-status-method"

def codeLabel : auths_model.VerificationCode → String
  | .Authorized => "authorized"
  | .Denied reason => denialLabel reason
  | .Indeterminate requirement => requirementLabel requirement

def code (value : auths_model.VerificationCode) : List Nat :=
  UnsignedWire.map [(0, UnsignedWire.uint (codeClass value)), (1, UnsignedObjects.identifier (codeLabel value))]

def codeCost (value : auths_model.VerificationCode) : Nat :=
  45 + (codeLabel value).toByteArray.size

def optionalTime : Option auths_model.Timestamp → List Nat
  | none => UnsignedWire.null
  | some value => UnsignedWire.uint value.val

def claim (value : auths_model.AssuranceClaim) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.kind),
    (1, UnsignedWire.array (value.parameters.val.map ContextObjects.parameter)),
    (2, optionalTime value.observed_at), (3, UnsignedObjects.identifier value.source)]

def claimCost (value : auths_model.AssuranceClaim) : Nat :=
  81 + value.kind.toByteArray.size + value.source.toByteArray.size + allocation ContextObjects.parameterCost value.parameters.val

def report (value : auths_model.ParticipantAssurance) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.identifier value.principal),
    (1, UnsignedWire.uint (ContextObjects.role value.role)),
    (2, UnsignedWire.array (value.claims.val.map claim)),
    (3, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest)),
    (4, UnsignedObjects.identifier value.adapter), (5, UnsignedWire.uint value.adapter_version.val)]

def reportCost (value : auths_model.ParticipantAssurance) : Nat :=
  117 + value.principal.toByteArray.size + value.adapter.toByteArray.size +
    allocation claimCost value.claims.val + 41 * value.evidence.val.length

def assuranceSatisfaction (value : auths_model.AssuranceSatisfaction) : List Nat :=
  UnsignedWire.map [(0, UnsignedWire.uint value.requirement_index.val),
    (1, UnsignedObjects.identifier value.principal), (2, claim value.claim),
    (3, UnsignedWire.array (value.evidence.val.map UnsignedObjects.digest))]

def assuranceSatisfactionCost (value : auths_model.AssuranceSatisfaction) : Nat :=
  72 + value.principal.toByteArray.size + claimCost value.claim + 41 * value.evidence.val.length

def resourceValues (value : auths_model.VerificationResources) : List Nat :=
  [value.proof_bytes.val, value.action_bytes.val, value.context_bytes.val, value.object_count.val,
    value.plan_leaves.val, value.plan_depth.val, value.work_units.val]

def resources (value : auths_model.VerificationResources) : List Nat :=
  UnsignedWire.map (ContextObjects.numbered 0 (resourceValues value))

def observationSatisfaction (value : auths_model.observation.ObservationSatisfaction) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.digest value.requirement), (1, UnsignedObjects.digest value.observation)]

def approvalSatisfaction (value : auths_model.approval.ApprovalSatisfaction) : List Nat :=
  UnsignedWire.map [(0, UnsignedObjects.digest value.requirement),
    (1, UnsignedWire.array (value.approvals.val.map UnsignedObjects.digest))]

def approvalSatisfactionCost (value : auths_model.approval.ApprovalSatisfaction) : Nat :=
  77 + 41 * value.approvals.val.length

def selfDigest (include : Bool) (value : auths_model.VerificationResultDigest) : List Nat :=
  if include then UnsignedObjects.digest value else UnsignedWire.bytes (List.replicate 32 0)

def result (include : Bool) (value : auths_model.PortableVerificationResult) : List Nat :=
  UnsignedWire.map [(0, UnsignedWire.uint (decision value.decision)), (1, UnsignedWire.uint (stage value.stage)),
    (2, code value.code), (3, UnsignedObjects.digest value.proof_digest),
    (4, UnsignedObjects.digest value.action_digest), (5, UnsignedObjects.digest value.context_digest),
    (6, UnsignedObjects.optionalDigest value.plan_id), (7, selfDigest include value.result_digest),
    (8, UnsignedWire.array (value.authorized_branches.val.map UnsignedObjects.digest)),
    (9, UnsignedWire.array (value.assurance.val.map report)),
    (10, UnsignedWire.array (value.assurance_satisfactions.val.map assuranceSatisfaction)),
    (11, resources value.resources), (12, UnsignedObjects.digest value.registry_manifest),
    (13, UnsignedObjects.optionalDigest value.required_configuration),
    (14, UnsignedObjects.digest value.local_configuration), (15, UnsignedWire.uint 4),
    (16, UnsignedWire.array (value.observation_satisfactions.val.map observationSatisfaction)),
    (17, UnsignedWire.array (value.approval_satisfactions.val.map approvalSatisfaction))]

def resultCost (value : auths_model.PortableVerificationResult) : Nat :=
  171 + ([9, 9, codeCost value.code, 41, 41, 41, 41, 41,
    9 + 41 * value.authorized_branches.val.length, 9 + allocation reportCost value.assurance.val,
    9 + allocation assuranceSatisfactionCost value.assurance_satisfactions.val, 135, 41, 41, 41, 9,
    9 + 109 * value.observation_satisfactions.val.length,
    9 + allocation approvalSatisfactionCost value.approval_satisfactions.val] : List Nat).sum

end Auths.Crypto.ResultObjects
