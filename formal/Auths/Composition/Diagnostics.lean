import qualification.aeneas.generated.composition.Types
import Mathlib.Tactic
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_composition

namespace Auths.Composition.Model
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096
/- Stable V1 code bytes are the independent lexical diagnostic contract.
The native catalog parity gate also checks the production string getter. -/
def denialRank : auths_composition.auths_model.DenialReason → Nat
  | .ActionBodyMismatch => 0
  | .ActionConstraintMismatch => 1
  | .ActionOutsideValidity => 2
  | .AmbiguousTerminalGrant => 3
  | .ApprovalThresholdNotMet => 4
  | .AttachmentDigestMismatch => 5
  | .AttachmentLengthMismatch => 6
  | .AttachmentMissing => 7
  | .AudienceMismatch => 8
  | .AuthorizationPlanInvalid => 9
  | .BrokenGrantChain => 10
  | .BudgetCeilingExceeded => 11
  | .ChallengeMismatch => 12
  | .CompositionRequirementNotMet => 13
  | .CriticalExtensionUnknown => 14
  | .DelegationExpanded => 15
  | .DigestMismatch => 16
  | .DuplicateAttachment => 17
  | .DuplicateObject => 18
  | .GrantRevoked => 19
  | .InvalidSignature => 20
  | .LocalPolicyDenied => 21
  | .MalformedProof => 22
  | .MissingReference => 23
  | .NonCanonicalProof => 24
  | .ObservationConditionFalse => 25
  | .ObservationRequirementDropped => 26
  | .ObserverInAuthorityChain => 27
  | .OpaqueAttachmentNotAllowed => 28
  | .PermissionNotGranted => 29
  | .PlanActionMismatch => 30
  | .PrincipalMethodMismatch => 31
  | .PrincipalRevoked => 32
  | .ReferenceCycle => 33
  | .RegistryManifestMismatch => 34
  | .ResourceLimitExceeded => 35
  | .ResourceNamespaceMismatch => 36
  | .SignatureSuiteMismatch => 37
  | .StatusIssuerUntrusted => 38
  | .StatusMethodMismatch => 39
  | .StatusSequenceRollback => 40
  | .UntrustedRoot => 41
  | .UnusedCriticalAttachment => 42
  | .UnusedCriticalEvidence => 43
  | .VerificationMethodMismatch => 44
  | .VerifierConfigurationMismatch => 45

def denialCode : auths_composition.auths_model.DenialReason → List Nat
  | .ActionBodyMismatch => [97, 99, 116, 105, 111, 110, 45, 98, 111, 100, 121, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .ActionConstraintMismatch => [97, 99, 116, 105, 111, 110, 45, 99, 111, 110, 115, 116, 114, 97, 105, 110, 116, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .ActionOutsideValidity => [97, 99, 116, 105, 111, 110, 45, 111, 117, 116, 115, 105, 100, 101, 45, 118, 97, 108, 105, 100, 105, 116, 121]
  | .AmbiguousTerminalGrant => [97, 109, 98, 105, 103, 117, 111, 117, 115, 45, 116, 101, 114, 109, 105, 110, 97, 108, 45, 103, 114, 97, 110, 116]
  | .ApprovalThresholdNotMet => [97, 112, 112, 114, 111, 118, 97, 108, 45, 116, 104, 114, 101, 115, 104, 111, 108, 100, 45, 110, 111, 116, 45, 109, 101, 116]
  | .AttachmentDigestMismatch => [97, 116, 116, 97, 99, 104, 109, 101, 110, 116, 45, 100, 105, 103, 101, 115, 116, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .AttachmentLengthMismatch => [97, 116, 116, 97, 99, 104, 109, 101, 110, 116, 45, 108, 101, 110, 103, 116, 104, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .AttachmentMissing => [97, 116, 116, 97, 99, 104, 109, 101, 110, 116, 45, 109, 105, 115, 115, 105, 110, 103]
  | .AudienceMismatch => [97, 117, 100, 105, 101, 110, 99, 101, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .AuthorizationPlanInvalid => [97, 117, 116, 104, 111, 114, 105, 122, 97, 116, 105, 111, 110, 45, 112, 108, 97, 110, 45, 105, 110, 118, 97, 108, 105, 100]
  | .BrokenGrantChain => [98, 114, 111, 107, 101, 110, 45, 103, 114, 97, 110, 116, 45, 99, 104, 97, 105, 110]
  | .BudgetCeilingExceeded => [98, 117, 100, 103, 101, 116, 45, 99, 101, 105, 108, 105, 110, 103, 45, 101, 120, 99, 101, 101, 100, 101, 100]
  | .ChallengeMismatch => [99, 104, 97, 108, 108, 101, 110, 103, 101, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .CompositionRequirementNotMet => [99, 111, 109, 112, 111, 115, 105, 116, 105, 111, 110, 45, 114, 101, 113, 117, 105, 114, 101, 109, 101, 110, 116, 45, 110, 111, 116, 45, 109, 101, 116]
  | .CriticalExtensionUnknown => [99, 114, 105, 116, 105, 99, 97, 108, 45, 101, 120, 116, 101, 110, 115, 105, 111, 110, 45, 117, 110, 107, 110, 111, 119, 110]
  | .DelegationExpanded => [100, 101, 108, 101, 103, 97, 116, 105, 111, 110, 45, 101, 120, 112, 97, 110, 100, 101, 100]
  | .DigestMismatch => [100, 105, 103, 101, 115, 116, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .DuplicateAttachment => [100, 117, 112, 108, 105, 99, 97, 116, 101, 45, 97, 116, 116, 97, 99, 104, 109, 101, 110, 116]
  | .DuplicateObject => [100, 117, 112, 108, 105, 99, 97, 116, 101, 45, 111, 98, 106, 101, 99, 116]
  | .GrantRevoked => [103, 114, 97, 110, 116, 45, 114, 101, 118, 111, 107, 101, 100]
  | .InvalidSignature => [105, 110, 118, 97, 108, 105, 100, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101]
  | .LocalPolicyDenied => [108, 111, 99, 97, 108, 45, 112, 111, 108, 105, 99, 121, 45, 100, 101, 110, 105, 101, 100]
  | .MalformedProof => [109, 97, 108, 102, 111, 114, 109, 101, 100, 45, 112, 114, 111, 111, 102]
  | .MissingReference => [109, 105, 115, 115, 105, 110, 103, 45, 114, 101, 102, 101, 114, 101, 110, 99, 101]
  | .NonCanonicalProof => [110, 111, 110, 45, 99, 97, 110, 111, 110, 105, 99, 97, 108, 45, 112, 114, 111, 111, 102]
  | .ObservationConditionFalse => [111, 98, 115, 101, 114, 118, 97, 116, 105, 111, 110, 45, 99, 111, 110, 100, 105, 116, 105, 111, 110, 45, 102, 97, 108, 115, 101]
  | .ObservationRequirementDropped => [111, 98, 115, 101, 114, 118, 97, 116, 105, 111, 110, 45, 114, 101, 113, 117, 105, 114, 101, 109, 101, 110, 116, 45, 100, 114, 111, 112, 112, 101, 100]
  | .ObserverInAuthorityChain => [111, 98, 115, 101, 114, 118, 101, 114, 45, 105, 110, 45, 97, 117, 116, 104, 111, 114, 105, 116, 121, 45, 99, 104, 97, 105, 110]
  | .OpaqueAttachmentNotAllowed => [111, 112, 97, 113, 117, 101, 45, 97, 116, 116, 97, 99, 104, 109, 101, 110, 116, 45, 110, 111, 116, 45, 97, 108, 108, 111, 119, 101, 100]
  | .PermissionNotGranted => [112, 101, 114, 109, 105, 115, 115, 105, 111, 110, 45, 110, 111, 116, 45, 103, 114, 97, 110, 116, 101, 100]
  | .PlanActionMismatch => [112, 108, 97, 110, 45, 97, 99, 116, 105, 111, 110, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .PrincipalMethodMismatch => [112, 114, 105, 110, 99, 105, 112, 97, 108, 45, 109, 101, 116, 104, 111, 100, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .PrincipalRevoked => [112, 114, 105, 110, 99, 105, 112, 97, 108, 45, 114, 101, 118, 111, 107, 101, 100]
  | .ReferenceCycle => [114, 101, 102, 101, 114, 101, 110, 99, 101, 45, 99, 121, 99, 108, 101]
  | .RegistryManifestMismatch => [114, 101, 103, 105, 115, 116, 114, 121, 45, 109, 97, 110, 105, 102, 101, 115, 116, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .ResourceLimitExceeded => [114, 101, 115, 111, 117, 114, 99, 101, 45, 108, 105, 109, 105, 116, 45, 101, 120, 99, 101, 101, 100, 101, 100]
  | .ResourceNamespaceMismatch => [114, 101, 115, 111, 117, 114, 99, 101, 45, 110, 97, 109, 101, 115, 112, 97, 99, 101, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .SignatureSuiteMismatch => [115, 105, 103, 110, 97, 116, 117, 114, 101, 45, 115, 117, 105, 116, 101, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .StatusIssuerUntrusted => [115, 116, 97, 116, 117, 115, 45, 105, 115, 115, 117, 101, 114, 45, 117, 110, 116, 114, 117, 115, 116, 101, 100]
  | .StatusMethodMismatch => [115, 116, 97, 116, 117, 115, 45, 109, 101, 116, 104, 111, 100, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .StatusSequenceRollback => [115, 116, 97, 116, 117, 115, 45, 115, 101, 113, 117, 101, 110, 99, 101, 45, 114, 111, 108, 108, 98, 97, 99, 107]
  | .UntrustedRoot => [117, 110, 116, 114, 117, 115, 116, 101, 100, 45, 114, 111, 111, 116]
  | .UnusedCriticalAttachment => [117, 110, 117, 115, 101, 100, 45, 99, 114, 105, 116, 105, 99, 97, 108, 45, 97, 116, 116, 97, 99, 104, 109, 101, 110, 116]
  | .UnusedCriticalEvidence => [117, 110, 117, 115, 101, 100, 45, 99, 114, 105, 116, 105, 99, 97, 108, 45, 101, 118, 105, 100, 101, 110, 99, 101]
  | .VerificationMethodMismatch => [118, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110, 45, 109, 101, 116, 104, 111, 100, 45, 109, 105, 115, 109, 97, 116, 99, 104]
  | .VerifierConfigurationMismatch => [118, 101, 114, 105, 102, 105, 101, 114, 45, 99, 111, 110, 102, 105, 103, 117, 114, 97, 116, 105, 111, 110, 45, 109, 105, 115, 109, 97, 116, 99, 104]

def requirementRank : auths_composition.auths_model.Requirement → Nat
  | .ApprovalUnavailable => 0
  | .AssuranceRequirementNotMet => 1
  | .ExternalFactUnavailable => 2
  | .HistoricalStateUnavailable => 3
  | .MissingGrantStatus => 4
  | .MissingPrincipalEvidence => 5
  | .MissingPrincipalStatus => 6
  | .ObservationActionFactUnavailable => 7
  | .ObservationMissing => 8
  | .StaleStatus => 9
  | .UnsupportedAssuranceClaim => 10
  | .UnsupportedBudgetAlgebra => 11
  | .UnsupportedCriticalExtension => 12
  | .UnsupportedEvidenceType => 13
  | .UnsupportedPrincipalMethod => 14
  | .UnsupportedProfile => 15
  | .UnsupportedProfilePolicy => 16
  | .UnsupportedProtocol => 17
  | .UnsupportedResourceMatcher => 18
  | .UnsupportedSignatureSuite => 19
  | .UnsupportedStatusMethod => 20

def requirementCode : auths_composition.auths_model.Requirement → List Nat
  | .ApprovalUnavailable => [97, 112, 112, 114, 111, 118, 97, 108, 45, 117, 110, 97, 118, 97, 105, 108, 97, 98, 108, 101]
  | .AssuranceRequirementNotMet => [97, 115, 115, 117, 114, 97, 110, 99, 101, 45, 114, 101, 113, 117, 105, 114, 101, 109, 101, 110, 116, 45, 110, 111, 116, 45, 109, 101, 116]
  | .ExternalFactUnavailable => [101, 120, 116, 101, 114, 110, 97, 108, 45, 102, 97, 99, 116, 45, 117, 110, 97, 118, 97, 105, 108, 97, 98, 108, 101]
  | .HistoricalStateUnavailable => [104, 105, 115, 116, 111, 114, 105, 99, 97, 108, 45, 115, 116, 97, 116, 101, 45, 117, 110, 97, 118, 97, 105, 108, 97, 98, 108, 101]
  | .MissingGrantStatus => [109, 105, 115, 115, 105, 110, 103, 45, 103, 114, 97, 110, 116, 45, 115, 116, 97, 116, 117, 115]
  | .MissingPrincipalEvidence => [109, 105, 115, 115, 105, 110, 103, 45, 112, 114, 105, 110, 99, 105, 112, 97, 108, 45, 101, 118, 105, 100, 101, 110, 99, 101]
  | .MissingPrincipalStatus => [109, 105, 115, 115, 105, 110, 103, 45, 112, 114, 105, 110, 99, 105, 112, 97, 108, 45, 115, 116, 97, 116, 117, 115]
  | .ObservationActionFactUnavailable => [111, 98, 115, 101, 114, 118, 97, 116, 105, 111, 110, 45, 97, 99, 116, 105, 111, 110, 45, 102, 97, 99, 116, 45, 117, 110, 97, 118, 97, 105, 108, 97, 98, 108, 101]
  | .ObservationMissing => [111, 98, 115, 101, 114, 118, 97, 116, 105, 111, 110, 45, 109, 105, 115, 115, 105, 110, 103]
  | .StaleStatus => [115, 116, 97, 108, 101, 45, 115, 116, 97, 116, 117, 115]
  | .UnsupportedAssuranceClaim => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 97, 115, 115, 117, 114, 97, 110, 99, 101, 45, 99, 108, 97, 105, 109]
  | .UnsupportedBudgetAlgebra => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 98, 117, 100, 103, 101, 116, 45, 97, 108, 103, 101, 98, 114, 97]
  | .UnsupportedCriticalExtension => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 99, 114, 105, 116, 105, 99, 97, 108, 45, 101, 120, 116, 101, 110, 115, 105, 111, 110]
  | .UnsupportedEvidenceType => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 101, 118, 105, 100, 101, 110, 99, 101, 45, 116, 121, 112, 101]
  | .UnsupportedPrincipalMethod => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 112, 114, 105, 110, 99, 105, 112, 97, 108, 45, 109, 101, 116, 104, 111, 100]
  | .UnsupportedProfile => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 112, 114, 111, 102, 105, 108, 101]
  | .UnsupportedProfilePolicy => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 112, 114, 111, 102, 105, 108, 101, 45, 112, 111, 108, 105, 99, 121]
  | .UnsupportedProtocol => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 112, 114, 111, 116, 111, 99, 111, 108]
  | .UnsupportedResourceMatcher => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 114, 101, 115, 111, 117, 114, 99, 101, 45, 109, 97, 116, 99, 104, 101, 114]
  | .UnsupportedSignatureSuite => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 45, 115, 117, 105, 116, 101]
  | .UnsupportedStatusMethod => [117, 110, 115, 117, 112, 112, 111, 114, 116, 101, 100, 45, 115, 116, 97, 116, 117, 115, 45, 109, 101, 116, 104, 111, 100]

theorem denial_rank_lexical (left right : auths_composition.auths_model.DenialReason) :
    denialRank left < denialRank right ↔ List.Lex (· < ·) (denialCode left) (denialCode right) := by
  cases hl : left <;> cases hr : right <;> decide

theorem requirement_rank_lexical (left right : auths_composition.auths_model.Requirement) :
    requirementRank left < requirementRank right ↔
      List.Lex (· < ·) (requirementCode left) (requirementCode right) := by
  cases hl : left <;> cases hr : right <;> decide


end Auths.Composition.Model
