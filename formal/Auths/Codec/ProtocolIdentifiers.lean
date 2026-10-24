import Auths.Codec.ProtocolPrincipalScheme
import Auths.Codec.ProtocolValidity
import Auths.Codec.Constructors
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.Codec.ProtocolIdentifiers
set_option maxHeartbeats 2000000
set_option maxRecDepth 4096
open Auths.Refinement.Identifier

/-- The two extraction contexts expose the same transparent byte classifier.
    This is a definitional bridge, not an assumed parser contract. -/
private theorem classifier_same (input : Slice Std.U8) (position : Std.Usize) :
    AuthsProtocolCodec.auths_model.identifier.forbidden_identifier_at input position =
      auths_model.identifier.forbidden_identifier_at input position := by
  unfold AuthsProtocolCodec.auths_model.identifier.forbidden_identifier_at
    auths_model.identifier.forbidden_identifier_at
    AuthsProtocolCodec.auths_model.identifier.forbidden_three_byte_prefix
    auths_model.identifier.forbidden_three_byte_prefix
  rfl

private theorem scan_suffix (remaining : List Std.U8) (input : Slice Std.U8) (position : Std.Usize)
    (suffix : input.val.drop position.val = remaining) :
    AuthsProtocolCodec.auths_model.identifier.contains_forbidden_identifier_loop input position ⦃ actual =>
      actual = containsExcluded remaining ⦄ := by
  induction remaining generalizing position with
  | nil =>
    have finished : ¬ position < input.len := by
      have size := congrArg List.length suffix
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    rw [AuthsProtocolCodec.auths_model.identifier.contains_forbidden_identifier_loop.eq_def]
    simp [finished, containsExcluded]
  | cons head rest ih =>
    obtain ⟨guard, _⟩ := Auths.StatusSelection.indexed_head input position head rest suffix
    obtain ⟨next, addition, nextValue, nextSuffix⟩ := Auths.StatusSelection.indexed_next input position head rest suffix
    obtain ⟨excluded, checks, meaning⟩ := spec_imp_exists (forbidden_at_exact input position)
    rw [AuthsProtocolCodec.auths_model.identifier.contains_forbidden_identifier_loop.eq_def]
    simp only [guard, ↓reduceIte, classifier_same, checks, bind_tc_ok]
    have exactPrefix : excluded = excludedPrefix (head :: rest) := by simpa only [suffix] using meaning
    cases found : excluded
    · simp only [Bool.false_eq_true, ↓reduceIte, addition, bind_tc_ok]
      simpa only [containsExcluded, ← exactPrefix, found, Bool.false_or] using ih next nextSuffix
    · simp [containsExcluded, ← exactPrefix, found]

/-- Complete result of the actual shared identifier scanner in the principal
    extraction context, including empty, oversized and forbidden-byte cases. -/
theorem bounded_identifier_exact (value : Str) (maximum : Std.Usize) :
    AuthsProtocolCodec.auths_model.identifier.bounded_identifier_valid value maximum ⦃ actual =>
      actual = (!value.val.isEmpty && decide (value.val.length ≤ maximum.val) &&
        !containsExcluded value.val) ⦄ := by
  unfold AuthsProtocolCodec.auths_model.identifier.bounded_identifier_valid
  simp only [AuthsProtocolCodec.core.str.Str.is_empty, AuthsProtocolCodec.core.str.Str.len,
    AuthsProtocolCodec.core.str.Str.as_bytes, _root_.core.str.Str.is_empty,
    _root_.core.str.Str.len, _root_.core.str.Str.as_bytes, bind_tc_ok]
  by_cases empty : value.val.isEmpty = true
  all_goals simp only [empty, Bool.false_eq_true, ↓reduceIte]
  · simp
  · by_cases fits : value.len ≤ maximum
    all_goals simp only [fits, ↓reduceIte]
    · unfold AuthsProtocolCodec.auths_model.identifier.contains_forbidden_identifier
      apply spec_bind (scan_suffix value.val value 0#usize (by simp))
      intro result meaning
      simp [meaning, show value.val.length ≤ maximum.val by scalar_tac]
    · simp [show ¬value.val.length ≤ maximum.val by scalar_tac]

/-- The readable constructor policy combines UTF-8 length/scalar restrictions
    with the independent principal-scheme grammar. -/
def valid (value : String) : Bool :=
  Auths.Codec.Constructors.identifierDecision value 512 &&
    Auths.PrincipalScheme.Model.evaluate (value.toByteArray.toList.map UInt8.toNat)

private theorem identifier_string (value : String) (maximum : Std.Usize)
    (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.identifier.bounded_identifier_valid (toStr value bounded) maximum =
      ok (Auths.Codec.Constructors.identifierDecision value maximum.val) := by
  obtain ⟨result, evaluates, meaning⟩ := spec_imp_exists (bounded_identifier_exact (toStr value bounded) maximum)
  have root := Auths.Refinement.Identifier.identifier_exact (toStr value bounded) maximum
  have copied : auths_model.identifier.bounded_identifier_valid (toStr value bounded) maximum =
      ok (Auths.Codec.Constructors.identifierDecision value maximum.val) :=
    Auths.Codec.Constructors.identifier_exact value maximum bounded
  rw [copied, spec_ok] at root
  rw [meaning, ← root] at evaluates
  exact evaluates

/-- Full accepted value and exact typed refusal for the shipping principal
    constructor on every actual Rust string carrier. No success premise. -/
theorem parse_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.PrincipalId.parse (toStr value bounded) =
      ok (if valid value then .Ok value else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidPrincipal) := by
  unfold AuthsProtocolCodec.auths_model.PrincipalId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  obtain ⟨scheme, schemeEvaluates, schemeMeaning⟩ := spec_imp_exists
    (Auths.Codec.ProtocolPrincipalScheme.scheme_refines (toStr value bounded))
  have representation : (toStr value bounded).val.map (·.val) =
      value.toByteArray.toList.map UInt8.toNat := by
    unfold toStr
    simp only [List.map_map]
    rfl
  rw [representation] at schemeMeaning
  rw [schemeMeaning] at schemeEvaluates
  split <;> simp_all [valid, bind_tc_ok,
    Auths.Codec.StringRefinement.string_copy_exact]
  all_goals split <;> rfl



/-- Source acceptance earns the independent principal grammar and bounded
Unicode policy. Cryptographic principal/key binding is not a parsing premise. -/
theorem principal_parse_valid (value output : String)
    (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.PrincipalId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Principal output := by
  rw [parse_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    have components : Constructors.identifierDecision value 512 = true ∧
        Auths.PrincipalScheme.Model.evaluate (ProtocolValidity.textBytes value) = true := by
      simpa only [valid, Bool.and_eq_true, ProtocolValidity.textBytes] using condition
    exact ⟨(Constructors.identifier_decision_valid value 512).mp components.1,
      (Auths.PrincipalScheme.Model.evaluate_iff_grammar _).mp components.2⟩
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem VerificationMethod_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.VerificationMethod.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 512 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidVerificationMethod) := by
  unfold AuthsProtocolCodec.auths_model.VerificationMethod.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem VerificationMethod_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.VerificationMethod.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 512 := by
  rw [VerificationMethod_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 512).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem ProfileId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.ProfileId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidProfile) := by
  unfold AuthsProtocolCodec.auths_model.ProfileId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem ProfileId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.ProfileId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [ProfileId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem CapabilityId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.CapabilityId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidCapability) := by
  unfold AuthsProtocolCodec.auths_model.CapabilityId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem CapabilityId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.CapabilityId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [CapabilityId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem ResourceId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.ResourceId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 1024 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidResource) := by
  unfold AuthsProtocolCodec.auths_model.ResourceId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem ResourceId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.ResourceId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 1024 := by
  rw [ResourceId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 1024).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem Audience_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.Audience.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 512 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidAudience) := by
  unfold AuthsProtocolCodec.auths_model.Audience.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem Audience_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.Audience.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 512 := by
  rw [Audience_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 512).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem MediaType_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.MediaType.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidMediaType) := by
  unfold AuthsProtocolCodec.auths_model.MediaType.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem MediaType_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.MediaType.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [MediaType_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem PrincipalMethodId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.PrincipalMethodId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.PrincipalMethodId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem PrincipalMethodId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.PrincipalMethodId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [PrincipalMethodId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem SignatureSuiteId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.SignatureSuiteId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.SignatureSuiteId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem SignatureSuiteId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.SignatureSuiteId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [SignatureSuiteId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem EvidenceTypeId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.EvidenceTypeId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.EvidenceTypeId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem EvidenceTypeId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.EvidenceTypeId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [EvidenceTypeId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem StatusMethodId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.StatusMethodId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.StatusMethodId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem StatusMethodId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.StatusMethodId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [StatusMethodId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem AssuranceClaimId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.AssuranceClaimId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.AssuranceClaimId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem AssuranceClaimId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.AssuranceClaimId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [AssuranceClaimId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem AssurancePolicyId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.AssurancePolicyId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.AssurancePolicyId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem AssurancePolicyId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.AssurancePolicyId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [AssurancePolicyId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem BudgetAlgebraId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.BudgetAlgebraId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.BudgetAlgebraId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem BudgetAlgebraId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.BudgetAlgebraId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [BudgetAlgebraId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem ResourceMatcherId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.ResourceMatcherId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.ResourceMatcherId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem ResourceMatcherId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.ResourceMatcherId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [ResourceMatcherId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem ChannelBindingId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.ChannelBindingId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.ChannelBindingId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem ChannelBindingId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.ChannelBindingId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [ChannelBindingId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem ProfilePolicyId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.ProfilePolicyId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.ProfilePolicyId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem ProfilePolicyId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.ProfilePolicyId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [ProfilePolicyId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem AssuranceImplicationId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.AssuranceImplicationId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.AssuranceImplicationId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem AssuranceImplicationId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.AssuranceImplicationId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [AssuranceImplicationId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem AdapterId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.AdapterId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.AdapterId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem AdapterId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.AdapterId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [AdapterId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem EvidenceSourceId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.EvidenceSourceId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.EvidenceSourceId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem EvidenceSourceId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.EvidenceSourceId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [EvidenceSourceId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem ClaimParameterId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.ClaimParameterId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.ClaimParameterId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem ClaimParameterId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.ClaimParameterId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [ClaimParameterId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem DispositionId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.DispositionId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.DispositionId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem DispositionId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.DispositionId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [DispositionId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem TrustAnchorId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.TrustAnchorId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidRegistryId) := by
  unfold AuthsProtocolCodec.auths_model.TrustAnchorId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem TrustAnchorId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.TrustAnchorId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [TrustAnchorId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem ExtensionId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.ExtensionId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidExtensionId) := by
  unfold AuthsProtocolCodec.auths_model.ExtensionId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem ExtensionId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.ExtensionId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [ExtensionId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem observation_ObservationSchemaId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.observation.ObservationSchemaId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidObservation) := by
  unfold AuthsProtocolCodec.auths_model.observation.ObservationSchemaId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem observation_ObservationSchemaId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.observation.ObservationSchemaId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [observation_ObservationSchemaId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem observation_ObserverAnchorId_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.observation.ObserverAnchorId.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidObserverAnchor) := by
  unfold AuthsProtocolCodec.auths_model.observation.ObserverAnchorId.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem observation_ObserverAnchorId_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.observation.ObserverAnchorId.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [observation_ObserverAnchorId_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Exact source constructor result; the bound counts UTF-8 bytes. -/
theorem observation_FactName_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.observation.FactName.parse (toStr value bounded) =
      ok (if Constructors.identifierDecision value 128 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidObservation) := by
  unfold AuthsProtocolCodec.auths_model.observation.FactName.parse
  rw [identifier_string]
  simp only [bind_tc_ok, UScalar.ofNatCore_val_eq]
  split <;> simp_all [Auths.Codec.StringRefinement.string_copy_exact]

theorem observation_FactName_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.observation.FactName.parse (toStr value bounded) = ok (.Ok output)) :
    ProtocolValidity.Identifier output 128 := by
  rw [observation_FactName_exact] at accepted
  split at accepted
  · rename_i condition
    have same : value = output := by simpa using accepted
    subst output
    exact (Constructors.identifier_decision_valid value 128).mp condition
  · simp at accepted

/-- Fact text is UTF-8 data, with a byte bound only: empty text and whitespace
are permitted. Reusing the identifier policy here would narrow the protocol. -/
theorem fact_text_exact (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    AuthsProtocolCodec.auths_model.observation.FactText.new (toStr value bounded) =
      ok (if value.toByteArray.size ≤ 256 then .Ok value
        else .Err AuthsProtocolCodec.auths_model.ModelError.InvalidObservation) := by
  unfold AuthsProtocolCodec.auths_model.observation.FactText.new
  simp only [AuthsProtocolCodec.core.str.Str.len, _root_.core.str.Str.len, bind_tc_ok,
    UScalar.lt_equiv]
  by_cases fits : value.toByteArray.size ≤ 256 <;>
    simp [AuthsProtocolCodec.auths_model.observation.MAX_FACT_VALUE_TEXT_BYTES,
      fits, toStr, Auths.Codec.StringRefinement.string_copy_exact]

theorem fact_text_output_valid (value output : String) (bounded : value.toByteArray.size ≤ U32.max)
    (accepted : AuthsProtocolCodec.auths_model.observation.FactText.new (toStr value bounded) = ok (.Ok output)) :
    output.toByteArray.size ≤ 256 := by
  rw [fact_text_exact] at accepted
  split at accepted
  · rename_i fits
    have same : value = output := by simpa using accepted
    subst output
    exact fits
  · simp at accepted

end Auths.Codec.ProtocolIdentifiers
