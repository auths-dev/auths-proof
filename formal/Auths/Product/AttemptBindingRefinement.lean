import Auths.Product.AttemptBinding
import Auths.Product.RecipeBindingRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity

namespace Auths.Product.AttemptBinding.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-! Authored bodies require actual generation, interface inspection and
elaboration/repairs. No native backend, Arc, closed-request constructor or
whole-driver theorem is asserted by these kernel byte comparisons. -/

def storedOf (stored : attempt_binding.StoredClaim) : Stored :=
  ⟨sliceBytes stored.namespace, sliceBytes stored.operation, sliceBytes stored.recipe_hex,
    sliceBytes stored.action_hex, stored.evaluated_at.val⟩

def requestOf (request : attempt_binding.RequestClaim) : Request :=
  ⟨sliceBytes request.namespace, sliceBytes request.operation,
    DerivedTokens.Refinement.digestBytes request.recipe_digest,
    DerivedTokens.Refinement.digestBytes request.action_commitment, request.evaluated_at.val⟩

private theorem bytes_exact (left right : Slice Std.U8) :
    construct.field_name_equal left right ⦃ actual => actual = decide (sliceBytes left = sliceBytes right) ⦄ := by
  simpa only [sliceBytes, byteList_inj] using field_name_equal_exact left right

theorem request_digest_bytes_valid (request : attempt_binding.RequestClaim) : DigestBytesValid (requestOf request) := by
  exact ⟨DerivedTokens.Refinement.digest_byte_bounds request.recipe_digest,
    DerivedTokens.Refinement.digest_byte_bounds request.action_commitment⟩

@[step] theorem installation_matches_exact (namespaceBytes : Slice Std.U8) (digest : Array Std.U8 32#usize)
    (installedNamespace : Slice Std.U8) (installedDigest : Array Std.U8 32#usize) :
    attempt_binding.installation_matches namespaceBytes digest installedNamespace installedDigest ⦃ actual =>
      actual = decide (InstallationMatches (sliceBytes namespaceBytes) (DerivedTokens.Refinement.digestBytes digest)
        (sliceBytes installedNamespace) (DerivedTokens.Refinement.digestBytes installedDigest)) ⦄ := by
  unfold attempt_binding.installation_matches
  step with bytes_exact as ⟨sameNamespace, namespaceMeaning⟩
  cases sameNamespace
  · simp_all [InstallationMatches]
  · step with bytes_exact as ⟨actual, digestMeaning⟩
    simp_all [InstallationMatches, DerivedTokens.Refinement.digestBytes, sliceBytes, byteList]

@[step] theorem claim_matches_exact (stage : transition.Stage) (stored : attempt_binding.StoredClaim)
    (request : attempt_binding.RequestClaim) :
    attempt_binding.claim_matches stage stored request ⦃ actual =>
      actual = decide (ClaimMatches (stageOf stage) (storedOf stored) (requestOf request)) ⦄ := by
  unfold attempt_binding.claim_matches
  cases stage with
  | Attempting =>
    by_cases time : stored.evaluated_at = request.evaluated_at
    · simp only [time, beq_self_eq_true, Bool.true_and]
      step with bytes_exact as ⟨sameNamespace, namespaceMeaning⟩
      cases sameNamespace
      · simp_all [ClaimMatches, stageOf, storedOf, requestOf, UScalar.eq_equiv]
      · step with bytes_exact as ⟨sameOperation, operationMeaning⟩
        cases sameOperation
        · simp_all [ClaimMatches, stageOf, storedOf, requestOf, UScalar.eq_equiv]
        · step with RecipeBinding.Refinement.schema_digest_matches_exact as ⟨sameRecipe, recipeMeaning⟩
          cases sameRecipe
          · simp_all [ClaimMatches, stageOf, storedOf, requestOf, RecipeBinding.SchemaDigestMatches, UScalar.eq_equiv]
          · step with RecipeBinding.Refinement.schema_digest_matches_exact as ⟨actual, actionMeaning⟩
            simp_all [ClaimMatches, stageOf, storedOf, requestOf, RecipeBinding.SchemaDigestMatches, UScalar.eq_equiv]
    · have differentTime : stored.evaluated_at.val ≠ request.evaluated_at.val := by
        intro equal
        exact time (UScalar.eq_of_val_eq equal)
      simp [time, differentTime, ClaimMatches, stageOf, storedOf, requestOf]
  | _ => simp [ClaimMatches, stageOf]

theorem source_claim_matching_retains_every_column (stage : transition.Stage) (stored : attempt_binding.StoredClaim)
    (request : attempt_binding.RequestClaim) : attempt_binding.claim_matches stage stored request ⦃ actual =>
      actual = true ↔ ClaimMatches (stageOf stage) (storedOf stored) (requestOf request) ⦄ := by
  apply spec_mono (claim_matches_exact stage stored request)
  intro actual exact
  simp [exact]

theorem source_shared_record_cannot_license_distinct_request_identities (stage : transition.Stage)
    (stored : attempt_binding.StoredClaim) (first second : attempt_binding.RequestClaim) :
    (do
      let left ← attempt_binding.claim_matches stage stored first
      let right ← attempt_binding.claim_matches stage stored second
      ok (left && right)) ⦃ actual => actual = true → requestOf first = requestOf second ⦄ := by
  step with claim_matches_exact as ⟨left, leftMeaning⟩
  step with claim_matches_exact as ⟨right, rightMeaning⟩
  simp only [spec_ok]
  intro both
  have leftTrue : left = true := (Bool.and_eq_true.mp both).1
  have rightTrue : right = true := (Bool.and_eq_true.mp both).2
  have leftMatch : ClaimMatches (stageOf stage) (storedOf stored) (requestOf first) := by simpa [leftTrue] using leftMeaning.symm
  have rightMatch : ClaimMatches (stageOf stage) (storedOf stored) (requestOf second) := by simpa [rightTrue] using rightMeaning.symm
  exact one_record_has_one_request_identity _ _ _ _ (request_digest_bytes_valid first)
    (request_digest_bytes_valid second) leftMatch rightMatch

theorem source_original_identity_has_useful_match (stored : attempt_binding.StoredClaim) (request : attempt_binding.RequestClaim)
    (original : storedOf stored = storedFor (requestOf request)) :
    attempt_binding.claim_matches .Attempting stored request ⦃ actual => actual = true ⦄ := by
  apply spec_mono (claim_matches_exact .Attempting stored request)
  intro actual exact
  simpa [original_identity_has_useful_match, original, stageOf] using exact

end Auths.Product.AttemptBinding.Refinement
