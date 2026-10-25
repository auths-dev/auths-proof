import Auths.Product.NativeCompilerVerifiedClaims
import Auths.Product.NativeCompilerRuleSource

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

theorem rule_segment_response_choice (segment : NativePathSource) :
    RecipeRuleAdmission.isResponseField (ruleSegment segment) = originalResponseField segment := by
  cases segment <;> rfl

/-- The complete actual precondition caller earns its fact decisions from the
same original field map, checks the read-back observation before claiming its
subject, and preserves every prior claim on later list refusal. Its room domain
covers the optional subject plus all original verified names. Observation
pointer/path payloads are not assumed admitted by this tag-only check. -/
@[step] theorem native_preconditions_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (source : AuthsNativeRecipe.recipe.source.PreconditionSource)
    (observation : Option AuthsNativeRecipe.recipe.source.ObservationSource)
    (subjectFits : ∀ subject, source.read_back_subject = some subject → TextFits subject)
    (nameFits : ∀ name ∈ source.verified.val, TextFits name)
    (fieldFits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1)
    (ordered : ConsumptionOrdered input.consumed)
    (room : input.consumed.all.elements.val.length + source.verified.val.length + 1 ≤ Usize.max) :
    AuthsNativeRecipe.recipe.validate.Rules.preconditions input source observation ⦃ actual =>
      ClaimMeaning input (RecipeRuleAdmission.preconditions (nativeRuleMapMeaning input.fields)
        (rulePreconditions source) (observation.map ruleObservation) (consumptionState input.consumed)) actual ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.preconditions
  cases subjectAt : source.read_back_subject with
  | none =>
      simp only [subjectAt, core.option.Option.is_none, Bool.true_eq_true, ↓reduceIte,
        AuthsNativeRecipe.alloc.vec.Vec.is_empty, bind_tc_ok]
      by_cases empty : source.verified.val = []
      · simp [empty, ClaimMeaning, RecipeRuleAdmission.preconditions, rulePreconditions,
          subjectAt, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
      · have notEmpty : source.verified.val.isEmpty = false := List.isEmpty_eq_false.mpr empty
        simp only [notEmpty, Bool.false_eq_true, ↓reduceIte]
        by_cases oversized : 8 < source.verified.val.length
        · have nativeOversized : AuthsNativeRecipe.alloc.vec.Vec.len source.verified >
              AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS := by
            simp only [AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS]
            scalar_tac
          simp [nativeOversized, ClaimMeaning, RecipeRuleAdmission.preconditions, rulePreconditions,
            subjectAt, empty, oversized, RecipeRuleAdmission.refused,
            consumptionVerdict, consumptionError, ordered]
        · have nativeBounded : ¬AuthsNativeRecipe.alloc.vec.Vec.len source.verified >
              AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS := by
            simp only [AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS]
            scalar_tac
          simp only [nativeBounded, ↓reduceIte, subjectAt]
          apply spec_mono (native_claim_verified_exact input
            (AuthsNativeRecipe.alloc.vec.Vec.deref source.verified) nameFits fieldFits ordered (by omega))
          intro actual meaning
          simpa [RecipeRuleAdmission.preconditions, rulePreconditions, subjectAt, notEmpty, oversized] using meaning
  | some subject =>
      simp only [subjectAt, core.option.Option.is_none, Bool.false_eq_true, ↓reduceIte]
      by_cases oversized : 8 < source.verified.val.length
      · have nativeOversized : AuthsNativeRecipe.alloc.vec.Vec.len source.verified >
            AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS := by
          simp only [AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS]
          scalar_tac
        simp [nativeOversized, ClaimMeaning, RecipeRuleAdmission.preconditions, rulePreconditions,
          subjectAt, oversized, RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
      · have nativeBounded : ¬AuthsNativeRecipe.alloc.vec.Vec.len source.verified >
            AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS := by
          simp only [AuthsNativeRecipe.recipe.MAX_VERIFIED_FIELDS]
          scalar_tac
        simp only [nativeBounded, ↓reduceIte, subjectAt]
        cases observationAt : observation with
        | none =>
            simp [observationAt, core.option.Option.ok_or,
              core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
              core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
              RecipeRuleAdmission.preconditions, rulePreconditions, subjectAt, oversized,
              RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
        | some read =>
            simp only [observationAt, core.option.Option.ok_or,
              core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            step with native_response_field_choice_exact (AuthsNativeRecipe.alloc.vec.Vec.deref read.path)
              as ⟨responseLocated, responseMeaning⟩
            have originalChoice : (ruleObservation read).path.any RecipeRuleAdmission.isResponseField =
                read.path.val.any originalResponseField := by
              simp [ruleObservation, List.any_map, Function.comp_def, rule_segment_response_choice]
            cases responseLocated with
            | true =>
                simp [ClaimMeaning, RecipeRuleAdmission.preconditions, rulePreconditions,
                  subjectAt, observationAt, oversized, originalChoice, ← responseMeaning,
                  RecipeRuleAdmission.refused, consumptionVerdict, consumptionError, ordered]
            | false =>
                simp only [Bool.false_eq_true, ↓reduceIte]
                have fits := subjectFits subject subjectAt
                step with native_deref_view_exact subject fits as ⟨subjectView, subjectViewMeaning⟩
                subst subjectView
                step with native_text_fact_field_exact input subject fits fieldFits as ⟨admissible, admissibleMeaning⟩
                step with native_claim_unused_exact input subject fits admissible ordered (by omega)
                  as ⟨claimed, claimMeaning, growth⟩
                let subjectModel := RecipeConsumption.claimUnused (consumptionState input.consumed) subject
                  (RecipeConsumption.fieldTest RecipeConsumption.textFactSchema (nativeRuleMapMeaning input.fields) subject)
                have subjectMeaning : ClaimMeaning input subjectModel claimed := by
                  simpa [subjectModel, admissibleMeaning] using claimMeaning
                have sameFields : claimed.2.fields = input.fields := subjectMeaning.2.2.1
                have sameState : consumptionState claimed.2.consumed = subjectModel.2 := subjectMeaning.2.1
                have nextOrdered := subjectMeaning.2.2.2
                cases verdict : subjectModel.1 with
                | error error =>
                    have refused : claimed.1 = .Err (consumptionError error) := by
                      simpa only [verdict, consumptionVerdict] using subjectMeaning.1
                    simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                      core.convert.FromSame, core.convert.FromSame.from, ClaimMeaning,
                      RecipeRuleAdmission.preconditions, rulePreconditions, subjectAt, observationAt,
                      oversized, originalChoice, ← responseMeaning, RecipeRuleAdmission.andThen,
                      ← subjectModel, verdict, sameState, sameFields, nextOrdered, consumptionVerdict]
                | ok unit =>
                    cases unit
                    have accepted : claimed.1 = .Ok () := by
                      simpa only [verdict, consumptionVerdict] using subjectMeaning.1
                    simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                    have nextFits : ∀ entry ∈ claimed.2.fields.entries.val, TextFits entry.1 := by
                      simpa only [sameFields] using fieldFits
                    apply spec_mono (native_claim_verified_exact claimed.2
                      (AuthsNativeRecipe.alloc.vec.Vec.deref source.verified) nameFits nextFits nextOrdered (by omega))
                    intro actual meaning
                    simpa [ClaimMeaning, RecipeRuleAdmission.preconditions, rulePreconditions,
                      subjectAt, observationAt, oversized, originalChoice, ← responseMeaning,
                      RecipeRuleAdmission.andThen, ← subjectModel, verdict, ← sameState,
                      sameFields] using meaning

end Auths.Product.NativeCompiler.Refinement
