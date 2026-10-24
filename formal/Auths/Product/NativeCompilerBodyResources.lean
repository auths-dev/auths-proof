import Auths.Product.NativeCompilerBodyViews

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open BodyCompiler
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_resource_add_exact (current : NativeUsage) (literal dynamic : Std.Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.add_resources current literal dynamic ⦃ actual =>
      actual.map nativeUsage = Resources.add (nativeUsage current) ⟨literal.val, dynamic.val⟩ ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.add_resources
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_LITERAL_BYTES
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases oldLiteral : 524288 < current.literal_bytes.val
  · have nativeOld : current.literal_bytes > 524288#usize := by scalar_tac
    simp [nativeOld, Resources.add, Resources.Bounded, nativeUsage, Nat.not_le.mpr oldLiteral]
  · have literalBound : current.literal_bytes.val ≤ 524288 := by omega
    have nativeLiteral : ¬current.literal_bytes > 524288#usize := by scalar_tac
    by_cases oldDynamic : 256 < current.dynamic_pieces.val
    · have nativeOld : current.dynamic_pieces > 256#usize := by scalar_tac
      simp [nativeLiteral, nativeOld, Resources.add, Resources.Bounded, nativeUsage,
        Nat.not_le.mpr oldDynamic]
    · have dynamicBound : current.dynamic_pieces.val ≤ 256 := by omega
      have nativeDynamic : ¬current.dynamic_pieces > 256#usize := by scalar_tac
      simp only [nativeLiteral, nativeDynamic, ↓reduceIte]
      step as ⟨literalRoom, literalRoomMeaning⟩
      by_cases excessLiteral : 524288 - current.literal_bytes.val < literal.val
      · have nativeExcess : literal > literalRoom := by scalar_tac
        have invalid : ¬Resources.Bounded (Resources.plus (nativeUsage current) ⟨literal.val, dynamic.val⟩) := by
          unfold Resources.Bounded Resources.plus nativeUsage
          omega
        simp [nativeExcess, Resources.add, invalid]
      · have totalLiteral : current.literal_bytes.val + literal.val ≤ 524288 := by omega
        have nativeFits : ¬literal > literalRoom := by scalar_tac
        simp only [nativeFits, ↓reduceIte]
        step as ⟨dynamicRoom, dynamicRoomMeaning⟩
        by_cases excessDynamic : 256 - current.dynamic_pieces.val < dynamic.val
        · have nativeExcess : dynamic > dynamicRoom := by scalar_tac
          have invalid : ¬Resources.Bounded (Resources.plus (nativeUsage current) ⟨literal.val, dynamic.val⟩) := by
            unfold Resources.Bounded Resources.plus nativeUsage
            omega
          simp [nativeExcess, Resources.add, invalid]
        · have totalDynamic : current.dynamic_pieces.val + dynamic.val ≤ 256 := by omega
          have nativeFits : ¬dynamic > dynamicRoom := by scalar_tac
          have currentBound : Resources.Bounded (nativeUsage current) := ⟨literalBound, dynamicBound⟩
          have totalBound : Resources.Bounded (Resources.plus (nativeUsage current) ⟨literal.val, dynamic.val⟩) :=
            ⟨totalLiteral, totalDynamic⟩
          simp only [nativeFits, ↓reduceIte]
          step as ⟨literalSum, literalSumMeaning⟩
          step as ⟨dynamicSum, dynamicSumMeaning⟩
          simp [Resources.add, Resources.plus, nativeUsage, currentBound, totalBound,
            literalSumMeaning, dynamicSumMeaning]

private theorem native_json_charge_exact (current : NativeUsage) (piece : NativeNamedJson) :
    (match piece with
      | .Raw value => AuthsNativeRecipe.auths_gateway_kernel.body_compiler.add_resources current
          (AuthsNativeRecipe.alloc.vec.Vec.len value) 0#usize
      | .Field _ | .Echo => AuthsNativeRecipe.auths_gateway_kernel.body_compiler.add_resources current 0#usize 1#usize)
      ⦃ actual => actual.map nativeUsage = Resources.jsonCharge (nativeUsage current) (nativeNamedJson piece) ⦄ := by
  cases piece <;>
    step with native_resource_add_exact as ⟨actual, exact⟩ <;>
    simpa [Resources.jsonCharge, Resources.jsonQuantity, nativeNamedJson, jsonLiteralSize,
      jsonDynamicSize, bytes] using exact

private theorem native_json_resources_suffix (source : Slice NativeNamedJson)
    (used : NativeUsage) (position : Std.Usize) (positionBound : position.val ≤ source.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.json_resources_loop source used position ⦃ actual =>
      actual.map nativeUsage = Resources.scan Resources.jsonCharge (nativeUsage used)
        ((nativeJsonSource source).drop position.val) ⦄ := by
  generalize remaining : source.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing used position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.json_resources_loop
      by_cases inside : position.val < source.val.length
      · have nativeInside : position < source.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec source position inside as ⟨piece, pieceAt⟩
        have suffix : (nativeJsonSource source).drop position.val = nativeNamedJson piece ::
            (nativeJsonSource source).drop (position.val + 1) := by
          simpa only [nativeJsonSource, List.drop_map, List.map_cons, pieceAt] using
            congrArg (List.map nativeNamedJson) (List.drop_eq_getElem_cons inside)
        step with native_json_charge_exact used piece as ⟨charged, chargeMeaning⟩
        cases charged with
        | none => simp [suffix, Resources.scan, ← chargeMeaning]
        | some next =>
            step as ⟨nextPosition, nextPositionMeaning⟩
            apply spec_mono (ih _ (by omega) next nextPosition (by omega) rfl)
            intro actual exact
            simpa [suffix, Resources.scan, ← chargeMeaning, nextPositionMeaning] using exact
      · have ended : source.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < source.len := by scalar_tac
        have modelEnded : (nativeJsonSource source).length ≤ position.val := by
          simpa only [nativeJsonSource, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, Resources.scan]

@[step] theorem native_json_resources_exact (source : Slice NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.json_resources source ⦃ actual =>
      actual.map nativeUsage = Resources.jsonResources (nativeJsonSource source) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.json_resources
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases large : 256 < source.val.length
  · have nativeLarge : source.len > 256#usize := by scalar_tac
    simp [nativeLarge, Resources.jsonResources, nativeJsonSource, Nat.not_le.mpr large]
  · have bounded : source.val.length ≤ 256 := by omega
    have nativeBound : ¬source.len > 256#usize := by scalar_tac
    simp only [nativeBound, ↓reduceIte]
    apply spec_mono (native_json_resources_suffix source ⟨0#usize, 0#usize⟩ 0#usize (by simp))
    intro actual exact
    simpa [Resources.jsonResources, nativeJsonSource, bounded, Resources.zero, nativeUsage] using exact

@[step] theorem native_form_piece_resources_exact (current : NativeUsage) (piece : NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_piece_resources current piece ⦃ actual =>
      actual.map nativeUsage = Resources.formCharge (nativeUsage current) (nativeNamedForm piece) ⦄ := by
  cases piece with
  | Raw value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_piece_resources
      step with native_resource_add_exact as ⟨actual, exact⟩
      simpa [Resources.formCharge, Resources.formQuantity, nativeNamedForm, NestedCount,
        formLiteralSize, formDynamicSize, bytes] using exact
  | Field name =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_piece_resources
      step with native_resource_add_exact as ⟨actual, exact⟩
      simpa [Resources.formCharge, Resources.formQuantity, nativeNamedForm, NestedCount,
        formLiteralSize, formDynamicSize] using exact
  | Echo =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_piece_resources
      step with native_resource_add_exact as ⟨actual, exact⟩
      simpa [Resources.formCharge, Resources.formQuantity, nativeNamedForm, NestedCount,
        formLiteralSize, formDynamicSize] using exact
  | Json pieces =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_piece_resources
      step with native_json_resources_exact (AuthsNativeRecipe.alloc.vec.Vec.deref pieces)
        as ⟨nested, nestedMeaning⟩
      have totals := Resources.json_resources_exact_totals (pieces.val.map nativeNamedJson)
      simp only [nativeJsonSource, native_deref_contents] at nestedMeaning
      rw [totals] at nestedMeaning
      cases nested with
      | none =>
          have invalid : ¬((pieces.val.map nativeNamedJson).length ≤ 256 ∧
              JsonResourceDomain (pieces.val.map nativeNamedJson)) := by
            intro admitted
            simp [admitted] at nestedMeaning
          by_cases count : (pieces.val.map nativeNamedJson).length ≤ 256
          · have badDomain : ¬JsonResourceDomain (pieces.val.map nativeNamedJson) := by tauto
            have badTotal : ¬Resources.Bounded (Resources.plus (nativeUsage current)
                ⟨jsonLiterals (pieces.val.map nativeNamedJson), jsonDynamics (pieces.val.map nativeNamedJson)⟩) := by
              intro bounded
              apply badDomain
              unfold JsonResourceDomain
              unfold Resources.Bounded Resources.plus at bounded
              constructor <;> omega
            simp [Resources.formCharge, Resources.formQuantity, nativeNamedForm, NestedCount,
              count, formLiteralSize, formDynamicSize, Resources.add, badTotal]
          · simp [Resources.formCharge, nativeNamedForm, NestedCount, count]
      | some nested =>
          have admitted : (pieces.val.map nativeNamedJson).length ≤ 256 ∧
              JsonResourceDomain (pieces.val.map nativeNamedJson) := by
            by_contra invalid
            simp [invalid] at nestedMeaning
          have exactTotals : nativeUsage nested =
              ⟨jsonLiterals (pieces.val.map nativeNamedJson), jsonDynamics (pieces.val.map nativeNamedJson)⟩ := by
            simpa [admitted] using nestedMeaning
          step with native_resource_add_exact current nested.literal_bytes nested.dynamic_pieces
            as ⟨actual, exact⟩
          simpa [Resources.formCharge, Resources.formQuantity, nativeNamedForm, NestedCount,
            admitted.1, formLiteralSize, formDynamicSize, ← exactTotals, nativeUsage] using exact

private theorem native_form_resources_suffix (source : Slice NativeNamedForm)
    (used : NativeUsage) (position : Std.Usize) (positionBound : position.val ≤ source.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_resources_loop source used position ⦃ actual =>
      actual.map nativeUsage = Resources.scan Resources.formCharge (nativeUsage used)
        ((nativeFormSource source).drop position.val) ⦄ := by
  generalize remaining : source.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing used position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_resources_loop
      by_cases inside : position.val < source.val.length
      · have nativeInside : position < source.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec source position inside as ⟨piece, pieceAt⟩
        have suffix : (nativeFormSource source).drop position.val = nativeNamedForm piece ::
            (nativeFormSource source).drop (position.val + 1) := by
          simpa only [nativeFormSource, List.drop_map, List.map_cons, pieceAt] using
            congrArg (List.map nativeNamedForm) (List.drop_eq_getElem_cons inside)
        step with native_form_piece_resources_exact used piece as ⟨charged, chargeMeaning⟩
        cases charged with
        | none => simp [suffix, Resources.scan, ← chargeMeaning]
        | some next =>
            step as ⟨nextPosition, nextPositionMeaning⟩
            apply spec_mono (ih _ (by omega) next nextPosition (by omega) rfl)
            intro actual exact
            simpa [suffix, Resources.scan, ← chargeMeaning, nextPositionMeaning] using exact
      · have ended : source.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < source.len := by scalar_tac
        have modelEnded : (nativeFormSource source).length ≤ position.val := by
          simpa only [nativeFormSource, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, Resources.scan]

@[step] theorem native_form_resources_exact (source : Slice NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_resources source ⦃ actual =>
      actual.map nativeUsage = Resources.formResources (nativeFormSource source) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_resources
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases large : 256 < source.val.length
  · have nativeLarge : source.len > 256#usize := by scalar_tac
    simp [nativeLarge, Resources.formResources, nativeFormSource, Nat.not_le.mpr large]
  · have bounded : source.val.length ≤ 256 := by omega
    have nativeBound : ¬source.len > 256#usize := by scalar_tac
    simp only [nativeBound, ↓reduceIte]
    apply spec_mono (native_form_resources_suffix source ⟨0#usize, 0#usize⟩ 0#usize (by simp))
    intro actual exact
    simpa [Resources.formResources, nativeFormSource, bounded, Resources.zero, nativeUsage] using exact

theorem native_json_resources_earns_original_totals (source : Slice NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.json_resources source ⦃ actual =>
      ∀ used, actual = some used →
        nativeUsage used = ⟨jsonLiterals (nativeJsonSource source), jsonDynamics (nativeJsonSource source)⟩ ∧
        (nativeJsonSource source).length ≤ 256 ∧ JsonResourceDomain (nativeJsonSource source) ⦄ := by
  apply spec_mono (native_json_resources_exact source)
  intro actual exact used accepted
  rw [accepted] at exact
  exact Resources.json_resources_success_earns_totals _ _ exact.symm

theorem native_form_resources_earns_original_totals (source : Slice NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.form_resources source ⦃ actual =>
      ∀ used, actual = some used →
        nativeUsage used = ⟨formLiterals (nativeFormSource source), formDynamics (nativeFormSource source)⟩ ∧
        (nativeFormSource source).length ≤ 256 ∧ FormResourceDomain (nativeFormSource source) ⦄ := by
  apply spec_mono (native_form_resources_exact source)
  intro actual exact used accepted
  rw [accepted] at exact
  exact Resources.form_resources_success_earns_totals _ _ exact.symm

end Auths.Product.NativeCompiler.Refinement
