import Auths.Product.NativeCompilerBodyResources
import Auths.Product.NativeCompilerBodyClones
import Auths.Product.NativeCompilerPaths

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open BodyCompiler
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_lower_json_piece_exact (names : Slice (NativeVec Std.U8)) (source : NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json_piece names source ⦃ actual =>
      nativeConstructResult nativeJsonPiece actual = lowerJsonPiece (nativeNameColumn names) (nativeNamedJson source) ⦄ := by
  cases source with
  | Raw value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json_piece
        AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_LITERAL_BYTES
      by_cases large : 524288 < value.val.length
      · have nativeLarge : AuthsNativeRecipe.alloc.vec.Vec.len value > 524288#usize := by scalar_tac
        simp [nativeLarge, lowerJsonPiece, nativeNamedJson, bytes, Nat.not_le.mpr large,
          nativeConstructResult, nativeConstructError]
      · have bounded : value.val.length ≤ 524288 := by omega
        have nativeBound : ¬AuthsNativeRecipe.alloc.vec.Vec.len value > 524288#usize := by scalar_tac
        simp only [nativeBound, ↓reduceIte]
        step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref value)
          as ⟨copied, copyMeaning⟩
        simp [lowerJsonPiece, nativeNamedJson, nativeJsonPiece, nativeConstructResult,
          bytes, bounded, copyMeaning, native_deref_contents]
  | Field name =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json_piece
      step with native_lower_field_exact names (AuthsNativeRecipe.alloc.vec.Vec.deref name)
        as ⟨index, meaning⟩
      cases index <;> simp [nativeNamedJson, lowerJsonPiece, ← meaning,
        nativeConstructResult, nativeJsonPiece, schemaSliceBytes, bytes, native_deref_contents]
  | Echo =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json_piece,
        nativeNamedJson, lowerJsonPiece, nativeConstructResult, nativeJsonPiece]

private theorem native_lower_json_suffix (names : Slice (NativeVec Std.U8))
    (source : Slice NativeNamedJson) (output : NativeVec NativeJsonPiece) (position : Std.Usize)
    (positionBound : position.val ≤ source.val.length)
    (room : output.val.length + (source.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json_loop names source output position
      ⦃ actual => nativeConstructResult (fun built => built.val.map nativeJsonPiece) actual =
        (lowerJsonList (nativeNameColumn names) ((nativeJsonSource source).drop position.val)).map
          (output.val.map nativeJsonPiece ++ ·) ⦄ := by
  generalize remaining : source.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json_loop
      by_cases inside : position.val < source.val.length
      · have nativeInside : position < source.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec source position inside as ⟨piece, pieceAt⟩
        have suffix : (nativeJsonSource source).drop position.val = nativeNamedJson piece ::
            (nativeJsonSource source).drop (position.val + 1) := by
          simpa only [nativeJsonSource, List.drop_map, List.map_cons, pieceAt] using
            congrArg (List.map nativeNamedJson) (List.drop_eq_getElem_cons inside)
        step with native_lower_json_piece_exact names piece as ⟨lowered, meaning⟩
        cases lowered with
        | Err error => simp [suffix, lowerJsonList, ← meaning, nativeConstructResult]
        | Ok compiled =>
            step with native_json_piece_clone_exact compiled as ⟨copied, copyMeaning⟩
            step with native_push_exact output copied (by omega) as ⟨updated, appended⟩
            have updatedLength : updated.val.length = output.val.length + 1 := by
              simp only [appended, List.length_append, List.length_singleton]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) updated next (by omega) (by omega) rfl)
            intro actual exact
            simpa [suffix, lowerJsonList, ← meaning, nativeConstructResult, appended,
              copyMeaning, nextValue, List.map_append, List.map_singleton,
              Except.map_map, Function.comp_def, List.append_assoc] using exact
      · have ended : source.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < source.len := by scalar_tac
        have modelEnded : (nativeJsonSource source).length ≤ position.val := by
          simpa only [nativeJsonSource, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, lowerJsonList, nativeConstructResult]

@[step] theorem native_lower_json_exact (names : Slice (NativeVec Std.U8)) (source : Slice NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json names source ⦃ actual =>
      nativeConstructResult (fun built => built.val.map nativeJsonPiece) actual =
        lowerJson (nativeNameColumn names) (nativeJsonSource source) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json
    AuthsNativeRecipe.auths_gateway_kernel.arguments.MAX_PROFILE_FIELDS
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases manyNames : 32 < names.val.length
  · have nativeMany : names.len > 32#usize := by scalar_tac
    simp [nativeMany, lowerJson, nativeNameColumn, Nat.not_le.mpr manyNames,
      nativeConstructResult, nativeConstructError]
  · have namesBound : names.val.length ≤ 32 := by omega
    have nativeNames : ¬names.len > 32#usize := by scalar_tac
    simp only [nativeNames, ↓reduceIte]
    by_cases manyPieces : 256 < source.val.length
    · have nativeMany : source.len > 256#usize := by scalar_tac
      simp [nativeMany, lowerJson, nativeJsonSource, Nat.not_le.mpr manyPieces,
        nativeConstructResult, nativeConstructError]
    · have sourceBound : source.val.length ≤ 256 := by omega
      have nativeSource : ¬source.len > 256#usize := by scalar_tac
      simp only [nativeSource, ↓reduceIte]
      step with native_json_resources_exact source as ⟨resources, resourcesMeaning⟩
      rw [Resources.json_resources_exact_totals] at resourcesMeaning
      cases resources with
      | none =>
          have invalid : ¬JsonResourceDomain (nativeJsonSource source) := by
            intro admitted
            simp [nativeJsonSource, sourceBound, admitted] at resourcesMeaning
          simp [lowerJson, nativeNameColumn, nativeJsonSource, namesBound, sourceBound,
            invalid, nativeConstructResult, nativeConstructError]
      | some used =>
          have admitted : JsonResourceDomain (nativeJsonSource source) := by
            by_contra invalid
            simp [invalid] at resourcesMeaning
          apply spec_mono (native_lower_json_suffix names source
            (AuthsNativeRecipe.alloc.vec.Vec.new NativeJsonPiece) 0#usize (by simp)
            (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add,
              Nat.sub_zero] using source.property))
          intro actual exact
          simpa [lowerJson, nativeNameColumn, nativeJsonSource, namesBound, sourceBound,
            admitted, native_empty_contents] using exact

@[step] theorem native_lower_form_piece_exact (names : Slice (NativeVec Std.U8)) (source : NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form_piece names source ⦃ actual =>
      nativeConstructResult nativeFormPiece actual = lowerFormPiece (nativeNameColumn names) (nativeNamedForm source) ⦄ := by
  cases source with
  | Raw value =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form_piece
        AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_LITERAL_BYTES
      by_cases large : 524288 < value.val.length
      · have nativeLarge : AuthsNativeRecipe.alloc.vec.Vec.len value > 524288#usize := by scalar_tac
        simp [nativeLarge, lowerFormPiece, nativeNamedForm, bytes, Nat.not_le.mpr large,
          nativeConstructResult, nativeConstructError]
      · have bounded : value.val.length ≤ 524288 := by omega
        have nativeBound : ¬AuthsNativeRecipe.alloc.vec.Vec.len value > 524288#usize := by scalar_tac
        simp only [nativeBound, ↓reduceIte]
        step with native_schema_copy_bytes (AuthsNativeRecipe.alloc.vec.Vec.deref value)
          as ⟨copied, copyMeaning⟩
        simp [lowerFormPiece, nativeNamedForm, nativeFormPiece, nativeConstructResult,
          bytes, bounded, copyMeaning, native_deref_contents]
  | Field name =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form_piece
      step with native_lower_field_exact names (AuthsNativeRecipe.alloc.vec.Vec.deref name)
        as ⟨index, meaning⟩
      cases index <;> simp [nativeNamedForm, lowerFormPiece, ← meaning,
        nativeConstructResult, nativeFormPiece, schemaSliceBytes, bytes, native_deref_contents]
  | Json source =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form_piece
      step with native_lower_json_exact names (AuthsNativeRecipe.alloc.vec.Vec.deref source)
        as ⟨compiled, meaning⟩
      cases compiled with
      | Err error =>
          simp [nativeNamedForm, lowerFormPiece, ← meaning, nativeConstructResult,
            nativeJsonSource, native_deref_contents]
      | Ok compiled =>
          step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone
            compiled (by intro piece _; exact native_json_piece_clone_result piece) as ⟨copied, same⟩
          simp [nativeNamedForm, lowerFormPiece, ← meaning, nativeConstructResult,
            nativeFormPiece, nativeJsonSource, native_deref_contents, same]
  | Echo =>
      simp [AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form_piece,
        nativeNamedForm, lowerFormPiece, nativeConstructResult, nativeFormPiece]

private theorem native_lower_form_suffix (names : Slice (NativeVec Std.U8))
    (source : Slice NativeNamedForm) (output : NativeVec NativeFormPiece) (position : Std.Usize)
    (positionBound : position.val ≤ source.val.length)
    (room : output.val.length + (source.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form_loop names source output position
      ⦃ actual => nativeConstructResult (fun built => built.val.map nativeFormPiece) actual =
        (lowerFormList (nativeNameColumn names) ((nativeFormSource source).drop position.val)).map
          (output.val.map nativeFormPiece ++ ·) ⦄ := by
  generalize remaining : source.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form_loop
      by_cases inside : position.val < source.val.length
      · have nativeInside : position < source.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec source position inside as ⟨piece, pieceAt⟩
        have suffix : (nativeFormSource source).drop position.val = nativeNamedForm piece ::
            (nativeFormSource source).drop (position.val + 1) := by
          simpa only [nativeFormSource, List.drop_map, List.map_cons, pieceAt] using
            congrArg (List.map nativeNamedForm) (List.drop_eq_getElem_cons inside)
        step with native_lower_form_piece_exact names piece as ⟨lowered, meaning⟩
        cases lowered with
        | Err error => simp [suffix, lowerFormList, ← meaning, nativeConstructResult]
        | Ok compiled =>
            step with native_form_piece_clone_exact compiled as ⟨copied, copyMeaning⟩
            step with native_push_exact output copied (by omega) as ⟨updated, appended⟩
            have updatedLength : updated.val.length = output.val.length + 1 := by
              simp only [appended, List.length_append, List.length_singleton]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) updated next (by omega) (by omega) rfl)
            intro actual exact
            simpa [suffix, lowerFormList, ← meaning, nativeConstructResult, appended,
              copyMeaning, nextValue, List.map_append, List.map_singleton,
              Except.map_map, Function.comp_def, List.append_assoc] using exact
      · have ended : source.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < source.len := by scalar_tac
        have modelEnded : (nativeFormSource source).length ≤ position.val := by
          simpa only [nativeFormSource, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, lowerFormList, nativeConstructResult]

@[step] theorem native_lower_form_exact (names : Slice (NativeVec Std.U8)) (source : Slice NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form names source ⦃ actual =>
      nativeConstructResult (fun built => built.val.map nativeFormPiece) actual =
        lowerForm (nativeNameColumn names) (nativeFormSource source) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form
    AuthsNativeRecipe.auths_gateway_kernel.arguments.MAX_PROFILE_FIELDS
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases manyNames : 32 < names.val.length
  · have nativeMany : names.len > 32#usize := by scalar_tac
    simp [nativeMany, lowerForm, nativeNameColumn, Nat.not_le.mpr manyNames,
      nativeConstructResult, nativeConstructError]
  · have namesBound : names.val.length ≤ 32 := by omega
    have nativeNames : ¬names.len > 32#usize := by scalar_tac
    simp only [nativeNames, ↓reduceIte]
    by_cases manyPieces : 256 < source.val.length
    · have nativeMany : source.len > 256#usize := by scalar_tac
      simp [nativeMany, lowerForm, nativeFormSource, Nat.not_le.mpr manyPieces,
        nativeConstructResult, nativeConstructError]
    · have sourceBound : source.val.length ≤ 256 := by omega
      have nativeSource : ¬source.len > 256#usize := by scalar_tac
      simp only [nativeSource, ↓reduceIte]
      step with native_form_resources_exact source as ⟨resources, resourcesMeaning⟩
      rw [Resources.form_resources_exact_totals] at resourcesMeaning
      cases resources with
      | none =>
          have invalid : ¬FormResourceDomain (nativeFormSource source) := by
            intro admitted
            simp [nativeFormSource, sourceBound, admitted] at resourcesMeaning
          simp [lowerForm, nativeNameColumn, nativeFormSource, namesBound, sourceBound,
            invalid, nativeConstructResult, nativeConstructError]
      | some used =>
          have admitted : FormResourceDomain (nativeFormSource source) := by
            by_contra invalid
            simp [invalid] at resourcesMeaning
          apply spec_mono (native_lower_form_suffix names source
            (AuthsNativeRecipe.alloc.vec.Vec.new NativeFormPiece) 0#usize (by simp)
            (by simpa only [native_empty_contents, List.length_nil, Nat.zero_add,
              Nat.sub_zero] using source.property))
          intro actual exact
          simpa [lowerForm, nativeNameColumn, nativeFormSource, namesBound, sourceBound,
            admitted, native_empty_contents] using exact

@[step] theorem native_named_body_lowering_exact (names : Slice (NativeVec Std.U8)) (body : NativeNamedBody) :
    AuthsNativeRecipe.auths_gateway_kernel.request_compiler.lower_body names body ⦃ actual =>
      nativeConstructResult nativeBodyPlan actual = RequestCompiler.lowerBody (nativeNameColumn names) (nativeNamedBody body) ⦄ := by
  cases body with
  | Json source =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.request_compiler.lower_body
      step with native_lower_json_exact names source as ⟨compiled, meaning⟩
      cases compiled with
      | Err error => simp [RequestCompiler.lowerBody, nativeNamedBody, ← meaning, nativeConstructResult]
      | Ok compiled =>
          step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece.Insts.CoreCloneClone
            compiled (by intro piece _; exact native_json_piece_clone_result piece) as ⟨copied, same⟩
          simp [RequestCompiler.lowerBody, nativeNamedBody, ← meaning, nativeConstructResult, nativeBodyPlan, same]
  | Form source =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.request_compiler.lower_body
      step with native_lower_form_exact names source as ⟨compiled, meaning⟩
      cases compiled with
      | Err error => simp [RequestCompiler.lowerBody, nativeNamedBody, ← meaning, nativeConstructResult]
      | Ok compiled =>
          step with native_vector_clone_exact AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece.Insts.CoreCloneClone
            compiled (by intro piece _; exact native_form_piece_clone_result piece) as ⟨copied, same⟩
          simp [RequestCompiler.lowerBody, nativeNamedBody, ← meaning, nativeConstructResult, nativeBodyPlan, same]

@[step] theorem native_template_source_exact (template : NativeNamedTemplate) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.source template ⦃ actual =>
      nativeNamedBody actual = nativeNamedTemplate template ⦄ := by
  cases template <;> simp [AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.source,
    nativeNamedBody, nativeNamedTemplate, nativeJsonSource, nativeFormSource, native_deref_contents]

theorem native_template_lowering_verdict (names : Slice (NativeVec Std.U8)) (template : NativeNamedTemplate) :
    (do let body ← AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate.source template
        AuthsNativeRecipe.auths_gateway_kernel.request_compiler.lower_body names body) ⦃ actual =>
      nativeConstructResult nativeBodyPlan actual = RequestCompiler.lowerBody (nativeNameColumn names) (nativeNamedTemplate template) ⦄ := by
  step with native_template_source_exact template as ⟨body, bodyMeaning⟩
  apply spec_mono (native_named_body_lowering_exact names body)
  intro actual exact
  simpa only [bodyMeaning] using exact

theorem native_named_json_retains_full_meaning (names : Slice (NativeVec Std.U8)) (source : Slice NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_json names source ⦃ actual =>
      ∀ built, actual = .Ok built →
        List.Forall₂ (JsonMeaning (nativeNameColumn names)) (nativeJsonSource source)
          (built.val.map nativeJsonPiece) ∧ JsonResourceDomain (nativeJsonSource source) ⦄ := by
  apply spec_mono (native_lower_json_exact names source)
  intro actual exact built accepted
  rw [accepted] at exact
  have compiled : lowerJson (nativeNameColumn names) (nativeJsonSource source) = .ok (built.val.map nativeJsonPiece) := by
    simpa only [nativeConstructResult] using exact.symm
  exact ⟨(lower_json_sound _ _ _ compiled).2.2, lower_json_earns_resources _ _ _ compiled⟩

theorem native_named_form_retains_full_meaning (names : Slice (NativeVec Std.U8)) (source : Slice NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.lower_form names source ⦃ actual =>
      ∀ built, actual = .Ok built →
        List.Forall₂ (FormMeaning (nativeNameColumn names)) (nativeFormSource source)
          (built.val.map nativeFormPiece) ∧ FormResourceDomain (nativeFormSource source) ⦄ := by
  apply spec_mono (native_lower_form_exact names source)
  intro actual exact built accepted
  rw [accepted] at exact
  have compiled : lowerForm (nativeNameColumn names) (nativeFormSource source) = .ok (built.val.map nativeFormPiece) := by
    simpa only [nativeConstructResult] using exact.symm
  exact ⟨(lower_form_sound _ _ _ compiled).2.2, lower_form_earns_resources _ _ _ compiled⟩

end Auths.Product.NativeCompiler.Refinement
