import Auths.Product.BodyCompilerResourcesRefinement

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.BodyCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

@[step] theorem lower_json_piece_exact (names : Slice (alloc.vec.Vec Std.U8))
    (source : body_compiler.NamedJsonPiece) :
    body_compiler.lower_json_piece names source ⦃ actual =>
      resultOf jsonPieceOf actual = lowerJsonPiece (namesView names) (jsonSourceView source) ⦄ := by
  cases source with
  | Raw bytes =>
    unfold body_compiler.lower_json_piece body_compiler.MAX_TEMPLATE_LITERAL_BYTES
    by_cases large : 524288 < bytes.val.length
    · have nativeLarge : bytes.length > 524288#usize := by scalar_tac
      simp [nativeLarge, lowerJsonPiece, jsonSourceView, vecBytes, length_byteList,
        Nat.not_le.mpr large, resultOf, errorOf]
    · have bounded : bytes.val.length ≤ 524288 := by omega
      have nativeBound : ¬bytes.length > 524288#usize := by scalar_tac
      have fits : bytes.val.length < 4294967295 := by omega
      simp only [nativeBound, ↓reduceIte]
      step with copy_bytes_spec as ⟨copied, sameBytes⟩
      simp [lowerJsonPiece, jsonSourceView, jsonPieceOf, resultOf, vecBytes,
        length_byteList, bounded, sameBytes]
  | Field name =>
    unfold body_compiler.lower_json_piece
    step with PathCompiler.Refinement.lower_field_exact as ⟨index, meaning⟩
    cases index <;>
      simp [jsonSourceView, lowerJsonPiece, ← meaning, resultOf, jsonPieceOf, vecBytes, sliceBytes]
  | Echo => simp [body_compiler.lower_json_piece, jsonSourceView, lowerJsonPiece, resultOf, jsonPieceOf]

private def jsonFrom (built : List JsonPiece) (names : List Bytes) : List NamedJson → Except ConstructError (List JsonPiece)
  | [] => .ok built
  | source :: rest => do
    let piece ← lowerJsonPiece names source
    jsonFrom (built ++ [piece]) names rest

private theorem json_from_refines (built : List JsonPiece) (names : List Bytes) (source : List NamedJson) :
    jsonFrom built names source = (lowerJsonList names source).map (built ++ ·) := by
  induction source generalizing built with
  | nil => simp [jsonFrom, lowerJsonList]
  | cons first rest ih =>
    cases firstRun : lowerJsonPiece names first <;>
      simp [jsonFrom, lowerJsonList, firstRun, ih, Except.map_map, Function.comp_def, List.append_assoc]

@[step] theorem json_loop_exact (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedJsonPiece) (bounded : source.val.length ≤ 256) :
    body_compiler.lower_json_loop names source (alloc.vec.Vec.new construct.JsonPiece) 0#usize
      ⦃ actual => resultOf (fun output => output.val.map jsonPieceOf) actual =
        lowerJsonList (namesView names) (jsonSource source) ⦄ := by
  unfold body_compiler.lower_json_loop
  let wanted := lowerJsonList (namesView names) (jsonSource source)
  apply loop.spec_decr_nat
    (measure := fun state => source.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ source.val.length ∧ state.1.val.length = state.2.val ∧
      wanted = jsonFrom (state.1.val.map jsonPieceOf) (namesView names) ((jsonSource source).drop state.2.val))
  · rintro ⟨current, index⟩ invariant
    unfold body_compiler.lower_json_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < source.val.length := by simpa using within
      step as ⟨piece, pieceAt⟩
      have suffix : (jsonSource source).drop index.val = jsonSourceView piece :: (jsonSource source).drop (index.val + 1) := by
        simpa [jsonSource, List.drop_map, pieceAt] using
          congrArg (List.map jsonSourceView) (List.drop_eq_getElem_cons inside)
      rw [suffix, jsonFrom] at invariant
      step with lower_json_piece_exact as ⟨lowered, meaning⟩
      cases lowered with
      | Err error =>
        simp only [resultOf] at meaning
        simp only [spec_ok, resultOf]
        simpa [← meaning] using invariant.2.2.symm
      | Ok piece =>
        have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
        step as ⟨updated, updateValue⟩
        step as ⟨next, nextValue⟩
        refine ⟨by omega, by simp [updateValue]; omega, ?_, by omega⟩
        simpa [← meaning, resultOf, updateValue, List.map_append, nextValue] using invariant.2.2
    · simp only [spec_ok, resultOf]
      have atEnd : source.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (jsonSource source).length ≤ index.val := by simpa [jsonSource] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, jsonFrom] using invariant.2.2.symm
  · simp [wanted, json_from_refines]

@[step] theorem lower_json_exact (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedJsonPiece) :
    body_compiler.lower_json names source ⦃ actual =>
      resultOf (fun output => output.val.map jsonPieceOf) actual = lowerJson (namesView names) (jsonSource source) ⦄ := by
  unfold body_compiler.lower_json body_compiler.MAX_TEMPLATE_PIECES arguments.MAX_PROFILE_FIELDS
  by_cases manyNames : 32 < names.val.length
  · have nativeMany : names.len > 32#usize := by scalar_tac
    simp [nativeMany, lowerJson, namesView, Nat.not_le.mpr manyNames, resultOf, errorOf]
  · have namesBound : names.val.length ≤ 32 := by omega
    have nativeNamesBound : ¬names.len > 32#usize := by scalar_tac
    by_cases tooMany : 256 < source.val.length
    · have nativeMany : source.len > 256#usize := by scalar_tac
      simp [nativeNamesBound, nativeMany, lowerJson, jsonSource, Nat.not_le.mpr tooMany, resultOf, errorOf]
    · have bounded : source.val.length ≤ 256 := by omega
      have nativeBound : ¬source.len > 256#usize := by scalar_tac
      simp only [nativeNamesBound, nativeBound, Bool.false_or, ↓reduceIte]
      step with json_resources_exact as ⟨resources, resourceMeaning⟩
      cases resources with
      | none =>
        have invalid : ¬JsonResourceDomain (jsonSource source) := by
          intro admitted
          rw [Resources.json_resources_exact_totals] at resourceMeaning
          simp [jsonSource, bounded, admitted] at resourceMeaning
        simp [lowerJson, namesView, jsonSource, namesBound, bounded, invalid, resultOf, errorOf]
      | some used =>
        have checked : Resources.jsonResources (jsonSource source) = some (usageOf used) := by
          simpa using resourceMeaning.symm
        have domain := (Resources.json_resources_success_earns_totals _ _ checked).2.2
        apply spec_mono (json_loop_exact names source bounded)
        intro actual meaning
        simpa [lowerJson, namesView, jsonSource, namesBound, bounded, domain] using meaning

@[step] theorem lower_form_piece_exact (names : Slice (alloc.vec.Vec Std.U8))
    (source : body_compiler.NamedFormPiece) :
    body_compiler.lower_form_piece names source ⦃ actual =>
      resultOf formPieceOf actual = lowerFormPiece (namesView names) (formSourceView source) ⦄ := by
  cases source with
  | Raw bytes =>
    unfold body_compiler.lower_form_piece body_compiler.MAX_TEMPLATE_LITERAL_BYTES
    by_cases large : 524288 < bytes.val.length
    · have nativeLarge : bytes.length > 524288#usize := by scalar_tac
      simp [nativeLarge, lowerFormPiece, formSourceView, vecBytes, length_byteList,
        Nat.not_le.mpr large, resultOf, errorOf]
    · have bounded : bytes.val.length ≤ 524288 := by omega
      have nativeBound : ¬bytes.length > 524288#usize := by scalar_tac
      have fits : bytes.val.length < 4294967295 := by omega
      simp only [nativeBound, ↓reduceIte]
      step with copy_bytes_spec as ⟨copied, sameBytes⟩
      simp [lowerFormPiece, formSourceView, formPieceOf, resultOf, vecBytes,
        length_byteList, bounded, sameBytes]
  | Field name =>
    unfold body_compiler.lower_form_piece
    step with PathCompiler.Refinement.lower_field_exact as ⟨index, meaning⟩
    cases index <;>
      simp [formSourceView, lowerFormPiece, ← meaning, resultOf, formPieceOf, vecBytes, sliceBytes]
  | Json pieces =>
    unfold body_compiler.lower_form_piece
    step with lower_json_exact as ⟨compiled, meaning⟩
    cases compiled <;>
      simp [formSourceView, lowerFormPiece, ← meaning, resultOf, formPieceOf, jsonSource]
  | Echo => simp [body_compiler.lower_form_piece, formSourceView, lowerFormPiece, resultOf, formPieceOf]

private def formFrom (built : List FormPiece) (names : List Bytes) : List NamedForm → Except ConstructError (List FormPiece)
  | [] => .ok built
  | source :: rest => do
    let piece ← lowerFormPiece names source
    formFrom (built ++ [piece]) names rest

private theorem form_from_refines (built : List FormPiece) (names : List Bytes) (source : List NamedForm) :
    formFrom built names source = (lowerFormList names source).map (built ++ ·) := by
  induction source generalizing built with
  | nil => simp [formFrom, lowerFormList]
  | cons first rest ih =>
    cases firstRun : lowerFormPiece names first <;>
      simp [formFrom, lowerFormList, firstRun, ih, Except.map_map, Function.comp_def, List.append_assoc]

@[step] theorem form_loop_exact (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedFormPiece) (bounded : source.val.length ≤ 256) :
    body_compiler.lower_form_loop names source (alloc.vec.Vec.new construct.FormPiece) 0#usize
      ⦃ actual => resultOf (fun output => output.val.map formPieceOf) actual =
        lowerFormList (namesView names) (formSource source) ⦄ := by
  unfold body_compiler.lower_form_loop
  let wanted := lowerFormList (namesView names) (formSource source)
  apply loop.spec_decr_nat
    (measure := fun state => source.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ source.val.length ∧ state.1.val.length = state.2.val ∧
      wanted = formFrom (state.1.val.map formPieceOf) (namesView names) ((formSource source).drop state.2.val))
  · rintro ⟨current, index⟩ invariant
    unfold body_compiler.lower_form_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < source.val.length := by simpa using within
      step as ⟨piece, pieceAt⟩
      have suffix : (formSource source).drop index.val = formSourceView piece :: (formSource source).drop (index.val + 1) := by
        simpa [formSource, List.drop_map, pieceAt] using
          congrArg (List.map formSourceView) (List.drop_eq_getElem_cons inside)
      rw [suffix, formFrom] at invariant
      step with lower_form_piece_exact as ⟨lowered, meaning⟩
      cases lowered with
      | Err error =>
        simp only [resultOf] at meaning
        simp only [spec_ok, resultOf]
        simpa [← meaning] using invariant.2.2.symm
      | Ok piece =>
        have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
        step as ⟨updated, updateValue⟩
        step as ⟨next, nextValue⟩
        refine ⟨by omega, by simp [updateValue]; omega, ?_, by omega⟩
        simpa [← meaning, resultOf, updateValue, List.map_append, nextValue] using invariant.2.2
    · simp only [spec_ok, resultOf]
      have atEnd : source.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (formSource source).length ≤ index.val := by simpa [formSource] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, formFrom] using invariant.2.2.symm
  · simp [wanted, form_from_refines]

@[step] theorem lower_form_exact (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedFormPiece) :
    body_compiler.lower_form names source ⦃ actual =>
      resultOf (fun output => output.val.map formPieceOf) actual = lowerForm (namesView names) (formSource source) ⦄ := by
  unfold body_compiler.lower_form body_compiler.MAX_TEMPLATE_PIECES arguments.MAX_PROFILE_FIELDS
  by_cases manyNames : 32 < names.val.length
  · have nativeMany : names.len > 32#usize := by scalar_tac
    simp [nativeMany, lowerForm, namesView, Nat.not_le.mpr manyNames, resultOf, errorOf]
  · have namesBound : names.val.length ≤ 32 := by omega
    have nativeNamesBound : ¬names.len > 32#usize := by scalar_tac
    by_cases tooMany : 256 < source.val.length
    · have nativeMany : source.len > 256#usize := by scalar_tac
      simp [nativeNamesBound, nativeMany, lowerForm, formSource, Nat.not_le.mpr tooMany, resultOf, errorOf]
    · have bounded : source.val.length ≤ 256 := by omega
      have nativeBound : ¬source.len > 256#usize := by scalar_tac
      simp only [nativeNamesBound, nativeBound, Bool.false_or, ↓reduceIte]
      step with form_resources_exact as ⟨resources, resourceMeaning⟩
      cases resources with
      | none =>
        have invalid : ¬FormResourceDomain (formSource source) := by
          intro admitted
          rw [Resources.form_resources_exact_totals] at resourceMeaning
          simp [formSource, bounded, admitted] at resourceMeaning
        simp [lowerForm, namesView, formSource, namesBound, bounded, invalid, resultOf, errorOf]
      | some used =>
        have checked : Resources.formResources (formSource source) = some (usageOf used) := by
          simpa using resourceMeaning.symm
        have domain := (Resources.form_resources_success_earns_totals _ _ checked).2.2
        apply spec_mono (form_loop_exact names source bounded)
        intro actual meaning
        simpa [lowerForm, namesView, formSource, namesBound, bounded, domain] using meaning

/-- Every actual emitted plan preserves named body bytes and validity for
every independently aligned action, including nested JSON and echo. The
source writer's mechanical refinement composes with this equation under its
explicit allocation envelope; native AST traversal remains a separate bridge. -/
theorem source_json_body_preserves_names (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedJsonPiece) :
    body_compiler.lower_json names source ⦃ actual => ∀ output, actual = .Ok output →
      ∀ values environment echo, SchemaIndex.Aligned (namesView names) values environment →
        buildBody (.json (output.val.map jsonPieceOf)) values echo =
          finishNamedBody ((jsonSource source).all (namedJsonValid environment)) (namedJson environment echo (jsonSource source)) ⦄ := by
  apply spec_mono (lower_json_exact names source)
  intro actual meaning output accepted values environment echo aligned
  rw [accepted] at meaning
  exact lowered_json_body_exact _ _ _ _ aligned _ _ (by simpa [resultOf] using meaning.symm)

theorem source_form_body_preserves_names (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedFormPiece) :
    body_compiler.lower_form names source ⦃ actual => ∀ output, actual = .Ok output →
      ∀ values environment echo, SchemaIndex.Aligned (namesView names) values environment →
        buildBody (.form (output.val.map formPieceOf)) values echo =
          finishNamedBody ((formSource source).all (namedFormValid environment)) (namedForm environment echo (formSource source)) ⦄ := by
  apply spec_mono (lower_form_exact names source)
  intro actual meaning output accepted values environment echo aligned
  rw [accepted] at meaning
  exact lowered_form_body_exact _ _ _ _ aligned _ _ (by simpa [resultOf] using meaning.symm)

theorem source_admissible_json_compiles (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedJsonPiece) (admitted : JsonTemplateAdmissible (namesView names) (jsonSource source)) :
    body_compiler.lower_json names source ⦃ actual => ∃ output, actual = .Ok output ∧
      List.Forall₂ (JsonMeaning (namesView names)) (jsonSource source) (output.val.map jsonPieceOf) ⦄ := by
  obtain ⟨pieces, run⟩ := lower_json_complete _ _ admitted
  apply spec_mono (lower_json_exact names source)
  intro actual meaning
  rw [run] at meaning
  cases actual with
  | Err error => simp [resultOf] at meaning
  | Ok output =>
    have same : output.val.map jsonPieceOf = pieces := by simpa [resultOf] using meaning
    exact ⟨output, rfl, by simpa [same] using (lower_json_sound _ _ _ run).2.2⟩

theorem source_admissible_form_compiles (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedFormPiece) (admitted : FormTemplateAdmissible (namesView names) (formSource source)) :
    body_compiler.lower_form names source ⦃ actual => ∃ output, actual = .Ok output ∧
      List.Forall₂ (FormMeaning (namesView names)) (formSource source) (output.val.map formPieceOf) ⦄ := by
  obtain ⟨pieces, run⟩ := lower_form_complete _ _ admitted
  apply spec_mono (lower_form_exact names source)
  intro actual meaning
  rw [run] at meaning
  cases actual with
  | Err error => simp [resultOf] at meaning
  | Ok output =>
    have same : output.val.map formPieceOf = pieces := by simpa [resultOf] using meaning
    exact ⟨output, rfl, by simpa [same] using (lower_form_sound _ _ _ run).2.2⟩

theorem source_json_compilation_earns_resources (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedJsonPiece) :
    body_compiler.lower_json names source ⦃ actual => ∀ output, actual = .Ok output →
      JsonResourceDomain (jsonSource source) ⦄ := by
  apply spec_mono (lower_json_exact names source)
  intro actual meaning output accepted
  rw [accepted] at meaning
  exact lower_json_earns_resources _ _ _ (by simpa [resultOf] using meaning.symm)

theorem source_form_compilation_earns_resources (names : Slice (alloc.vec.Vec Std.U8))
    (source : Slice body_compiler.NamedFormPiece) :
    body_compiler.lower_form names source ⦃ actual => ∀ output, actual = .Ok output →
      FormResourceDomain (formSource source) ⦄ := by
  apply spec_mono (lower_form_exact names source)
  intro actual meaning output accepted
  rw [accepted] at meaning
  exact lower_form_earns_resources _ _ _ (by simpa [resultOf] using meaning.symm)

end Auths.Product.BodyCompiler.Refinement
