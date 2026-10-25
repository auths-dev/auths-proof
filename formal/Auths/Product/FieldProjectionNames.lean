import Auths.Product.FieldProjection
import Auths.Product.ScalarDispatchRefinement
import Auths.Product.Refinement.OperationIdentity

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity
open Auths.Product.ScalarProjection.Dispatch

namespace Auths.Product.FieldProjection.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def fieldsView (fields : Slice field_projection.FieldSpec) : List Field :=
  fields.val.map (fun field => ⟨vecBytes field.name, schemaView field.schema⟩)

def inputsView (inputs : Slice field_projection.NamedInput) : Inputs :=
  inputs.val.map (fun input => (sliceBytes input.name, inputView input.value))

def rowsView (rows : alloc.vec.Vec arguments.NamedArgument) : ArgumentBinding.Environment :=
  ArgumentBinding.Refinement.environment (alloc.vec.Vec.deref rows)

private def Lexical (fields : List Field) : Prop :=
  ∀ field ∈ fields, OperationIdentity.validToken field.name 64 = true
private instance (fields : List Field) : Decidable (Lexical fields) := by unfold Lexical; infer_instance

@[step] theorem name_copy_loop_exact (fields : Slice field_projection.FieldSpec)
    (bounded : fields.val.length ≤ 32) :
    field_projection.copy_field_names_loop fields (alloc.vec.Vec.new (alloc.vec.Vec Std.U8)) 0#usize
      ⦃ actual => resultOf (fun names => names.val.map vecBytes) actual =
        if Lexical (fieldsView fields) then .ok (names (fieldsView fields)) else .error .argumentMismatch ⦄ := by
  unfold field_projection.copy_field_names_loop
  apply loop.spec_decr_nat
    (measure := fun state => fields.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ fields.val.length ∧
      state.1.val.map vecBytes = (names (fieldsView fields)).take state.2.val ∧
      Lexical ((fieldsView fields).take state.2.val))
  · rintro ⟨current, index⟩ invariant
    unfold field_projection.copy_field_names_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < fields.val.length := by simpa using within
      step as ⟨field, fieldAt⟩
      step with OperationIdentity.Refinement.token_exact as ⟨valid, validMeaning⟩
      have indexed : (fieldsView fields)[index.val]? =
          some ⟨vecBytes field.name, schemaView field.schema⟩ := by
        simp [fieldsView, List.getElem?_map, List.getElem?_eq_getElem inside, fieldAt]
      cases valid
      · have invalid : OperationIdentity.validToken (vecBytes field.name) 64 ≠ true := by
          simpa [alloc.vec.Vec.deref, sliceBytes] using validMeaning.symm
        have notLexical : ¬Lexical (fieldsView fields) := by
          intro all
          exact invalid (all _ (List.mem_iff_getElem?.mpr ⟨index.val, indexed⟩))
        simp [notLexical, resultOf, errorOf]
      · have lexical : OperationIdentity.validToken (vecBytes field.name) 64 = true := by
          simpa [alloc.vec.Vec.deref, sliceBytes] using validMeaning.symm
        have nameBound := token_length (vecBytes field.name) lexical
        have copyFits : field.name.val.length < 4294967295 := by
          simp only [vecBytes, byteList, List.length_map] at nameBound
          omega
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step with copy_bytes_spec as ⟨copied, copyValue⟩
        have currentLength : current.val.length = index.val := by
          have size := congrArg List.length invariant.2.1
          simp only [List.length_map, List.length_take, names, fieldsView] at size
          simp only [List.length_map] at size
          omega
        have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
        step as ⟨updated, updateValue⟩
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, ?_, by omega⟩
        · rw [nextValue, List.take_succ_eq_append_getElem (by simpa [names, fieldsView] using inside)]
          simp [updateValue, List.map_append, invariant.2.1, vecBytes, copyValue,
            names, fieldsView, fieldAt]
        · rw [nextValue, List.take_succ_eq_append_getElem (by simpa [fieldsView] using inside)]
          intro value member
          rcases List.mem_append.mp member with earlier | current
          · exact invariant.2.2 _ earlier
          · have same : value = ⟨vecBytes field.name, schemaView field.schema⟩ := by
              simpa [List.mem_singleton, fieldsView, fieldAt] using current
            simpa [same] using lexical
    · simp only [spec_ok, resultOf]
      have atEnd : fields.val.length ≤ index.val := by simpa using within
      have fieldsAtEnd : (fieldsView fields).length ≤ index.val := by simpa [fieldsView] using atEnd
      have namesAtEnd : (names (fieldsView fields)).length ≤ index.val := by simpa [names] using fieldsAtEnd
      have lexical : Lexical (fieldsView fields) := by
        simpa [List.take_of_length_le fieldsAtEnd] using invariant.2.2
      simpa [lexical, List.take_of_length_le namesAtEnd] using invariant.2.1
  · exact ⟨by simp, by simp, by simp [Lexical]⟩

@[step] theorem copy_names_exact (fields : Slice field_projection.FieldSpec) :
    field_projection.copy_field_names fields ⦃ actual =>
      resultOf (fun names => names.val.map vecBytes) actual =
        if (fieldsView fields).length ≤ 32 ∧ Lexical (fieldsView fields)
          then .ok (names (fieldsView fields)) else .error .argumentMismatch ⦄ := by
  unfold field_projection.copy_field_names arguments.MAX_PROFILE_FIELDS
  by_cases large : 32 < fields.val.length
  · have nativeLarge : fields.len > 32#usize := by scalar_tac
    simp [nativeLarge, fieldsView, Nat.not_le.mpr large, resultOf, errorOf]
  · have bounded : fields.val.length ≤ 32 := by omega
    have nativeBound : ¬fields.len > 32#usize := by scalar_tac
    simp only [nativeBound, ↓reduceIte]
    apply spec_mono (name_copy_loop_exact fields bounded)
    intro actual meaning
    simpa [fieldsView, bounded] using meaning

@[step] theorem field_names_exact (fields : Slice field_projection.FieldSpec) :
    field_projection.field_names fields ⦃ actual =>
      resultOf (fun names => names.val.map vecBytes) actual =
        if LayoutValid (fieldsView fields) then .ok (names (fieldsView fields)) else .error .argumentMismatch ⦄ := by
  unfold field_projection.field_names
  step with copy_names_exact as ⟨copied, copiedMeaning⟩
  cases copied with
  | Err error =>
    have invalid : ¬((fieldsView fields).length ≤ 32 ∧ Lexical (fieldsView fields)) := by
      by_contra valid
      simp [valid, resultOf] at copiedMeaning
    have layoutInvalid : ¬LayoutValid (fieldsView fields) := fun valid => invalid ⟨valid.1, valid.2.2⟩
    simpa [layoutInvalid, invalid, resultOf] using copiedMeaning
  | Ok copied =>
    have valid : (fieldsView fields).length ≤ 32 ∧ Lexical (fieldsView fields) := by
      by_contra invalid
      simp [invalid, resultOf] at copiedMeaning
    have copiedNames : copied.val.map vecBytes = names (fieldsView fields) := by
      simpa [valid, resultOf] using copiedMeaning
    step with ArgumentBinding.Refinement.unique_fields_exact as ⟨unique, uniqueMeaning⟩
    have uniqueSpec : unique = decide (names (fieldsView fields)).Nodup := by
      simpa [Auths.Product.SchemaIndex.Refinement.namesView, vecBytes, copiedNames] using uniqueMeaning
    cases unique
    · have duplicate : ¬(names (fieldsView fields)).Nodup := by simpa using uniqueSpec.symm
      simp [LayoutValid, duplicate, resultOf, errorOf]
    · have distinct : (names (fieldsView fields)).Nodup := by simpa using uniqueSpec.symm
      have layout : LayoutValid (fieldsView fields) := ⟨valid.1, distinct, valid.2⟩
      simp [layout, resultOf, copiedNames]

@[step] theorem schema_for_exact (fields : Slice field_projection.FieldSpec) (name : Slice Std.U8) :
    field_projection.schema_for fields name ⦃ actual =>
      actual.map schemaView = schemaFor (sliceBytes name) (fieldsView fields) ⦄ := by
  unfold field_projection.schema_for field_projection.schema_for_loop
  apply loop.spec_decr_nat
    (measure := fun index => fields.val.length - index.val)
    (inv := fun index => index.val ≤ fields.val.length ∧
      schemaFor (sliceBytes name) (fieldsView fields) =
        schemaFor (sliceBytes name) ((fieldsView fields).drop index.val))
  · intro index invariant
    unfold field_projection.schema_for_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < fields.val.length := by simpa using within
      step as ⟨field, fieldAt⟩
      step with field_name_equal_exact as ⟨same, sameMeaning⟩
      have suffix : (fieldsView fields).drop index.val =
          ⟨vecBytes field.name, schemaView field.schema⟩ :: (fieldsView fields).drop (index.val + 1) := by
        simpa [fieldsView, List.drop_map, fieldAt] using
          congrArg (List.map (fun field => Field.mk (vecBytes field.name) (schemaView field.schema)))
            (List.drop_eq_getElem_cons inside)
      rw [suffix, schemaFor] at invariant
      cases same
      · have different : vecBytes field.name ≠ sliceBytes name := by
          intro equal
          have raw := byteList_inj _ _ |>.mp equal
          simp [alloc.vec.Vec.deref, raw] at sameMeaning
        simp only [Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        simpa [different, nextValue] using invariant.2
      · have equal : vecBytes field.name = sliceBytes name := by
          have raw : field.name.val = name.val := by simpa [alloc.vec.Vec.deref] using sameMeaning.symm
          simp [vecBytes, sliceBytes, raw]
        simpa [equal] using invariant.2.symm
    · simp only [spec_ok, Option.map_none]
      have atEnd : fields.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (fieldsView fields).length ≤ index.val := by simpa [fieldsView] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, schemaFor] using invariant.2.symm
  · exact ⟨by simp, by simp⟩

end Auths.Product.FieldProjection.Refinement
