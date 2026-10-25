import Auths.Product.FieldProjectionNames

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.ScalarProjection.Dispatch

namespace Auths.Product.FieldProjection.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem rejected_member (fields : List Field) (inputs : Inputs) (input : Bytes × ScalarProjection.Scalar)
    (member : input ∈ inputs) (invalid : ¬RowAccepted fields input) : ¬RowsAccepted fields inputs :=
  fun accepted => invalid (accepted.2.2 input member)

@[step] theorem rows_loop_exact (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput)
    (fieldsBound : fields.val.length ≤ 32) (inputsBound : supplied.val.length ≤ 32) :
    field_projection.project_rows_loop fields supplied (alloc.vec.Vec.new arguments.NamedArgument) 0#usize
      ⦃ actual => RowsOutcome (fieldsView fields) (inputsView supplied) (resultOf rowsView actual) ⦄ := by
  unfold field_projection.project_rows_loop
  apply loop.spec_decr_nat
    (measure := fun state => supplied.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ supplied.val.length ∧
      RowsMeaning (fieldsView fields) ((inputsView supplied).take state.2.val) (rowsView state.1))
  · rintro ⟨current, index⟩ invariant
    unfold field_projection.project_rows_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < supplied.val.length := by simpa using within
      step as ⟨input, inputAt⟩
      have indexed : (inputsView supplied)[index.val]? =
          some (sliceBytes input.name, inputView input.value) := by
        simp [inputsView, List.getElem?_map, List.getElem?_eq_getElem inside, inputAt]
      have member : (sliceBytes input.name, inputView input.value) ∈ inputsView supplied :=
        List.mem_iff_getElem?.mpr ⟨index.val, indexed⟩
      step with OperationIdentity.Refinement.token_exact as ⟨allowed, allowedMeaning⟩
      cases allowed
      · have invalidName : OperationIdentity.validToken (sliceBytes input.name) 64 ≠ true := by
          simpa using allowedMeaning.symm
        have invalidRow : ¬RowAccepted (fieldsView fields) (sliceBytes input.name, inputView input.value) :=
          fun accepted => invalidName accepted.1
        simp only [spec_ok, resultOf, errorOf, RowsOutcome]
        exact ⟨rfl, rejected_member _ _ _ member invalidRow⟩
      · have validName : OperationIdentity.validToken (sliceBytes input.name) 64 = true := by
          simpa using allowedMeaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step with schema_for_exact as ⟨schema, schemaMeaning⟩
        cases schema with
        | none =>
          have missing : schemaFor (sliceBytes input.name) (fieldsView fields) = none := by
            simpa using schemaMeaning.symm
          have invalidRow : ¬RowAccepted (fieldsView fields) (sliceBytes input.name, inputView input.value) := by
            simp [RowAccepted, missing]
          simp only [spec_ok, resultOf, errorOf, RowsOutcome]
          exact ⟨rfl, rejected_member _ _ _ member invalidRow⟩
        | some schema =>
          have selected : schemaFor (sliceBytes input.name) (fieldsView fields) = some (schemaView schema) := by
            simpa using schemaMeaning.symm
          step with ScalarProjection.Dispatch.projection_exact as ⟨value, refused, valueMeaning⟩
          cases value with
          | none =>
            have invalidValue := refused.mp rfl
            have invalidRow : ¬RowAccepted (fieldsView fields) (sliceBytes input.name, inputView input.value) := by
              simp [RowAccepted, selected, invalidValue]
            simp only [spec_ok, resultOf, errorOf, RowsOutcome]
            exact ⟨rfl, rejected_member _ _ _ member invalidRow⟩
          | some value =>
            obtain ⟨projected, bounded⟩ := valueMeaning value rfl
            have nameBound := token_length (sliceBytes input.name) validName
            have copyFits : input.name.val.length < 4294967295 := by
              simp only [sliceBytes, byteList, List.length_map] at nameBound
              omega
            step with copy_bytes_spec as ⟨copiedName, copiedMeaning⟩
            have currentSize := rows_preserve_length _ _ _ invariant.2
            simp only [rowsView, ArgumentBinding.Refinement.environment, alloc.vec.Vec.deref,
              List.length_map, List.length_take, inputsView] at currentSize
            simp only [List.length_map] at currentSize
            have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
            step as ⟨updated, updatedMeaning⟩
            step as ⟨next, nextValue⟩
            have one : RowProjects (fieldsView fields) (sliceBytes input.name, inputView input.value)
                (vecBytes copiedName, argOf value) :=
              ⟨by simp [vecBytes, sliceBytes, copiedMeaning], validName,
                schemaView schema, selected, projected, bounded⟩
            have viewUpdate : rowsView updated = rowsView current ++ [(vecBytes copiedName, argOf value)] := by
              simp [rowsView, ArgumentBinding.Refinement.environment, updatedMeaning, List.map_append]
            have prefix : (inputsView supplied).take (index.val + 1) =
                (inputsView supplied).take index.val ++ [(sliceBytes input.name, inputView input.value)] := by
              simpa [inputsView, inputAt] using List.take_succ_eq_append_getElem (by simpa [inputsView] using inside)
            refine ⟨by omega, ?_, by omega⟩
            rw [nextValue, prefix, viewUpdate]
            exact invariant.2.append (List.Forall₂.cons one List.Forall₂.nil)
    · simp only [spec_ok, resultOf, RowsOutcome]
      have atEnd : supplied.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (inputsView supplied).length ≤ index.val := by simpa [inputsView] using atEnd
      have complete : RowsMeaning (fieldsView fields) (inputsView supplied) (rowsView current) := by
        simpa [List.take_of_length_le modelAtEnd] using invariant.2
      exact ⟨⟨by simpa [fieldsView] using fieldsBound, by simpa [inputsView] using inputsBound,
        rows_all_accepted _ _ _ complete⟩, complete⟩
  · exact ⟨by simp, List.Forall₂.nil⟩

@[step] theorem project_rows_exact (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) :
    field_projection.project_rows fields supplied ⦃ actual =>
      RowsOutcome (fieldsView fields) (inputsView supplied) (resultOf rowsView actual) ⦄ := by
  unfold field_projection.project_rows arguments.MAX_PROFILE_FIELDS
  by_cases fieldsLarge : 32 < fields.val.length
  · have nativeLarge : fields.len > 32#usize := by scalar_tac
    simp [nativeLarge, RowsOutcome, RowsAccepted, fieldsView, Nat.not_le.mpr fieldsLarge, resultOf, errorOf]
  · have fieldsBound : fields.val.length ≤ 32 := by omega
    have nativeFieldsBound : ¬fields.len > 32#usize := by scalar_tac
    by_cases inputsLarge : 32 < supplied.val.length
    · have nativeLarge : supplied.len > 32#usize := by scalar_tac
      simp [nativeFieldsBound, nativeLarge, RowsOutcome, RowsAccepted, inputsView,
        Nat.not_le.mpr inputsLarge, resultOf, errorOf]
    · have inputsBound : supplied.val.length ≤ 32 := by omega
      have nativeInputsBound : ¬supplied.len > 32#usize := by scalar_tac
      simp only [nativeFieldsBound, nativeInputsBound, Bool.false_or, ↓reduceIte]
      exact rows_loop_exact fields supplied fieldsBound inputsBound

theorem source_rows_earn_payloads (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) :
    field_projection.project_rows fields supplied ⦃ actual =>
      ∀ rows, actual = .Ok rows →
        ArgumentBinding.Refinement.PayloadsFit (alloc.vec.Vec.deref rows) ⦄ := by
  apply spec_mono (project_rows_exact fields supplied)
  intro actual meaning rows accepted
  rw [accepted] at meaning
  have bounded := rows_earn_payloads _ _ _ meaning.2
  apply ScalarProjection.Refinement.bounded_named_environment_fits
  intro entry member
  have projectedMember : (vecBytes entry.name, argOf entry.value) ∈ rowsView rows :=
    List.mem_map.mpr ⟨entry, member, rfl⟩
  exact bounded _ projectedMember

end Auths.Product.FieldProjection.Refinement
