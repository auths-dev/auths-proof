import Auths.Product.FieldProjectionRows

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway

namespace Auths.Product.FieldProjection.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem projected_payloads_fit (fields : List Field) (inputs : Inputs)
    (rows : alloc.vec.Vec arguments.NamedArgument) (meaning : RowsMeaning fields inputs (rowsView rows)) :
    ArgumentBinding.Refinement.PayloadsFit (alloc.vec.Vec.deref rows) := by
  have bounded := rows_earn_payloads fields inputs (rowsView rows) meaning
  apply ScalarProjection.Refinement.bounded_named_environment_fits
  intro entry member
  exact bounded _ (List.mem_map.mpr ⟨entry, member, rfl⟩)

/-- The full shipping object function composes lexical unique names, exact
schema lookup, all scalar projections and complete name binding. Every success
and refusal has an independent decoded-object meaning, with no caller-supplied
alignment, projected rows, schema-selection or payload-bound premise. -/
@[step] theorem project_object_exact (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) :
    field_projection.project_object fields supplied ⦃ actual =>
      ObjectOutcome (fieldsView fields) (inputsView supplied)
        (resultOf (fun values => values.val.map argOf) actual) ⦄ := by
  unfold field_projection.project_object arguments.MAX_PROFILE_FIELDS
  by_cases large : 32 < fields.val.length
  · have nativeLarge : fields.len > 32#usize := by scalar_tac
    have invalid : ¬ObjectAccepted (fieldsView fields) (inputsView supplied) := by
      intro valid
      have bound := valid.1.1
      simp only [fieldsView, List.length_map] at bound
      omega
    simp [nativeLarge, ObjectOutcome, resultOf, errorOf, invalid]
  · have bounded : fields.val.length ≤ 32 := by omega
    have nativeBound : ¬fields.len > 32#usize := by scalar_tac
    by_cases lengths : supplied.val.length = fields.val.length
    · have nativeLengths : supplied.len = fields.len := by scalar_tac
      simp only [nativeBound, nativeLengths, bne_self_eq_false, Bool.false_or,
        Bool.false_eq_true, ↓reduceIte]
      step with field_names_exact as ⟨compiledNames, namesMeaning⟩
      cases compiledNames with
      | Err error =>
        have invalid : ¬LayoutValid (fieldsView fields) := by
          intro valid
          simp [valid, resultOf] at namesMeaning
        have errorClass : errorOf error = .argumentMismatch := by
          simpa [invalid, resultOf] using namesMeaning
        simp only [spec_ok, resultOf, ObjectOutcome]
        exact ⟨errorClass, fun valid => invalid valid.1⟩
      | Ok compiledNames =>
        have layout : LayoutValid (fieldsView fields) := by
          by_contra invalid
          simp [invalid, resultOf] at namesMeaning
        have exactNames : compiledNames.val.map vecBytes = names (fieldsView fields) := by
          simpa [layout, resultOf] using namesMeaning
        have indexedNames : Auths.Product.SchemaIndex.Refinement.namesView (alloc.vec.Vec.deref compiledNames) =
            names (fieldsView fields) := by
          simpa [Auths.Product.SchemaIndex.Refinement.namesView, vecBytes] using exactNames
        step with project_rows_exact as ⟨projected, rowsMeaning⟩
        cases projected with
        | Err error =>
          simp only [resultOf, RowsOutcome] at rowsMeaning
          simp only [spec_ok, resultOf, ObjectOutcome]
          exact ⟨rowsMeaning.1, fun valid => rowsMeaning.2 valid.2.2.1⟩
        | Ok projected =>
          simp only [resultOf, RowsOutcome] at rowsMeaning
          have fits := projected_payloads_fit _ _ projected rowsMeaning.2
          step with ArgumentBinding.Refinement.bind_exact as ⟨bound, boundMeaning⟩
          have boundModel : ArgumentBinding.bind (names (fieldsView fields)) (rowsView projected) =
              resultOf (fun values => values.val.map argOf) bound := by
            simpa [indexedNames, rowsView] using boundMeaning.symm
          cases bound with
          | Err error =>
            have errorClass := binder_error_class _ _ (errorOf error) boundModel
            have invalid : ¬ObjectAccepted (fieldsView fields) (inputsView supplied) := by
              intro valid
              obtain ⟨values, accepted⟩ := accepted_rows_bind _ _ _ valid rowsMeaning.2
              rw [accepted] at boundModel
              simp [resultOf] at boundModel
            simp only [spec_ok, resultOf, ObjectOutcome]
            exact ⟨errorClass, invalid⟩
          | Ok values =>
            have successful : ArgumentBinding.bind (names (fieldsView fields)) (rowsView projected) =
                .ok (values.val.map argOf) := by simpa [resultOf] using boundModel
            have boundNames := ArgumentBinding.bind_earns_exact_names _ _ _ successful
            have sameNames := rows_preserve_names _ _ _ rowsMeaning.2
            have inputNames : ((inputsView supplied).map Prod.fst).Perm (names (fieldsView fields)) := by
              simpa only [sameNames] using boundNames
            have modelLengths : (inputsView supplied).length = (fieldsView fields).length := by
              simpa [inputsView, fieldsView] using lengths
            simp only [spec_ok, resultOf, ObjectOutcome]
            exact ⟨⟨layout, modelLengths, rowsMeaning.1, inputNames⟩,
              rowsView projected, rowsMeaning.2, successful⟩
    · have nativeDifferent : supplied.len ≠ fields.len := by scalar_tac
      have invalid : ¬ObjectAccepted (fieldsView fields) (inputsView supplied) := by
        intro valid
        apply lengths
        simpa [fieldsView, inputsView] using valid.2.1
      simp [nativeBound, nativeDifferent, ObjectOutcome, resultOf, errorOf, invalid]

theorem source_object_earns_alignment (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) :
    field_projection.project_object fields supplied ⦃ actual =>
      ∀ values, actual = .Ok values → ∃ projected,
        RowsMeaning (fieldsView fields) (inputsView supplied) projected ∧
          SchemaIndex.Aligned (names (fieldsView fields)) (values.val.map argOf)
            (fun name => ArgumentBinding.lookup name projected) ⦄ := by
  apply spec_mono (project_object_exact fields supplied)
  intro actual meaning values accepted
  rw [accepted] at meaning
  exact object_result_earns_named_alignment _ _ _ meaning

theorem source_object_earns_exact_names (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) :
    field_projection.project_object fields supplied ⦃ actual =>
      ∀ values, actual = .Ok values →
        ((inputsView supplied).map Prod.fst).Perm (names (fieldsView fields)) ∧
          ((inputsView supplied).map Prod.fst).Nodup ⦄ := by
  apply spec_mono (project_object_exact fields supplied)
  intro actual meaning values accepted
  rw [accepted] at meaning
  have exactNames := meaning.1.2.2.2
  exact ⟨exactNames, exactNames.nodup_iff.mpr meaning.1.1.2.1⟩

theorem source_complete_objects_accept (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput)
    (valid : ObjectAccepted (fieldsView fields) (inputsView supplied)) :
    field_projection.project_object fields supplied ⦃ actual => ∃ values,
      actual = .Ok values ∧ ObjectOutcome (fieldsView fields) (inputsView supplied) (.ok (values.val.map argOf)) ⦄ := by
  apply spec_mono (project_object_exact fields supplied)
  intro actual meaning
  cases actual with
  | Err error => exact False.elim (meaning.2 valid)
  | Ok values => exact ⟨values, rfl, meaning⟩

theorem source_invalid_objects_refuse (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput)
    (invalid : ¬ObjectAccepted (fieldsView fields) (inputsView supplied)) :
    field_projection.project_object fields supplied ⦃ actual => actual = .Err .ArgumentMismatch ⦄ := by
  apply spec_mono (project_object_exact fields supplied)
  intro actual meaning
  cases actual with
  | Ok values => exact False.elim (invalid meaning.1)
  | Err error => cases error <;> simp_all [ObjectOutcome, resultOf, errorOf]

theorem source_referenced_value_is_named (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (name : Bytes) (index : Nat)
    (lowered : SchemaIndex.position (names (fieldsView fields)) name = some index) :
    field_projection.project_object fields supplied ⦃ actual =>
      ∀ values, actual = .Ok values → ∃ projected,
        RowsMeaning (fieldsView fields) (inputsView supplied) projected ∧
          (values.val.map argOf)[index]? = ArgumentBinding.lookup name projected ⦄ := by
  apply spec_mono (source_object_earns_alignment fields supplied)
  intro actual meaning values accepted
  obtain ⟨projected, projectedMeaning, aligned⟩ := meaning values accepted
  exact ⟨projected, projectedMeaning,
    SchemaIndex.indexed_argument_is_named _ _ _ aligned name index lowered⟩

end Auths.Product.FieldProjection.Refinement
