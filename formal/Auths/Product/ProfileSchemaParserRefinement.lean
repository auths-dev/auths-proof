import Auths.Product.ProfileSchemaRefinement
import Auths.Product.ProfileSchemaFolds

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.ScalarProjection
open Auths.Product.ScalarProjection.Dispatch
open Auths.Product.FieldProjection
open Auths.Product.FieldProjection.Refinement

namespace Auths.Product.ProfileSchema.Refinement
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

/-! Complete parser source bodies, including typed refusal and useful
acceptance. All new loop/record/borrow interfaces await actual generation and
inspection; no generated ABI or successful evidence is asserted by this file. -/

@[step] theorem enum_schema_exact (values : Slice profile_schema.SchemaValue) :
    profile_schema.enum_schema values ⦃ actual =>
      actual.map schemaView = enumResult (valuesOf values.val) ⦄ := by
  unfold profile_schema.enum_schema scalars.MAX_ENUM_VARIANTS
  by_cases empty : values.val = []
  · have refused := enum_result_count_refusal (valuesOf values.val) (Or.inl (by simp [empty, valuesOf]))
    simp [empty, core.slice.Slice.is_empty, refused]
  · have nonempty : (valuesOf values.val) ≠ [] := by
      intro absent
      have sizes := congrArg List.length absent
      simp [values_count] at sizes
      exact empty (List.eq_nil_of_length_eq_zero sizes)
    by_cases large : 32 < values.val.length
    · have nativeLarge : values.len > 32#usize := by scalar_tac
      have refused := enum_result_count_refusal (valuesOf values.val) (Or.inr (by simpa [values_count] using large))
      simp [nativeLarge, empty, core.slice.Slice.is_empty, refused]
    · have bounded : values.val.length ≤ 32 := by omega
      have nativeBound : ¬values.len > 32#usize := by scalar_tac
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
        nativeBound, Bool.false_or, Bool.false_eq_true, ↓reduceIte]
      unfold profile_schema.enum_schema_loop
      apply loop.spec_decr_nat
        (measure := fun state => values.val.length - state.2.val)
        (inv := fun state => state.2.val ≤ values.val.length ∧ state.1.val.length = state.2.val ∧
          enumResult (valuesOf values.val) =
            enumFold (state.1.val.map vecBytes) (valuesOf (values.val.drop state.2.val)))
      · rintro ⟨current, position⟩ invariant
        unfold profile_schema.enum_schema_loop.body
        dsimp only
        split <;> rename_i finished
        · have atEnd : values.val.length ≤ position.val := by simpa using finished
          have suffixEmpty : valuesOf (values.val.drop position.val) = [] := by
            simp [List.drop_eq_nil_of_le atEnd, valuesOf]
          rw [suffixEmpty, enumFold] at invariant
          step with ScalarProjection.Refinement.enum_schema_exact as ⟨valid, validMeaning⟩
          cases valid <;> simp_all [schemaView, Auths.Product.SchemaIndex.Refinement.namesView]
        · have inside : position.val < values.val.length := by simpa using finished
          step as ⟨value, valueAt⟩
          have suffix : valuesOf (values.val.drop position.val) =
              valueOf value :: valuesOf (values.val.drop (position.val + 1)) := by
            rw [List.drop_eq_getElem_cons inside]
            simpa [valuesOf, valueAt]
          cases value with
          | Text text =>
            step with ScalarProjection.Refinement.enum_variant_exact as ⟨allowed, allowedMeaning⟩
            cases allowed
            · have invalid : ¬EnumVariant (vecBytes text) := by
                simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using allowedMeaning.symm
              simp_all [suffix, valueOf, enumFold]
            · have admitted : EnumVariant (vecBytes text) := by
                simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using allowedMeaning.symm
              have fits : text.val.length < 4294967295 := by
                have size := admitted.2.1
                simp only [vecBytes, byteList, List.length_map] at size
                omega
              simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
              step with copy_bytes_spec as ⟨copied, copiedValue⟩
              have room : current.val.length < Usize.max := lt_usize_max (by omega)
              step as ⟨nextVariants, nextVariantsValue⟩
              step as ⟨nextPosition, nextPositionValue⟩
              refine ⟨by omega, ?_, ?_, by omega⟩
              · simp [nextVariantsValue, nextPositionValue, invariant.2.1]
              · simpa [suffix, valueOf, enumFold, admitted, nextVariantsValue,
                  nextPositionValue, List.map_append, vecBytes, byteList, copiedValue] using invariant.2.2
          | _ => simp_all [suffix, valueOf, enumFold]
      · refine ⟨by simp, by simp, ?_⟩
        simpa [valuesOf] using (enum_fold_start (valuesOf values.val)).symm

@[step] theorem parse_scalar_exact (value : profile_schema.SchemaValue) :
    profile_schema.parse_scalar value ⦃ actual =>
      actual.map schemaView = parseScalar (valueOf value) ⦄ := by
  unfold profile_schema.parse_scalar
  cases value with
  | Object members =>
    have reference := scalar_source_order_exact (membersOf members.val)
    repeat' first
      | step with member_exact
      | step with text_is_exact
      | step with one_key_exact
      | step with two_keys_exact
      | step with three_keys_exact
      | step with string_bound_exact
      | step with signed_bound_exact
      | step with enum_schema_exact
      | step with ScalarProjection.Refinement.string_schema_exact
      | step with ScalarProjection.Refinement.integer_schema_exact
      | split
    all_goals simp_all [← reference, scalarSourceOrder, valueOf, schemaView, members_count,
      kindKey, typeKey, variantsKey, minimumKey, maximumKey, enumTag, booleanTag,
      stringTag, integerTag, alloc.vec.Vec.deref, sliceBytes, vecBytes, byteList,
      Option.map_eq_none_iff, UScalar.eq_equiv, UScalar.le_equiv]
  | _ => simp [valueOf, parseScalar]

@[step] theorem parse_fields_exact (members : Slice profile_schema.SchemaMember) :
    profile_schema.parse_fields members ⦃ actual =>
      actual.map (fun fields => fieldsView (alloc.vec.Vec.deref fields)) = parseFields (membersOf members.val) ⦄ := by
  unfold profile_schema.parse_fields arguments.MAX_PROFILE_FIELDS
  by_cases empty : members.val = []
  · simp [empty, core.slice.Slice.is_empty, parseFields, membersOf]
  · by_cases large : 32 < members.val.length
    · have nativeLarge : members.len > 32#usize := by scalar_tac
      have modelLarge : 32 < (membersOf members.val).length := by simpa [members_count] using large
      simp [nativeLarge, empty, core.slice.Slice.is_empty, parseFields, modelLarge]
    · have bounded : members.val.length ≤ 32 := by omega
      have nativeBound : ¬members.len > 32#usize := by scalar_tac
      have admitted : membersOf members.val ≠ [] ∧ (membersOf members.val).length ≤ 32 := by
        refine ⟨?_, by simpa [members_count] using bounded⟩
        intro absent
        have size := congrArg List.length absent
        simp [members_count] at size
        exact empty (List.eq_nil_of_length_eq_zero size)
      simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false, nativeBound,
        Bool.false_or, Bool.false_eq_true, ↓reduceIte]
      unfold profile_schema.parse_fields_loop
      apply loop.spec_decr_nat
        (measure := fun state => members.val.length - state.2.val)
        (inv := fun state => state.2.val ≤ members.val.length ∧ state.1.val.length = state.2.val ∧
          parseFields (membersOf members.val) = fieldsFold (fieldsView (alloc.vec.Vec.deref state.1))
            (membersOf (members.val.drop state.2.val)))
      · rintro ⟨current, position⟩ invariant
        unfold profile_schema.parse_fields_loop.body
        dsimp only
        split <;> rename_i finished
        · have atEnd : members.val.length ≤ position.val := by simpa using finished
          have suffixEmpty : membersOf (members.val.drop position.val) = [] := by
            simp [List.drop_eq_nil_of_le atEnd, membersOf]
          rw [suffixEmpty, fieldsFold] at invariant
          step with field_names_exact as ⟨names, namesMeaning⟩
          cases names with
          | Err error =>
            have invalid : ¬LayoutValid (fieldsView (alloc.vec.Vec.deref current)) := by
              intro valid
              simp [valid, resultOf] at namesMeaning
            simp_all
          | Ok names =>
            have valid : LayoutValid (fieldsView (alloc.vec.Vec.deref current)) := by
              by_contra invalid
              simp [invalid, resultOf] at namesMeaning
            simp_all
        · have inside : position.val < members.val.length := by simpa using finished
          step as ⟨original, originalAt⟩
          have suffix : membersOf (members.val.drop position.val) =
              (vecBytes original.name, valueOf original.value) :: membersOf (members.val.drop (position.val + 1)) := by
            rw [List.drop_eq_getElem_cons inside]
            simpa [membersOf, originalAt]
          step with OperationIdentity.Refinement.token_exact as ⟨valid, validMeaning⟩
          cases valid
          · have invalid : OperationIdentity.validToken (vecBytes original.name) 64 ≠ true := by
              simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using validMeaning.symm
            simp_all [suffix, fieldsFold]
          · have lexical : OperationIdentity.validToken (vecBytes original.name) 64 = true := by
              simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using validMeaning.symm
            simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
            step with parse_scalar_exact as ⟨schema, schemaMeaning⟩
            cases schema with
            | none => simp_all [suffix, fieldsFold, lexical]
            | some schema =>
              have nameBound := FieldProjection.token_length (vecBytes original.name) lexical
              have fits : original.name.val.length < 4294967295 := by
                simp only [vecBytes, byteList, List.length_map] at nameBound
                omega
              step with copy_bytes_spec as ⟨copied, copiedValue⟩
              have room : current.val.length < Usize.max := lt_usize_max (by omega)
              step as ⟨nextFields, nextFieldsValue⟩
              step as ⟨nextPosition, nextPositionValue⟩
              refine ⟨by omega, ?_, ?_, by omega⟩
              · simp [nextFieldsValue, nextPositionValue, invariant.2.1]
              · simpa [suffix, fieldsFold, lexical, schemaMeaning, fieldsView,
                  nextFieldsValue, nextPositionValue, List.map_append, vecBytes,
                  byteList, copiedValue] using invariant.2.2
      · refine ⟨by simp, by simp, ?_⟩
        simpa [fieldsView] using (fields_fold_start (membersOf members.val) admitted).symm

@[step] theorem parse_root_exact (value : profile_schema.SchemaValue) :
    profile_schema.parse_root value ⦃ actual =>
      actual.map (fun fields => fieldsView (alloc.vec.Vec.deref fields)) = parseRoot (valueOf value) ⦄ := by
  unfold profile_schema.parse_root
  cases value with
  | Object members =>
    repeat' first
      | step with two_keys_exact
      | step with member_exact
      | step with text_is_exact
      | step with parse_fields_exact
      | split
    all_goals simp_all [parseRoot, valueOf, kindKey, fieldsKey, objectTag,
      alloc.vec.Vec.deref, sliceBytes, vecBytes, byteList, Option.map_eq_none_iff]
  | _ => simp [parseRoot, valueOf]

theorem source_scalar_has_exact_meaning (value : profile_schema.SchemaValue) :
    profile_schema.parse_scalar value ⦃ actual =>
      (actual = none ↔ ¬∃ schema, ScalarMeaning (valueOf value) schema) ∧
        ∀ schema, actual = some schema → ScalarMeaning (valueOf value) (schemaView schema) ⦄ := by
  apply spec_mono (parse_scalar_exact value)
  intro actual exact
  constructor
  · simpa [← exact, Option.map_eq_none_iff] using scalar_refusal_exact (valueOf value)
  · intro schema accepted
    apply (scalar_parse_exact (valueOf value) (schemaView schema)).mp
    simpa [accepted] using exact.symm

theorem source_root_has_exact_original_meaning (value : profile_schema.SchemaValue) :
    profile_schema.parse_root value ⦃ actual =>
      (actual = none ↔ ¬∃ fields, RootMeaning (valueOf value) fields) ∧
        ∀ fields, actual = some fields → RootMeaning (valueOf value) (fieldsView (alloc.vec.Vec.deref fields)) ⦄ := by
  apply spec_mono (parse_root_exact value)
  intro actual exact
  constructor
  · simpa [← exact, Option.map_eq_none_iff] using root_refusal_exact (valueOf value)
  · intro fields accepted
    apply (root_parse_exact (valueOf value) (fieldsView (alloc.vec.Vec.deref fields))).mp
    simpa [accepted] using exact.symm

theorem source_valid_profile_has_useful_acceptance (value : profile_schema.SchemaValue) (fields : List Field)
    (meaning : RootMeaning (valueOf value) fields) :
    profile_schema.parse_root value ⦃ actual => ∃ output, actual = some output ∧
      fieldsView (alloc.vec.Vec.deref output) = fields ∧ LayoutValid fields ∧
      ∀ field ∈ fields, SchemaValid field.schema ⦄ := by
  apply spec_mono (parse_root_exact value)
  intro actual exact
  have accepted := (root_parse_exact (valueOf value) fields).mpr meaning
  rw [accepted] at exact
  cases actual with
  | none => simp at exact
  | some output =>
    have same : fieldsView (alloc.vec.Vec.deref output) = fields := by simpa using exact
    have complete := root_meaning_earns_complete_valid_layout (valueOf value) fields meaning
    exact ⟨output, rfl, same, complete.2.1, complete.2.2⟩

end Auths.Product.ProfileSchema.Refinement
