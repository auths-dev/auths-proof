import Auths.Product.ProfileSchemaCorrectness
import Auths.Product.FieldProjectionRefinement

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity
open Auths.Product.ScalarProjection.Dispatch
open Auths.Product.FieldProjection.Refinement

namespace Auths.Product.ProfileSchema.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/-! These authored source bodies require actual extraction/ABI inspection and
elaboration/repairs at the final validation phase. Native serde/JSON conversion
and the complete parser loops remain separate obligations. -/

mutual
  def valueOf : profile_schema.SchemaValue → Value
    | .Text bytes => .text (vecBytes bytes)
    | .Signed value => .signed value.val
    | .Unsigned value => .unsigned value.val
    | .Array values => .array (valuesOf values.val)
    | .Object members => .object (membersOf members.val)
    | .Unsupported => .unsupported
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf [alloc.vec.Vec]

  def valuesOf : List profile_schema.SchemaValue → List Value
    | [] => []
    | value :: rest => valueOf value :: valuesOf rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf

  def membersOf : List profile_schema.SchemaMember → List (Bytes × Value)
    | [] => []
    | .mk name value :: rest => (vecBytes name, valueOf value) :: membersOf rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf
end

theorem members_count (members : List profile_schema.SchemaMember) :
    (membersOf members).length = members.length := by
  induction members with
  | nil => rfl
  | cons member rest ih => cases member; simp [membersOf, ih]

theorem values_count (values : List profile_schema.SchemaValue) :
    (valuesOf values).length = values.length := by
  induction values with
  | nil => rfl
  | cons value rest ih => simp [valuesOf, ih]

theorem members_drop (members : List profile_schema.SchemaMember) (position : Nat) :
    membersOf (members.drop position) = (membersOf members).drop position := by
  induction members generalizing position with
  | nil => simp [membersOf]
  | cons member rest ih => cases position <;> cases member <;> simp [membersOf, ih]

theorem values_drop (values : List profile_schema.SchemaValue) (position : Nat) :
    valuesOf (values.drop position) = (valuesOf values).drop position := by
  induction values generalizing position with
  | nil => simp [valuesOf]
  | cons value rest ih => cases position <;> simp [valuesOf, ih]

private theorem bytes_exact (left right : Slice Std.U8) :
    construct.field_name_equal left right ⦃ actual =>
      actual = decide (sliceBytes left = sliceBytes right) ⦄ := by
  simpa only [sliceBytes, byteList_inj] using field_name_equal_exact left right

@[step] theorem member_exact (members : Slice profile_schema.SchemaMember) (wanted : Slice Std.U8) :
    profile_schema.member members wanted ⦃ actual =>
      actual.map valueOf = member (sliceBytes wanted) (membersOf members.val) ⦄ := by
  unfold profile_schema.member profile_schema.member_loop
  apply loop.spec_decr_nat
    (measure := fun position => members.val.length - position.val)
    (inv := fun position => position.val ≤ members.val.length ∧
      member (sliceBytes wanted) (membersOf members.val) =
        member (sliceBytes wanted) (membersOf (members.val.drop position.val)))
  · intro position invariant
    unfold profile_schema.member_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : position.val < members.val.length := by simpa using within
      step as ⟨current, currentAt⟩
      have suffix : membersOf (members.val.drop position.val) =
          (vecBytes current.name, valueOf current.value) :: membersOf (members.val.drop (position.val + 1)) := by
        rw [List.drop_eq_getElem_cons inside]
        simpa [membersOf, currentAt]
      step with bytes_exact as ⟨same, sameMeaning⟩
      cases same
      · have different : vecBytes current.name ≠ sliceBytes wanted := by
          simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using sameMeaning.symm
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        simpa [suffix, member, different, nextValue] using invariant.2
      · have equal : vecBytes current.name = sliceBytes wanted := by
          simpa [alloc.vec.Vec.deref, sliceBytes, vecBytes] using sameMeaning.symm
        simp only [spec_ok, Option.map_some]
        simpa [suffix, member, equal] using invariant.2.symm
    · have finished : members.val.length ≤ position.val := by simpa using within
      simpa [List.drop_eq_nil_of_le finished, membersOf, member] using invariant.2.symm
  · exact ⟨by simp, by simp⟩

@[step] theorem text_is_exact (value : Option profile_schema.SchemaValue) (expected : Slice Std.U8) :
    profile_schema.text_is value expected ⦃ actual =>
      actual = decide (value.map valueOf = some (.text (sliceBytes expected))) ⦄ := by
  cases value with
  | none => simp [profile_schema.text_is]
  | some value =>
    cases value with
    | Text bytes =>
      unfold profile_schema.text_is
      step with bytes_exact as ⟨actual, meaning⟩
      simpa [valueOf, alloc.vec.Vec.deref, sliceBytes, vecBytes] using meaning
    | _ => simp [profile_schema.text_is, valueOf]

@[step] theorem one_key_exact (members : Slice profile_schema.SchemaMember) (first : Slice Std.U8) :
    profile_schema.one_key members first ⦃ actual =>
      actual = decide (ExactKeys (membersOf members.val) [sliceBytes first]) ⦄ := by
  have independent := exact_keys_from_presence (membersOf members.val) [sliceBytes first] (by simp)
  unfold profile_schema.one_key
  repeat' first | step with member_exact | split
  all_goals simp_all [independent, members_count, Option.map_eq_none_iff, UScalar.eq_equiv]

@[step] theorem two_keys_exact (members : Slice profile_schema.SchemaMember) (first second : Slice Std.U8)
    (distinct : sliceBytes first ≠ sliceBytes second) :
    profile_schema.two_keys members first second ⦃ actual =>
      actual = decide (ExactKeys (membersOf members.val) [sliceBytes first, sliceBytes second]) ⦄ := by
  have independent := exact_keys_from_presence (membersOf members.val)
    [sliceBytes first, sliceBytes second] (by simp [distinct])
  unfold profile_schema.two_keys
  repeat' first | step with member_exact | split
  all_goals simp_all [independent, members_count, Option.map_eq_none_iff, UScalar.eq_equiv]

@[step] theorem three_keys_exact (members : Slice profile_schema.SchemaMember) (first second third : Slice Std.U8)
    (distinct : ([sliceBytes first, sliceBytes second, sliceBytes third] : List Bytes).Nodup) :
    profile_schema.three_keys members first second third ⦃ actual =>
      actual = decide (ExactKeys (membersOf members.val) [sliceBytes first, sliceBytes second, sliceBytes third]) ⦄ := by
  have independent := exact_keys_from_presence (membersOf members.val)
    [sliceBytes first, sliceBytes second, sliceBytes third] distinct
  unfold profile_schema.three_keys
  repeat' first | step with member_exact | split
  all_goals simp_all [independent, members_count, Option.map_eq_none_iff, UScalar.eq_equiv]

@[step] theorem string_bound_exact (value : Option profile_schema.SchemaValue) :
    profile_schema.string_bound value ⦃ actual =>
      actual.map UScalar.val = stringBound (value.map valueOf) ⦄ := by
  cases value with
  | none => simp [profile_schema.string_bound, stringBound]
  | some value =>
    cases value <;> simp only [profile_schema.string_bound, valueOf, Option.map_some]
    all_goals first
      | simp [stringBound, numeric]
      | (split_ifs <;> simp_all [stringBound, numeric] <;> scalar_tac)

@[step] theorem signed_bound_exact (value : Option profile_schema.SchemaValue) :
    profile_schema.signed_bound value ⦃ actual =>
      actual.map IScalar.val = signedBound (value.map valueOf) ⦄ := by
  cases value with
  | none => simp [profile_schema.signed_bound, signedBound]
  | some value =>
    cases value <;> simp only [profile_schema.signed_bound, valueOf, Option.map_some]
    all_goals first
      | simp [signedBound]
      | (split_ifs <;> simp_all [signedBound, UScalar.le_equiv] <;> scalar_tac)

@[step] theorem binding_fields_match_exact (fields : Slice field_projection.FieldSpec) (namespaceBytes : Slice Std.U8) :
    profile_schema.binding_fields_match fields namespaceBytes ⦃ actual =>
      actual = bindingFieldsMatch (fieldsView fields) (sliceBytes namespaceBytes) ⦄ := by
  unfold profile_schema.binding_fields_match
  step with schema_for_exact as ⟨namespaceSchema, namespaceMeaning⟩
  cases namespaceSchema with
  | none => simp_all [bindingFieldsMatch, namespaceName]
  | some namespaceSchema =>
    cases namespaceSchema with
    | Enum variants =>
      by_cases singleton : variants.val.length = 1
      · obtain ⟨name, original⟩ := List.length_eq_one.mp singleton
        simp only [original] at *
        step with bytes_exact as ⟨same, sameMeaning⟩
        cases same
        · simp_all [bindingFieldsMatch, schemaView, namespaceName, alloc.vec.Vec.deref, sliceBytes, vecBytes]
        · step with schema_for_exact as ⟨operationSchema, operationMeaning⟩
          cases operationSchema with
          | none => simp_all [bindingFieldsMatch, schemaView, namespaceName, operationName]
          | some operationSchema =>
            cases operationSchema with
            | String minimum maximum =>
              split_ifs <;>
                try { simp_all [bindingFieldsMatch, schemaView, namespaceName, operationName,
                  alloc.vec.Vec.deref, sliceBytes, vecBytes, UScalar.le_equiv] }
              step with schema_for_exact as ⟨digestSchema, digestMeaning⟩
              cases digestSchema with
              | none => simp_all [bindingFieldsMatch, schemaView, namespaceName, operationName, digestName]
              | some digestSchema =>
                cases digestSchema <;> simp_all [bindingFieldsMatch, schemaView, namespaceName,
                  operationName, digestName, alloc.vec.Vec.deref, sliceBytes, vecBytes,
                  UScalar.eq_equiv, UScalar.le_equiv]
            | _ => simp_all [bindingFieldsMatch, schemaView, namespaceName, operationName]
      · simp_all [bindingFieldsMatch, schemaView, namespaceName, UScalar.eq_equiv]
    | _ => simp_all [bindingFieldsMatch, schemaView, namespaceName]

theorem source_reserved_binding_exact (fields : Slice field_projection.FieldSpec) (namespaceBytes : Slice Std.U8) :
    profile_schema.binding_fields_match fields namespaceBytes ⦃ actual =>
      actual = true ↔ BindingFields (fieldsView fields) (sliceBytes namespaceBytes) ⦄ := by
  apply spec_mono (binding_fields_match_exact fields namespaceBytes)
  intro actual exact
  rw [exact]
  exact binding_boolean_exact _ _

end Auths.Product.ProfileSchema.Refinement
