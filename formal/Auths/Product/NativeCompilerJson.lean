import Auths.Product.NativeCompilerContainers
import qualification.aeneas.generated.native_recipe.Funs

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

/- The private loop lemmas take child specifications only to perform structural
induction. The public native-source theorem below discharges those premises from
the original input's own recursive bounds; it assumes no converter result. -/
private theorem array_suffix
    (values : Slice Json) (position : Std.Usize) (output : NativeVec SchemaNode)
    (copies : ∀ value ∈ values.val,
      AuthsNativeRecipe.recipe.profile.schema_value value ⦃ actual => JsonCopy value actual ⦄)
    (positionBound : position.val ≤ values.val.length)
    (room : output.val.length + (values.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.recipe.profile.schema_array_loop values output position ⦃ actual =>
      ∃ suffix, actual.val = output.val ++ suffix ∧
        JsonCopies (values.val.drop position.val) suffix ⦄ := by
  generalize remaining : values.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.profile.schema_array_loop
    split <;> rename_i within
    · have inside : position.val < values.val.length := by simpa using within
      step with Slice.index_usize_spec values position inside as ⟨value, valueAt⟩
      have member : value ∈ values.val := by
        rw [valueAt]
        exact List.getElem_mem inside
      step with copies value member as ⟨copied, copiedMeaning⟩
      have capacity : output.val.length < Usize.max := by omega
      step with native_push_exact output copied capacity as ⟨updated, appended⟩
      have updatedLength : updated.val.length = output.val.length + 1 := by simp only [appended, List.length_append, List.length_singleton]
      step as ⟨next, nextValue⟩
      have nextBound : next.val ≤ values.val.length := by omega
      have nextRoom : updated.val.length + (values.val.length - next.val) ≤ Usize.max := by omega
      have smaller : values.val.length - next.val < count := by omega
      apply spec_mono (ih _ smaller next updated nextBound nextRoom rfl)
      rintro actual ⟨suffix, exactSuffix, suffixCopy⟩
      refine ⟨copied :: suffix, ?_, ?_⟩
      · simpa only [appended, List.append_assoc, List.singleton_append] using exactSuffix
      · have original : values.val.drop position.val = value :: values.val.drop next.val := by
          simpa only [nextValue, valueAt] using List.drop_eq_getElem_cons inside
        rw [original]
        exact .cons copiedMeaning suffixCopy
    · have done : position.val = values.val.length := by
        have ended : values.val.length ≤ position.val := by simpa using within
        omega
      simp only [spec_ok]
      exact ⟨[], by simp, by simpa only [done, List.drop_length] using JsonCopies.nil⟩

private theorem member_suffix
    (iterator : AuthsNativeRecipe.serde_json.map.Iter) (output : NativeVec SchemaMember)
    (names : ∀ pair ∈ iterator.val, TextFits pair.1)
    (copies : ∀ pair ∈ iterator.val,
      AuthsNativeRecipe.recipe.profile.schema_value pair.2 ⦃ actual => JsonCopy pair.2 actual ⦄)
    (room : output.val.length + iterator.val.length ≤ Usize.max) :
    AuthsNativeRecipe.recipe.profile.schema_members_loop iterator output ⦃ actual =>
      ∃ suffix, actual.val = output.val ++ suffix ∧ MemberCopies iterator.val suffix ⦄ := by
  generalize remaining : iterator.val.length = count
  induction count using Nat.strong_induction_on generalizing iterator output with
  | h count ih =>
    unfold AuthsNativeRecipe.recipe.profile.schema_members_loop
    simp only [AuthsNativeRecipe.serde_json.map.Iter.Insts.CoreIterTraitsIteratorIteratorPairSharedAStringSharedAValue.next]
    step with next_pair_exact iterator as ⟨next, nextMeaning⟩
    cases original : iterator.val with
    | nil =>
        have ended : next.1 = none := (by simpa only [original] using nextMeaning).1
        simp only [ended, spec_ok]
        exact ⟨[], by simp, by simpa only [original] using MemberCopies.nil⟩
    | cons pair rest =>
        obtain ⟨headAt, tailAt⟩ : next.1 = some pair ∧ next.2.val = rest := by
          simpa only [original] using nextMeaning
        simp only [headAt]
        have headMember : pair ∈ iterator.val := by simp only [original, List.mem_cons]; exact Or.inl rfl
        step with borrow_text_exact pair.1 (names pair headMember) as ⟨rawName, rawMeaning⟩
        step with copy_u8_exact rawName as ⟨copiedName, copiedNameMeaning⟩
        step with copies pair headMember as ⟨copiedValue, copiedValueMeaning⟩
        let member : SchemaMember := .mk copiedName copiedValue
        have capacity : output.val.length < Usize.max := by simp only [original, List.length_cons] at room; omega
        step with native_push_exact output member capacity as ⟨updated, appended⟩
        have updatedLength : updated.val.length = output.val.length + 1 := by simp only [appended, List.length_append, List.length_singleton]
        have nextNames : ∀ pair ∈ next.2.val, TextFits pair.1 := by
          intro other belongs
          apply names other
          simp only [original, List.mem_cons]
          exact Or.inr (by simpa only [tailAt] using belongs)
        have nextCopies : ∀ pair ∈ next.2.val,
            AuthsNativeRecipe.recipe.profile.schema_value pair.2 ⦃ actual => JsonCopy pair.2 actual ⦄ := by
          intro other belongs
          apply copies other
          simp only [original, List.mem_cons]
          exact Or.inr (by simpa only [tailAt] using belongs)
        have nextRoom : updated.val.length + next.2.val.length ≤ Usize.max := by
          simp only [original, List.length_cons] at room
          simp only [tailAt]
          omega
        have smaller : next.2.val.length < count := by simp only [tailAt, original, List.length_cons] at *; omega
        apply spec_mono (ih _ smaller next.2 updated nextNames nextCopies nextRoom rfl)
        rintro actual ⟨suffix, exactSuffix, suffixCopy⟩
        refine ⟨member :: suffix, ?_, ?_⟩
        · simpa only [appended, List.append_assoc, List.singleton_append] using exactSuffix
        · rw [original]
          apply MemberCopies.cons
          · exact copiedNameMeaning.trans rawMeaning
          · exact copiedValueMeaning
          · simpa only [tailAt] using suffixCopy

/-- The shipping native conversion retains every original JSON kind, name and
child in the complete schema AST. This covers all represented recursive input
shapes, with no schema-validity flag, desired AST, successful parser or depth fuel.
The domain is only native string representability, earned separately at entry. -/
@[step] theorem native_schema_copy (input : Json) (bounded : JsonBounds input) :
    AuthsNativeRecipe.recipe.profile.schema_value input ⦃ actual => JsonCopy input actual ⦄ := by
  induction bounded with
  | null => simp [AuthsNativeRecipe.recipe.profile.schema_value, JsonCopy.null]
  | boolean value => simp [AuthsNativeRecipe.recipe.profile.schema_value, JsonCopy.boolean]
  | number value =>
    cases value with
    | Float bits =>
        simp [AuthsNativeRecipe.recipe.profile.schema_value,
          AuthsNativeRecipe.serde_json.number.Number.as_i64,
          AuthsNativeRecipe.serde_json.number.Number.as_u64, JsonCopy.float]
    | NegInt value =>
        simp [AuthsNativeRecipe.recipe.profile.schema_value,
          AuthsNativeRecipe.serde_json.number.Number.as_i64, JsonCopy.negative]
    | PosInt value =>
        by_cases fits : value.val ≤ 9223372036854775807
        · simp only [AuthsNativeRecipe.recipe.profile.schema_value,
            AuthsNativeRecipe.serde_json.number.Number.as_i64, dif_pos fits, bind_tc_ok, spec_ok]
          exact .smallPositive value _ fits rfl
        · simp only [AuthsNativeRecipe.recipe.profile.schema_value,
            AuthsNativeRecipe.serde_json.number.Number.as_i64, dif_neg fits,
            AuthsNativeRecipe.serde_json.number.Number.as_u64, bind_tc_ok, spec_ok]
          exact .largePositive value (by omega)
  | text value fits =>
      unfold AuthsNativeRecipe.recipe.profile.schema_value
      step with borrow_text_exact value fits as ⟨raw, rawMeaning⟩
      step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
      exact .text value copied (copiedMeaning.trans rawMeaning)
  | array values children ih =>
      unfold AuthsNativeRecipe.recipe.profile.schema_value AuthsNativeRecipe.recipe.profile.schema_array
      have childCopies : ∀ value ∈ (AuthsNativeRecipe.alloc.vec.Vec.deref values).val,
          AuthsNativeRecipe.recipe.profile.schema_value value ⦃ actual => JsonCopy value actual ⦄ := by
        simpa only [native_deref_contents] using ih
      step with array_suffix (AuthsNativeRecipe.alloc.vec.Vec.deref values) 0#usize
        (AuthsNativeRecipe.alloc.vec.Vec.new SchemaNode) childCopies
        (by simp) (by simpa using values.property) as ⟨output, suffix, exactOutput, copied⟩
      have outputIsSuffix : output.val = suffix := by simpa only [native_empty_contents, List.nil_append] using exactOutput
      have originalCopies : JsonCopies values.val suffix := by
        simpa only [native_deref_contents, List.drop_zero] using copied
      have fullCopy : JsonCopies values.val output.val := by
        simpa only [outputIsSuffix] using originalCopies
      exact .array values output fullCopy
  | object members names children ih =>
      unfold AuthsNativeRecipe.recipe.profile.schema_value AuthsNativeRecipe.recipe.profile.schema_members
      simp only [AuthsNativeRecipe.SharedAMapStringValue.Insts.CoreIterTraitsCollectIntoIteratorPairSharedAStringSharedAValueIter.into_iter,
        bind_tc_ok]
      step with member_suffix members.entries (AuthsNativeRecipe.alloc.vec.Vec.new SchemaMember)
        names ih (by simpa using members.entries.property) as ⟨output, suffix, exactOutput, copied⟩
      have outputIsSuffix : output.val = suffix := by simpa only [native_empty_contents, List.nil_append] using exactOutput
      exact .object members output (by simpa only [outputIsSuffix] using copied)

/-- Composition with original decoded meaning earns the independent schema
interpretation from the actual native result. No interpretation is supplied by
the caller, and every original nested pair/child is included. -/
theorem native_schema_has_original_meaning (input : Json) (bounded : JsonBounds input) :
    AuthsNativeRecipe.recipe.profile.schema_value input ⦃ actual =>
      ∃ meaning, JsonMeaning input meaning ∧ SchemaMeaning actual meaning ⦄ := by
  apply spec_mono (native_schema_copy input bounded)
  intro actual copied
  exact copy_has_original_meaning copied

theorem native_object_retains_complete_name_column (members : JsonMap)
    (names : ∀ pair ∈ members.entries.val, TextFits pair.1)
    (children : ∀ pair ∈ members.entries.val, JsonBounds pair.2) :
    AuthsNativeRecipe.recipe.profile.schema_value (.Object members) ⦃ actual =>
      ∃ output : NativeVec SchemaMember,
        actual = .Object output ∧ output.val.length = members.entries.val.length ∧
        output.val.map (fun member => bytes member.name) = members.entries.val.map (fun pair => textBytes pair.1) ⦄ := by
  apply spec_mono (native_schema_copy (.Object members) (.object members names children))
  intro actual copied
  cases copied with
  | object _ output children => exact ⟨output, rfl, copied_member_count children, copied_member_names children⟩

theorem native_array_retains_complete_child_count (values : NativeVec Json)
    (children : ∀ value ∈ values.val, JsonBounds value) :
    AuthsNativeRecipe.recipe.profile.schema_value (.Array values) ⦃ actual =>
      ∃ output : NativeVec SchemaNode,
        actual = .Array output ∧ output.val.length = values.val.length ⦄ := by
  apply spec_mono (native_schema_copy (.Array values) (.array values children))
  intro actual copied
  cases copied with
  | array _ output children => exact ⟨output, rfl, copied_array_count children⟩

/-- Conversion has a real result and an original-source meaning. This supplies
the model witness from native execution rather than taking a desired converted
value, successful decoder or already accepted schema as a premise. -/
theorem native_conversion_earns_independent_meaning (input : Json) (bounded : JsonBounds input) :
    ∃ actual meaning,
      AuthsNativeRecipe.recipe.profile.schema_value input = ok actual ∧
      JsonMeaning input meaning ∧ SchemaMeaning actual meaning := by
  obtain ⟨actual, evaluates, meaning, original, target⟩ :=
    spec_imp_exists (native_schema_has_original_meaning input bounded)
  exact ⟨actual, meaning, evaluates, original, target⟩

theorem native_float_never_becomes_a_schema_integer (bits : Std.U64) :
    AuthsNativeRecipe.recipe.profile.schema_value (.Number (.Float bits)) = ok .Unsupported := by
  simp [AuthsNativeRecipe.recipe.profile.schema_value,
    AuthsNativeRecipe.serde_json.number.Number.as_i64,
    AuthsNativeRecipe.serde_json.number.Number.as_u64]

end Auths.Product.NativeCompiler.Refinement
