import Auths.Product.NativeCompilerConsumptionInterfaces
import Auths.Product.NativeCompilerBytes
import Auths.Product.NativeCompilerRules

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

theorem native_borrowed_name_comparison (wanted first : String)
    (wantedFits : TextFits wanted) (firstFits : TextFits first) :
    AuthsNativeRecipe.NativeModel.byteOrdering (nativeTextView wanted wantedFits).val
      (nativeTextView first firstFits).val = .eq ↔ wanted = first := by
  simp only [AuthsNativeRecipe.NativeModel.byteOrdering, Std.compare_eq_iff_eq,
    ← schemaSliceBytes, native_text_view_bytes]
  exact text_bytes_injective.eq_iff

private theorem borrowed_name_contains (values : List String) (wanted : String)
    (wantedFits : TextFits wanted) (fits : ∀ value ∈ values, TextFits value) :
    AuthsNativeRecipe.NativeModel.containsBorrowed
      AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr
      AuthsNativeRecipe.Str.Insts.CoreCmpOrd (nativeTextView wanted wantedFits) values =
        ok (decide (wanted ∈ values)) := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
      have firstFits := fits first (by simp)
      have tailFits : ∀ value ∈ rest, TextFits value := fun value member => fits value (by simp [member])
      have borrow : AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr.borrow first =
          ok (nativeTextView first firstFits) := by
        simp [AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr.borrow,
          AuthsNativeRecipe.alloc.string.String.as_bytes, nativeTextView, firstFits,
          native_text_length, TextFits]
      unfold AuthsNativeRecipe.NativeModel.containsBorrowed
      rw [borrow]
      simp only [bind_tc_ok, AuthsNativeRecipe.Str.Insts.CoreCmpOrd.cmp]
      by_cases same : wanted = first
      · simp [(native_borrowed_name_comparison wanted first wantedFits firstFits).mpr same, same]
      · have different : AuthsNativeRecipe.NativeModel.byteOrdering
            (nativeTextView wanted wantedFits).val (nativeTextView first firstFits).val ≠ .eq :=
          fun equal => same ((native_borrowed_name_comparison wanted first wantedFits firstFits).mp equal)
        simp [different, ih tailFits, same]

@[step] theorem native_name_set_contains_borrowed (input : NativeNameSet) (wanted : String)
    (wantedFits : TextFits wanted) (fits : ∀ value ∈ input.elements.val, TextFits value) :
    AuthsNativeRecipe.alloc.collections.btree.set.BTreeSet.contains core.core.clone.CloneGlobal
      AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd
      AuthsNativeRecipe.Str.Insts.CoreCmpOrd input (nativeTextView wanted wantedFits) ⦃ actual =>
      actual = decide (wanted ∈ nameSet input) ⦄ := by
  simpa only [AuthsNativeRecipe.alloc.collections.btree.set.BTreeSet.contains,
    nameSet, List.mem_toFinset, spec_ok] using
    borrowed_name_contains input.elements.val wanted wantedFits fits

private theorem borrowed_rule_lookup (values : List (String × NativeScalarSchema))
    (wanted : String) (wantedFits : TextFits wanted)
    (fits : ∀ entry ∈ values, TextFits entry.1) :
    AuthsNativeRecipe.NativeModel.lookupBorrowed
      AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr
      AuthsNativeRecipe.Str.Insts.CoreCmpOrd (nativeTextView wanted wantedFits) values ⦃ actual =>
      actual.map nativeScalarMeaning = RecipeConsumption.schemaFor wanted
        (values.map fun entry => (entry.1, nativeScalarMeaning entry.2)) ⦄ := by
  induction values with
  | nil => simp [AuthsNativeRecipe.NativeModel.lookupBorrowed, RecipeConsumption.schemaFor]
  | cons first rest ih =>
      rcases first with ⟨name, schema⟩
      have nameFits := fits (name, schema) (by simp)
      have borrow : AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr.borrow name =
          ok (nativeTextView name nameFits) := by
        simp [AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr.borrow,
          AuthsNativeRecipe.alloc.string.String.as_bytes, nativeTextView, nameFits,
          native_text_length, TextFits]
      unfold AuthsNativeRecipe.NativeModel.lookupBorrowed
      rw [borrow]
      simp only [bind_tc_ok, AuthsNativeRecipe.Str.Insts.CoreCmpOrd.cmp]
      by_cases same : wanted = name
      · simp [(native_borrowed_name_comparison wanted name wantedFits nameFits).mpr same,
          same, RecipeConsumption.schemaFor]
      · have different : AuthsNativeRecipe.NativeModel.byteOrdering
            (nativeTextView wanted wantedFits).val (nativeTextView name nameFits).val ≠ .eq :=
          fun equal => same ((native_borrowed_name_comparison wanted name wantedFits nameFits).mp equal)
        simpa [different, RecipeConsumption.schemaFor, Ne.symm same] using
          ih (fun entry member => fits entry (by simp [member]))

@[step] theorem native_rule_map_lookup (input : NativeRuleMap) (wanted : String)
    (wantedFits : TextFits wanted) (fits : ∀ entry ∈ input.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.alloc.collections.btree.map.BTreeMap.get core.core.clone.CloneGlobal
      AuthsNativeRecipe.alloc.string.String.Insts.CoreBorrowBorrowStr
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd
      AuthsNativeRecipe.Str.Insts.CoreCmpOrd input (nativeTextView wanted wantedFits) ⦃ actual =>
      actual.map nativeScalarMeaning = RecipeConsumption.schemaFor wanted (nativeRuleMapMeaning input) ⦄ := by
  exact borrowed_rule_lookup input.entries.val wanted wantedFits fits

end Auths.Product.NativeCompiler.StdModel

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-- Original lexical field admission earns representability of every map key.
The map's full original association is used; no selected lookup-success flag
or caller-supplied name-length invariant substitutes for it. -/
theorem original_rule_fields_earn_name_bounds (original : List FieldProjection.Field)
    (input : NativeRuleMap) (layout : FieldProjection.LayoutValid original)
    (meaning : Rules.Meaning original (nativeRuleMapMeaning input)) :
    ∀ entry ∈ input.entries.val, entry.1.toByteArray.size ≤ 64 ∧ TextFits entry.1 := by
  intro entry member
  have projected : (entry.1, nativeScalarMeaning entry.2) ∈ nativeRuleMapMeaning input :=
    List.mem_map.mpr ⟨entry, member, rfl⟩
  obtain ⟨field, present, originalName, originalSchema⟩ :=
    Rules.meaning_has_no_extra_entries original (nativeRuleMapMeaning input) meaning
      (entry.1, nativeScalarMeaning entry.2) projected
  have length := FieldProjection.token_length field.name (layout.2.2 field present)
  have bound : entry.1.toByteArray.size ≤ 64 := by
    simpa only [← originalName, textBytes, List.length_map, ByteArray.size] using length
  exact ⟨bound, by unfold TextFits; scalar_tac⟩

@[step] theorem native_rule_fields_earn_lookup_domain (fields : Slice NativeFieldSpec)
    (layout : FieldProjection.LayoutValid (nativeFieldColumn fields)) :
    AuthsNativeRecipe.recipe.profile.rule_fields fields ⦃ actual =>
      ∃ output : NativeRuleMap, actual = .Ok output ∧
        Rules.Meaning (nativeFieldColumn fields) (nativeRuleMapMeaning output) ∧
        ∀ entry ∈ output.entries.val, entry.1.toByteArray.size ≤ 64 ∧ TextFits entry.1 ⦄ := by
  apply spec_mono (native_rule_fields_useful_layout fields layout)
  rintro actual ⟨output, same, meaning⟩
  exact ⟨output, same, meaning, original_rule_fields_earn_name_bounds _ _ layout meaning⟩

@[step] theorem native_path_field_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (wanted : String) (wantedFits : TextFits wanted)
    (fits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.Rules.path_field input (nativeTextView wanted wantedFits) ⦃ actual =>
      actual = RecipeConsumption.fieldTest RecipeConsumption.pathSchema (nativeRuleMapMeaning input.fields) wanted ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.path_field
  step with native_rule_map_lookup input.fields wanted wantedFits fits as ⟨selected, meaning⟩
  cases selected with
  | none => simp [RecipeConsumption.fieldTest, ← meaning]
  | some schema =>
      cases schema <;> simp [RecipeConsumption.fieldTest, ← meaning, nativeScalarMeaning,
        RecipeConsumption.pathSchema,
        AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.Auths_gatewayRecipeFieldSchemaRuntime.is_path_scalar]

@[step] theorem native_fact_field_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (wanted : String) (wantedFits : TextFits wanted)
    (fits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.Rules.fact_field input (nativeTextView wanted wantedFits) ⦃ actual =>
      actual = RecipeConsumption.fieldTest RecipeConsumption.factSchema (nativeRuleMapMeaning input.fields) wanted ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.fact_field
  step with native_rule_map_lookup input.fields wanted wantedFits fits as ⟨selected, meaning⟩
  cases selected with
  | none => simp [RecipeConsumption.fieldTest, ← meaning]
  | some schema =>
      cases schema <;> simp [RecipeConsumption.fieldTest, ← meaning, nativeScalarMeaning,
        RecipeConsumption.factSchema,
        AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.Auths_gatewayRecipeFieldSchemaRuntime.has_fact_form,
        AuthsNativeRecipe.auths_model.observation.MAX_FACT_VALUE_TEXT_BYTES,
        UScalar.le_equiv, IScalar.le_equiv]

@[step] theorem native_text_fact_field_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (wanted : String) (wantedFits : TextFits wanted)
    (fits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.Rules.text_fact_field input (nativeTextView wanted wantedFits) ⦃ actual =>
      actual = RecipeConsumption.fieldTest RecipeConsumption.textFactSchema (nativeRuleMapMeaning input.fields) wanted ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.text_fact_field
  step with native_rule_map_lookup input.fields wanted wantedFits fits as ⟨selected, meaning⟩
  cases selected with
  | none => simp [RecipeConsumption.fieldTest, ← meaning]
  | some schema =>
      cases schema <;> simp [RecipeConsumption.fieldTest, ← meaning, nativeScalarMeaning,
        RecipeConsumption.textFactSchema,
        AuthsNativeRecipe.auths_gateway_kernel.scalars.ScalarSchema.Insts.Auths_gatewayRecipeFieldSchemaRuntime.has_fact_form,
        AuthsNativeRecipe.auths_model.observation.MAX_FACT_VALUE_TEXT_BYTES, UScalar.le_equiv]

@[step] theorem native_integer_field_exact (input : AuthsNativeRecipe.recipe.validate.Rules)
    (wanted : String) (wantedFits : TextFits wanted)
    (fits : ∀ entry ∈ input.fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.Rules.integer_field input (nativeTextView wanted wantedFits) ⦃ actual =>
      actual = RecipeConsumption.fieldTest RecipeConsumption.integerSchema (nativeRuleMapMeaning input.fields) wanted ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.Rules.integer_field
  step with native_rule_map_lookup input.fields wanted wantedFits fits as ⟨selected, meaning⟩
  cases selected with
  | none => simp [RecipeConsumption.fieldTest, ← meaning]
  | some schema =>
      cases schema <;> simp [RecipeConsumption.fieldTest, ← meaning,
        nativeScalarMeaning, RecipeConsumption.integerSchema]

end Auths.Product.NativeCompiler.Refinement
