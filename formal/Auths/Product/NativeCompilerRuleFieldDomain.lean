import Auths.Product.NativeCompilerFieldLookup
import Auths.Product.NativeCompilerSchemaRoot
import Auths.Product.NativeCompilerRuleState

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

theorem original_rule_map_count (original : List FieldProjection.Field) (fields : NativeRuleMap)
    (layout : FieldProjection.LayoutValid original)
    (meaning : Rules.Meaning original (nativeRuleMapMeaning fields)) : fields.entries.val.length ≤ 32 := by
  have complete := Rules.meaning_keeps_complete_count original (nativeRuleMapMeaning fields) meaning
  have sameCount : fields.entries.val.length = original.length := by simpa [nativeRuleMapMeaning] using complete
  exact sameCount.symm ▸ layout.1

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

/-- The actual rule-map builder earns the exact field count and all original
name bounds. These are the source-rule induction inputs, not assertions about
an arbitrary map supplied by a successful validator. -/
@[step] theorem native_rule_fields_earn_source_domain (fields : Slice NativeFieldSpec)
    (layout : FieldProjection.LayoutValid (nativeFieldColumn fields)) :
    AuthsNativeRecipe.recipe.profile.rule_fields fields ⦃ actual =>
      ∃ output : NativeRuleMap, actual = .Ok output ∧
        Rules.Meaning (nativeFieldColumn fields) (nativeRuleMapMeaning output) ∧
        output.entries.val.length ≤ 32 ∧ ∀ entry ∈ output.entries.val, TextFits entry.1 ⦄ := by
  apply spec_mono (native_rule_fields_earn_lookup_domain fields layout)
  rintro actual ⟨output, same, meaning, names⟩
  exact ⟨output, same, meaning, original_rule_map_count _ _ layout meaning,
    fun entry member => (names entry member).2⟩

/-- All parser outcomes are retained. A successful original JSON parse earns
layout/uniqueness and thus useful construction of the bounded original map.
Binding/namespace installation checks remain at the actual constructor caller. -/
@[step] theorem native_profile_root_earns_rule_map_domain (input : Json) (bounded : JsonBounds input)
    (original : ProfileSchema.Value) (meaning : JsonMeaning input original) :
    AuthsNativeRecipe.recipe.parse_root_fields input ⦃ actual =>
      match actual with
      | .Err error => error = .InvalidProfileLock ∧ ¬∃ fields, ProfileSchema.RootMeaning original fields
      | .Ok fields => ProfileSchema.RootMeaning original (nativeFieldsMeaning fields) ∧
          (AuthsNativeRecipe.recipe.profile.rule_fields (AuthsNativeRecipe.alloc.vec.Vec.deref fields) ⦃ built =>
            ∃ output : NativeRuleMap, built = .Ok output ∧
              Rules.Meaning (nativeFieldsMeaning fields) (nativeRuleMapMeaning output) ∧
              output.entries.val.length ≤ 32 ∧ ∀ entry ∈ output.entries.val, TextFits entry.1 ⦄) ⦄ := by
  unfold AuthsNativeRecipe.recipe.parse_root_fields
  apply spec_mono (native_profile_root_has_exact_semantics input bounded original meaning)
  intro actual semantic
  cases actual with
  | Err error => exact semantic
  | Ok fields =>
      have layout := (ProfileSchema.root_meaning_earns_complete_valid_layout original (nativeFieldsMeaning fields) semantic).2.1
      refine ⟨semantic, ?_⟩
      simpa [nativeFieldColumn, nativeFieldsMeaning, native_deref_contents] using
        native_rule_fields_earn_source_domain (AuthsNativeRecipe.alloc.vec.Vec.deref fields) layout

end Auths.Product.NativeCompiler.Refinement
