import Auths.Product.NativeCompilerConsumption
import Auths.Product.RecipeRuleProperties

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

/-- Internal induction domain, earned initially from the original field map
and the actual empty ledger. It contains representation, finite storage and
original-field containment facts, not an accepted-source or validator flag. -/
structure RuleStateDomain (input : AuthsNativeRecipe.recipe.validate.Rules) : Prop where
  fieldCount : input.fields.entries.val.length ≤ 32
  fieldNames : ∀ entry ∈ input.fields.entries.val, TextFits entry.1
  ordered : ConsumptionOrdered input.consumed
  known : RecipeConsumption.WellFormed (nativeRuleMapMeaning input.fields) (consumptionState input.consumed)

theorem rule_state_storage (input : AuthsNativeRecipe.recipe.validate.Rules) (domain : RuleStateDomain input) :
    input.consumed.all.elements.val.length ≤ 32 ∧ input.consumed.body.elements.val.length ≤ 32 ∧
      input.consumed.binds.elements.val.length ≤ 32 := by
  have count : (nativeRuleMapMeaning input.fields).length ≤ 32 := by
    simpa [nativeRuleMapMeaning] using domain.fieldCount
  have all := StdModel.native_name_set_storage_bound input.consumed.all _ domain.ordered.1 domain.known.1
  have body := StdModel.native_name_set_storage_bound input.consumed.body _ domain.ordered.2.1
    (domain.known.2.1.trans domain.known.1)
  have binds := StdModel.native_name_set_storage_bound input.consumed.binds _ domain.ordered.2.2
    (domain.known.2.2.trans domain.known.1)
  exact ⟨all.trans count, body.trans count, binds.trans count⟩

theorem rule_state_transfer (before after : AuthsNativeRecipe.recipe.validate.Rules)
    (domain : RuleStateDomain before) (fields : after.fields = before.fields)
    (ordered : ConsumptionOrdered after.consumed)
    (known : RecipeConsumption.WellFormed (nativeRuleMapMeaning before.fields) (consumptionState after.consumed)) :
    RuleStateDomain after := by
  exact ⟨by simpa [fields] using domain.fieldCount,
    by simpa [fields] using domain.fieldNames, ordered, by simpa [fields] using known⟩

theorem rule_state_names_fit (input : AuthsNativeRecipe.recipe.validate.Rules) (domain : RuleStateDomain input) :
    (∀ name ∈ input.consumed.all.elements.val, TextFits name) ∧
    (∀ name ∈ input.consumed.body.elements.val, TextFits name) ∧
    (∀ name ∈ input.consumed.binds.elements.val, TextFits name) := by
  have original (name : String) (member : name ∈ (consumptionState input.consumed).all) : TextFits name := by
    have known := domain.known.1 member
    have nativeKeys : name ∈ input.fields.entries.val.map Prod.fst := by
      simpa [nativeRuleMapMeaning, List.map_map] using known
    obtain ⟨entry, present, same⟩ := List.mem_map.mp nativeKeys
    simpa only [same] using domain.fieldNames entry present
  refine ⟨?_, ?_, ?_⟩
  · intro name member
    exact original name (by simpa [consumptionState, nameSet] using member)
  · intro name member
    exact original name (domain.known.2.1 (by simpa [consumptionState, nameSet] using member))
  · intro name member
    exact original name (domain.known.2.2 (by simpa [consumptionState, nameSet] using member))

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

/-- The real default constructor earns the ledger part of the induction
domain; field-map size/name premises are facts supplied by its original parser
and lossless map builder, not an assumed successful body/rule validation. -/
@[step] theorem native_initial_rule_state (fields : NativeRuleMap)
    (count : fields.entries.val.length ≤ 32)
    (names : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    AuthsNativeRecipe.recipe.validate.Consumption.Insts.CoreDefaultDefault.default ⦃ actual =>
      RuleStateDomain ⟨fields, actual⟩ ⦄ := by
  apply spec_mono native_consumption_default
  rintro actual ⟨empty, ordered⟩
  refine ⟨count, names, ordered, ?_⟩
  rw [empty]
  exact RecipeConsumption.empty_well_formed _

end Auths.Product.NativeCompiler.Refinement
