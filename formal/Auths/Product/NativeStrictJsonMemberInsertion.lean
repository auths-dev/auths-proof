import Auths.Product.StrictJsonMemberCorrectness
import Auths.Product.NativeCompilerConsumptionInterfaces
import qualification.aeneas.generated.native_recipe.Funs

/-!
The shipping strict visitor's exact decoded-name insertion root is newly
selected for final native generation. The generated unit must be refreshed;
no generated definition or successful qualification is authored here. The
ordinary set/String-order and byte-parser adequacy obligations remain explicit.
-/
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

/-- All original decoded Strings participate in the actual set decision.
Empty/Unicode/NUL names are not normalized or subjected to Auths field grammar.
Refusal is duplicate detection only; typed/source admission remains separate. -/
@[step] theorem native_strict_member_insert_exact (seen : NativeNameSet) (name : String)
    (ordered : NameSetOrdered seen) (room : seen.elements.val.length < Usize.max) :
    AuthsNativeRecipe.recipe.strict_json.insert_member_name seen name ⦃ actual =>
      actual.1 = decide (name ∉ nameSet seen) ∧ nameSet actual.2 = insert name (nameSet seen) ∧
      NameSetOrdered actual.2 ∧ actual.2.elements.val.length = seen.elements.val.length + (if actual.1 then 1 else 0) ∧
      (∀ value ∈ actual.2.elements.val, value = name ∨ value ∈ seen.elements.val) ⦄ := by
  simpa [AuthsNativeRecipe.recipe.strict_json.insert_member_name] using native_name_set_insert seen name ordered room

theorem native_strict_duplicate_keeps_prefix (seen : NativeNameSet) (name : String)
    (ordered : NameSetOrdered seen) (room : seen.elements.val.length < Usize.max) (repeated : name ∈ nameSet seen) :
    AuthsNativeRecipe.recipe.strict_json.insert_member_name seen name ⦃ actual =>
      actual.1 = false ∧ nameSet actual.2 = nameSet seen ∧
      actual.2.elements.val.length = seen.elements.val.length ∧ NameSetOrdered actual.2 ⦄ := by
  apply spec_mono (native_strict_member_insert_exact seen name ordered room)
  rintro actual ⟨decision, members, nextOrder, count, _⟩
  have refused : actual.1 = false := by simpa [repeated] using decision
  exact ⟨refused, by simpa only [Finset.insert_eq_of_mem repeated] using members,
    by simpa [refused] using count, nextOrder⟩

theorem native_strict_fresh_name_grows_once (seen : NativeNameSet) (name : String)
    (ordered : NameSetOrdered seen) (room : seen.elements.val.length < Usize.max) (fresh : name ∉ nameSet seen) :
    AuthsNativeRecipe.recipe.strict_json.insert_member_name seen name ⦃ actual =>
      actual.1 = true ∧ nameSet actual.2 = insert name (nameSet seen) ∧
      actual.2.elements.val.length = seen.elements.val.length + 1 ∧ NameSetOrdered actual.2 ⦄ := by
  apply spec_mono (native_strict_member_insert_exact seen name ordered room)
  rintro actual ⟨decision, members, nextOrder, count, _⟩
  have accepted : actual.1 = true := by simpa [fresh] using decision
  exact ⟨accepted, members, by simpa [accepted] using count, nextOrder⟩

/-- The actual decoded-name insertion earns the exact original structural
checker continuation, including all child/rest successes and refusals. This
does not stand in for serde token/visitor/EOF or typed-deserializer adequacy. -/
theorem native_strict_member_original_continuation (seen : NativeNameSet) (name : String)
    (ordered : NameSetOrdered seen) (room : seen.elements.val.length < Usize.max)
    (child : StrictJsonMembers.Value) (rest : List (String × StrictJsonMembers.Value)) :
    AuthsNativeRecipe.recipe.strict_json.insert_member_name seen name ⦃ actual =>
      StrictJsonMembers.memberContinuation actual.1 (nameSet actual.2) child rest =
        StrictJsonMembers.checkMembers (nameSet seen) ((name, child) :: rest) ⦄ := by
  apply spec_mono (native_strict_member_insert_exact seen name ordered room)
  rintro actual ⟨decision, members, _, _, _⟩
  rw [decision, members]
  exact StrictJsonMembers.original_member_step_exact _ _ _ _

end Auths.Product.NativeCompiler.Refinement
