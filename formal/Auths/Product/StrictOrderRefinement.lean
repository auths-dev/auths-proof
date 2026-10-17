import qualification.aeneas.generated.connections.Funs
import Auths.Verifier.StatusLeaves
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_connections
namespace Auths.Product.StrictOrder.Refinement

def chain {T : Type} (less : T → T → Bool) : T → List T → Bool
  | _, [] => true
  | previous, next :: rest => less previous next && chain less next rest

def ordered {T : Type} (less : T → T → Bool) : List T → Bool
  | [] => true
  | first :: rest => chain less first rest

private theorem suffix_exact {T : Type} (order : core.cmp.Ord T) (less : T → T → Bool)
    (comparison : ∀ a b, order.partialOrdInst.lt a b ⦃ actual => actual = less a b ⦄)
    (remaining : List T) (values : Slice T) (index : Std.Usize) (previous : T)
    (positive : 0 < index.val) (atPrevious : values.val[index.val - 1]? = some previous)
    (suffix : values.val.drop index.val = remaining) :
    kernel.strictly_sorted_unique_loop order values index ⦃ actual => actual = chain less previous remaining ⦄ := by
  induction remaining generalizing index previous with
  | nil =>
    have finished : ¬ index < values.len := by
      have size := congrArg List.length suffix
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    unfold kernel.strictly_sorted_unique_loop
    rw [loop.eq_def]
    simp [kernel.strictly_sorted_unique_loop.body, finished, chain]
  | cons head rest ih =>
    obtain ⟨guard, indexed⟩ := Auths.StatusSelection.indexed_head values index head rest suffix
    obtain ⟨next, addition, nextValue, nextSuffix⟩ := Auths.StatusSelection.indexed_next values index head rest suffix
    obtain ⟨prior, subtraction, priorValue⟩ := spec_imp_exists (Usize.sub_spec (x := index) (y := 1#usize) (by scalar_tac))
    have priorMeaning : prior.val = index.val - 1 := by simpa using priorValue.1
    have previousIndexed : Slice.index_usize values prior = ok previous := by
      simp [Slice.index_usize, priorMeaning, atPrevious]
    have nextPrevious : values.val[next.val - 1]? = some head := by
      rw [nextValue, Nat.add_sub_cancel]
      have inside : index.val < values.val.length := by simpa [Slice.length] using guard
      have atHead : values.val[index.val] = head := by
        have split := List.drop_eq_getElem_cons inside
        rw [suffix] at split
        exact (List.cons.inj split).1.symm
      simp [List.getElem?_eq_getElem inside, atHead]
    obtain ⟨result, compared, comparisonMeaning⟩ := spec_imp_exists (comparison previous head)
    unfold kernel.strictly_sorted_unique_loop
    rw [loop.eq_def]
    simp only [kernel.strictly_sorted_unique_loop.body, guard, ↓reduceIte, subtraction,
      previousIndexed, indexed, compared, comparisonMeaning, bind_tc_ok]
    cases allowed : less previous head
    · simp [allowed, chain]
    · simp only [↓reduceIte, addition, bind_tc_ok]
      change kernel.strictly_sorted_unique_loop order values next ⦃ actual => actual = chain less previous (head :: rest) ⦄
      simpa [chain, allowed] using ih next head (by omega) nextPrevious nextSuffix

@[step] theorem strict_order_exact {T : Type} (order : core.cmp.Ord T) (less : T → T → Bool)
    (comparison : ∀ a b, order.partialOrdInst.lt a b ⦃ actual => actual = less a b ⦄)
    (values : Slice T) :
    kernel.strictly_sorted_unique order values ⦃ actual => actual = ordered less values.val ⦄ := by
  unfold kernel.strictly_sorted_unique
  step as ⟨empty, emptyMeaning⟩
  cases contents : values.val with
  | nil => simp [contents, Slice.length] at emptyMeaning; simp [emptyMeaning, ordered]
  | cons first rest =>
    have nonempty : empty = false := by simp [contents, Slice.length] at emptyMeaning; exact emptyMeaning
    simp only [nonempty, Bool.false_eq_true, ↓reduceIte]
    apply spec_mono (suffix_exact order less comparison rest values 1#usize first (by decide)
      (by simp [contents]) (by simp [contents]))
    intro actual meaning
    simpa [ordered, contents] using meaning

private theorem chain_facts {T : Type} (less : T → T → Bool)
    (transitive : ∀ a b c, less a b = true → less b c = true → less a c = true)
    (values : List T) (previous : T) (accepted : chain less previous values = true) :
    (∀ next ∈ values, less previous next = true) ∧ values.Pairwise (fun a b => less a b = true) := by
  induction values generalizing previous with
  | nil => simp
  | cons head rest ih =>
    simp only [chain, Bool.and_eq_true] at accepted
    obtain ⟨fromHead, sortedRest⟩ := ih head accepted.2
    constructor
    · intro next member
      rcases List.mem_cons.mp member with rfl | member
      · exact accepted.1
      · exact transitive previous head next accepted.1 (fromHead next member)
    · exact List.Pairwise.cons fromHead sortedRest

theorem ordered_implies_pairwise {T : Type} (less : T → T → Bool)
    (transitive : ∀ a b c, less a b = true → less b c = true → less a c = true)
    (values : List T) (accepted : ordered less values = true) :
    values.Pairwise (fun a b => less a b = true) := by
  cases values with
  | nil => exact List.Pairwise.nil
  | cons first rest =>
    obtain ⟨fromFirst, sortedRest⟩ := chain_facts less transitive rest first accepted
    exact List.Pairwise.cons fromFirst sortedRest

theorem ordered_implies_no_duplicates {T : Type} (less : T → T → Bool)
    (transitive : ∀ a b c, less a b = true → less b c = true → less a c = true)
    (irreflexive : ∀ value, less value value = false)
    (values : List T) (accepted : ordered less values = true) : values.Nodup := by
  have sorted := ordered_implies_pairwise less transitive values accepted
  change values.Pairwise (fun a b => a ≠ b)
  exact sorted.imp (by intro a b related same; subst b; simp [irreflexive] at related)

theorem source_earns_no_duplicates {T : Type} (order : core.cmp.Ord T) (less : T → T → Bool)
    (comparison : ∀ a b, order.partialOrdInst.lt a b ⦃ actual => actual = less a b ⦄)
    (transitive : ∀ a b c, less a b = true → less b c = true → less a c = true)
    (irreflexive : ∀ value, less value value = false)
    (values : Slice T) :
    kernel.strictly_sorted_unique order values ⦃ actual => actual = true → values.val.Nodup ⦄ := by
  step with strict_order_exact order less comparison as ⟨actual, meaning⟩
  rename_i accepted
  rw [accepted] at meaning
  exact ordered_implies_no_duplicates less transitive irreflexive values.val meaning.symm

end Auths.Product.StrictOrder.Refinement
