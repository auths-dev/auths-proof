import Auths.Product.EntryDeadline
import Auths.Product.EntryGate
import qualification.aeneas.generated.gateway.Funs

open Aeneas Aeneas.Std Result
open Auths.Product.EntryDeadline

namespace Auths.Product.Refinement.EntryDeadline

def boundView (bound : auths_gateway_kernel.deadline.EntryBound) : Bound :=
  ⟨bound.not_after.val, bound.inclusive⟩

theorem translated_entry_time_refines_model (evaluatedAt now : Std.U64)
    (bound : auths_gateway_kernel.deadline.EntryBound) :
    auths_gateway_kernel.deadline.entry_time_allows evaluatedAt now bound =
      ok (decide (admits evaluatedAt.val (boundView bound) now.val)) := by
  simp only [auths_gateway_kernel.deadline.entry_time_allows]
  split <;> rename_i ordered
  · split <;> rename_i before
    · simp [admits, permits, boundView, UScalar.le_equiv, UScalar.lt_equiv] at *
      omega
    · split <;> rename_i equal
      · subst now
        cases inclusive : bound.inclusive <;>
          simp_all [admits, permits, boundView, UScalar.le_equiv]
      · simp [admits, permits, boundView, UScalar.le_equiv, UScalar.lt_equiv] at *
        omega
  · simp [admits, permits, boundView, UScalar.le_equiv] at *
    omega

theorem translated_intersection_refines_model
    (left right : auths_gateway_kernel.deadline.EntryBound) :
    auths_gateway_kernel.deadline.intersect_entry_bounds left right
      ⦃ result => boundView result = meet (boundView left) (boundView right) ⦄ := by
  simp only [auths_gateway_kernel.deadline.intersect_entry_bounds, lift, bind_tc_ok,
    core.cmp.impls.OrdU64.cmp]
  by_cases first : left.not_after.val < right.not_after.val
  · have order := Nat.compare_eq_lt.mpr first
    simp [order, boundView, meet, first]
  · by_cases second : right.not_after.val < left.not_after.val
    · have order := Nat.compare_eq_gt.mpr second
      simp [order, boundView, meet, first, second]
    · have equal : left.not_after.val = right.not_after.val := by omega
      have order := Nat.compare_eq_eq.mpr equal
      cases inclusive : left.inclusive <;>
        simp [order, boundView, meet, first, second, inclusive]

theorem translated_clock_rollback_refuses (evaluatedAt now : Std.U64)
    (bound : auths_gateway_kernel.deadline.EntryBound)
    (rollback : now.val < evaluatedAt.val) :
    auths_gateway_kernel.deadline.entry_time_allows evaluatedAt now bound = ok false := by
  rw [translated_entry_time_refines_model]
  have refused : ¬ admits evaluatedAt.val (boundView bound) now.val := by
    intro accepted
    have ordered := accepted.1
    omega
  simp [refused]

/-- Complete source gate, including missing samples and the exact nanosecond
limit. Generated declarations and this body require the deferred final
extraction/elaboration pass; this is not current compiled evidence. -/
@[step] theorem translated_gate_refines_original_bounds
    (evaluatedAt : Std.U64) (now : Option Std.U64)
    (authority prepared : auths_gateway_kernel.deadline.EntryBound)
    (current : Option auths_gateway_kernel.deadline.EntryBound) (elapsed : Std.U128) :
    auths_gateway_kernel.deadline.entry_gate_allows evaluatedAt now authority prepared current elapsed
      ⦃ actual => actual = decide (Auths.Product.EntryGate.Allows evaluatedAt.val
        (now.map (·.val)) (boundView authority) (boundView prepared)
        (current.map boundView) elapsed.val) ⦄ := by
  cases now with
  | none => simp [auths_gateway_kernel.deadline.entry_gate_allows, Auths.Product.EntryGate.Allows]
  | some now =>
    cases current with
    | none => simp [auths_gateway_kernel.deadline.entry_gate_allows, Auths.Product.EntryGate.Allows]
    | some current =>
      unfold auths_gateway_kernel.deadline.entry_gate_allows
      simp only [auths_gateway_kernel.deadline.MAX_ENTRY_ELAPSED_NANOS]
      split
      · rename_i expired
        have timeout : Auths.Product.EntryGate.maximumElapsedNanos < elapsed.val := by
          simpa [Auths.Product.EntryGate.maximumElapsedNanos, UScalar.lt_equiv] using expired
        have refused := Auths.Product.EntryGate.elapsed_timeout_refuses
          evaluatedAt.val (some now.val) (boundView authority) (boundView prepared)
          (some (boundView current)) elapsed.val timeout
        simp [spec_ok, refused]
      · rename_i notExpired
        have elapsedFits : elapsed.val ≤ Auths.Product.EntryGate.maximumElapsedNanos := by
          simp only [UScalar.lt_equiv] at notExpired
          simp only [Auths.Product.EntryGate.maximumElapsedNanos]
          omega
        step with translated_intersection_refines_model prepared current as ⟨inner, innerMeaning⟩
        step with translated_intersection_refines_model authority inner as ⟨bound, boundMeaning⟩
        rw [translated_entry_time_refines_model]
        simp only [spec_ok, Option.map_some]
        rw [Auths.Product.EntryGate.original_bounds_iff_intersection]
        simp only [elapsedFits, true_and, boundMeaning, innerMeaning]

theorem translated_gate_preserves_original_bounds
    (evaluatedAt : Std.U64) (now : Option Std.U64)
    (authority prepared : auths_gateway_kernel.deadline.EntryBound)
    (current : Option auths_gateway_kernel.deadline.EntryBound) (elapsed : Std.U128) :
    auths_gateway_kernel.deadline.entry_gate_allows evaluatedAt now authority prepared current elapsed
      ⦃ actual => actual = true →
        ∃ sampledNow checkedCurrent,
          now.map (·.val) = some sampledNow ∧ current.map boundView = some checkedCurrent ∧
          elapsed.val ≤ Auths.Product.EntryGate.maximumElapsedNanos ∧
          admits evaluatedAt.val (boundView authority) sampledNow ∧
          admits evaluatedAt.val (boundView prepared) sampledNow ∧
          admits evaluatedAt.val checkedCurrent sampledNow ⦄ := by
  apply spec_mono (translated_gate_refines_original_bounds evaluatedAt now authority prepared current elapsed)
  intro actual meaning accepted
  have allowed : Auths.Product.EntryGate.Allows evaluatedAt.val (now.map (·.val))
      (boundView authority) (boundView prepared) (current.map boundView) elapsed.val := by
    simpa only [accepted, eq_comm, decide_eq_true_eq] using meaning
  exact Auths.Product.EntryGate.requires_present_samples _ _ _ _ _ _ allowed

theorem translated_gate_timeout_refuses
    (evaluatedAt : Std.U64) (now : Option Std.U64)
    (authority prepared : auths_gateway_kernel.deadline.EntryBound)
    (current : Option auths_gateway_kernel.deadline.EntryBound) (elapsed : Std.U128)
    (expired : Auths.Product.EntryGate.maximumElapsedNanos < elapsed.val) :
    auths_gateway_kernel.deadline.entry_gate_allows evaluatedAt now authority prepared current elapsed
      ⦃ actual => actual = false ⦄ := by
  apply spec_mono (translated_gate_refines_original_bounds evaluatedAt now authority prepared current elapsed)
  intro actual meaning
  have refused := Auths.Product.EntryGate.elapsed_timeout_refuses evaluatedAt.val (now.map (·.val))
    (boundView authority) (boundView prepared) (current.map boundView) elapsed.val expired
  simpa only [refused, decide_false] using meaning

theorem translated_gate_useful_original_endpoints
    (evaluatedAt now : Std.U64) (authority prepared current : auths_gateway_kernel.deadline.EntryBound)
    (elapsed : Std.U128) (elapsedFits : elapsed.val ≤ Auths.Product.EntryGate.maximumElapsedNanos)
    (authorityAllows : admits evaluatedAt.val (boundView authority) now.val)
    (preparedAllows : admits evaluatedAt.val (boundView prepared) now.val)
    (currentAllows : admits evaluatedAt.val (boundView current) now.val) :
    auths_gateway_kernel.deadline.entry_gate_allows evaluatedAt (some now) authority prepared (some current) elapsed
      ⦃ actual => actual = true ⦄ := by
  apply spec_mono (translated_gate_refines_original_bounds evaluatedAt (some now) authority prepared (some current) elapsed)
  intro actual meaning
  have allowed := Auths.Product.EntryGate.useful_original_endpoints evaluatedAt.val now.val elapsed.val
    (boundView authority) (boundView prepared) (boundView current)
    elapsedFits authorityAllows preparedAllows currentAllows
  simpa only [Option.map_some, allowed, decide_true] using meaning


end Auths.Product.Refinement.EntryDeadline
