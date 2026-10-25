import Auths.Product.CollectionFence
import qualification.aeneas.generated.stores.Funs

open Aeneas Aeneas.Std Result
open Auths.Product.CollectionFence

namespace Auths.Product.Refinement.CollectionFence

def cutoffView (current : Option Std.U64) : Option Nat := current.map (·.val)

theorem translated_window_open_refines_model (expiry : Std.U64)
    (current : Option Std.U64) :
    auths_stores.gateway_fence.gateway_window_open expiry current =
      ok (decide (openWindow (cutoffView current) expiry.val)) := by
  cases current with
  | none => simp [auths_stores.gateway_fence.gateway_window_open, cutoffView, openWindow]
  | some previous =>
    simp [auths_stores.gateway_fence.gateway_window_open, cutoffView, openWindow]

theorem translated_advance_refines_model (current : Option Std.U64)
    (requested : Std.U64) :
    auths_stores.gateway_fence.advance_gateway_collection current requested
      ⦃ result => result.val = advance (cutoffView current) requested.val ⦄ := by
  cases currentCase : current with
  | none =>
    simp [auths_stores.gateway_fence.advance_gateway_collection, cutoffView, advance]
  | some previous =>
    simp only [auths_stores.gateway_fence.advance_gateway_collection]
    split <;> rename_i later
    · simp only [Aeneas.Std.WP.spec_ok]
      simp only [advance, cutoffView, Option.map_some]
      exact (Nat.max_eq_left (by scalar_tac)).symm
    · simp only [Aeneas.Std.WP.spec_ok]
      simp only [advance, cutoffView, Option.map_some]
      exact (Nat.max_eq_right (by scalar_tac)).symm

theorem translated_closed_window_refuses (cutoff : Nat) (expiry : Std.U64)
    (current : Option Std.U64)
    (history : History (some cutoff) (cutoffView current))
    (collected : expiry.val ≤ cutoff) :
    auths_stores.gateway_fence.gateway_window_open expiry current = ok false := by
  rw [translated_window_open_refines_model]
  have closed := swept_window_cannot_readmit cutoff expiry.val history collected
  simp [closed]

end Auths.Product.Refinement.CollectionFence
