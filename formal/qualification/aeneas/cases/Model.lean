import qualification.aeneas.generated.model.Funs

open Aeneas Aeneas.Std Result
open auths_model

-- These are executable boundary cases over the exact functions translated
-- from `auths-model`. Loop-bearing set cases are exercised by the Rust
-- qualification corpus and compiled here as part of the same module closure.

example :
    inclusive_window_contains
      0#u64 18446744073709551615#u64
      0#u64 18446744073709551615#u64 = ok true := by
  rfl

example :
    inclusive_window_contains
      1#u64 18446744073709551615#u64
      0#u64 18446744073709551615#u64 = ok false := by
  rfl

example :
    validity_window_contains
      { not_before := 0#u64, expires_at := 18446744073709551615#u64 }
      { not_before := 1#u64, expires_at := 18446744073709551614#u64 } =
      ok true := by
  rfl

example :
    action_constraint_allows ActionConstraint.AnyBody
      ⟨List.replicate 32 0#u8, by simp⟩ = ok true := by
  rfl

example :
    action_constraint_attenuates ActionConstraint.AnyBody
      ActionConstraint.AnyBody = ok true := by
  rfl

example : optional_budget_attenuates none none = ok true := by
  rfl

example :
    optional_budget_attenuates none
      (some { algebra := "usd", value := 1#u64 }) = ok false := by
  rfl

example :
    optional_budget_covers
      (some { algebra := "usd", value := 1#u64 }) none = ok true := by
  rfl

example :
    status_policy_attenuates StatusPolicy.ExpiryOnly
      StatusPolicy.ExpiryOnly = ok true := by
  rfl

example :
    status_policy_attenuates StatusPolicy.ExpiryOnly
      (StatusPolicy.SnapshotRequired "status-v1" 1#u64) = ok false := by
  rfl
