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

-- A bounded ceiling with no declared request is DENIED. This vector asserted
-- `ok true` while the pinned translation was stale; the regenerated translation
-- matches the shipping Rust.
example :
    optional_budget_covers
      (some { algebra := "usd", value := 1#u64 }) none = ok false := by
  rfl

-- Both profile-budget-expression modes, on the one input class the capability
-- reclassifies: an absent request.
example :
    budget_ceiling_covers_action
      (some { algebra := "usd", value := 1#u64 }) none
      ProfileBudgetExpression.Expressible = ok false := by
  rfl

example :
    budget_ceiling_covers_action
      (some { algebra := "usd", value := 1#u64 }) none
      ProfileBudgetExpression.Inexpressible = ok true := by
  rfl

-- A DECLARED request is deliberately not vectored here. Comparing two ceilings
-- reaches `alloc::string::String::as_bytes`, which this translation carries as
-- an opaque external, so the goal cannot reduce without assuming semantics for
-- it -- exactly what these qualification cases exist to avoid. That the
-- capability leaves a declared request alone is proved abstractly instead, by
-- `Auths.Rich.budgetCoversAction_declared`.
--
-- Every vector above concerns an ABSENT request, which is the only input class
-- profile expressibility reclassifies, and each short-circuits before any
-- string comparison.

example :
    status_policy_attenuates StatusPolicy.ExpiryOnly
      StatusPolicy.ExpiryOnly = ok true := by
  rfl

example :
    status_policy_attenuates StatusPolicy.ExpiryOnly
      (StatusPolicy.SnapshotRequired "status-v1" 1#u64) = ok false := by
  rfl
