import Auths.Support.BorrowTagTopology
import Auths.Support.BorrowViewCompatibility
import qualification.aeneas.generated.model.Funs
import Auths.Refinement.Identifier
import Auths.Support.VTableDispatchModel
import Auths.Support.VTableOwnershipModel
import Auths.Support.VTableCallScopeModel
import Auths.Support.SourceClosureCapture
import qualification.aeneas.cases.SourceClosureCapture
import qualification.aeneas.cases.ClosedWriterRuntime
import qualification.aeneas.cases.WriterInputBound
import qualification.aeneas.cases.BorrowProjection
import qualification.aeneas.cases.NativeCaptureValue
import qualification.aeneas.cases.NativeBorrowProtocol
import qualification.aeneas.cases.NativeBorrowWiring
import qualification.aeneas.cases.NativeBorrowView
import qualification.aeneas.cases.NativeBorrowTransport
import qualification.aeneas.cases.NativeBorrowComposition
import qualification.aeneas.cases.CurrentBorrowCarrier
import qualification.aeneas.cases.CurrentBorrowCarrierOrigins
import qualification.aeneas.cases.NativeBorrowDefaults
import qualification.aeneas.cases.NativeBorrowExecution
import qualification.aeneas.cases.NativeBorrowFullABI
import qualification.aeneas.cases.NativePurePayload
import qualification.aeneas.cases.NativePureExpressions
import qualification.aeneas.cases.NativeCurrentWiring
import qualification.aeneas.cases.NativeCurrentSeeds
import qualification.aeneas.cases.NativeCaptureClosures
import qualification.aeneas.cases.NativeDefaultBindings
import qualification.aeneas.cases.NativeProjectorLevels
import qualification.aeneas.cases.NativeProjectorKinds
import qualification.aeneas.cases.NativeConsumedCoverage
import qualification.aeneas.cases.NativeConsumedReconstruction
import qualification.aeneas.cases.NativeBindingClosures
import qualification.aeneas.cases.NativeCompatiblePrograms
import qualification.aeneas.cases.NativeBorrowLevels
import qualification.aeneas.cases.NativeBackwardTypes
import qualification.aeneas.cases.NativeRootOrigins
import qualification.aeneas.cases.NativeRootPayload
import qualification.aeneas.cases.NativeRootBindings
import qualification.aeneas.cases.NativeNestedReconstruction
import qualification.aeneas.cases.NativeScopedDefaults
import qualification.aeneas.cases.NativeForeignDefaults
import qualification.aeneas.cases.NativeOwnedBindings
import qualification.aeneas.cases.NativeRootPrograms
import qualification.aeneas.cases.NativeCaptureComponent

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

-- Evidence-conditioned authority. Freshness is inclusive at the maximum age
-- and exact at the evaluation second; one second more is stale, one second in
-- the future is never fresh, and the anchor validity bounds the observation.
example :
    observation.observation_fresh
      40#u64 100#u64 60#u64 0#u64 200#u64 = ok true := by
  rfl

example :
    observation.observation_fresh
      39#u64 100#u64 60#u64 0#u64 200#u64 = ok false := by
  rfl

example :
    observation.observation_fresh
      100#u64 100#u64 60#u64 0#u64 200#u64 = ok true := by
  rfl

example :
    observation.observation_fresh
      101#u64 100#u64 60#u64 0#u64 200#u64 = ok false := by
  rfl

example :
    observation.observation_fresh
      50#u64 100#u64 60#u64 51#u64 200#u64 = ok false := by
  rfl

example :
    observation.observation_fresh
      50#u64 100#u64 60#u64 0#u64 49#u64 = ok false := by
  rfl

example :
    observation.observation_fresh
      0#u64 18446744073709551615#u64 18446744073709551615#u64
      0#u64 0#u64 = ok true := by
  rfl

example : observation.uint_range_contains 1#u64 9#u64 9#u64 = ok true := by
  rfl

example : observation.uint_range_contains 1#u64 9#u64 10#u64 = ok false := by
  rfl

example : observation.uint_range_contains 1#u64 9#u64 0#u64 = ok false := by
  rfl

example :
    observation.fact_value_equal
      (observation.FactValue.Uint 7#u64)
      (observation.FactValue.Uint 7#u64) = ok true := by
  rfl

-- A type mismatch is never equal, and needs no string comparison to decide.
example :
    observation.fact_value_equal
      (observation.FactValue.Uint 7#u64)
      (observation.FactValue.Text "7") = ok false := by
  rfl

-- A missing observed fact makes every atom false.
example :
    observation.condition_value_holds
      (observation.ConditionTest.UintRange { lo := 1#u64, hi := 9#u64 })
      none none = ok false := by
  rfl

example :
    observation.condition_value_holds
      (observation.ConditionTest.UintRange { lo := 1#u64, hi := 9#u64 })
      (some (observation.FactValue.Uint 9#u64)) none = ok true := by
  rfl

example :
    observation.condition_value_holds
      (observation.ConditionTest.EqLiteral (observation.FactValue.Uint 7#u64))
      (some (observation.FactValue.Uint 8#u64)) none = ok false := by
  rfl

-- An action-fact atom without a resolved action value is false.
example :
    observation.condition_value_holds
      (observation.ConditionTest.EqAction "expected")
      (some (observation.FactValue.Uint 7#u64)) none = ok false := by
  rfl

example :
    observation.condition_value_holds
      (observation.ConditionTest.EqAction "expected")
      (some (observation.FactValue.Uint 7#u64))
      (some (observation.FactValue.Uint 7#u64)) = ok true := by
  rfl

example :
    observation.requirement_verdict true true =
      ok observation.RequirementVerdict.Satisfied := by
  rfl

example :
    observation.requirement_verdict true false =
      ok observation.RequirementVerdict.ConditionFalse := by
  rfl

example :
    observation.requirement_verdict false false =
      ok observation.RequirementVerdict.Missing := by
  rfl

-- Per-extension attenuation leaves. Condition atoms compare exactly: a changed
-- range bound is a different atom, and atoms of different kinds never match.
example :
    observation.condition_test_equal
      (observation.ConditionTest.UintRange { lo := 1#u64, hi := 5#u64 })
      (observation.ConditionTest.UintRange { lo := 1#u64, hi := 5#u64 }) =
      ok true := by
  rfl

example :
    observation.condition_test_equal
      (observation.ConditionTest.UintRange { lo := 1#u64, hi := 5#u64 })
      (observation.ConditionTest.UintRange { lo := 1#u64, hi := 6#u64 }) =
      ok false := by
  rfl

example :
    observation.condition_test_equal
      (observation.ConditionTest.EqLiteral (observation.FactValue.Uint 1#u64))
      (observation.ConditionTest.UintRange { lo := 1#u64, hi := 1#u64 }) =
      ok false := by
  rfl

-- The loop-bearing requirement and extension laws compile in this closure and
-- are exercised by the native corpus through the handler laws.
#check observation.observation_requirements_attenuate
#check observation.observation_requirement_covers
#check observation.observation_requirement_narrows
#check critical_extension_find
#check critical_extension_id
#check critical_extension_payload
#check critical_extension_entries

-- The bounded-policy link law: no link is accepted only without a parent
-- bound, and a link needs a parent bound.
example : bounded_policy.bounded_policy_link_accepts none none = ok true := by
  rfl

example :
    bounded_policy.bounded_policy_link_accepts none
      (some (Array.repeat 32#usize 0#u8)) = ok false := by
  rfl

example :
    bounded_policy.bounded_policy_link_accepts
      (some (Array.repeat 32#usize 0#u8)) none = ok false := by
  rfl

#check bounded_policy.digest_equal

-- Identifier witnesses use the translated shipping validator and its exact
-- refinement. `decide` reduces only the small, independent byte predicate.
private theorem identifier_case (value : Str) (maximum : Std.Usize)
    (expected : Bool)
    (meaning : (!value.val.isEmpty && decide (value.val.length ≤ maximum.val) &&
      !Auths.Refinement.Identifier.containsExcluded value.val) = expected) :
    identifier.bounded_identifier_valid value maximum ⦃ result => result = expected ⦄ := by
  apply WP.spec_mono (Auths.Refinement.Identifier.identifier_exact value maximum)
  intro result resultEq
  exact resultEq.trans meaning

private def asciiIdentifier : Str :=
  ⟨[97#u8, 117#u8, 116#u8, 104#u8, 115#u8], by scalar_tac⟩
example : identifier.bounded_identifier_valid asciiIdentifier 5#usize ⦃ result => result = true ⦄ := by
  apply identifier_case
  decide
example : identifier.bounded_identifier_valid asciiIdentifier 4#usize ⦃ result => result = false ⦄ := by
  apply identifier_case
  decide
example : identifier.bounded_identifier_valid ⟨[], by scalar_tac⟩ 128#usize ⦃ result => result = false ⦄ := by
  apply identifier_case
  decide
-- U+2028 is whitespace; U+200B is permitted by the pinned character rule.
example : identifier.bounded_identifier_valid ⟨[226#u8, 128#u8, 168#u8], by scalar_tac⟩ 3#usize
    ⦃ result => result = false ⦄ := by
  apply identifier_case
  decide
example : identifier.bounded_identifier_valid ⟨[226#u8, 128#u8, 139#u8], by scalar_tac⟩ 3#usize
    ⦃ result => result = true ⦄ := by
  apply identifier_case
  decide
