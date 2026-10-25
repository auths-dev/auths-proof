import Auths.Codec.ObjectFields
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.DecodedFields
open ProfileDecode

/-- Constructor-valid field semantics are earned by successful parsing.
These relations are independent of the source string allocation carrier. -/
def ProfileValid (id : List Nat) (version : Nat) : Prop :=
  identifierDecision id 128 = true ∧ 0 < version ∧ version ≤ 65535

def PermissionValid (capability resource : List Nat) : Prop :=
  identifierDecision capability 128 = true ∧ identifierDecision resource 1024 = true

def BudgetValid (algebra : List Nat) (amount : Nat) : Prop :=
  identifierDecision algebra 128 = true ∧ amount < 2 ^ 64

theorem identifier_earns_bound (bytes : List Nat) (maximum : Nat)
    (valid : identifierDecision bytes maximum = true) :
    bytes ≠ [] ∧ bytes.length ≤ maximum ∧
      Auths.Model.Identifier.containsExcluded bytes = false := by
  simpa [identifierDecision, Bool.and_eq_true, Bool.not_eq_true'] using valid

private theorem narrow_success (input : List Nat) (position maximum word next : Nat)
    (accepted : Cursor.narrowHead input position maximum = (some word, next)) : word ≤ maximum := by
  unfold Cursor.narrowHead at accepted
  split at accepted
  rename_i raw finish
  cases raw <;> simp only [Option.filter] at accepted
  · simp at accepted
  · split at accepted <;> simp_all

private theorem word16_success (input : List Nat) (position word next : Nat)
    (accepted : ProfileDecode.wordAt input position = (.Ok word, next)) : word ≤ 65535 := by
  unfold ProfileDecode.wordAt at accepted
  cases meaning : Cursor.narrowHead input position 65535 with
  | mk raw finish =>
    cases raw with
    | none => simp [meaning] at accepted
    | some value =>
      simp only [meaning, core.result.Result.Ok.injEq, Prod.mk.injEq] at accepted
      obtain ⟨rfl, rfl⟩ := accepted
      exact narrow_success input position 65535 value finish meaning


theorem profile_model_valid (input : List Nat) (position : Nat) (id : List Nat) (version next : Nat)
    (accepted : profileAt input position = (.Ok (id, version), next)) : ProfileValid id version := by
  unfold profileAt at accepted
  repeat' first
    | dsimp only [andThen] at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [Prod.mk.injEq, core.result.Result.Ok.injEq,
        reduceCtorEq] at accepted
    | contradiction
  all_goals
    obtain ⟨same, _⟩ := accepted
    cases same
    refine ⟨by assumption, by omega, ?_⟩
    apply word16_success
    assumption

theorem permission_model_valid (input : List Nat) (position : Nat) (capability resource : List Nat) (next : Nat)
    (accepted : PermissionDecode.permissionAt input position = (.Ok (capability, resource), next)) :
    PermissionValid capability resource := by
  unfold PermissionDecode.permissionAt at accepted
  repeat' first
    | dsimp only [andThen] at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [Prod.mk.injEq, core.result.Result.Ok.injEq,
        reduceCtorEq] at accepted
    | contradiction
  all_goals
    obtain ⟨same, _⟩ := accepted
    cases same
    exact ⟨by assumption, by assumption⟩

theorem budget_model_valid (input : List Nat) (position : Nat) (algebra : List Nat) (amount next : Nat)
    (accepted : BudgetDecode.budgetAt input position = (.Ok (algebra, amount), next)) : identifierDecision algebra 128 = true := by
  unfold BudgetDecode.budgetAt at accepted
  repeat' first
    | dsimp only [andThen] at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [Prod.mk.injEq, core.result.Result.Ok.injEq,
        reduceCtorEq] at accepted
    | contradiction
  all_goals
    obtain ⟨same, _⟩ := accepted
    cases same
    assumption

@[step] theorem profile_success_valid (self : cbor.Decoder) :
    decode.profile_ref self ⦃ actual =>
      ∀ value, actual.1 = .Ok value →
        ProfileValid (value.id.toByteArray.toList.map UInt8.toNat) value.version.val ⦄ := by
  apply spec_mono (ProfileDecode.profile_exact self)
  rintro actual ⟨meaning, _⟩ value accepted
  rw [accepted] at meaning
  exact profile_model_valid _ _ _ _ _ meaning.symm

@[step] theorem permission_success_valid (self : cbor.Decoder) :
    decode.permission self ⦃ actual =>
      ∀ value, actual.1 = .Ok value →
        PermissionValid (value.capability.toByteArray.toList.map UInt8.toNat)
          (value.resource.toByteArray.toList.map UInt8.toNat) ⦄ := by
  apply spec_mono (PermissionDecode.permission_exact self)
  rintro actual ⟨meaning, _⟩ value accepted
  rw [accepted] at meaning
  exact permission_model_valid _ _ _ _ _ meaning.symm

@[step] theorem budget_success_valid (self : cbor.Decoder) :
    decode.budget self ⦃ actual =>
      ∀ value, actual.1 = .Ok value →
        BudgetValid (value.algebra.toByteArray.toList.map UInt8.toNat) value.value.val ⦄ := by
  apply spec_mono (BudgetDecode.budget_exact self)
  rintro actual ⟨meaning, _⟩ value accepted
  rw [accepted] at meaning
  exact ⟨budget_model_valid _ _ _ _ _ meaning.symm, by scalar_tac⟩

end Auths.Codec.DecodedFields
