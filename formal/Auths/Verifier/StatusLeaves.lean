import Auths.Verifier.StatusModel
import qualification.aeneas.generated.status_selection.Funs
import Mathlib.Tactic
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
set_option maxHeartbeats 2000000
namespace Auths.StatusSelection

def scopeView : AuthsStatusSelection.auths_model.StatusScope → Model.Scope
  | .OwnAnchor => .ownAnchor
  | .Anchors ids => .anchors ids.val
  | .AnyAnchor => .anyAnchor

def ruleView (rule : AuthsStatusSelection.auths_model.StatusTrustRule) : Model.Rule :=
  ⟨rule.method, rule.issuer, rule.sequence_floor.val, scopeView rule.scope⟩

def viewView : AuthsStatusSelection.auths_model.StatusView → Model.View
  | .Anchor anchor => .anchor anchor.id anchor.principal
  | .Approver => .approver

theorem principal_eq (left right : AuthsStatusSelection.auths_model.PrincipalId) :
    AuthsStatusSelection.auths_model.PrincipalId.Insts.CoreCmpPartialEqPrincipalId.eq left right = ok (left == right) := rfl

theorem method_eq (left right : AuthsStatusSelection.auths_model.StatusMethodId) :
    AuthsStatusSelection.auths_model.StatusMethodId.Insts.CoreCmpPartialEqStatusMethodId.eq left right = ok (left == right) := rfl

theorem timestamp_lt (left right : AuthsStatusSelection.auths_model.Timestamp) :
    core.cmp.PartialOrd.lt.default AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp left right =
      ok (decide (left.val < right.val)) := by
  simp [AuthsStatusSelection.core.cmp.PartialOrd.lt.default,
    Aeneas.Std.core.cmp.PartialOrd.lt.default, Aeneas.Std.core.cmp.PartialOrd.lt_body,
    AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp.partial_cmp,
    AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpOrd.cmp, core.cmp.impls.OrdU64.cmp, Nat.compare_eq_lt]

theorem timestamp_gt (left right : AuthsStatusSelection.auths_model.Timestamp) :
    core.cmp.PartialOrd.gt.default AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp left right =
      ok (decide (left.val > right.val)) := by
  simp [AuthsStatusSelection.core.cmp.PartialOrd.gt.default,
    Aeneas.Std.core.cmp.PartialOrd.gt.default, Aeneas.Std.core.cmp.PartialOrd.gt_body,
    AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp.partial_cmp,
    AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpOrd.cmp, core.cmp.impls.OrdU64.cmp, Nat.compare_eq_gt]

theorem saturation_sub_exact (left right : Std.U64) :
    (core.num.U64.saturating_sub left right).val = left.val - right.val := by
  change (max 0 (left.val - right.val)) % 2^64 = _
  rw [Nat.max_eq_right (Nat.zero_le _)]
  apply Nat.mod_eq_of_lt
  exact lt_of_le_of_lt (Nat.sub_le _ _) left.hBounds

theorem freshness_exact (method : AuthsStatusSelection.auths_model.StatusMethodId) (age : AuthsStatusSelection.auths_model.FreshnessLimit)
    (observed expiresAt now : AuthsStatusSelection.auths_model.Timestamp) :
    ExactStatusMethod.freshness (.SnapshotRequired method age) observed expiresAt now =
      ok (if Model.fresh age.val observed.val expiresAt.val now.val then .Active else .Stale) := by
  simp only [ExactStatusMethod.freshness, timestamp_gt, timestamp_lt, bind_tc_ok,
    AuthsStatusSelection.auths_model.Timestamp.get, AuthsStatusSelection.auths_model.FreshnessLimit.get, lift]
  simp only [UScalar.lt_equiv, saturation_sub_exact]
  split_ifs <;> simp_all [Model.fresh] <;> omega

theorem indexed_next {T : Type} (values : Slice T) (position : Std.Usize)
    (head : T) (tail : List T) (remaining : values.val.drop position.val = head :: tail) :
    ∃ next, position + 1#usize = ok next ∧ next.val = position.val + 1 ∧
      values.val.drop next.val = tail := by
  have within : position.val < values.val.length := by
    have size := congrArg List.length remaining
    simp only [List.length_drop, List.length_cons] at size
    omega
  have incrementFits : position.val + 1 ≤ Usize.max := by have := values.property; omega
  obtain ⟨next, step, meaning⟩ := spec_imp_exists (Usize.add_spec (x := position) (y := 1#usize) incrementFits)
  refine ⟨next, step, ?_, ?_⟩
  · simpa using meaning
  · have drop := congrArg (List.drop 1) remaining
    simpa [meaning, List.drop_drop, Nat.add_comm] using drop

theorem indexed_head {T : Type} (values : Slice T) (position : Std.Usize)
    (head : T) (tail : List T) (remaining : values.val.drop position.val = head :: tail) :
    position < values.len ∧ Slice.index_usize values position = ok head := by
  have within : position.val < values.val.length := by
    have size := congrArg List.length remaining
    simp only [List.length_drop, List.length_cons] at size
    omega
  have headEq : values.val[position.val] = head := by
    have split := List.drop_eq_getElem_cons within
    rw [remaining] at split
    exact (List.cons.inj split).1.symm
  constructor
  · simpa only [UScalar.lt_equiv, Slice.len_val] using within
  · simp [Slice.index_usize, List.getElem?_eq_getElem within, headEq]
end Auths.StatusSelection
