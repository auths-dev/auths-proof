import Auths.Verifier.StatusVisibility
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection
set_option maxHeartbeats 4000000

def principalActive : AuthsStatusSelection.auths_model.PrincipalState → Bool
  | .Active => true
  | _ => false

def principalView (signed : AuthsStatusSelection.auths_model.SignedPrincipalStatus) : Model.Statement String :=
  let row := signed.statement
  ⟨row.principal, row.method, row.issuer, row.sequence.val, row.observed_at.val,
    row.valid_until.val, principalActive row.state⟩

def scanView (state : Bool × Bool × Bool × Option Std.U64 × Bool × Bool × AuthsStatusSelection.auths_model.Timestamp) : Model.Scan :=
  ⟨state.1, state.2.1, state.2.2.1, state.2.2.2.1.map (fun value => value.val),
    state.2.2.2.2.1, state.2.2.2.2.2.1, state.2.2.2.2.2.2.val⟩

theorem principal_not_active (state : AuthsStatusSelection.auths_model.PrincipalState) :
    core.cmp.PartialEq.ne.trait_default AuthsStatusSelection.auths_model.PrincipalState.Insts.CoreCmpPartialEqPrincipalState
      state .Active = ok (!principalActive state) := by
  cases state <;> simp [core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,

    AuthsStatusSelection.auths_model.PrincipalState.Insts.CoreCmpPartialEqPrincipalState.eq,
    principalActive, AuthsStatusSelection.auths_model.PrincipalState.read_discriminant]

theorem stale_comparison (fresh : Bool) :
    (do let value ← ok (if fresh then AuthsStatusSelection.auths_ports.StatusDecision.Active else .Stale)
        AuthsStatusSelection.auths_ports.StatusDecision.Insts.CoreCmpPartialEqStatusDecision.eq value .Stale) = ok (!fresh) := by
  cases fresh <;> simp [AuthsStatusSelection.auths_ports.StatusDecision.Insts.CoreCmpPartialEqStatusDecision.eq,
    AuthsStatusSelection.auths_ports.StatusDecision.read_discriminant]

theorem timestamp_min_exact (left right : AuthsStatusSelection.auths_model.Timestamp) :
    core.cmp.Ord.min.trait_default AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpOrd left right =
      ok (if left.val < right.val then left else right) := by
  simp [core.cmp.Ord.min.trait_default, core.cmp.Ord.min.default, core.cmp.Ord.min_body,
    Aeneas.Std.core.cmp.PartialOrd.lt.default, Aeneas.Std.core.cmp.PartialOrd.lt_body,
    AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpPartialOrdTimestamp.partial_cmp,
    AuthsStatusSelection.auths_model.Timestamp.Insts.CoreCmpOrd.cmp, core.cmp.impls.OrdU64.cmp, Nat.compare_eq_lt]
  split <;> rfl

theorem minimum_value (left right : Std.U64) :
    (if left.val < right.val then left else right).val = min left.val right.val := by
  split
  · rename_i ordered
    exact (Nat.min_eq_left (Nat.le_of_lt ordered)).symm
  · rename_i ordered
    exact (Nat.min_eq_right (Nat.le_of_not_gt ordered)).symm

theorem saturation_exact (left right : Std.U64) :
    (core.num.U64.saturating_add left right).val = min Model.wordMaximum (left.val + right.val) := by
  change (min (UScalar.max .U64) (left.val + right.val)) % (2^64) = _
  rw [UScalar.max_UScalarTy_U64_eq, U64.max_eq]
  unfold Model.wordMaximum
  apply Nat.mod_eq_of_lt
  have bounded := Nat.min_le_left (18446744073709551615 : Nat) (left.val + right.val)
  omega

theorem stale_test (fresh : Bool) :
    AuthsStatusSelection.auths_ports.StatusDecision.Insts.CoreCmpPartialEqStatusDecision.eq
      (if fresh then .Active else .Stale) .Stale = ok (!fresh) := by
  cases fresh <;> simp [AuthsStatusSelection.auths_ports.StatusDecision.Insts.CoreCmpPartialEqStatusDecision.eq,
    AuthsStatusSelection.auths_ports.StatusDecision.read_discriminant]

theorem result_ite {T : Type} (condition : Prop) [Decidable condition] (left right : T) :
    (if condition then Result.ok left else Result.ok right) = Result.ok (if condition then left else right) := by
  by_cases condition <;> simp_all

theorem boolean_or (left right : Bool) : (if left then true else right) = (left || right) := by
  cases left <;> rfl

abbrev NativeScan := Bool × Bool × Bool × Option Std.U64 × Bool × Bool × AuthsStatusSelection.auths_model.Timestamp

def principalLoop (method : String) (age : Std.U64) (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (subject : String) (now : Std.U64) (statements : Slice AuthsStatusSelection.auths_model.SignedPrincipalStatus)
    (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule) (state : NativeScan) (position : Std.Usize) :=
  select_principal_from_snapshot_loop method age snapshot subject .Approver now statements rules
    state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position

theorem principal_loop_refines (records : List AuthsStatusSelection.auths_model.SignedPrincipalStatus)
    (statements : Slice AuthsStatusSelection.auths_model.SignedPrincipalStatus) (rules : Slice AuthsStatusSelection.auths_model.StatusTrustRule)
    (method subject : String) (age now : Std.U64) (snapshot : AuthsStatusSelection.auths_model.PrincipalStatusSnapshot)
    (state : NativeScan) (position : Std.Usize)
    (remaining : statements.val.drop position.val = records) :
    AuthsStatusSelection.select_principal_from_snapshot_loop method age snapshot subject .Approver now statements rules
      state.1 state.2.1 state.2.2.1 state.2.2.2.1 state.2.2.2.2.1 state.2.2.2.2.2.1 state.2.2.2.2.2.2 position ⦃ actual =>
      scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
        (rules.val.map ruleView) subject .approver (records.map principalView) (scanView state) ⦄ := by
  change Aeneas.Std.WP.spec (principalLoop method age snapshot subject now statements rules state position) _
  induction records generalizing state position with
  | nil =>
    have finished : ¬ position < statements.len := by
      have size := congrArg List.length remaining
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    unfold principalLoop
    rw [select_principal_from_snapshot_loop.eq_def]
    simp [finished, Model.scan]
  | cons head tail ih =>
    obtain ⟨guard, atHead⟩ := indexed_head statements position head tail remaining
    obtain ⟨next, step, nextValue, nextRemaining⟩ := indexed_next statements position head tail remaining
    rcases state with ⟨seen, methodSeen, rollback, maximum, stale, revoked, through⟩
    by_cases stopped : rollback = true
    ·
      unfold principalLoop
      rw [select_principal_from_snapshot_loop.eq_def]
      simp [guard, stopped, Model.scan, scanView]
    · have running : rollback = false := by simpa using stopped
      subst rollback
      have advance (nextSeen nextMethod nextRollback : Bool) (nextMaximum : Option Std.U64)
          (nextStale nextRevoked : Bool) (nextThrough : Std.U64)
          (meaning : scanView (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) = Model.record snapshot.valid_until.val age.val now.val method
            (rules.val.map ruleView) subject .approver (principalView head)
            (scanView (seen, methodSeen, false, maximum, stale, revoked, through))) :
          select_principal_from_snapshot_loop method age snapshot subject .Approver now statements rules
            nextSeen nextMethod nextRollback nextMaximum nextStale nextRevoked nextThrough next ⦃ actual =>
            scanView actual = Model.scan snapshot.valid_until.val age.val now.val method
              (rules.val.map ruleView) subject .approver ((head :: tail).map principalView)
              (scanView (seen, methodSeen, false, maximum, stale, revoked, through)) ⦄ := by
        have contract := ih (nextSeen, nextMethod, nextRollback, nextMaximum, nextStale, nextRevoked, nextThrough) next nextRemaining
        rw [meaning] at contract
        simpa only [principalLoop, List.map_cons, Model.scan, Bool.false_eq_true, ↓reduceIte, scanView] using contract
      unfold principalLoop
      rw [select_principal_from_snapshot_loop.eq_def]
      simp only [guard, ↓reduceIte, atHead, bind_tc_ok,
        AuthsStatusSelection.auths_model.SignedPrincipalStatus.impl.statement,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.principal, principal_eq,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.issuer, approver_visibility_exact,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.method, method_eq,
        sequence_floor_exact, AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.sequence,
        AuthsStatusSelection.auths_model.PrincipalStatusSnapshot.impl.valid_until,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.observed_at,
        AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.valid_until,
        freshness_exact, stale_test, AuthsStatusSelection.auths_model.PrincipalStatusStatement.impl.state,
        principal_not_active, timestamp_min_exact,
        AuthsStatusSelection.auths_model.Timestamp.get, AuthsStatusSelection.auths_model.FreshnessLimit.get,
        AuthsStatusSelection.auths_model.Timestamp.new, lift, step]
      cases subjectMatch : (head.statement.principal == subject) <;>
        cases visible : Model.visible (rules.val.map ruleView) head.statement.issuer .approver <;>
        cases methodMatch : (head.statement.method == method) <;>
        simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
      all_goals
        first
        | exact advance _ _ _ _ _ _ _ (by simp [Model.record, principalView, scanView, subjectMatch, visible, methodMatch])
        | skip
      all_goals
        cases floor : nativeFloor rules method head.statement.issuer <;>
          try simp only [bind_tc_ok]
      all_goals
        first
        | exact advance _ _ _ _ _ _ _ (by simp [Model.record, principalView, scanView, subjectMatch, visible, methodMatch,
            ← native_floor_view rules method head.statement.issuer, floor])
        | skip
      all_goals
        cases maximum <;> try simp only [bind_tc_ok]
      all_goals
        repeat' (split_ifs <;> try simp (config := { zeta := true, zetaHave := true }) only [bind_tc_ok])
      all_goals try simp only [result_ite, bind_tc_ok, boolean_or]
      all_goals
        exact advance _ _ _ _ _ _ _ (by
          clear ih advance
          simp only [scanView]
          repeat' rw [minimum_value]
          simp_all [Model.record, Model.contribute, principalView, Model.deadline,
            ← native_floor_view rules method head.statement.issuer,
            saturation_exact, UScalar.lt_equiv, UScalar.eq_equiv, Nat.min_assoc, beq_iff_eq] <;>
            (split_ifs <;> simp_all <;> omega))

end Auths.StatusSelection
