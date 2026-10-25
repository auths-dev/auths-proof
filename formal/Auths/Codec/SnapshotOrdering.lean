import Auths.Codec.ProtocolOrdering
import Auths.Codec.StableNormalization
import Aesop

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.SnapshotOrdering

/- These primary keys describe exactly the model constructor's partial
statement order. State, timestamps, extensions and signatures are retained
payloads, not hidden tie breakers. Equal primary keys need not identify equal
statements or signed records. No hash is part of this primary order. -/

abbrev PrincipalKey := String ×ₗ (String ×ₗ (Nat ×ₗ String))
abbrev GrantKey := List Nat ×ₗ (String ×ₗ (Nat ×ₗ String))

def principalKey (value : auths_model.SignedPrincipalStatus) : PrincipalKey :=
  toLex (value.statement.principal,
    toLex (value.statement.method,
      toLex (value.statement.sequence.val, value.statement.issuer)))

def grantKey (value : auths_model.SignedGrantStatus) : GrantKey :=
  toLex (ProtocolOrdering.grantIdKey value.statement.grant_id,
    toLex (value.statement.method,
      toLex (value.statement.sequence.val, value.statement.issuer)))

theorem sequence_compare (left right : Std.U64) :
    core.cmp.impls.OrdU64.cmp left right = compare left.val right.val := rfl

theorem principal_source_compare (left right : auths_model.SignedPrincipalStatus) :
    auths_model.status_snapshot.principal_order left right =
      ok (compare (principalKey left) (principalKey right)) := by
  unfold auths_model.status_snapshot.principal_order
  simp only [auths_model.SignedPrincipalStatus.impl.statement,
    auths_model.PrincipalStatusStatement.impl.principal,
    auths_model.PrincipalStatusStatement.impl.method,
    auths_model.PrincipalStatusStatement.impl.sequence,
    auths_model.PrincipalStatusStatement.impl.issuer,
    ProtocolOrdering.principal_compare, ProtocolOrdering.status_method_compare,
    core.cmp.OrdU64, sequence_compare, bind_tc_ok]
  cases first : compare left.statement.principal right.statement.principal <;>
    cases second : compare left.statement.method right.statement.method <;>
    cases third : compare left.statement.sequence.val right.statement.sequence.val <;>
    simp_all [principalKey, Prod.Lex.compare_def, compareLex, compareOn]

theorem grant_source_compare (left right : auths_model.SignedGrantStatus) :
    auths_model.status_snapshot.grant_order left right =
      ok (compare (grantKey left) (grantKey right)) := by
  unfold auths_model.status_snapshot.grant_order
  simp only [auths_model.SignedGrantStatus.impl.statement,
    auths_model.GrantStatusStatement.impl.grant_id,
    auths_model.GrantStatusStatement.impl.method,
    auths_model.GrantStatusStatement.impl.sequence,
    auths_model.GrantStatusStatement.impl.issuer,
    ProtocolOrdering.grant_id_compare, ProtocolOrdering.principal_compare,
    ProtocolOrdering.status_method_compare, core.cmp.OrdU64, sequence_compare, bind_tc_ok]
  cases first : compare (ProtocolOrdering.grantIdKey left.statement.grant_id)
      (ProtocolOrdering.grantIdKey right.statement.grant_id) <;>
    cases second : compare left.statement.method right.statement.method <;>
    cases third : compare left.statement.sequence.val right.statement.sequence.val <;>
    simp_all [grantKey, Prod.Lex.compare_def, compareLex, compareOn]

/-- Byte/word-key order is weak order on keys; it does not assume full
record equality whenever a primary comparison returns equality. -/
theorem compare_is_le {Key : Type} [LinearOrder Key] (left right : Key) :
    (compare left right).isLE = true ↔ left ≤ right := by
  cases ordering : compare left right with
  | lt =>
    have less : left < right := compare_lt_iff_lt.mp ordering
    simp [ordering, le_of_lt less]
  | eq =>
    have same : left = right := compare_eq_iff_eq.mp ordering
    simp [ordering, same]
  | gt =>
    have greater : right < left := compare_gt_iff_gt.mp ordering
    simp [ordering, not_le.mpr greater]

theorem principal_relation (left right : auths_model.SignedPrincipalStatus) :
    ProtocolSort.relation (fun first second => compare (principalKey first) (principalKey second)) left right ↔
      StableNormalization.before principalKey left right :=
  compare_is_le _ _

theorem grant_relation (left right : auths_model.SignedGrantStatus) :
    ProtocolSort.relation (fun first second => compare (grantKey first) (grantKey second)) left right ↔
      StableNormalization.before grantKey left right :=
  compare_is_le _ _

theorem principal_primary_ordered (values : List auths_model.SignedPrincipalStatus) :
    (StableNormalization.sort principalKey values).Pairwise (StableNormalization.before principalKey) :=
  StableNormalization.ordered principalKey values

theorem grant_primary_ordered (values : List auths_model.SignedGrantStatus) :
    (StableNormalization.sort grantKey values).Pairwise (StableNormalization.before grantKey) :=
  StableNormalization.ordered grantKey values

theorem compare_key_relation {Value Key : Type} [LinearOrder Key]
    (key : Value → Key) :
    ProtocolSort.relation (fun left right => compare (key left) (key right)) =
      StableNormalization.before key := by
  funext left right
  exact propext (compare_is_le _ _)

def sortedByKey {Value Key : Type} [LinearOrder Key] (key : Value → Key)
    (values : alloc.vec.Vec Value) : alloc.vec.Vec Value :=
  alloc.vec.Vec.ofBase ⟨StableNormalization.sort key values.val, by
    rw [(StableNormalization.permutation key values.val).length_eq]
    exact values.property⟩

@[simp] theorem sorted_by_key_contents {Value Key : Type} [LinearOrder Key]
    (key : Value → Key) (values : alloc.vec.Vec Value) :
    (sortedByKey key values).val = StableNormalization.sort key values.val := by
  simp [sortedByKey, alloc.vec.Vec.ofBase, alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

/-- The comparison callback in this concrete source helper calls the actual
Auths comparator. Only the standard stable-sort operation is modelled. -/
theorem principal_sort_exact (values : alloc.vec.Vec auths_model.SignedPrincipalStatus) :
    auths_model.status_snapshot.sort_principal values = ok (sortedByKey principalKey values) := by
  unfold auths_model.status_snapshot.sort_principal
  simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut, bind_tc_ok]
  rw [ProtocolSort.slice_compared_sort_exact _ _
    (fun left right => compare (principalKey left) (principalKey right)) (by
      intro left right
      change (do let ordering ← auths_model.status_snapshot.principal_order left right
                 ok (ordering, _)) = _
      rw [principal_source_compare]
      rfl)]
  simp only [bind_tc_ok]
  congr 1
  apply alloc.vec.contents_injective
  simp [Aeneas.Std.alloc.vec.Vec.deref_mut, alloc.vec.Vec.ofBase,
    alloc.vec.Vec.toBase, alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
    auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.SizedList.toList_ofList,
    sortedByKey, StableNormalization.sort, compare_key_relation]

theorem grant_sort_exact (values : alloc.vec.Vec auths_model.SignedGrantStatus) :
    auths_model.status_snapshot.sort_grant values = ok (sortedByKey grantKey values) := by
  unfold auths_model.status_snapshot.sort_grant
  simp only [core.ops.deref.DerefMutVec, alloc.vec.Vec.deref_mut, bind_tc_ok]
  rw [ProtocolSort.slice_compared_sort_exact _ _
    (fun left right => compare (grantKey left) (grantKey right)) (by
      intro left right
      change (do let ordering ← auths_model.status_snapshot.grant_order left right
                 ok (ordering, _)) = _
      rw [grant_source_compare]
      rfl)]
  simp only [bind_tc_ok]
  congr 1
  apply alloc.vec.contents_injective
  simp [Aeneas.Std.alloc.vec.Vec.deref_mut, alloc.vec.Vec.ofBase,
    alloc.vec.Vec.toBase, alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.toBase,
    auths_composition.alloc.vec.Vec.val, auths_composition.alloc.vec.SizedList.toList_ofList,
    sortedByKey, StableNormalization.sort, compare_key_relation]

macro "auths_snapshot_statement_projection" accepted:ident : tactic => `(tactic|
  (simp only [principal_sort_exact, grant_sort_exact, Bind.bind, Aeneas.Std.bind] at $accepted
   repeat' first
     | casesm* _ × _
     | dsimp only at $accepted
     | split at $accepted
     | simp (failIfUnchanged := true) only [
         uncurry, Bind.bind, Aeneas.Std.bind, bind_tc_ok, bind_tc_fail, bind_tc_div,
         core.result.Result.Insts.CoreOpsTry.branch,
         core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
         core.convert.FromSame, core.convert.FromSame.from,
         Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at $accepted
     | contradiction
   all_goals subst_vars
   all_goals simp only [sorted_by_key_contents]
   all_goals aesop))

/-- Successful actual snapshot construction earns the primary-order premise
used by wire preservation. Its other validation stages are not assumed to
accept: any refusal branch is incompatible with this source-success premise. -/
theorem principal_constructor_statements
    (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.PrincipalStatusSnapshot)
    (accepted : auths_model.PrincipalStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    output.statements.val = StableNormalization.sort principalKey statements.val := by
  unfold auths_model.PrincipalStatusSnapshot.with_trust at accepted
  auths_snapshot_statement_projection accepted

theorem grant_constructor_statements
    (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedGrantStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.GrantStatusSnapshot)
    (accepted : auths_model.GrantStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    output.statements.val = StableNormalization.sort grantKey statements.val := by
  unfold auths_model.GrantStatusSnapshot.with_trust at accepted
  auths_snapshot_statement_projection accepted

theorem principal_constructor_ordered
    (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.PrincipalStatusSnapshot)
    (accepted : auths_model.PrincipalStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    output.statements.val.Pairwise (StableNormalization.before principalKey) := by
  rw [principal_constructor_statements id observed validUntil statements checkpoints trust output accepted]
  exact principal_primary_ordered _

theorem grant_constructor_ordered
    (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedGrantStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.GrantStatusSnapshot)
    (accepted : auths_model.GrantStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    output.statements.val.Pairwise (StableNormalization.before grantKey) := by
  rw [grant_constructor_statements id observed validUntil statements checkpoints trust output accepted]
  exact grant_primary_ordered _

theorem principal_constructor_fields
    (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedPrincipalStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.PrincipalStatusSnapshot) (field : auths_model.SignedPrincipalStatus → Prop)
    (accepted : auths_model.PrincipalStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    (∀ statement ∈ output.statements.val, field statement) ↔
      ∀ statement ∈ statements.val, field statement := by
  rw [principal_constructor_statements id observed validUntil statements checkpoints trust output accepted]
  exact (StableNormalization.permutation principalKey statements.val).forall_mem_iff

theorem grant_constructor_fields
    (id : auths_model.StatusSnapshotId) (observed validUntil : auths_model.Timestamp)
    (statements : alloc.vec.Vec auths_model.SignedGrantStatus)
    (checkpoints : alloc.vec.Vec auths_model.EvidenceId)
    (trust : alloc.vec.Vec auths_model.StatusTrustRule)
    (output : auths_model.GrantStatusSnapshot) (field : auths_model.SignedGrantStatus → Prop)
    (accepted : auths_model.GrantStatusSnapshot.with_trust
      id observed validUntil statements checkpoints trust = ok (.Ok output)) :
    (∀ statement ∈ output.statements.val, field statement) ↔
      ∀ statement ∈ statements.val, field statement := by
  rw [grant_constructor_statements id observed validUntil statements checkpoints trust output accepted]
  exact (StableNormalization.permutation grantKey statements.val).forall_mem_iff

end Auths.Codec.SnapshotOrdering
