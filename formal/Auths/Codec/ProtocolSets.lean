import Auths.Codec.ProtocolOrdering
import Auths.Codec.ProtocolBoundedSet

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolSets
set_option maxHeartbeats 2000000

def mapBoundError {T : Type} (invalid duplicate : auths_model.ModelError) :
    core.result.Result T auths_model.bounded.BoundError → core.result.Result T auths_model.ModelError
  | .Ok value => .Ok value
  | .Err .Duplicate => .Err duplicate
  | .Err .Empty => .Err invalid
  | .Err .AboveMaximum => .Err invalid

private theorem map_success {T : Type} (invalid duplicate : auths_model.ModelError)
    (result : core.result.Result T auths_model.bounded.BoundError) (output : T) :
    mapBoundError invalid duplicate result = .Ok output ↔ result = .Ok output := by
  cases result with
  | Ok value => simp [mapBoundError]
  | Err failure => cases failure <;> simp [mapBoundError]

structure Facts {T Key : Type} [Ord Key] (maximum : Nat) (view : T → Key)
    (input output : alloc.vec.Vec T) : Prop where
  nonempty : output.val ≠ []
  count : output.val.length ≤ maximum
  permutation : output.val.Perm input.val
  unique : (output.val.map view).Nodup
  ordered : (output.val.map view).Pairwise KeyOrder.LT

private theorem core_facts {T Key : Type} [DecidableEq Key] [Ord Key]
    [Std.TransOrd Key] [Std.LawfulEqOrd Key]
    (maximum : Std.Usize) (order : core.cmp.Ord T) (view : T → Key)
    (compareLaw : ∀ left right, order.cmp left right = ok (compare (view left) (view right)))
    (equalLaw : ∀ left right,
      order.eqInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (partialEqualLaw : ∀ left right,
      order.partialOrdInst.partialEqInst.eq left right = ok (decide (view left = view right)))
    (input output : alloc.vec.Vec T)
    (accepted : @auths_model.bounded.BoundedSet.new T maximum order input = ok (.Ok output)) :
    Facts maximum.val view input output := by
  let comparison := fun left right => compare (view left) (view right)
  obtain ⟨nonempty, bounded, clean, rfl⟩ :=
    (ProtocolBoundedSet.accepts_iff maximum order comparison view compareLaw equalLaw partialEqualLaw input output).mp accepted
  have same := ProtocolSort.sorted_vector_permutation comparison input
  refine ⟨?_, ?_, same, KeyOrder.sorted_clean_unique view input clean,
    KeyOrder.sorted_clean_strict view input clean⟩
  · intro empty
    have lengths := same.length_eq
    rw [empty, List.length_nil] at lengths
    exact nonempty (List.length_eq_zero_iff.mp lengths.symm)
  · simpa [same.length_eq] using bounded

private theorem permission_equal (left right : auths_model.Permission) :
    auths_model.Permission.Insts.CoreCmpOrd.eqInst.partialEqInst.eq left right =
      ok (decide (ProtocolEquality.permissionView left = ProtocolEquality.permissionView right)) := by
  simpa [auths_model.Permission.Insts.CoreCmpOrd, auths_model.Permission.Insts.CoreCmpEq]
    using ProtocolEquality.permission_exact left right

private theorem permission_partial_equal (left right : auths_model.Permission) :
    auths_model.Permission.Insts.CoreCmpOrd.partialOrdInst.partialEqInst.eq left right =
      ok (decide (ProtocolEquality.permissionView left = ProtocolEquality.permissionView right)) := by
  simpa [auths_model.Permission.Insts.CoreCmpOrd, auths_model.Permission.Insts.CoreCmpPartialOrdPermission]
    using ProtocolEquality.permission_exact left right

private theorem audience_equal (left right : auths_model.Audience) :
    auths_model.Audience.Insts.CoreCmpOrd.eqInst.partialEqInst.eq left right = ok (decide (left = right)) := by
  simpa [auths_model.Audience.Insts.CoreCmpOrd, auths_model.Audience.Insts.CoreCmpEq]
    using ProtocolEquality.audience_exact left right

private theorem audience_partial_equal (left right : auths_model.Audience) :
    auths_model.Audience.Insts.CoreCmpOrd.partialOrdInst.partialEqInst.eq left right = ok (decide (left = right)) := by
  simpa [auths_model.Audience.Insts.CoreCmpOrd, auths_model.Audience.Insts.CoreCmpPartialOrdAudience]
    using ProtocolEquality.audience_exact left right

private theorem digest_equal (left right : auths_model.Digest) :
    auths_model.Digest.Insts.CoreCmpOrd.eqInst.partialEqInst.eq left right =
      ok (decide (ProtocolOrdering.digestKey left = ProtocolOrdering.digestKey right)) := by
  simpa [auths_model.Digest.Insts.CoreCmpOrd, auths_model.Digest.Insts.CoreCmpEq,
    ProtocolOrdering.digest_key_injective.eq_iff] using ProtocolEquality.digest_exact left right

private theorem digest_partial_equal (left right : auths_model.Digest) :
    auths_model.Digest.Insts.CoreCmpOrd.partialOrdInst.partialEqInst.eq left right =
      ok (decide (ProtocolOrdering.digestKey left = ProtocolOrdering.digestKey right)) := by
  simpa [auths_model.Digest.Insts.CoreCmpOrd, auths_model.Digest.Insts.CoreCmpPartialOrdDigest,
    ProtocolOrdering.digest_key_injective.eq_iff] using ProtocolEquality.digest_exact left right

theorem permissions_exact (input : alloc.vec.Vec auths_model.Permission) :
    auths_model.PermissionSet.new input = ok (mapBoundError .InvalidPermissionSet .DuplicatePermission
      (ProtocolBoundedSet.expected 1024#usize
        (fun left right => compare (ProtocolEquality.permissionView left) (ProtocolEquality.permissionView right))
        ProtocolEquality.permissionView input)) := by
  unfold auths_model.PermissionSet.new
  rw [ProtocolBoundedSet.source_exact 1024#usize auths_model.Permission.Insts.CoreCmpOrd
    (fun left right => compare (ProtocolEquality.permissionView left) (ProtocolEquality.permissionView right))
    ProtocolEquality.permissionView ProtocolOrdering.permission_compare permission_equal permission_partial_equal]
  simp only [bind_tc_ok]
  split <;> rfl

theorem audiences_exact (input : alloc.vec.Vec auths_model.Audience) :
    auths_model.AudienceSet.new input = ok (mapBoundError .InvalidAudienceSet .DuplicateAudience
      (ProtocolBoundedSet.expected 256#usize (fun left right => compare left right) id input)) := by
  unfold auths_model.AudienceSet.new
  rw [ProtocolBoundedSet.source_exact 256#usize auths_model.Audience.Insts.CoreCmpOrd
    (fun left right => compare left right) id ProtocolOrdering.audience_compare audience_equal audience_partial_equal]
  simp only [bind_tc_ok]
  split <;> rfl

theorem body_digests_exact (input : alloc.vec.Vec auths_model.Digest) :
    auths_model.BodyDigestSet.new input = ok (mapBoundError .InvalidActionConstraint .DuplicateBodyDigest
      (ProtocolBoundedSet.expected 256#usize
        (fun left right => compare (ProtocolOrdering.digestKey left) (ProtocolOrdering.digestKey right))
        ProtocolOrdering.digestKey input)) := by
  unfold auths_model.BodyDigestSet.new
  rw [ProtocolBoundedSet.source_exact 256#usize auths_model.Digest.Insts.CoreCmpOrd
    (fun left right => compare (ProtocolOrdering.digestKey left) (ProtocolOrdering.digestKey right))
    ProtocolOrdering.digestKey ProtocolOrdering.digest_compare digest_equal digest_partial_equal]
  simp only [bind_tc_ok]
  split <;> rfl

theorem permission_facts (input : alloc.vec.Vec auths_model.Permission)
    (output : auths_model.PermissionSet) (accepted : auths_model.PermissionSet.new input = ok (.Ok output)) :
    Facts 1024 ProtocolEquality.permissionView input output := by
  rw [permissions_exact] at accepted
  have coreSuccess := (map_success .InvalidPermissionSet .DuplicatePermission _ output).mp (Result.ok.inj accepted)
  apply core_facts 1024#usize auths_model.Permission.Insts.CoreCmpOrd ProtocolEquality.permissionView
    ProtocolOrdering.permission_compare permission_equal permission_partial_equal input output
  rw [ProtocolBoundedSet.source_exact 1024#usize auths_model.Permission.Insts.CoreCmpOrd
    (fun left right => compare (ProtocolEquality.permissionView left) (ProtocolEquality.permissionView right))
    ProtocolEquality.permissionView ProtocolOrdering.permission_compare permission_equal permission_partial_equal, coreSuccess]

theorem audience_facts (input : alloc.vec.Vec auths_model.Audience)
    (output : auths_model.AudienceSet) (accepted : auths_model.AudienceSet.new input = ok (.Ok output)) :
    Facts 256 id input output := by
  rw [audiences_exact] at accepted
  have coreSuccess := (map_success .InvalidAudienceSet .DuplicateAudience _ output).mp (Result.ok.inj accepted)
  apply core_facts 256#usize auths_model.Audience.Insts.CoreCmpOrd id
    ProtocolOrdering.audience_compare audience_equal audience_partial_equal input output
  rw [ProtocolBoundedSet.source_exact 256#usize auths_model.Audience.Insts.CoreCmpOrd
    (fun left right => compare left right) id ProtocolOrdering.audience_compare audience_equal audience_partial_equal, coreSuccess]

theorem body_digest_facts (input : alloc.vec.Vec auths_model.Digest)
    (output : auths_model.BodyDigestSet) (accepted : auths_model.BodyDigestSet.new input = ok (.Ok output)) :
    Facts 256 ProtocolOrdering.digestKey input output := by
  rw [body_digests_exact] at accepted
  have coreSuccess := (map_success .InvalidActionConstraint .DuplicateBodyDigest _ output).mp (Result.ok.inj accepted)
  apply core_facts 256#usize auths_model.Digest.Insts.CoreCmpOrd ProtocolOrdering.digestKey
    ProtocolOrdering.digest_compare digest_equal digest_partial_equal input output
  rw [ProtocolBoundedSet.source_exact 256#usize auths_model.Digest.Insts.CoreCmpOrd
    (fun left right => compare (ProtocolOrdering.digestKey left) (ProtocolOrdering.digestKey right))
    ProtocolOrdering.digestKey ProtocolOrdering.digest_compare digest_equal digest_partial_equal, coreSuccess]

/-- The representation premises are component validity, not a desired source
outcome. Actual construction earns count, canonical byte order and uniqueness. -/
theorem permissions_valid (input : alloc.vec.Vec auths_model.Permission)
    (output : auths_model.PermissionSet) (fields : ∀ value ∈ input.val, ProtocolValidity.Permission value)
    (accepted : auths_model.PermissionSet.new input = ok (.Ok output)) : ProtocolValidity.Permissions output := by
  have facts := permission_facts input output accepted
  refine ⟨facts.nonempty, facts.count, ?_, ?_, ?_⟩
  · intro value member
    exact fields value (facts.permutation.mem_iff.mp member)
  · have ordered := List.pairwise_map.mp facts.ordered
    exact ordered.imp (fun left right less => (ProtocolOrdering.permission_lt_iff left right).mp less)
  · exact facts.unique.of_map

theorem audiences_valid (input : alloc.vec.Vec auths_model.Audience)
    (output : auths_model.AudienceSet) (fields : ∀ value ∈ input.val, ProtocolValidity.Identifier value 512)
    (accepted : auths_model.AudienceSet.new input = ok (.Ok output)) : ProtocolValidity.Audiences output := by
  have facts := audience_facts input output accepted
  refine ⟨facts.nonempty, facts.count, ?_, ?_, ?_⟩
  · intro value member
    exact fields value (facts.permutation.mem_iff.mp member)
  · have ordered := List.pairwise_map.mp facts.ordered
    exact ordered.imp (fun left right less => (ProtocolOrdering.text_lt_iff left right).mp less)
  · simpa using facts.unique

theorem body_digests_valid (input : alloc.vec.Vec auths_model.Digest)
    (output : auths_model.BodyDigestSet) (accepted : auths_model.BodyDigestSet.new input = ok (.Ok output)) :
    ProtocolValidity.BodyDigests output := by
  have facts := body_digest_facts input output accepted
  refine ⟨facts.nonempty, facts.count, ?_, facts.unique.of_map⟩
  have ordered := List.pairwise_map.mp facts.ordered
  exact ordered.imp (fun left right less => (ProtocolOrdering.digest_lt_iff left right).mp less)

end Auths.Codec.ProtocolSets
