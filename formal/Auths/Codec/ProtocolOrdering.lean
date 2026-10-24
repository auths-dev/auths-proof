import Auths.Codec.ProtocolEquality
import Auths.Codec.KeyOrder
import Auths.Codec.Utf8Order
import Auths.Composition.Order

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.ProtocolOrdering

def digestKey (value : auths_model.Digest) : List Nat := value.val.map UScalar.val

theorem digest_key_injective : Function.Injective digestKey := by
  intro left right same
  apply Subtype.ext
  apply (List.map_injective_iff.mpr (show Function.Injective (fun value : Std.U8 => value.val) from by
    intro first second equal
    scalar_tac))
  exact same

theorem list_comparison (left right : List Nat) :
    List.compareLex compare left right = compare left right := by
  cases computed : List.compareLex compare left right with
  | lt => exact (compare_lt_iff_lt.mpr (Auths.Composition.Order.nat_lists_lt _ _ |>.mp computed)).symm
  | eq => exact (compare_eq_iff_eq.mpr (Auths.Composition.Order.nat_lists_eq _ _ |>.mp computed)).symm
  | gt => exact (compare_gt_iff_gt.mpr (Auths.Composition.Order.nat_lists_gt _ _ |>.mp computed)).symm

theorem digest_compare (left right : auths_model.Digest) :
    auths_model.Digest.Insts.CoreCmpOrd.cmp left right = ok (compare (digestKey left) (digestKey right)) := by
  unfold auths_model.Digest.Insts.CoreCmpOrd.cmp
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison, list_comparison]

def grantIdKey (value : auths_model.GrantId) : List Nat := value.val.map UScalar.val
def principalStatusIdKey (value : auths_model.PrincipalStatusId) : List Nat := value.val.map UScalar.val
def grantStatusIdKey (value : auths_model.GrantStatusId) : List Nat := value.val.map UScalar.val
def approvalRequirementIdKey (value : auths_model.ApprovalRequirementId) : List Nat :=
  value.val.map UScalar.val

-- These are injective representations of ID bytes, not injectivity of a
-- content hash from statements to IDs. Different records may share an ID.
theorem grant_id_key_injective : Function.Injective grantIdKey := by
  intro left right same
  exact digest_key_injective same

theorem principal_status_id_key_injective : Function.Injective principalStatusIdKey := by
  intro left right same
  exact digest_key_injective same

theorem grant_status_id_key_injective : Function.Injective grantStatusIdKey := by
  intro left right same
  exact digest_key_injective same

theorem approval_requirement_id_key_injective : Function.Injective approvalRequirementIdKey := by
  intro left right same
  exact digest_key_injective same

theorem grant_id_compare (left right : auths_model.GrantId) :
    auths_model.GrantId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (grantIdKey left) (grantIdKey right)) := by
  simp only [auths_model.GrantId.Insts.CoreCmpOrd.cmp, auths_model.Digest.Insts.CoreCmpOrd.cmp]
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison, list_comparison]

theorem principal_status_id_compare (left right : auths_model.PrincipalStatusId) :
    auths_model.PrincipalStatusId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (principalStatusIdKey left) (principalStatusIdKey right)) := by
  simp only [auths_model.PrincipalStatusId.Insts.CoreCmpOrd.cmp, auths_model.Digest.Insts.CoreCmpOrd.cmp]
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison, list_comparison]

theorem grant_status_id_compare (left right : auths_model.GrantStatusId) :
    auths_model.GrantStatusId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (grantStatusIdKey left) (grantStatusIdKey right)) := by
  simp only [auths_model.GrantStatusId.Insts.CoreCmpOrd.cmp, auths_model.Digest.Insts.CoreCmpOrd.cmp]
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison, list_comparison]

theorem approval_requirement_id_compare
    (left right : auths_model.ApprovalRequirementId) :
    auths_model.ApprovalRequirementId.Insts.CoreCmpOrd.cmp left right =
      ok (compare (approvalRequirementIdKey left) (approvalRequirementIdKey right)) := by
  simp only [auths_model.ApprovalRequirementId.Insts.CoreCmpOrd.cmp, auths_model.Digest.Insts.CoreCmpOrd.cmp]
  rw [Auths.Composition.Order.array_comparison, Auths.Composition.Order.bytes_comparison, list_comparison]

theorem audience_compare (left right : auths_model.Audience) :
    auths_model.Audience.Insts.CoreCmpOrd.cmp left right = ok (compare left right) := by
  simp [auths_model.Audience.Insts.CoreCmpOrd.cmp,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpOrd.cmp,
    _root_.alloc.string.String.Insts.CoreCmpOrd.cmp]

theorem principal_compare (left right : auths_model.PrincipalId) :
    auths_model.PrincipalId.Insts.CoreCmpOrd.cmp left right = ok (compare left right) := by
  simp [auths_model.PrincipalId.Insts.CoreCmpOrd.cmp,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpOrd.cmp,
    _root_.alloc.string.String.Insts.CoreCmpOrd.cmp]

theorem status_method_compare (left right : auths_model.StatusMethodId) :
    auths_model.StatusMethodId.Insts.CoreCmpOrd.cmp left right = ok (compare left right) := by
  simp [auths_model.StatusMethodId.Insts.CoreCmpOrd.cmp,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpOrd.cmp,
    _root_.alloc.string.String.Insts.CoreCmpOrd.cmp]

theorem permission_compare (left right : auths_model.Permission) :
    auths_model.Permission.Insts.CoreCmpOrd.cmp left right =
      ok (compare (ProtocolEquality.permissionView left) (ProtocolEquality.permissionView right)) := by
  simp only [auths_model.Permission.Insts.CoreCmpOrd.cmp,
    auths_model.CapabilityId.Insts.CoreCmpOrd.cmp, auths_model.ResourceId.Insts.CoreCmpOrd.cmp,
    AuthsProtocolCodec.alloc.string.String.Insts.CoreCmpOrd.cmp,
    _root_.alloc.string.String.Insts.CoreCmpOrd.cmp, bind_tc_ok]
  cases ordering : compare left.capability right.capability <;>
    simp [ProtocolEquality.permissionView, Prod.Lex.compare_def, compareLex, compareOn, ordering]

theorem text_lt_iff (left right : String) : KeyOrder.LT left right ↔ ProtocolValidity.textLT left right := by
  rw [KeyOrder.LT, compare_lt_iff_lt, Utf8Order.string_order]
  rfl

theorem digest_lt_iff (left right : auths_model.Digest) :
    KeyOrder.LT (digestKey left) (digestKey right) ↔ ProtocolValidity.digestLT left right := by
  rw [KeyOrder.LT, compare_lt_iff_lt]
  rfl

theorem permission_lt_iff (left right : auths_model.Permission) :
    KeyOrder.LT (ProtocolEquality.permissionView left) (ProtocolEquality.permissionView right) ↔
      ProtocolValidity.permissionLT left right := by
  unfold KeyOrder.LT ProtocolEquality.permissionView ProtocolValidity.permissionLT
  cases ordering : compare left.capability right.capability with
  | lt =>
    have less := text_lt_iff left.capability right.capability |>.mp ordering
    simp [Prod.Lex.compare_def, compareLex, compareOn, ordering, less]
  | eq =>
    have same := Std.compare_eq_iff_eq.mp ordering
    simp [Prod.Lex.compare_def, compareLex, compareOn, ordering, same, ← text_lt_iff]
  | gt =>
    have reversed := text_lt_iff right.capability left.capability |>.mp (Std.OrientedCmp.lt_of_gt ordering)
    have notLess : ¬ ProtocolValidity.textLT left.capability right.capability := by
      rw [← text_lt_iff, KeyOrder.LT]
      simp [ordering]
    have different : left.capability ≠ right.capability := by intro same; simp [same] at ordering
    simp [Prod.Lex.compare_def, compareLex, compareOn, ordering, notLess, different]

end Auths.Codec.ProtocolOrdering
