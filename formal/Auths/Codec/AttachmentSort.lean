import Auths.Codec.AttachmentOrder
import Auths.Codec.AttachmentResources
import Auths.Composition.Order
import Auths.Verifier.StatusGrantLeaves
import Mathlib.Data.List.Sort
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentSort
open Refinement AttachmentOrder

abbrev Attachment := auths_codec.auths_model.DetachedAttachment
abbrev digestLE (left right : Attachment) : Prop := byteList left.digest.val ≤ byteList right.digest.val

local instance : Std.Total digestLE where
  total left right := le_total _ _
local instance : IsTrans Attachment digestLE where
  trans _ _ _ left right := le_trans left right

def sorted (values : List Attachment) : List Attachment := values.insertionSort digestLE

theorem sorted_perm (values : List Attachment) : (sorted values).Perm values :=
  List.perm_insertionSort digestLE values

theorem sorted_length (values : List Attachment) : (sorted values).length = values.length :=
  List.length_insertionSort digestLE values

theorem sorted_ordered (values : List Attachment) : (sorted values).Pairwise digestLE :=
  List.pairwise_insertionSort digestLE values


abbrev key := auths_model.CanonicalAction.with_detached_attachments.closure.Insts.CoreOpsFunctionFnMutTupleSharedDetachedAttachmentAttachmentDigest

theorem key_call (value : Attachment) : key.call_mut () value = ok (value.digest, ()) := rfl

theorem insert_exact (item : Attachment) (values : List Attachment) :
    StdModel.insertKeyValues key auths_model.AttachmentDigest.Insts.CoreCmpOrd () item values =
      ok ⟨values.orderedInsert digestLE item, List.orderedInsert_length digestLE values item⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [StdModel.insertKeyValues_cons]
    simp only [key_call, digest_comparison, bind_tc_ok]
    have greater := Auths.Composition.Order.nat_lists_gt (byteList item.digest.val) (byteList first.digest.val)
    by_cases ordered : digestLE item first
    · have notGreater : List.compareLex compare (byteList item.digest.val) (byteList first.digest.val) ≠ .gt := by
        intro comparison
        have reversed := greater.mp comparison
        exact not_lt_of_ge ordered reversed
      simp [notGreater, List.orderedInsert_cons, ordered]
    · have isGreater : List.compareLex compare (byteList item.digest.val) (byteList first.digest.val) = .gt := by
        exact greater.mpr (lt_of_not_ge ordered)
      simp [isGreater, List.orderedInsert_cons, ordered, ih]

theorem sort_exact_values (values : List Attachment) :
    StdModel.sortKeyValues key auths_model.AttachmentDigest.Insts.CoreCmpOrd () values =
      ok ⟨sorted values, sorted_length values⟩ := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    rw [StdModel.sortKeyValues_cons, ih]
    simp only [bind_tc_ok, insert_exact]
    rfl

/-- A concrete stateless digest callback and actual byte-array comparison
close the generic sorting contract for the action constructor. -/
theorem sort_exact (values : Slice Attachment) :
    alloc.slice.Slice.sort_by_key key auths_model.AttachmentDigest.Insts.CoreCmpOrd values () =
      ok ⟨sorted values.val, by rw [sorted_length]; exact values.property⟩ := by
  rw [StdModel.sort_by_key_values, sort_exact_values]
  rfl

theorem sort_preserves_bytes (values : List Attachment) :
    AttachmentResources.byteSum (sorted values) = AttachmentResources.byteSum values := by
  exact List.Perm.sum_eq ((sorted_perm values).map fun attachment => attachment.bytes.val.length)

end Auths.Codec.AttachmentSort
