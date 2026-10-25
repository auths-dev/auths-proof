import Auths.Codec.Refinement
import Auths.Composition.Order
import Auths.Verifier.StatusGrantLeaves
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentOrder
open Refinement

theorem digest_equal (left right : auths_codec.auths_model.AttachmentDigest) :
    auths_model.AttachmentDigest.Insts.CoreCmpPartialEqAttachmentDigest.eq left right = ok (left == right) := by
  simp only [auths_model.AttachmentDigest.Insts.CoreCmpPartialEqAttachmentDigest.eq,
    auths_model.Digest.Insts.CoreCmpPartialEqDigest.eq]
  exact Auths.StatusSelection.byte_array_comparison left right

theorem digest_comparison (left right : auths_codec.auths_model.AttachmentDigest) :
    auths_model.AttachmentDigest.Insts.CoreCmpOrd.cmp left right =
      ok (List.compareLex compare (byteList left.val) (byteList right.val)) := by
  unfold auths_model.AttachmentDigest.Insts.CoreCmpOrd.cmp auths_model.Digest.Insts.CoreCmpOrd.cmp
  rw [Auths.Composition.Order.array_comparison]
  exact Auths.Composition.Order.bytes_comparison left.val right.val

@[step] theorem digest_equal_exact (left right : auths_codec.auths_model.AttachmentDigest) :
    auths_model.AttachmentDigest.Insts.CoreCmpPartialEqAttachmentDigest.eq left right
      ⦃ actual => actual = (left == right) ⦄ := by
  rw [digest_equal]
  rfl

end Auths.Codec.AttachmentOrder
