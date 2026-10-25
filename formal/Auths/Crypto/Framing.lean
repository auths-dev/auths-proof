import Auths.Codec.Semantics
open Auths.Codec
namespace Auths.Crypto.Framing

structure Frame where
  objectTag : Nat
  profile : List Nat
  profileVersion : Nat
  statement : List Nat
  deriving DecidableEq

def Frame.Valid (frame : Frame) : Prop :=
  frame.objectTag < 65536 ∧ frame.profile.length < 65536 ∧
    frame.profileVersion < 65536 ∧ frame.statement.length < 18446744073709551616 ∧
    BytesValid frame.profile ∧ BytesValid frame.statement

/-- The protocol's signing frame, independently described as natural-number bytes. -/
def encode (frame : Frame) : List Nat :=
  [65, 85, 84, 72, 83, 0, 1] ++
    bigEndian 2 frame.objectTag ++ bigEndian 2 frame.profile.length ++ frame.profile ++
    bigEndian 2 frame.profileVersion ++ bigEndian 8 frame.statement.length ++ frame.statement

theorem length_exact (frame : Frame) :
    (encode frame).length = 21 + frame.profile.length + frame.statement.length := by
  simp [encode, bigEndian_length]
  omega

theorem endian_injective (width left right : Nat)
    (leftBound : left < 256 ^ width) (rightBound : right < 256 ^ width)
    (same : bigEndian width left = bigEndian width right) : left = right := by
  have := congrArg unsigned same
  simpa only [unsigned_bigEndian width left leftBound,
    unsigned_bigEndian width right rightBound] using this

/-- Equal signing bytes have equal framed inputs. No hash property is assumed. -/
theorem framing_is_unambiguous (left right : Frame)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (same : encode left = encode right) : left = right := by
  have rest :
      bigEndian 2 left.objectTag ++
        (bigEndian 2 left.profile.length ++ (left.profile ++
          (bigEndian 2 left.profileVersion ++ (bigEndian 8 left.statement.length ++ left.statement)))) =
      bigEndian 2 right.objectTag ++
        (bigEndian 2 right.profile.length ++ (right.profile ++
          (bigEndian 2 right.profileVersion ++ (bigEndian 8 right.statement.length ++ right.statement)))) := by
    simpa only [encode, List.append_assoc, List.cons_append, List.nil_append,
      List.cons.injEq, true_and] using same
  obtain ⟨tagBytes, rest⟩ := List.append_inj rest (by simp [bigEndian_length])
  have tags := endian_injective 2 left.objectTag right.objectTag
    leftValid.1 rightValid.1 tagBytes
  obtain ⟨profileLengths, rest⟩ := List.append_inj rest (by simp [bigEndian_length])
  have lengths := endian_injective 2 left.profile.length right.profile.length
    leftValid.2.1 rightValid.2.1 profileLengths
  obtain ⟨profiles, rest⟩ := List.append_inj rest lengths
  obtain ⟨versionBytes, rest⟩ := List.append_inj rest (by simp [bigEndian_length])
  have versions := endian_injective 2 left.profileVersion right.profileVersion
    leftValid.2.2.1 rightValid.2.2.1 versionBytes
  obtain ⟨_, statements⟩ := List.append_inj rest (by simp [bigEndian_length])
  cases left
  cases right
  simp_all

/-- Distinct registered object tags cannot share signing bytes, regardless of payload. -/
theorem different_tags_separate (left right : Frame)
    (leftValid : left.Valid) (rightValid : right.Valid)
    (different : left.objectTag ≠ right.objectTag) : encode left ≠ encode right := by
  intro same
  exact different (congrArg Frame.objectTag (framing_is_unambiguous left right leftValid rightValid same))

end Auths.Crypto.Framing
