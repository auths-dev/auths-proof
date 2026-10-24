import Auths.Codec.ObjectEncode
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentEncode
open Refinement EncoderState ProtocolEncode ObjectEncode

def attachmentEncoding (attachment : auths_codec.auths_model.DetachedAttachment) : List Nat :=
  [162, 0] ++ payloadEncoding 2 (byteList attachment.digest.val) ++ [1] ++
    payloadEncoding 2 (byteList attachment.bytes.val)

def attachmentCost (attachment : auths_codec.auths_model.DetachedAttachment) : Nat :=
  77 + attachment.bytes.val.length

def attachmentsEncoding (attachments : List auths_codec.auths_model.DetachedAttachment) : List Nat :=
  attachments.flatMap attachmentEncoding

def attachmentsCost (attachments : List auths_codec.auths_model.DetachedAttachment) : Nat :=
  (attachments.map attachmentCost).sum

def encoderView (state : core.result.Result cbor.Encoder error.CodecError) :
    core.result.Result (List Nat) error.CodecError :=
  match state with | .Err error => .Err error | .Ok encoder => .Ok (byteList encoder.output.val)

theorem attachment_length_bound (attachment : auths_codec.auths_model.DetachedAttachment) :
    (attachmentEncoding attachment).length ≤ attachmentCost attachment := by
  have digestLength : attachment.digest.val.length = 32 := by simpa using attachment.digest.property
  have digestBound := payload_length_bound 2 (byteList attachment.digest.val)
  have bytesBound := payload_length_bound 2 (byteList attachment.bytes.val)
  simp only [attachmentEncoding, attachmentCost, List.length_append, List.length_cons,
    List.length_nil, byteList, List.length_map] at *
  omega

theorem attachments_length_bound (attachments : List auths_codec.auths_model.DetachedAttachment) :
    (attachmentsEncoding attachments).length ≤ attachmentsCost attachments := by
  induction attachments with
  | nil => simp [attachmentsEncoding, attachmentsCost]
  | cons first rest ih =>
    have bound := attachment_length_bound first
    simpa [attachmentsEncoding, attachmentsCost, List.flatMap_cons] using Nat.add_le_add bound ih

@[step] theorem attachment_exact
    (state : core.result.Result cbor.Encoder error.CodecError)
    (attachment : auths_codec.auths_model.DetachedAttachment)
    (space : match state with | .Err _ => True
      | .Ok encoder => encoder.output.val.length + attachmentCost attachment ≤ Usize.max) :
    encode.encode_canonical_attachment state attachment ⦃ actual =>
      encoderView actual = match state with
        | .Err error => .Err error
        | .Ok encoder => .Ok (byteList encoder.output.val ++ attachmentEncoding attachment) ⦄ := by
  unfold encode.encode_canonical_attachment
  cases state with
  | Err error =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from, encoderView]
  | Ok self =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    simp only [attachmentCost] at space
    have digestLength : attachment.digest.val.length = 32 := by simpa using attachment.digest.property
    step with ProtocolEncode.map_exact self 2#u64 (by omega) as ⟨r0, e0, ok0, bytes0⟩
    have len0 := output_length bytes0
    have bound0 := encodeHead_length_le_nine ⟨5, 2⟩
    simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncode.key_exact e0 0#u8 (by omega) as ⟨r1, e1, ok1, bytes1⟩
    have len1 := output_length bytes1
    have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
    simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
      auths_model.DetachedAttachment.impl.digest, auths_model.AttachmentDigest.as_bytes,
      lift, Array.to_slice]
    step with ProtocolEncode.bytes_exact e1 (Array.to_slice attachment.digest) (by change e1.output.val.length + (9 + attachment.digest.val.length) ≤ Usize.max; omega)
      as ⟨r2, e2, ok2, bytes2⟩
    have len2 := output_length bytes2
    have bound2 := payload_length_bound 2 (byteList attachment.digest.val)
    simp only [byteList, List.length_map] at bound2
    simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with ProtocolEncode.key_exact e2 1#u8 (by omega) as ⟨r3, e3, ok3, bytes3⟩
    have len3 := output_length bytes3
    have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
    simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok,
      auths_model.DetachedAttachment.impl.bytes]
    step with ProtocolEncode.bytes_exact e3 (alloc.vec.Vec.deref attachment.bytes) (by
      simpa only [alloc.vec.Vec.deref] using (show e3.output.val.length + (9 + attachment.bytes.val.length) ≤ Usize.max by omega))
      as ⟨r4, e4, ok4, bytes4⟩
    simp [ok4, core.result.Result.Insts.CoreOpsTry.branch, encoderView,
      bytes4, bytes3, bytes2, bytes1, bytes0, attachmentEncoding,
      Array.to_slice, alloc.vec.Vec.deref, List.append_assoc,
      encodeHead, additionalTag, argumentWidth, bigEndian]

/-- The real source loop preserves typed failure and writes every attachment
once, in order. Its decreasing measure is the remaining input length. -/
@[step] theorem attachments_exact
    (iter : core.slice.iter.Iter auths_codec.auths_model.DetachedAttachment)
    (self : cbor.Encoder)
    (space : self.output.val.length + attachmentsCost (iter.slice.val.drop iter.i) ≤ Usize.max) :
    encode.encode_canonical_action_loop iter (.Ok self) ⦃ actual =>
      encoderView actual = .Ok (byteList self.output.val ++
        attachmentsEncoding (iter.slice.val.drop iter.i)) ⦄ := by
  let expected := byteList self.output.val ++ attachmentsEncoding (iter.slice.val.drop iter.i)
  unfold encode.encode_canonical_action_loop
  apply loop.spec_decr_nat
    (measure := fun state => state.1.slice.val.length - state.1.i)
    (inv := fun state => state.1.slice = iter.slice ∧
      match state.2 with
      | .Err _ => False
      | .Ok current =>
        current.output.val.length + attachmentsCost (state.1.slice.val.drop state.1.i) ≤ Usize.max ∧
        byteList current.output.val ++ attachmentsEncoding (state.1.slice.val.drop state.1.i) = expected)
  · rintro ⟨currentIter, current⟩ ⟨sameSlice, invariant⟩
    cases current with
    | Err error => simp at invariant
    | Ok current =>
      obtain ⟨capacity, meaning⟩ := invariant
      unfold encode.encode_canonical_action_loop.body core.slice.iter.IteratorSliceIter.next
      dsimp only
      split <;> rename_i within
      · have inside : currentIter.i < currentIter.slice.val.length := by simpa [Slice.len] using within
        let attachment := currentIter.slice.val[currentIter.i]
        have remaining : currentIter.slice.val.drop currentIter.i =
            attachment :: currentIter.slice.val.drop (currentIter.i + 1) := by
          exact List.drop_eq_getElem_cons inside
        have costs : attachmentsCost (currentIter.slice.val.drop currentIter.i) =
            attachmentCost attachment + attachmentsCost (currentIter.slice.val.drop (currentIter.i + 1)) := by
          rw [remaining]
          simp [attachmentsCost]
        simp only [bind_tc_ok]
        step with attachment_exact (.Ok current) attachment (by simp only; omega)
          as ⟨updated, written⟩
        cases updated with
        | Err error => simp [encoderView] at written
        | Ok updated =>
          have exactBytes : byteList updated.output.val = byteList current.output.val ++ attachmentEncoding attachment := by
            simpa [encoderView] using written
          have length := output_length exactBytes
          have encodedBound := attachment_length_bound attachment
          simp only [spec_ok]
          refine ⟨sameSlice, ?_, ?_, by omega⟩
          · omega
          · rw [remaining] at meaning
            simpa [attachmentsEncoding, List.flatMap_cons, exactBytes, List.append_assoc] using meaning
      · have atEnd : currentIter.slice.val.length ≤ currentIter.i := by simpa [Slice.len] using Nat.le_of_not_lt within
        simp only [List.drop_eq_nil_of_le atEnd, attachmentsEncoding, List.flatMap_nil,
          List.append_nil] at meaning
        simpa [encoderView] using meaning
  · exact ⟨rfl, space, rfl⟩

end Auths.Codec.AttachmentEncode
