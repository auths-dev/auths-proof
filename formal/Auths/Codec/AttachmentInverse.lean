import Auths.Codec.NativeFieldInverse
import Auths.Codec.AttachmentDecodeSafety
import Auths.Codec.AttachmentEncode
import Auths.Codec.AttachmentResources
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentInverse
open Refinement WireInverse EncoderState AttachmentEncode

abbrev Attachment := auths_codec.auths_model.DetachedAttachment

def view (value : Attachment) : AttachmentDecode.Attachment :=
  (byteList value.digest.val, byteList value.bytes.val)

def WellFormed (values : List Attachment) : Prop :=
  ∀ value ∈ values, 0 < value.bytes.val.length ∧ value.bytes.val.length ≤ 8388608

theorem bytes_injective : Function.Injective (fun bytes : List Std.U8 => byteList bytes) := by
  apply List.map_injective_iff.mpr
  intro left right same
  exact UScalar.eq_of_val_eq same

theorem view_injective : Function.Injective view := by
  intro left right same
  have fields := Prod.mk.inj same
  have digest : left.digest = right.digest := Subtype.ext (bytes_injective fields.1)
  have bytes : left.bytes = right.bytes := Subtype.ext (bytes_injective fields.2)
  cases left
  cases right
  simp_all

theorem views_injective : Function.Injective (fun values : List Attachment => values.map view) :=
  List.map_injective_iff.mpr view_injective

theorem bounded_bytes_consumes (bytes : List Nat) (maximum : Nat)
    (nonempty : bytes ≠ []) (bounded : bytes.length ≤ maximum)
    (lengthBound : bytes.length < 2 ^ 64) :
    Consumes (fun input position => Fields.boundedBytesAt input position maximum true)
      (payloadEncoding 2 bytes) bytes := by
  intro leading trailing
  have payload := payload_prefix 2 (by decide) bytes leading trailing lengthBound
  simp [Fields.boundedBytesAt, payload, nonempty, bounded.not_gt]

theorem digest_consumes (bytes : List Nat) (length : bytes.length = 32) :
    Consumes Fields.digestAt (payloadEncoding 2 bytes) bytes := by
  intro leading trailing
  have payload := payload_prefix 2 (by decide) bytes leading trailing (by omega)
  simp [Fields.digestAt, payload, length]

theorem attachment_consumes (value : Attachment) (maximum : Nat)
    (valid : 0 < value.bytes.val.length ∧ value.bytes.val.length ≤ 8388608)
    (bounded : value.bytes.val.length ≤ maximum) :
    Consumes (fun input position => AttachmentDecode.readAttachment input maximum position)
      (attachmentEncoding value) (view value) := by
  have digestLength : (byteList value.digest.val).length = 32 := by
    simpa only [byteList, List.length_map] using value.digest.property
  have nonempty : byteList value.bytes.val ≠ [] := by
    simp only [byteList, List.map_eq_nil_iff]
    exact List.ne_nil_of_length_pos valid.1
  have bodyLength : (byteList value.bytes.val).length = value.bytes.val.length := by simp [byteList]
  unfold AttachmentDecode.readAttachment attachmentEncoding view
  change Consumes _ (encodeHead ⟨5, 2⟩ ++ (encodeHead ⟨0, 0⟩ ++
    (payloadEncoding 2 (byteList value.digest.val) ++ (encodeHead ⟨0, 1⟩ ++
    (payloadEncoding 2 (byteList value.bytes.val) ++ []))))) _
  apply consumes_then _ _ (encodeHead ⟨5, 2⟩) _ () _ (map_consumes 2 (by decide))
  apply consumes_then _ _ (encodeHead ⟨0, 0⟩) _ () _ (key_consumes 0 (by decide))
  apply consumes_then _ _ (payloadEncoding 2 (byteList value.digest.val)) _ (byteList value.digest.val) _
    (digest_consumes _ digestLength)
  apply consumes_then _ _ (encodeHead ⟨0, 1⟩) _ () _ (key_consumes 1 (by decide))
  apply consumes_then _ _ (payloadEncoding 2 (byteList value.bytes.val)) [] (byteList value.bytes.val) _
    (bounded_bytes_consumes _ maximum nonempty (by omega) (by omega))
  exact consumes_return _

theorem iterate_prefix (values : List Attachment) (leading trailing : List Nat)
    (previous : List AttachmentDecode.Attachment) (total maximum : Nat)
    (valid : WellFormed values)
    (bounded : total + AttachmentResources.byteSum values ≤ maximum) :
    AttachmentDecode.iterate (leading ++ attachmentsEncoding values ++ trailing) maximum values.length
      (.Ok ⟨previous, total, leading.length⟩) =
      .Ok ⟨previous ++ values.map view, total + AttachmentResources.byteSum values,
        leading.length + (attachmentsEncoding values).length⟩ := by
  induction values generalizing leading previous total with
  | nil => simp [AttachmentDecode.iterate, attachmentsEncoding, AttachmentResources.byteSum]
  | cons first rest ih =>
    have firstValid := valid first (by simp)
    have restValid : WellFormed rest := fun value member => valid value (by simp [member])
    have totalBound : total + first.bytes.val.length + AttachmentResources.byteSum rest ≤ maximum := by
      simpa [AttachmentResources.byteSum] using bounded
    have parsed := attachment_consumes first maximum firstValid (by omega) leading
      (attachmentsEncoding rest ++ trailing)
    have startsInside : leading.length ≤ (leading ++ attachmentsEncoding (first :: rest) ++ trailing).length := by
      simp only [List.length_append]
      omega
    have noEmpty : byteList first.bytes.val ≠ [] := by
      simp only [byteList, List.map_eq_nil_iff]
      exact List.ne_nil_of_length_pos firstValid.1
    have firstStep : AttachmentDecode.stepAt (leading ++ attachmentsEncoding (first :: rest) ++ trailing) maximum
        (.Ok ⟨previous, total, leading.length⟩) =
        .Ok ⟨previous ++ [view first], total + first.bytes.val.length,
          (leading ++ attachmentEncoding first).length⟩ := by
      simp only [AttachmentDecode.stepAt, startsInside, ↓reduceIte]
      have read : AttachmentDecode.readAttachment (leading ++ attachmentsEncoding (first :: rest) ++ trailing)
          maximum leading.length = (.Ok (view first), leading.length + (attachmentEncoding first).length) := by
        simpa only [attachmentsEncoding, List.flatMap_cons, List.append_assoc] using parsed
      rw [read]
      simp [view, byteList, List.length_map, noEmpty, firstValid.2.not_gt, totalBound,
        show total + first.bytes.val.length ≤ maximum by omega]
    have rest := ih (leading ++ attachmentEncoding first) (previous ++ [view first])
      (total + first.bytes.val.length) restValid totalBound
    simpa only [AttachmentDecode.iterate, firstStep, attachmentsEncoding, List.flatMap_cons,
      List.length_cons, List.map_cons, List.append_assoc, List.cons_append, List.nil_append,
      AttachmentResources.byteSum, List.map_cons, List.sum_cons, List.length_append, Nat.add_assoc] using rest

theorem batch_prefix (values : List Attachment) (leading trailing : List Nat) (maximum : Nat)
    (valid : WellFormed values) (bounded : AttachmentResources.byteSum values ≤ maximum) :
    AttachmentDecode.batchAt (leading ++ attachmentsEncoding values ++ trailing) maximum leading.length values.length =
      .Ok ⟨values.map view, AttachmentResources.byteSum values,
        leading.length + (attachmentsEncoding values).length⟩ := by
  simpa [AttachmentDecode.batchAt] using iterate_prefix values leading trailing [] 0 maximum valid (by omega)

/-- Actual batched parsing reconstructs the complete identical native list,
not just its count or sum. Every payload and aggregate must fit deployment. -/
@[step] theorem source_batch_inverse (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (position count : Std.Usize)
    (values : List Attachment) (leading trailing : List Nat)
    (inputBytes : byteList input.val = leading ++ attachmentsEncoding values ++ trailing)
    (atStart : position.val = leading.length) (exactCount : count.val = values.length)
    (valid : WellFormed values) (bounded : AttachmentResources.byteSum values ≤ limits.attachment_bytes.val) :
    decode.attachment_batch input limits position count ⦃ actual =>
      ∃ batch, actual = .Ok batch ∧ batch.attachments.val = values ∧
        batch.attachment_bytes.val = AttachmentResources.byteSum values ∧
        batch.position.val = leading.length + (attachmentsEncoding values).length ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact input limits position count)
  intro actual meaning
  rw [inputBytes, atStart, exactCount, batch_prefix values leading trailing _ valid bounded] at meaning
  cases actual with
  | Err error => simp [AttachmentDecode.resultView] at meaning
  | Ok batch =>
    have same : AttachmentDecode.batchView batch =
        ⟨values.map view, AttachmentResources.byteSum values,
          leading.length + (attachmentsEncoding values).length⟩ := by
      simpa [AttachmentDecode.resultView] using meaning
    have lists : batch.attachments.val.map view = values.map view := congrArg AttachmentDecode.Batch.attachments same
    have bytes : batch.attachment_bytes.val = AttachmentResources.byteSum values := congrArg AttachmentDecode.Batch.byteCount same
    have position : batch.position.val = leading.length + (attachmentsEncoding values).length :=
      congrArg AttachmentDecode.Batch.position same
    exact ⟨batch, rfl, views_injective lists, bytes, position⟩

@[step] theorem source_batch_roundtrip (self : cbor.Encoder) (values : Slice Attachment)
    (limits : auths_codec.auths_model.VerifierLimits)
    (valid : WellFormed values.val)
    (bounded : AttachmentResources.byteSum values.val ≤ limits.attachment_bytes.val)
    (space : self.output.val.length + attachmentsCost values.val ≤ Usize.max) :
    encode.encode_canonical_action_loop ⟨values, 0⟩ (.Ok self) ⦃ encoded =>
      ∃ finalEncoder, encoded = .Ok finalEncoder ∧
        decode.attachment_batch (alloc.vec.Vec.deref finalEncoder.output) limits
          (alloc.vec.Vec.len self.output) (Slice.len values) ⦃ actual =>
            ∃ batch, actual = .Ok batch ∧ batch.attachments.val = values.val ∧
              batch.attachment_bytes.val = AttachmentResources.byteSum values.val ∧
              batch.position.val = self.output.val.length + (attachmentsEncoding values.val).length ⦄ ⦄ := by
  apply spec_mono (AttachmentEncode.attachments_exact ⟨values, 0⟩ self (by simpa using space))
  intro encoded meaning
  cases encoded with
  | Err error => simp [AttachmentEncode.encoderView] at meaning
  | Ok finalEncoder =>
    refine ⟨finalEncoder, rfl, ?_⟩
    have inputBytes : byteList (alloc.vec.Vec.deref finalEncoder.output).val =
        byteList self.output.val ++ attachmentsEncoding values.val ++ [] := by
      simpa [AttachmentEncode.encoderView, alloc.vec.Vec.deref] using meaning
    apply spec_mono (source_batch_inverse (alloc.vec.Vec.deref finalEncoder.output) limits
      (alloc.vec.Vec.len self.output) (Slice.len values) values.val (byteList self.output.val) []
      inputBytes (by simp [byteList, alloc.vec.Vec.len_val]) (by simp [Slice.len]) valid bounded)
    rintro actual ⟨batch, same, attachments, bytes, position⟩
    exact ⟨batch, same, attachments, bytes, by simpa [byteList] using position⟩

end Auths.Codec.AttachmentInverse
