import Auths.Codec.ObjectFields
import Auths.Codec.ByteFields
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentDecode
open Refinement ProfileDecode

abbrev Attachment := List Nat × List Nat
structure Batch where
  attachments : List Attachment
  byteCount : Nat
  position : Nat

def batchView (batch : decode.AttachmentBatch) : Batch :=
  ⟨batch.attachments.val.map (fun value => (byteList value.digest.val, byteList value.bytes.val)),
    batch.attachment_bytes.val, batch.position.val⟩

def resultView (value : core.result.Result decode.AttachmentBatch error.CodecError) :
    core.result.Result Batch error.CodecError :=
  match value with | .Err error => .Err error | .Ok value => .Ok (batchView value)

def readAttachment (input : List Nat) (maximum position : Nat) :
    core.result.Result Attachment error.CodecError × Nat :=
  andThen (Fields.mapAt input position 2) fun _ position =>
  andThen (Fields.keyAt input position 0) fun _ position =>
  andThen (Fields.digestAt input position) fun digest position =>
  andThen (Fields.keyAt input position 1) fun _ position =>
  andThen (Fields.boundedBytesAt input position maximum true) fun bytes position =>
  (.Ok (digest, bytes), position)

def stepAt (input : List Nat) (maximum : Nat) :
    core.result.Result Batch error.CodecError → core.result.Result Batch error.CodecError
  | .Err error => .Err error
  | .Ok batch =>
    if batch.position ≤ input.length then
      match readAttachment input maximum batch.position with
      | (.Err error, _) => .Err error
      | (.Ok (digest, bytes), position) =>
        if batch.byteCount + bytes.length ≤ maximum then
          if bytes = [] ∨ 8388608 < bytes.length then .Err (.Model .InvalidAttachment)
          else .Ok ⟨batch.attachments ++ [(digest, bytes)], batch.byteCount + bytes.length, position⟩
        else .Err .LimitExceeded
    else .Err .Malformed

def iterate (input : List Nat) (maximum : Nat) : Nat →
    core.result.Result Batch error.CodecError → core.result.Result Batch error.CodecError
  | 0, state => state
  | remaining + 1, state => iterate input maximum remaining (stepAt input maximum state)

def batchAt (input : List Nat) (maximum position count : Nat) :
    core.result.Result Batch error.CodecError :=
  iterate input maximum count (.Ok ⟨[], 0, position⟩)

@[step] theorem step_exact (input : Slice Std.U8) (limits : auths_codec.auths_model.VerifierLimits)
    (state : core.result.Result decode.AttachmentBatch error.CodecError)
    (space : match state with | .Err _ => True | .Ok batch => batch.attachments.val.length < Usize.max) :
    decode.attachment_batch_step input limits state ⦃ actual =>
      resultView actual = stepAt (byteList input.val) limits.attachment_bytes.val (resultView state) ⦄ := by
  unfold decode.attachment_batch_step
  cases state with
  | Err error =>
    simp [resultView, stepAt, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame.from]
  | Ok batch =>
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with Cursor.at_exact input batch.position as ⟨decoder, decoderMeaning⟩
    by_cases inside : batch.position.val ≤ input.val.length
    · simp only [inside, ↓reduceIte] at decoderMeaning
      simp only [decoderMeaning]
      step with Fields.map_exact ⟨input, batch.position⟩ 2#u64 as ⟨r0, decoder0, mapMeaning, mapInput⟩
      cases r0 with
      | Err error =>
        simp [core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, resultView, stepAt, batchView, inside, readAttachment, andThen, Fields.digestView, Fields.vecView, byteList, List.length_map, ← mapMeaning, mapInput]
      | Ok _ =>
        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        step with Fields.key_exact decoder0 0#u8 as ⟨r1, decoder1, digestKeyMeaning, digestKeyInput⟩
        simp only [mapInput] at digestKeyMeaning
        cases r1 with
        | Err error =>
          simp [core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, resultView, stepAt, batchView, inside, readAttachment, andThen, Fields.digestView, Fields.vecView, byteList, List.length_map, ← mapMeaning, ← digestKeyMeaning, mapInput, digestKeyInput]
        | Ok _ =>
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step with Fields.digest_bytes_exact decoder1  as ⟨r2, decoder2, digestMeaning, digestInput⟩
          simp only [digestKeyInput, mapInput] at digestMeaning
          cases r2 with
          | Err error =>
            simp [core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, resultView, stepAt, batchView, inside, readAttachment, andThen, Fields.digestView, Fields.vecView, byteList, List.length_map, ← mapMeaning, ← digestKeyMeaning, ← digestMeaning, mapInput, digestKeyInput, digestInput]
          | Ok digest =>
            simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
            simp only [auths_model.AttachmentDigest.new, bind_tc_ok]
            step with Fields.key_exact decoder2 1#u8 as ⟨r3, decoder3, bytesKeyMeaning, bytesKeyInput⟩
            simp only [digestInput, digestKeyInput, mapInput] at bytesKeyMeaning
            cases r3 with
            | Err error =>
              simp [core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, resultView, stepAt, batchView, inside, readAttachment, andThen, Fields.digestView, Fields.vecView, byteList, List.length_map, ← mapMeaning, ← digestKeyMeaning, ← digestMeaning, ← bytesKeyMeaning, mapInput, digestKeyInput, digestInput, bytesKeyInput]
            | Ok _ =>
              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              simp only [auths_model.VerifierLimits.get, bind_tc_ok]
              step with Fields.bounded_bytes_exact decoder3 limits.attachment_bytes true as ⟨r4, decoder4, bytesMeaning, bytesInput⟩
              simp only [bytesKeyInput, digestInput, digestKeyInput, mapInput] at bytesMeaning
              cases r4 with
              | Err error =>
                simp [core.result.Result.Insts.CoreOpsTry.branch, core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual, core.convert.FromSame.from, resultView, stepAt, batchView, inside, readAttachment, andThen, Fields.digestView, Fields.vecView, byteList, List.length_map, ← mapMeaning, ← digestKeyMeaning, ← digestMeaning, ← bytesKeyMeaning, ← bytesMeaning, mapInput, digestKeyInput, digestInput, bytesKeyInput, bytesInput]
              | Ok bytes =>
                simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                simp only [alloc.vec.Vec.len_val]
                have checked := Usize.checked_add_bv_spec batch.attachment_bytes (alloc.vec.Vec.len bytes)
                cases sum : Usize.checked_add batch.attachment_bytes (alloc.vec.Vec.len bytes) with
                | none =>
                  simp only [sum] at checked
                  have exceeds : ¬ batch.attachment_bytes.val + bytes.val.length ≤ limits.attachment_bytes.val := by
                    have maximum := limits.attachment_bytes.hBounds
                    scalar_tac
                  simp [sum, core.option.Option.ok_or, core.result.Result.Insts.CoreOpsTry.branch,
                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                    core.convert.FromSame.from, resultView, stepAt, batchView, inside, readAttachment,
                    andThen, Fields.digestView, Fields.vecView, ← mapMeaning, ← digestKeyMeaning,
                    ← digestMeaning, ← bytesKeyMeaning, ← bytesMeaning, byteList, List.length_map,
                    exceeds, bytesInput, bytesKeyInput, digestInput, digestKeyInput, mapInput]
                | some total =>
                  simp only [sum] at checked
                  have totalMeaning : total.val = batch.attachment_bytes.val + bytes.val.length := by
                    simpa only [alloc.vec.Vec.len_val] using checked.2.1
                  simp only [sum, lift, bind_tc_ok, core.option.Option.ok_or,
                    core.result.Result.Insts.CoreOpsTry.branch]
                  by_cases exceeds : limits.attachment_bytes.val < total.val
                  · simp [UScalar.lt_equiv, exceeds, resultView, stepAt, batchView, inside,
                      readAttachment, andThen, Fields.digestView, Fields.vecView,
                      ← mapMeaning, ← digestKeyMeaning, ← digestMeaning, ← bytesKeyMeaning, ← bytesMeaning,
                      byteList, List.length_map, totalMeaning, Nat.not_le_of_gt exceeds,
                      bytesInput, bytesKeyInput, digestInput, digestKeyInput, mapInput]
                  · simp only [UScalar.lt_equiv, exceeds, ↓reduceIte]
                    unfold auths_model.DetachedAttachment.new
                    simp only [alloc.vec.Vec.is_empty, bind_tc_ok]
                    rw [Evaluation.hard_bundle_bytes]
                    simp only [bind_tc_ok]
                    by_cases empty : bytes.val = []
                    · simp [empty, resultView, stepAt, batchView, inside, readAttachment, andThen,
                        Fields.digestView, Fields.vecView, ← mapMeaning, ← digestKeyMeaning, ← digestMeaning,
                        ← bytesKeyMeaning, ← bytesMeaning, byteList, List.length_map, totalMeaning,
                        Nat.le_of_not_gt exceeds, error.CodecError.Insts.CoreConvertFromModelError.from,
                        core.result.Result.Insts.CoreOpsTry.branch,
                        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                        core.convert.FromSame.from, bytesInput, bytesKeyInput, digestInput, digestKeyInput, mapInput]
                    · by_cases oversized : 8388608 < bytes.val.length
                      · simp [empty, UScalar.lt_equiv, oversized, resultView, stepAt, batchView, inside,
                          readAttachment, andThen, Fields.digestView, Fields.vecView,
                          ← mapMeaning, ← digestKeyMeaning, ← digestMeaning, ← bytesKeyMeaning, ← bytesMeaning,
                          byteList, List.length_map, totalMeaning, Nat.le_of_not_gt exceeds,
                          error.CodecError.Insts.CoreConvertFromModelError.from,
                          core.result.Result.Insts.CoreOpsTry.branch,
                          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                          core.convert.FromSame.from, bytesInput, bytesKeyInput, digestInput, digestKeyInput, mapInput]
                      · simp only [empty, List.isEmpty_eq_false, Bool.false_eq_true, UScalar.lt_equiv,
                          alloc.vec.Vec.len_val, UScalar.ofNatCore_val_eq, oversized, ↓reduceIte,
                          core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                        step with alloc.vec.Vec.push_spec batch.attachments ⟨digest, bytes⟩ space
                          as ⟨attachments, appended⟩
                        simp [cbor.Decoder.impl.position, resultView, stepAt, batchView, inside,
                          readAttachment, andThen, Fields.digestView, Fields.vecView,
                          ← mapMeaning, ← digestKeyMeaning, ← digestMeaning, ← bytesKeyMeaning, ← bytesMeaning,
                          appended, byteList, List.map_append, List.length_map, totalMeaning,
                          Nat.le_of_not_gt exceeds, empty, oversized,
                          bytesInput, bytesKeyInput, digestInput, digestKeyInput, mapInput]
    · simp only [inside, ↓reduceIte] at decoderMeaning
      simp [decoderMeaning, resultView, stepAt, batchView, byteList, inside]

def Room (state : core.result.Result Batch error.CodecError) (remaining : Nat) : Prop :=
  match state with | .Err _ => True | .Ok batch => batch.attachments.length + remaining ≤ Usize.max

theorem step_room (input : List Nat) (maximum : Nat)
    (state : core.result.Result Batch error.CodecError) (remaining : Nat)
    (room : Room state (remaining + 1)) : Room (stepAt input maximum state) remaining := by
  cases state with
  | Err error => simp [stepAt, Room]
  | Ok batch =>
    unfold stepAt
    split
    · split
      · trivial
      · split
        · split
          · trivial
          · simp only [Room, List.length_append, List.length_cons, List.length_nil]
            simp only [Room] at room
            omega
        · trivial
    · trivial

theorem iterate_succ_last (input : List Nat) (maximum count : Nat)
    (state : core.result.Result Batch error.CodecError) :
    iterate input maximum (count + 1) state = stepAt input maximum (iterate input maximum count state) := by
  induction count generalizing state with
  | zero => rfl
  | succ count ih => simp only [iterate, ih]

/-- Every source iteration, including iterations after typed failure, is
accounted for. The only allocation premise concerns the real Vec capacity. -/
@[step] theorem loop_exact (input : Slice Std.U8) (limits : auths_codec.auths_model.VerifierLimits)
    (remaining : Std.Usize) (state : core.result.Result decode.AttachmentBatch error.CodecError)
    (room : Room (resultView state) remaining.val) :
    decode.attachment_batch_loop input limits remaining state ⦃ actual =>
      resultView actual = iterate (byteList input.val) limits.attachment_bytes.val remaining.val (resultView state) ⦄ := by
  let expected := iterate (byteList input.val) limits.attachment_bytes.val remaining.val (resultView state)
  unfold decode.attachment_batch_loop
  apply loop.spec_decr_nat
    (measure := fun current => current.1.val)
    (inv := fun current => Room (resultView current.2) current.1.val ∧
      iterate (byteList input.val) limits.attachment_bytes.val current.1.val (resultView current.2) = expected)
  · rintro ⟨left, current⟩ ⟨space, meaning⟩
    unfold decode.attachment_batch_loop.body
    dsimp only
    split <;> rename_i positive
    · have nonzero : 0 < left.val := by scalar_tac
      have stepRoom : match current with | .Err _ => True
          | .Ok batch => batch.attachments.val.length < Usize.max := by
        cases current with
        | Err error => trivial
        | Ok batch =>
          simp only [Room, resultView, batchView, List.length_map] at space
          omega
      step with step_exact input limits current stepRoom as ⟨updated, updatedMeaning⟩
      step as ⟨next, nextMeaning⟩
      have decrements : next.val + 1 = left.val := by omega
      simp only [spec_ok]
      refine ⟨?_, ?_, by omega⟩
      · rw [updatedMeaning]
        apply step_room
        simpa only [decrements] using space
      · rw [updatedMeaning]
        have unfolded : iterate (byteList input.val) limits.attachment_bytes.val left.val (resultView current) =
            iterate (byteList input.val) limits.attachment_bytes.val next.val
              (stepAt (byteList input.val) limits.attachment_bytes.val (resultView current)) := by
          rw [← decrements]
          rfl
        exact unfolded.symm.trans meaning
    · have zero : left.val = 0 := by scalar_tac
      simpa only [spec_ok, zero, iterate] using meaning
  · exact ⟨room, rfl⟩

@[step] theorem batch_exact (input : Slice Std.U8) (limits : auths_codec.auths_model.VerifierLimits)
    (position remaining : Std.Usize) :
    decode.attachment_batch input limits position remaining ⦃ actual =>
      resultView actual = batchAt (byteList input.val) limits.attachment_bytes.val position.val remaining.val ⦄ := by
  unfold decode.attachment_batch
  have room : Room (resultView (.Ok ⟨alloc.vec.Vec.with_capacity _ remaining, 0#usize, position⟩)) remaining.val := by
    simp only [Room, resultView, batchView, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
      List.map_nil, List.length_nil, Nat.zero_add]
    scalar_tac
  simpa only [batchAt, batchView, resultView, alloc.vec.Vec.with_capacity, alloc.vec.Vec.new,
    List.map_nil, UScalar.ofNatCore_val_eq] using loop_exact input limits remaining
      (.Ok ⟨alloc.vec.Vec.with_capacity _ remaining, 0#usize, position⟩) room

end Auths.Codec.AttachmentDecode
