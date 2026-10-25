import Auths.Codec.AttachmentSort
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentValidation
open AttachmentOrder AttachmentSort
abbrev Attachment := auths_codec.auths_model.DetachedAttachment

/-- Independent list validator. The hard byte ceiling is checked after each
payload; duplicate digests are compared with the preceding canonical entry. -/
def validFrom (previous : Option auths_codec.auths_model.AttachmentDigest) (total : Nat) : List Attachment → Bool
  | [] => true
  | first :: rest =>
    if previous = some first.digest then false
    else if total + first.bytes.val.length ≤ 8388608 then
      validFrom (some first.digest) (total + first.bytes.val.length) rest
    else false

def valid (values : List Attachment) : Bool := validFrom none 0 values

/-- A single aggregate-byte update agrees with natural addition and its hard
ceiling, including machine addition overflow on hostile native carriers. -/
theorem checked_sum (total : Std.Usize) (bytes : alloc.vec.Vec Std.U8) :
    (match Usize.checked_add total (alloc.vec.Vec.len bytes) with
      | none => none
      | some updated => if updated.val ≤ 8388608 then some updated.val else none) =
      if total.val + bytes.val.length ≤ 8388608 then some (total.val + bytes.val.length) else none := by
  have checked := Usize.checked_add_bv_spec total (alloc.vec.Vec.len bytes)
  have portable : 8388608 ≤ Usize.max := by scalar_tac
  cases sum : Usize.checked_add total (alloc.vec.Vec.len bytes) with
  | none =>
    simp only [sum, alloc.vec.Vec.len_val] at checked
    have over : ¬ total.val + bytes.val.length ≤ 8388608 := by omega
    simp [sum, over]
  | some updated =>
    simp only [sum, alloc.vec.Vec.len_val] at checked
    simp [sum, checked.2.1]

/-- Source validation of the complete collection, using the actual digest
comparison, checked accumulation and index transitions. -/
@[step] theorem validation_exact (values : Slice Attachment) :
    auths_model.canonical_attachments_valid values ⦃ actual => actual = valid values.val ⦄ := by
  let expected := valid values.val
  unfold auths_model.canonical_attachments_valid auths_model.canonical_attachments_valid_loop
  apply loop.spec_decr_nat
    (measure := fun state => values.val.length - state.1.val)
    (inv := fun state => state.1.val ≤ values.val.length ∧
      validFrom (if state.1.val = 0 then none else
        (values.val[state.1.val - 1]?).map (fun value => value.digest))
        state.2.val (values.val.drop state.1.val) = expected)
  · rintro ⟨index, total⟩ ⟨indexBound, meaning⟩
    unfold auths_model.canonical_attachments_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < values.val.length := by simpa [Slice.len] using within
      have remaining := List.drop_eq_getElem_cons inside
      split <;> rename_i positive
      · have nonzero : index.val ≠ 0 := by scalar_tac
        step as ⟨beforeIndex, beforeMeaning⟩
        step as ⟨before, beforeAt⟩
        simp only [auths_model.DetachedAttachment.impl.digest, bind_tc_ok]
        step as ⟨attachment, attachmentAt⟩
        simp only [auths_model.DetachedAttachment.impl.digest, bind_tc_ok]
        step with digest_equal_exact as ⟨equal, equalMeaning⟩
        have previous : (values.val[index.val - 1]?).map (fun value => value.digest) = some before.digest := by
          simp only [List.getElem?_eq_getElem (by omega), Option.map_some]
          simp only [beforeMeaning] at beforeAt
          rw [← beforeAt]
        have current : values.val[index.val] = attachment := attachmentAt.symm
        rw [if_neg nonzero, remaining, previous, current, validFrom] at meaning
        split <;> rename_i duplicate
        · have same : before.digest = attachment.digest := by simpa [equalMeaning, beq_iff_eq] using duplicate
          simpa [same, spec_ok] using meaning.symm
        · have different : before.digest ≠ attachment.digest := by simpa [equalMeaning, beq_iff_eq] using duplicate
          simp only [Option.some.injEq, different, ↓reduceIte] at meaning
          simp only [auths_model.DetachedAttachment.impl.bytes, bind_tc_ok,
            alloc.vec.Vec.deref, Slice.len]
          have checked := Usize.checked_add_bv_spec total (alloc.vec.Vec.len attachment.bytes)
          cases sum : Usize.checked_add total (alloc.vec.Vec.len attachment.bytes) with
          | none =>
            simp only [sum, alloc.vec.Vec.len_val] at checked
            have portable : 8388608 ≤ Usize.max := by scalar_tac
            have over : ¬ total.val + attachment.bytes.val.length ≤ 8388608 := by omega
            simp [sum, over] at meaning ⊢
            exact meaning.symm
          | some updated =>
            simp only [sum, alloc.vec.Vec.len_val] at checked
            have updatedValue := checked.2.1
            simp only [sum, lift, bind_tc_ok]
            rw [Evaluation.hard_attachment_bytes]
            simp only [bind_tc_ok]
            split <;> rename_i exceeds
            · have over : ¬ total.val + attachment.bytes.val.length ≤ 8388608 := by scalar_tac
              simpa [spec_ok, over] using meaning.symm
            · have retained : total.val + attachment.bytes.val.length ≤ 8388608 := by scalar_tac
              simp only [retained, ↓reduceIte] at meaning
              step as ⟨next, nextMeaning⟩
              simp only [spec_ok]
              refine ⟨by omega, ?_, by omega⟩
              have previousAt : (values.val[next.val - 1]?).map (fun value => value.digest) = some attachment.digest := by
                have nextBack : next.val - 1 = index.val := by omega
                rw [nextBack]
                simp only [List.getElem?_eq_getElem inside, Option.map_some, current]
              have nextPositive : next.val ≠ 0 := by omega
              simp only [nextPositive, ↓reduceIte, previousAt, updatedValue]
              simpa only [nextMeaning] using meaning
      · have zero : index.val = 0 := by scalar_tac
        step as ⟨attachment, attachmentAt⟩
        have current : values.val[index.val] = attachment := attachmentAt.symm
        rw [if_pos zero, remaining, current, validFrom] at meaning
        simp only [reduceCtorEq, ↓reduceIte] at meaning
        simp only [auths_model.DetachedAttachment.impl.bytes, bind_tc_ok,
          alloc.vec.Vec.deref, Slice.len]
        have checked := Usize.checked_add_bv_spec total (alloc.vec.Vec.len attachment.bytes)
        cases sum : Usize.checked_add total (alloc.vec.Vec.len attachment.bytes) with
        | none =>
          simp only [sum, alloc.vec.Vec.len_val] at checked
          have portable : 8388608 ≤ Usize.max := by scalar_tac
          have over : ¬ total.val + attachment.bytes.val.length ≤ 8388608 := by omega
          simp [sum, over] at meaning ⊢
          exact meaning.symm
        | some updated =>
          simp only [sum, alloc.vec.Vec.len_val] at checked
          have updatedValue := checked.2.1
          simp only [sum, lift, bind_tc_ok]
          rw [Evaluation.hard_attachment_bytes]
          simp only [bind_tc_ok]
          split <;> rename_i exceeds
          · have over : ¬ total.val + attachment.bytes.val.length ≤ 8388608 := by scalar_tac
            simpa [spec_ok, over] using meaning.symm
          · have retained : total.val + attachment.bytes.val.length ≤ 8388608 := by scalar_tac
            simp only [retained, ↓reduceIte] at meaning
            step as ⟨next, nextMeaning⟩
            simp only [spec_ok]
            refine ⟨by omega, ?_, by omega⟩
            have previousAt : (values.val[next.val - 1]?).map (fun value => value.digest) = some attachment.digest := by
              have nextBack : next.val - 1 = index.val := by omega
              rw [nextBack]
              simp only [List.getElem?_eq_getElem inside, Option.map_some, current]
            have nextPositive : next.val ≠ 0 := by omega
            simp only [nextPositive, ↓reduceIte, previousAt, updatedValue]
            simpa only [nextMeaning] using meaning
    · have atEnd : values.val.length ≤ index.val := by simpa [Slice.len] using Nat.le_of_not_lt within
      simp only [List.drop_eq_nil_of_le atEnd, validFrom] at meaning
      simpa only [spec_ok] using meaning.symm
  · simp [valid, validFrom, expected]

/-- Actual normalization uses the concrete sorted collection and complete
validator. The source result, including refusal, is fixed by this contract. -/
@[step] theorem constructor_exact (action : auths_codec.auths_model.CanonicalAction)
    (attachments : alloc.vec.Vec Attachment) :
    auths_model.CanonicalAction.with_detached_attachments action attachments ⦃ actual =>
      actual = if attachments.val.length ≤ 512 ∧ valid (AttachmentSort.sorted attachments.val) then
        .Ok {action with detached_attachments :=
          ⟨AttachmentSort.sorted attachments.val, by rw [sorted_length]; exact attachments.property⟩}
      else .Err .InvalidAttachment ⦄ := by
  unfold auths_model.CanonicalAction.with_detached_attachments
  by_cases count : attachments.val.length ≤ 512
  · have within : ¬ alloc.vec.Vec.len attachments > auths_model.HARD_MAX_ATTACHMENTS := by
      simpa [auths_model.HARD_MAX_ATTACHMENTS, UScalar.lt_equiv, alloc.vec.Vec.len_val] using count.not_gt
    simp only [within, ↓reduceIte, lift, alloc.vec.Vec.deref_mut, bind_tc_ok]
    rw [AttachmentSort.sort_exact]
    simp only [bind_tc_ok, alloc.vec.Vec.deref]
    step with validation_exact as ⟨accepted, exactValidation⟩
    simp [exactValidation, count]
  · have exceeds : alloc.vec.Vec.len attachments > auths_model.HARD_MAX_ATTACHMENTS := by
      simpa [auths_model.HARD_MAX_ATTACHMENTS, UScalar.lt_equiv, alloc.vec.Vec.len_val] using Nat.lt_of_not_ge count
    simp [exceeds, count]

end Auths.Codec.AttachmentValidation
