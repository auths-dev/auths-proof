import Auths.Codec.AttachmentOrder
import Auths.Codec.ActionDecodedFields
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentResources

/-- Count all payloads, including duplicates. Rejection must not make a
resource-accounting proof forget bytes an adversary supplied. -/
def byteSum (attachments : List auths_codec.auths_model.DetachedAttachment) : Nat :=
  (attachments.map fun attachment => attachment.bytes.val.length).sum

theorem take_next_sum (attachments : List auths_codec.auths_model.DetachedAttachment)
    (index : Nat) (inside : index < attachments.length) :
    byteSum (attachments.take (index + 1)) =
      byteSum (attachments.take index) + attachments[index].bytes.val.length := by
  rw [List.take_succ_eq_append_getElem inside]
  simp [byteSum, List.map_append]

/-- The actual validation loop is total on the represented slice. Any true
result earns the aggregate attachment-byte hard limit. Duplicate-digest
refusal can occur earlier and is intentionally not weakened into acceptance. -/
@[step] theorem validation_earns_byte_bound
    (attachments : Slice auths_codec.auths_model.DetachedAttachment) :
    auths_model.canonical_attachments_valid attachments ⦃ actual =>
      actual = true → byteSum attachments.val ≤ 8388608 ⦄ := by
  unfold auths_model.canonical_attachments_valid auths_model.canonical_attachments_valid_loop
  apply loop.spec_decr_nat
    (measure := fun state => attachments.val.length - state.1.val)
    (inv := fun state => state.1.val ≤ attachments.val.length ∧
      state.2.val = byteSum (attachments.val.take state.1.val) ∧ state.2.val ≤ 8388608)
  · rintro ⟨index, total⟩ ⟨indexBound, totalMeaning, totalBound⟩
    unfold auths_model.canonical_attachments_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < attachments.val.length := by simpa [Slice.len] using within
      have nextSum := take_next_sum attachments.val index.val inside
      split <;> rename_i positive
      · step as ⟨previous, previousMeaning⟩
        step as ⟨before, beforeAt⟩
        simp only [auths_model.DetachedAttachment.impl.digest, bind_tc_ok]
        step as ⟨attachment, attachmentAt⟩
        simp only [auths_model.DetachedAttachment.impl.digest, bind_tc_ok]
        step with AttachmentOrder.digest_equal_exact as ⟨equal, equalityMeaning⟩
        split
        · simp only [spec_ok, Bool.false_eq_true, false_implies]
        ·
          simp only [auths_model.DetachedAttachment.impl.bytes, bind_tc_ok,
            alloc.vec.Vec.deref, Slice.len]
          have checked := Usize.checked_add_bv_spec total (alloc.vec.Vec.len attachment.bytes)
          cases sum : Usize.checked_add total (alloc.vec.Vec.len attachment.bytes) with
          | none => simp [sum]
          | some updated =>
            simp only [sum] at checked
            have updatedValue : updated.val = total.val + attachment.bytes.val.length := by
              simpa only [alloc.vec.Vec.len_val] using checked.2.1
            simp only [sum, lift, bind_tc_ok]
            rw [Evaluation.hard_attachment_bytes]
            simp only [bind_tc_ok]
            split <;> rename_i exceeds
            · simp only [spec_ok, Bool.false_eq_true, false_implies]
            · step as ⟨next, nextMeaning⟩
              simp only [spec_ok]
              have atElement : attachment = attachments.val[index.val] := by simpa using attachmentAt
              have retained : updated.val ≤ 8388608 := by scalar_tac
              refine ⟨by omega, ?_, retained, by omega⟩
              rw [updatedValue, atElement, totalMeaning]
              simpa only [nextMeaning] using nextSum.symm
      · step as ⟨attachment, attachmentAt⟩
        simp only [auths_model.DetachedAttachment.impl.bytes, bind_tc_ok,
          alloc.vec.Vec.deref, Slice.len]
        have checked := Usize.checked_add_bv_spec total (alloc.vec.Vec.len attachment.bytes)
        cases sum : Usize.checked_add total (alloc.vec.Vec.len attachment.bytes) with
        | none => simp [sum]
        | some updated =>
          simp only [sum] at checked
          have updatedValue : updated.val = total.val + attachment.bytes.val.length := by
            simpa only [alloc.vec.Vec.len_val] using checked.2.1
          simp only [sum, lift, bind_tc_ok]
          rw [Evaluation.hard_attachment_bytes]
          simp only [bind_tc_ok]
          split <;> rename_i exceeds
          · simp only [spec_ok, Bool.false_eq_true, false_implies]
          · step as ⟨next, nextMeaning⟩
            simp only [spec_ok]
            have atElement : attachment = attachments.val[index.val] := by simpa using attachmentAt
            have retained : updated.val ≤ 8388608 := by scalar_tac
            refine ⟨by omega, ?_, retained, by omega⟩
            rw [updatedValue, atElement, totalMeaning]
            simpa only [nextMeaning] using nextSum.symm
    · have atEnd : attachments.val.length ≤ index.val := by simpa [Slice.len] using Nat.le_of_not_lt within
      simp only [List.take_of_length_le atEnd] at totalMeaning
      simp only [spec_ok]
      intro _
      omega
  · simp [byteSum]

theorem validation_accepted_bound
    (attachments : Slice auths_codec.auths_model.DetachedAttachment)
    (accepted : auths_model.canonical_attachments_valid attachments = ok true) :
    byteSum attachments.val ≤ 8388608 := by
  have valid := validation_earns_byte_bound attachments
  rw [accepted] at valid
  exact valid rfl

/-- Sorting's existing reviewed leaf preserves length on every successful
return; its callback is not replaced by an opaque Auths sorting algorithm. -/
theorem sort_success_length {T K F : Type}
    (key : core.ops.function.FnMut F T K) (order : core.cmp.Ord K)
    (input : Slice T) (callback : F) (output : Slice T)
    (sorted : alloc.slice.Slice.sort_by_key key order input callback = ok output) :
    output.val.length = input.val.length := by
  rw [StdModel.sort_by_key_values] at sorted
  simp only [Bind.bind, Aeneas.Std.bind] at sorted
  split at sorted
  · rename_i values evaluated
    have same : (⟨values.val, by rw [values.property]; exact input.property⟩ : Slice T) = output := by simpa using sorted
    rw [← same]
    exact values.property
  · simp at sorted
  · simp at sorted

def Bounded (action : auths_codec.auths_model.CanonicalAction) : Prop :=
  action.detached_attachments.val.length ≤ 512 ∧ byteSum action.detached_attachments.val ≤ 8388608

theorem constructor_earns_bounds (action : auths_codec.auths_model.CanonicalAction)
    (attachments : alloc.vec.Vec auths_codec.auths_model.DetachedAttachment)
    (output : auths_codec.auths_model.CanonicalAction)
    (accepted : auths_model.CanonicalAction.with_detached_attachments action attachments = ok (.Ok output)) :
    Bounded output := by
  unfold auths_model.CanonicalAction.with_detached_attachments at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame.from, Result.ok.injEq, core.result.Result.Ok.injEq,
        reduceCtorEq] at accepted
    | contradiction
  all_goals subst output
  all_goals
    constructor
    · have count : attachments.val.length ≤ 512 := by
        simp_all only [alloc.vec.Vec.len_val, UScalar.lt_equiv, auths_model.HARD_MAX_ATTACHMENTS,
          UScalar.ofNatCore_val_eq]
        omega
      have sortedCount := sort_success_length
        auths_model.CanonicalAction.with_detached_attachments.closure.Insts.CoreOpsFunctionFnMutTupleSharedDetachedAttachmentAttachmentDigest
        auths_model.AttachmentDigest.Insts.CoreCmpOrd _ () _ (by assumption)
      simpa [alloc.vec.Vec.deref_mut, alloc.vec.Vec.deref] using sortedCount.trans_le count
    · apply validation_accepted_bound
      assumption

theorem decoded_earns_bounds (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (action : auths_codec.auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) : Bounded action := by
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, bind_tc_fail, bind_tc_div,
        Result.ok.injEq, core.result.Result.Ok.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals subst action
  all_goals casesm* core.result.Result auths_codec.auths_model.CanonicalAction _
  all_goals simp_all only [Result.ok.injEq, core.result.Result.Ok.injEq,
    core.ops.control_flow.ControlFlow.Continue.injEq, reduceCtorEq]
  all_goals aesop (add safe forward constructor_earns_bounds)

end Auths.Codec.AttachmentResources
