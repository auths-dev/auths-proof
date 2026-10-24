import Auths.Codec.AttachmentDecode
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentDecodeSafety
open AttachmentDecode

def byteSum (attachments : List AttachmentDecode.Attachment) : Nat :=
  (attachments.map fun attachment => attachment.2.length).sum

def Valid (maximum : Nat) (batch : Batch) : Prop :=
  batch.byteCount = byteSum batch.attachments ∧ batch.byteCount ≤ maximum ∧
    ∀ attachment ∈ batch.attachments, attachment.2 ≠ [] ∧ attachment.2.length ≤ maximum

theorem bounded_payload (input : List Nat) (position maximum : Nat)
    (bytes : List Nat) (next : Nat)
    (accepted : Fields.boundedBytesAt input position maximum true = (.Ok bytes, next)) :
    bytes ≠ [] ∧ bytes.length ≤ maximum ∧ next ≤ input.length := by
  unfold Fields.boundedBytesAt at accepted
  cases payload : Payload.payloadAt input position 2 with
  | mk raw finish =>
    cases raw with
    | none => simp [payload] at accepted
    | some raw =>
      by_cases invalid : maximum < raw.length ∨ raw = []
      · simp [payload, invalid] at accepted
      · have same : raw = bytes ∧ finish = next := by simpa [payload, invalid] using accepted
        obtain ⟨rfl, rfl⟩ := same
        refine ⟨by tauto, by omega, ?_⟩
        unfold Payload.payloadAt at payload
        repeat' first
          | split at payload
          | simp (failIfUnchanged := true) only [Prod.mk.injEq, Option.some.injEq, reduceCtorEq] at payload
          | contradiction
        all_goals omega

theorem read_success (input : List Nat) (maximum position : Nat)
    (digest bytes : List Nat) (next : Nat)
    (accepted : readAttachment input maximum position = (.Ok (digest, bytes), next)) :
    bytes ≠ [] ∧ bytes.length ≤ maximum ∧ next ≤ input.length := by
  unfold readAttachment at accepted
  repeat' first
    | dsimp only [ProfileDecode.andThen] at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [Prod.mk.injEq, core.result.Result.Ok.injEq,
        reduceCtorEq] at accepted
    | contradiction
  all_goals
    obtain ⟨same, atEnd⟩ := accepted
    cases same
    subst next
    apply bounded_payload
    assumption

theorem step_success (input : List Nat) (maximum : Nat) (before after : Batch)
    (valid : Valid maximum before)
    (accepted : stepAt input maximum (.Ok before) = .Ok after) :
    Valid maximum after ∧ after.attachments.length = before.attachments.length + 1 ∧
      after.position ≤ input.length := by
  unfold stepAt at accepted
  split at accepted
  · cases read : readAttachment input maximum before.position with
    | mk result finish =>
      cases result with
      | Err error => simp [read] at accepted
      | Ok value =>
        rcases value with ⟨digest, bytes⟩
        simp only [read] at accepted
        split at accepted
        · rename_i totalBound
          split at accepted
          · simp at accepted
          · have same : (⟨before.attachments ++ [(digest, bytes)],
                before.byteCount + bytes.length, finish⟩ : Batch) = after := by simpa using accepted
            subst after
            have payload := read_success input maximum before.position digest bytes finish read
            refine ⟨⟨?_, totalBound, ?_⟩, by simp, payload.2.2⟩
            · simp [byteSum, List.map_append, valid.1]
            · intro attachment member
              simp only [List.mem_append, List.mem_cons, List.not_mem_nil, or_false] at member
              rcases member with earlier | rfl
              · exact valid.2.2 attachment earlier
              · exact ⟨payload.1, payload.2.1⟩
        · simp at accepted
  · simp at accepted

theorem iterate_error (input : List Nat) (maximum count : Nat) (error : error.CodecError) :
    iterate input maximum count (.Err error) = .Err error := by
  induction count with
  | zero => rfl
  | succ count ih => simpa [iterate, stepAt] using ih

theorem iterate_success (input : List Nat) (maximum count : Nat) (before after : Batch)
    (valid : Valid maximum before)
    (accepted : iterate input maximum count (.Ok before) = .Ok after) :
    Valid maximum after ∧ after.attachments.length = before.attachments.length + count := by
  induction count generalizing before with
  | zero =>
    simp only [iterate, core.result.Result.Ok.injEq] at accepted
    subst after
    exact ⟨valid, by omega⟩
  | succ count ih =>
    cases stepped : stepAt input maximum (.Ok before) with
    | Err error => simp [iterate, stepped, iterate_error] at accepted
    | Ok updated =>
      have first := step_success input maximum before updated valid stepped
      have tail : iterate input maximum count (.Ok updated) = .Ok after := by
        simpa only [iterate, stepped] using accepted
      have remainder := ih updated first.1 tail
      exact ⟨remainder.1, by omega⟩

theorem batch_success (input : List Nat) (maximum position count : Nat) (after : Batch)
    (accepted : batchAt input maximum position count = .Ok after) :
    Valid maximum after ∧ after.attachments.length = count := by
  have initial : Valid maximum ⟨[], 0, position⟩ := by simp [Valid, byteSum]
  simpa only [List.length_nil, Nat.zero_add] using
    iterate_success input maximum count ⟨[], 0, position⟩ after initial accepted

/-- The actual parser earns exact count, aggregate accounting and deployment
payload limits. Individual body limits are checked before owned allocation. -/
@[step] theorem source_batch_success (input : Slice Std.U8)
    (limits : auths_codec.auths_model.VerifierLimits) (position count : Std.Usize) :
    decode.attachment_batch input limits position count ⦃ actual =>
      ∀ batch, actual = .Ok batch →
        Valid limits.attachment_bytes.val (batchView batch) ∧
          batch.attachments.val.length = count.val ⦄ := by
  apply spec_mono (AttachmentDecode.batch_exact input limits position count)
  intro actual meaning batch accepted
  rw [accepted] at meaning
  have valid := batch_success _ _ _ _ (batchView batch) meaning.symm
  simpa only [batchView, List.length_map] using valid

end Auths.Codec.AttachmentDecodeSafety
