import Auths.Codec.ActionCarrier
import Auths.Codec.AttachmentDecodeSafety
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.AttachmentCanonical
open AttachmentSort AttachmentValidation Refinement
abbrev Attachment := auths_codec.auths_model.DetachedAttachment

def digestKey (value : auths_codec.auths_model.AttachmentDigest) : List Nat := byteList value.val

theorem digestKey_injective : Function.Injective digestKey := by
  intro left right same
  exact Subtype.ext (AttachmentInverse.bytes_injective same)

/-- For a nondecreasing sequence, distinct neighboring keys imply global
strict order. This closes the gap between adjacent validation and duplicate
freedom without assuming that the validator already established Nodup. -/
theorem ordered_neighbors_strict {α : Type} [LinearOrder α] (values : List α)
    (ordered : values.Pairwise (· ≤ ·)) (neighbors : values.Chain' (· ≠ ·)) :
    values.Pairwise (· < ·) := by
  induction values with
  | nil => simp
  | cons first rest ih =>
    have source := List.pairwise_cons.mp ordered
    have tail : rest.Pairwise (· < ·) := ih source.2 neighbors.tail
    refine List.pairwise_cons.mpr ⟨?_, tail⟩
    cases rest with
    | nil => simp
    | cons next remaining =>
      have nextLess : first < next := lt_of_le_of_ne (source.1 next (by simp)) neighbors.rel_head
      intro value member
      rcases List.mem_cons.mp member with same | later
      · simpa only [same] using nextLess
      · exact lt_trans nextLess ((List.pairwise_cons.mp tail).1 value later)

theorem valid_neighbors (values : List Attachment)
    (previous : Option auths_codec.auths_model.AttachmentDigest) (total : Nat)
    (accepted : validFrom previous total values = true) :
    (values.map fun value => digestKey value.digest).Chain' (· ≠ ·) := by
  induction values generalizing previous total with
  | nil => simp
  | cons first rest ih =>
    unfold validFrom at accepted
    split at accepted
    · simp at accepted
    · split at accepted
      · rename_i previousDifferent inBudget
        have tail := ih (some first.digest) (total + first.bytes.val.length) accepted
        cases rest with
        | nil => simp
        | cons next remaining =>
          have unequal : first.digest ≠ next.digest := by
            intro equal
            simp [validFrom, equal] at accepted
          have keyDifferent : digestKey first.digest ≠ digestKey next.digest :=
            fun equal => unequal (digestKey_injective equal)
          simpa only [List.map_cons, List.chain'_cons] using ⟨keyDifferent, tail⟩
      · simp at accepted

theorem sorted_valid_unique (values : List Attachment)
    (accepted : valid (sorted values) = true) :
    ((sorted values).map (fun value => value.digest)).Nodup := by
  have ordered : ((sorted values).map fun value => digestKey value.digest).Pairwise (· ≤ ·) := by
    simpa only [List.pairwise_map, digestKey, digestLE] using sorted_ordered values
  have strict := ordered_neighbors_strict _ ordered (valid_neighbors (sorted values) none 0 accepted)
  have distinct : ((sorted values).map fun value => digestKey value.digest).Nodup :=
    strict.imp (fun _ _ less => ne_of_lt less)
  have mapped : (((sorted values).map fun value => value.digest).map digestKey).Nodup := by
    simpa only [List.map_map, Function.comp_def] using distinct
  exact mapped.of_map

theorem constructor_canonical (action : auths_codec.auths_model.CanonicalAction)
    (values : alloc.vec.Vec Attachment) (output : auths_codec.auths_model.CanonicalAction)
    (accepted : auths_model.CanonicalAction.with_detached_attachments action values = ok (.Ok output)) :
    output.detached_attachments.val.Pairwise digestLE ∧
      (output.detached_attachments.val.map fun value => value.digest).Nodup ∧
      output.detached_attachments.val.Perm values.val := by
  have contract := constructor_exact action values
  rw [accepted] at contract
  simp only [spec_ok] at contract
  by_cases admitted : values.val.length ≤ 512 ∧ valid (sorted values.val) = true
  · simp only [admitted, ↓reduceIte, core.result.Result.Ok.injEq] at contract
    rw [contract]
    exact ⟨sorted_ordered values.val, sorted_valid_unique values.val admitted.2, sorted_perm values.val⟩
  · simp [admitted] at contract

theorem constructor_preserves_payloads (action : auths_codec.auths_model.CanonicalAction)
    (values : alloc.vec.Vec Attachment) (output : auths_codec.auths_model.CanonicalAction)
    (valid : AttachmentInverse.WellFormed values.val)
    (accepted : auths_model.CanonicalAction.with_detached_attachments action values = ok (.Ok output)) :
    AttachmentInverse.WellFormed output.detached_attachments.val := by
  have permutation := (constructor_canonical action values output accepted).2.2
  intro value member
  exact valid value (permutation.mem_iff.mp member)

theorem batch_payloads (input : Slice Std.U8) (limits : auths_codec.auths_model.VerifierLimits)
    (position count : Std.Usize) (batch : decode.AttachmentBatch)
    (limitsValid : Limits.Valid limits)
    (accepted : decode.attachment_batch input limits position count = ok (.Ok batch)) :
    AttachmentInverse.WellFormed batch.attachments.val := by
  have source := AttachmentDecodeSafety.source_batch_success input limits position count
  rw [accepted] at source
  have validity := (source batch rfl).1
  have payloads := validity.2.2
  have maximum : limits.attachment_bytes.val ≤ 8388608 := by
    simp only [Limits.Valid, Limits.hard, UScalar.ofNatCore_val_eq] at limitsValid
    tauto
  intro value member
  have mapped : AttachmentInverse.view value ∈ (AttachmentDecode.batchView batch).attachments := by
    exact List.mem_map.mpr ⟨value, member, rfl⟩
  have payload := payloads (AttachmentInverse.view value) mapped
  have nonempty : value.bytes.val ≠ [] := by
    simpa only [AttachmentInverse.view, byteList, List.map_eq_nil_iff] using payload.1
  have bounded : value.bytes.val.length ≤ limits.attachment_bytes.val := by
    simpa only [AttachmentInverse.view, byteList, List.length_map] using payload.2
  exact ⟨List.length_pos_iff.mpr nonempty, le_trans bounded maximum⟩

end Auths.Codec.AttachmentCanonical
