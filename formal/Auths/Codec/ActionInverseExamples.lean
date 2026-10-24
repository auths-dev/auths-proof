import Auths.Codec.ActionInverse
import Auths.Codec.Examples
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionInverseExamples
open Refinement ActionCarrier ActionInverse

/-- Positive examples include distinct sufficient carriers: absent budget,
zero-valued present budget and multiple canonical detached attachments. -/
def zeroBudgetAction : auths_codec.auths_model.CanonicalAction :=
  {Examples.minimalAction with requested_budget := some ⟨"count", 0#u64⟩}

def firstAttachment : auths_codec.auths_model.DetachedAttachment :=
  ⟨⟨List.replicate 32 0#u8, by simp⟩, ⟨[7#u8], by scalar_tac⟩⟩

def secondAttachment : auths_codec.auths_model.DetachedAttachment :=
  ⟨⟨List.replicate 32 1#u8, by simp⟩, ⟨[8#u8, 9#u8], by scalar_tac⟩⟩

def attachedAction : auths_codec.auths_model.CanonicalAction :=
  {zeroBudgetAction with detached_attachments := ⟨[firstAttachment, secondAttachment], by scalar_tac⟩}

def roomyLimits : auths_codec.auths_model.VerifierLimits :=
  {Examples.minimalLimits with action_bytes := 1024#usize, attachments := 2#usize,
    attachment_bytes := 3#usize}

theorem minimal_valid : Valid Examples.minimalAction := by
  constructor <;> cbv <;> simp

theorem minimal_fits : Fits Examples.minimalLimits Examples.minimalAction := by
  constructor <;> cbv

theorem zero_budget_valid : Valid zeroBudgetAction := by
  constructor <;> cbv <;> simp

theorem zero_budget_fits : Fits roomyLimits zeroBudgetAction := by
  constructor <;> cbv

theorem attached_valid : Valid attachedAction := by
  constructor <;> cbv <;> simp

theorem attached_fits : Fits roomyLimits attachedAction := by
  constructor <;> cbv

/-- The actual writer result is passed directly to the actual public parser.
There is no fixture decoder or assumed acceptance result in this witness. -/
theorem minimal_source_roundtrip :
    encode.encode_canonical_action Examples.minimalAction ⦃ encoded =>
      ∃ bytes, encoded = .Ok bytes ∧
        decode.decode_canonical_action (alloc.vec.Vec.deref bytes) Examples.minimalLimits
          ⦃ decoded => decoded = .Ok Examples.minimalAction ⦄ ⦄ :=
  encode_decode _ _ minimal_valid minimal_fits

theorem zero_budget_source_roundtrip :
    encode.encode_canonical_action zeroBudgetAction ⦃ encoded =>
      ∃ bytes, encoded = .Ok bytes ∧
        decode.decode_canonical_action (alloc.vec.Vec.deref bytes) roomyLimits
          ⦃ decoded => decoded = .Ok zeroBudgetAction ⦄ ⦄ :=
  encode_decode _ _ zero_budget_valid zero_budget_fits

theorem attached_source_roundtrip :
    encode.encode_canonical_action attachedAction ⦃ encoded =>
      ∃ bytes, encoded = .Ok bytes ∧
        decode.decode_canonical_action (alloc.vec.Vec.deref bytes) roomyLimits
          ⦃ decoded => decoded = .Ok attachedAction ⦄ ⦄ :=
  encode_decode _ _ attached_valid attached_fits

end Auths.Codec.ActionInverseExamples
