import Auths.Crypto.CommitmentRefinement
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
open auths_codec
set_option cbv.warning false
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
namespace Auths.Crypto.CommitmentExamples

def emptyDomain : Str := ⟨[], by scalar_tac⟩
def tooLongDomain : Str := ⟨List.replicate 129 97#u8, by scalar_tac⟩
def sampleDomain : Str := ⟨[100#u8, 101#u8, 109#u8, 111#u8], by scalar_tac⟩
def payload : Slice Std.U8 := ⟨[0#u8, 255#u8], by scalar_tac⟩

def applicationOutput : alloc.vec.Vec Std.U8 := ⟨[
  65#u8, 85#u8, 84#u8, 72#u8, 83#u8, 45#u8, 67#u8, 79#u8,
  77#u8, 77#u8, 73#u8, 84#u8, 77#u8, 69#u8, 78#u8, 84#u8,
  0#u8, 1#u8, 0#u8, 4#u8, 100#u8, 101#u8, 109#u8, 111#u8,
  0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 2#u8, 0#u8, 255#u8
], by scalar_tac⟩

def tagByte : hash.IdentifierType → Std.U8
  | .Grant => 1#u8 | .Action => 2#u8 | .Plan => 3#u8 | .Evidence => 4#u8
  | .PrincipalStatus => 5#u8 | .GrantStatus => 6#u8 | .Context => 9#u8
  | .ObservationRequirement => 11#u8 | .ApprovalRequirement => 12#u8

def identifierOutput (kind : hash.IdentifierType) : alloc.vec.Vec Std.U8 := ⟨[
  65#u8, 85#u8, 84#u8, 72#u8, 83#u8, 45#u8, 73#u8, 68#u8,
  0#u8, 1#u8, 0#u8, tagByte kind,
  0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 0#u8, 2#u8, 0#u8, 255#u8
], by scalar_tac⟩

theorem empty_domain_refused (bytes : Slice Std.U8) :
    hash.commitment_preimage emptyDomain bytes = ok (.Err .LimitExceeded) := by
  cbv

theorem oversized_domain_refused (bytes : Slice Std.U8) :
    hash.commitment_preimage tooLongDomain bytes = ok (.Err .LimitExceeded) := by
  cbv

theorem application_sample_admitted : ∃ output,
    hash.commitment_preimage sampleDomain payload = ok (.Ok output) := by
  refine ⟨applicationOutput, ?_⟩
  unfold hash.commitment_preimage
  simp only [BufferAllocation.buffer_conservative_model]
  cbv

theorem every_identifier_tag_admitted (kind : hash.IdentifierType) : ∃ output,
    hash.identifier_preimage kind payload = ok (.Ok output) := by
  refine ⟨identifierOutput kind, ?_⟩
  unfold hash.identifier_preimage
  simp only [BufferAllocation.buffer_conservative_model, CommitmentRefinement.identifier_tag_word]
  cases kind <;> cbv

end Auths.Crypto.CommitmentExamples
