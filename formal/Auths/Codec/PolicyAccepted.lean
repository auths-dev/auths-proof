import Auths.Codec.PolicyInverse
import Auths.Codec.ProtocolStrings
import Auths.Codec.ProtocolReencoding

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyAccepted
open Auths.Codec.Refinement Auths.Crypto

set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

/- Accepted-value consequences for the actual source parser. Acceptance is a
postcondition premise, not a claim of all-input decoder totality or a trusted
validity flag. Field validity is earned by the real lexical/model algorithms. -/
theorem identifier_valid (input : Str) (maximum : Std.Usize) (output : String)
    (accepted : auths_model.bounded_policy.PolicyIdentifier.parse input maximum = ok (.Ok output)) :
    PolicyValidity.Identifier output maximum.val := by
  obtain ⟨allowed, guardRun, guardMeaning⟩ := spec_imp_exists (PolicyIdentifiers.valid_exact input maximum)
  unfold auths_model.bounded_policy.PolicyIdentifier.parse at accepted
  rw [guardRun] at accepted
  cases allowed with
  | false => simp [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok] at accepted
  | true =>
    have checks : (!input.val.isEmpty && decide (input.val.length ≤ maximum.val) &&
        !PolicyValidity.invalid (byteList input.val)) = true := by simpa using guardMeaning.symm
    simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte, bind_tc_ok] at accepted
    cases copied : alloc.string.String.Insts.CoreConvertFromShared0Str.from input with
    | fail reason => simp [copied, bind_tc_fail] at accepted
    | div => simp [copied, bind_tc_div] at accepted
    | ok value =>
      rw [copied, bind_tc_ok] at accepted
      have same : value = output := by simpa using accepted
      subst output
      have bytes := ProtocolStrings.copy_accepted input value copied
      have length : value.toByteArray.size = input.val.length := by
        have exactLength := congrArg List.length bytes
        simpa only [UnsignedLeaves.utf8_length, byteList, List.length_map] using exactLength
      apply (PolicyValidity.accepts_iff value maximum.val).mp
      simpa only [PolicyValidity.accepts, bytes, length, byteList, List.isEmpty_map] using checks

def inputAccepted (input : Str) (maximum : Std.Usize) : Bool :=
  !input.val.isEmpty && decide (input.val.length ≤ maximum.val) &&
    !PolicyValidity.invalid (byteList input.val)

theorem identifier_exact (input : Str) (maximum : Std.Usize)
    (utf8 : (Auths.Codec.StdModel.bytes input).IsValidUTF8) :
    auths_model.bounded_policy.PolicyIdentifier.parse input maximum =
      ok (if inputAccepted input maximum then .Ok (ProtocolStrings.owned input utf8) else .Err .InvalidBoundedPolicy) := by
  obtain ⟨allowed, guardRun, guardMeaning⟩ := spec_imp_exists (PolicyIdentifiers.valid_exact input maximum)
  have guard : auths_model.bounded_policy.policy_identifier_valid input maximum = ok (inputAccepted input maximum) := by
    rw [guardMeaning] at guardRun
    exact guardRun
  unfold auths_model.bounded_policy.PolicyIdentifier.parse
  rw [guard]
  cases decision : inputAccepted input maximum <;>
    simp [decision, ProtocolStrings.copy_exact input utf8, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]

@[step] theorem identifier_total (input : Str) (maximum : Std.Usize)
    (utf8 : (Auths.Codec.StdModel.bytes input).IsValidUTF8) :
    auths_model.bounded_policy.PolicyIdentifier.parse input maximum ⦃ result =>
      match result with
      | .Err reason => reason = .InvalidBoundedPolicy ∧ inputAccepted input maximum = false
      | .Ok value => PolicyValidity.Identifier value maximum.val ∧
          UnsignedObjects.utf8 value = byteList input.val ⦄ := by
  have exactRun := identifier_exact input maximum utf8
  rw [exactRun]
  cases decision : inputAccepted input maximum with
  | false => simp [decision, spec_ok]
  | true =>
    have accepted : auths_model.bounded_policy.PolicyIdentifier.parse input maximum =
        ok (.Ok (ProtocolStrings.owned input utf8)) := by simpa only [decision, ↓reduceIte] using exactRun
    simp only [decision, ↓reduceIte, spec_ok]
    exact ⟨identifier_valid input maximum _ accepted, ProtocolStrings.owned_bytes input utf8⟩

macro "policy_trace" accepted:ident : tactic => `(tactic|
  (simp only [Bind.bind, Aeneas.Std.bind] at $accepted
   repeat' first
     | casesm* _ × _
     | dsimp only at $accepted
     | split at $accepted
     | simp (failIfUnchanged := true) only [
         uncurry, Bind.bind, Aeneas.Std.bind,
         core.result.Result.Insts.CoreOpsTry.branch,
         core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
         core.convert.FromSame, core.convert.FromSame.from,
         core.result.Result.map_err, BuiltinFnOnce,
         bind_tc_ok, bind_tc_fail, bind_tc_div, Result.ok.injEq,
         core.result.Result.Ok.injEq, Prod.mk.injEq, reduceCtorEq] at $accepted
     | contradiction
   all_goals subst_vars
   all_goals aesop))

theorem commitment_trace (self next : cbor.Decoder) (output : auths_model.bounded_policy.PolicyCommitment)
    (accepted : bounded_policy.commitment self = ok (.Ok output, next)) :
    ∃ (typeText canonicalizationText evaluatorText : Str)
      (policyType canonicalization evaluator : String) (version : Std.U16) (digest : auths_model.Digest),
      auths_model.bounded_policy.PolicyIdentifier.parse typeText 128#usize = ok (.Ok policyType) ∧
      auths_model.bounded_policy.PolicyIdentifier.parse canonicalizationText 64#usize = ok (.Ok canonicalization) ∧
      auths_model.bounded_policy.PolicyIdentifier.parse evaluatorText 128#usize = ok (.Ok evaluator) ∧
      auths_model.bounded_policy.PolicyCommitment.new policyType version canonicalization digest evaluator = ok (.Ok output) := by
  unfold bounded_policy.commitment at accepted
  simp only [auths_model.bounded_policy.MAX_POLICY_IDENTIFIER_BYTES,
    auths_model.bounded_policy.MAX_POLICY_CANONICALIZATION_BYTES, bind_tc_ok] at accepted
  policy_trace accepted

theorem commitment_valid (self next : cbor.Decoder) (output : auths_model.bounded_policy.PolicyCommitment)
    (accepted : bounded_policy.commitment self = ok (.Ok output, next)) : PolicyValidity.Commitment output := by
  obtain ⟨typeText, canonicalizationText, evaluatorText, policyType, canonicalization, evaluator,
    version, digest, typeRun, canonicalizationRun, evaluatorRun, constructorRun⟩ := commitment_trace self next output accepted
  have typeValid := identifier_valid typeText 128#usize policyType typeRun
  have canonicalizationValid := identifier_valid canonicalizationText 64#usize canonicalization canonicalizationRun
  have evaluatorValid := identifier_valid evaluatorText 128#usize evaluator evaluatorRun
  let prototype : auths_model.bounded_policy.PolicyCommitment := ⟨policyType, version, canonicalization, digest, evaluator⟩
  have carriers : BoundedPolicyWriters.Fields prototype := by
    have typeBound := typeValid.2
    have canonicalizationBound := canonicalizationValid.2
    have evaluatorBound := evaluatorValid.2
    constructor <;> scalar_tac
  have language : PolicyValidity.CommitmentLanguage prototype :=
    ⟨typeValid.1, canonicalizationValid.1, evaluatorValid.1⟩
  exact (PolicyConstructors.commitment_output_valid prototype output carriers language constructorRun).2

theorem decoder_trace [primitive : Sha256Primitives] (input : Slice Std.U8)
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : bounded_policy.decode_bounded_policy_commitment input = ok (.Ok carrier)) :
    ∃ (self next : cbor.Decoder) (commitment : auths_model.bounded_policy.PolicyCommitment)
      (policy : alloc.vec.Vec Std.U8) (parent : Option auths_model.Digest)
      (body gateBody : auths_model.bounded_policy.BoundedPolicyCommitment) (encoded : alloc.vec.Vec Std.U8),
      bounded_policy.commitment self = ok (.Ok commitment, next) ∧
      auths_model.bounded_policy.BoundedPolicyCommitment.new commitment policy parent = ok (.Ok body) ∧
      canonical.accept input encoded body = ok (.Ok gateBody) ∧
      canonical_value.checked_bounded_policy gateBody = ok (.Ok carrier) := by
  unfold bounded_policy.decode_bounded_policy_commitment at accepted
  policy_trace accepted

theorem decoder_valid [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256)
    (input : Slice Std.U8) (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : bounded_policy.decode_bounded_policy_commitment input = ok (.Ok carrier)) :
    ∃ value, canonical_value.Canonical.as_value carrier = ok value ∧
      PolicyValidity.Body value ∧ PolicyValidity.Opening sha256 value := by
  obtain ⟨self, next, commitment, policy, parent, body, gateBody, encoded,
    commitmentRun, bodyRun, gateRun, checkedRun⟩ := decoder_trace input carrier accepted
  have commitmentValid := commitment_valid self next commitment commitmentRun
  let prototype : auths_model.bounded_policy.BoundedPolicyCommitment := ⟨commitment, policy, parent⟩
  have bodyValid := (PolicyConstructors.body_output_valid prototype body commitmentValid bodyRun).2
  have sameBody := (ProtocolCanonical.accepted_preserves input encoded body gateBody gateRun).2
  have gateValid : PolicyValidity.Body gateBody := by simpa only [← sameBody] using bodyValid
  have checked := PolicyCanonical.checked_total sha256 contract gateBody gateValid
  rw [checkedRun, spec_ok] at checked
  exact ⟨gateBody, checked.1, checked.2.1, checked.2.2.1⟩

theorem decoder_closed [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256)
    (input : Slice Std.U8) (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : bounded_policy.decode_bounded_policy_commitment input = ok (.Ok carrier)) :
    ∃ value encoded, canonical_value.Canonical.as_value carrier = ok value ∧
      PolicyValidity.Body value ∧ PolicyValidity.Opening sha256 value ∧
      bounded_policy.encode_bounded_policy_commitment carrier = ok (.Ok encoded) ∧
      encoded.val = input.val ∧ byteList input.val = BoundedPolicyObjects.body value := by
  obtain ⟨value, projection, valid, opened⟩ := decoder_valid sha256 contract input carrier accepted
  obtain ⟨encoded, encodeRun, sameBytes⟩ :=
    ProtocolReencoding.decode_bounded_policy_commitment_reencodes input carrier accepted
  obtain ⟨space, native, length⟩ := PolicyConstructors.body_resources value valid
  have writer := BoundedPolicyWriters.canonical_encoder carrier value projection
    (PolicyConstructors.fields_valid value.commitment valid.1) space native
  rw [encodeRun, spec_ok] at writer
  have wire : byteList input.val = BoundedPolicyObjects.body value := by
    simpa only [SigningObjectWriters.Encodes, sameBytes] using writer
  exact ⟨value, encoded, projection, valid, opened, encodeRun, sameBytes, wire⟩

/-- Accepted bytes earn their complete writer envelope. This is a logical
byte/capacity bound, not a bound on malformed-input work or physical memory. -/
theorem decoder_envelope [primitive : Sha256Primitives]
    (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256)
    (input : Slice Std.U8) (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (accepted : bounded_policy.decode_bounded_policy_commitment input = ok (.Ok carrier)) :
    input.val.length ≤ 4633 ∧ ∃ value,
      canonical_value.Canonical.as_value carrier = ok value ∧
      value.policy.val.length ≤ 4096 ∧ BoundedPolicyObjects.bodyCost value ≤ 4633 ∧
      BoundedPolicyWriters.Fields value.commitment ∧
      BoundedPolicyObjects.bodyCost value ≤ Usize.max ∧
      (2 * BoundedPolicyObjects.bodyCost value : Int) ≤ Isize.max := by
  obtain ⟨value, encoded, projection, valid, opened, encodeRun, sameBytes, wire⟩ :=
    decoder_closed sha256 contract input carrier accepted
  have cost := PolicyConstructors.body_cost_valid value valid
  have length := BoundedPolicyWriters.body_length value
  have byteLength := congrArg List.length wire
  simp only [byteList, List.length_map] at byteLength
  obtain ⟨space, native, extension⟩ := PolicyConstructors.body_resources value valid
  refine ⟨by omega, value, projection, valid.2.2, cost,
    PolicyConstructors.fields_valid value.commitment valid.1, space, native⟩

end Auths.Codec.PolicyAccepted
