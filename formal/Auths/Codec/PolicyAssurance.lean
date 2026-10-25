import Auths.Codec.PolicyReadTotal
import Auths.Codec.PolicyCursor

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsProtocolCodec

namespace Auths.Codec.PolicyAssurance
open Auths.Codec.Refinement Auths.Crypto

/- Complete acceptance semantics for this one object. The independent domain
contains full constructor/lexical validity, the mathematical opening and every
canonical byte. It contains no source verdict, trusted carrier flag, expected
intermediate parser output or evaluator/parent-link authorization claim. -/
def Accepts (sha256 : List Nat → auths_model.Digest) (input : Slice Std.U8)
    (value : auths_model.bounded_policy.BoundedPolicyCommitment) : Prop :=
  PolicyValidity.Body value ∧ PolicyValidity.Opening sha256 value ∧
    byteList input.val = BoundedPolicyObjects.body value

variable [primitive : Sha256Primitives]

theorem accepted_iff (sha256 : List Nat → auths_model.Digest) (contract : FramedHash.Contract sha256)
    (input : Slice Std.U8) (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment) :
    bounded_policy.decode_bounded_policy_commitment input = ok (.Ok carrier) ↔
      Accepts sha256 input carrier.value := by
  constructor
  · intro accepted
    obtain ⟨value, encoded, projection, valid, opened, encodeRun, sameBytes, wire⟩ :=
      PolicyAccepted.decoder_closed sha256 contract input carrier accepted
    have sameValue : carrier.value = value := by
      simpa only [canonical_value.Canonical.as_value, Result.ok.injEq] using projection
    simpa only [Accepts, sameValue] using And.intro valid (And.intro opened wire)
  · rintro ⟨valid, opened, wire⟩
    obtain ⟨result, run, meaning⟩ := spec_imp_exists
      (PolicyInverse.decode_encoding sha256 contract input carrier.value valid wire)
    rw [meaning, if_pos opened] at run
    have sameCarrier : (⟨carrier.value⟩ :
        canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment) = carrier := by
      cases carrier
      rfl
    simpa only [sameCarrier] using run

/-- All represented input returns a typed result. Refusal excludes every value
in the independent complete acceptance domain, not merely a chosen candidate.
This is verdict adequacy; it does not classify each malformed-input error code. -/
@[step] theorem decoder_refines (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (input : Slice Std.U8) :
    bounded_policy.decode_bounded_policy_commitment input ⦃ result =>
      match result with
      | .Err _ => ∀ carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment,
          ¬ Accepts sha256 input carrier.value
      | .Ok carrier => Accepts sha256 input carrier.value ∧
          ∃ encoded, bounded_policy.encode_bounded_policy_commitment carrier = ok (.Ok encoded) ∧
            encoded.val = input.val ⦄ := by
  obtain ⟨result, run, meaning⟩ := spec_imp_exists (PolicyReadTotal.decoder_total sha256 contract input)
  rw [run, spec_ok]
  cases result with
  | Err reason =>
    intro carrier allowed
    have accepted := (accepted_iff sha256 contract input carrier).mpr allowed
    rw [run] at accepted
    contradiction
  | Ok carrier =>
    refine ⟨(accepted_iff sha256 contract input carrier).mp run, ?_⟩
    obtain ⟨value, encoded, projection, valid, opened, encodeRun, sameBytes, wire⟩ := meaning
    exact ⟨encoded, encodeRun, sameBytes⟩

theorem unique_accepted_bytes (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256) (left right : Slice Std.U8)
    (carrier : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment)
    (leftRun : bounded_policy.decode_bounded_policy_commitment left = ok (.Ok carrier))
    (rightRun : bounded_policy.decode_bounded_policy_commitment right = ok (.Ok carrier)) :
    left.val = right.val := by
  have leftWire := ((accepted_iff sha256 contract left carrier).mp leftRun).2.2
  have rightWire := ((accepted_iff sha256 contract right carrier).mp rightRun).2.2
  exact ProtocolPrimitiveInverse.bytes_injective (leftWire.trans rightWire.symm)

/-- Full value injectivity comes from source decoder determinism and the useful
inverse. Neither digest injectivity nor a cryptographic collision premise is
used: the wire representation retains the entire body and commitment. -/
theorem encoding_injective (sha256 : List Nat → auths_model.Digest)
    (contract : FramedHash.Contract sha256)
    (left right : auths_model.bounded_policy.BoundedPolicyCommitment)
    (leftValid : PolicyValidity.Body left) (rightValid : PolicyValidity.Body right)
    (leftOpened : PolicyValidity.Opening sha256 left) (rightOpened : PolicyValidity.Opening sha256 right)
    (sameWire : BoundedPolicyObjects.body left = BoundedPolicyObjects.body right) : left = right := by
  obtain ⟨encoded, encodeRun, bytes⟩ := SigningObjectWriters.encoder_success
    (PolicyConstructors.body_encoder_valid left leftValid)
  let input := alloc.vec.Vec.deref encoded
  have leftWire : byteList input.val = BoundedPolicyObjects.body left := by
    simpa only [input, alloc.vec.deref_exact] using bytes
  have rightWire : byteList input.val = BoundedPolicyObjects.body right := leftWire.trans sameWire
  have leftRun := (accepted_iff sha256 contract input ⟨left⟩).mpr ⟨leftValid, leftOpened, leftWire⟩
  have rightRun := (accepted_iff sha256 contract input ⟨right⟩).mpr ⟨rightValid, rightOpened, rightWire⟩
  have sameCarrier : (⟨left⟩ : canonical_value.Canonical auths_model.bounded_policy.BoundedPolicyCommitment) =
      ⟨right⟩ := by
    simpa only [Result.ok.injEq, core.result.Result.Ok.injEq] using leftRun.symm.trans rightRun
  exact congrArg (fun carrier => carrier.value) sameCarrier

end Auths.Codec.PolicyAssurance
