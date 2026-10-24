import Auths.Product.DerivedTokens
import Auths.Product.Refinement.Gateway

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway

namespace Auths.Product.DerivedTokens.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def digestBytes (digest : Array Std.U8 32#usize) : Bytes := byteList digest.val
theorem digest_size (digest : Array Std.U8 32#usize) : (digestBytes digest).length = 32 := by
  have size : digest.val.length = 32 := by simpa using digest.property
  simpa [digestBytes, byteList] using size

theorem digest_byte_bounds (digest : Array Std.U8 32#usize) : ∀ byte ∈ digestBytes digest, byte < 256 := by
  intro byte member
  obtain ⟨native, _, same⟩ := List.mem_map.mp member
  have nativeBound := native.hmax
  change native.val = byte at same
  scalar_tac

@[step] theorem append_digest_hex_exact (output : alloc.vec.Vec Std.U8) (digest : Array Std.U8 32#usize)
    (fits : output.val.length + 64 < 4294967295) :
    derived_tokens.append_digest_hex output digest ⦃ actual =>
      vecBytes actual = vecBytes output ++ hexDigest (digestBytes digest) ⦄ := by
  have digestSize : digest.val.length = 32 := by simpa using digest.property
  unfold derived_tokens.append_digest_hex derived_tokens.append_digest_hex_loop
  apply loop.spec_decr_nat
    (measure := fun state => 32 - state.2.val)
    (inv := fun state => state.2.val ≤ 32 ∧
      vecBytes state.1 = vecBytes output ++ hexDigest (byteList (digest.val.take state.2.val)))
  · rintro ⟨current, index⟩ invariant
    unfold derived_tokens.append_digest_hex_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < digest.val.length := by simpa [digestSize] using within
      have indexSmall : index.val < 32 := by omega
      have currentSize : current.val.length = output.val.length + 2 * index.val := by
        have sizes := congrArg List.length invariant.2
        simpa [vecBytes, byteList, hex_digest_length, List.length_take, Nat.min_eq_left (by omega)] using sizes
      step as ⟨byte, byteAt⟩
      step as ⟨high, highValue⟩
      step with hex_lower_spec as ⟨highDigit, highMeaning⟩
      have firstFits : current.val.length < Usize.max := lt_usize_max (by omega)
      step as ⟨withHigh, withHighValue⟩
      step as ⟨low, lowValue⟩
      step with hex_lower_spec as ⟨lowDigit, lowMeaning⟩
      have secondFits : withHigh.val.length < Usize.max := by
        apply lt_usize_max
        rw [withHighValue, List.length_append, List.length_singleton]
        omega
      step as ⟨withLow, withLowValue⟩
      step as ⟨nextIndex, nextIndexValue⟩
      refine ⟨by omega, ?_, by omega⟩
      simp only [vecBytes, byteList, withLowValue, withHighValue, List.map_append, List.map_singleton,
        highMeaning, lowMeaning, highValue, lowValue, nextIndexValue]
      rw [List.take_succ_eq_append_getElem inside]
      simp [vecBytes, byteList, List.map_append, hexDigest, hexByte, invariant.2, byteAt, List.append_assoc]
    · simp only [spec_ok]
      have finished : 32 ≤ index.val := by simpa [digestSize] using within
      simpa [digestBytes, List.take_of_length_le (show digest.val.length ≤ index.val by omega)] using invariant.2
  · simp [vecBytes, byteList, hexDigest]

@[step] theorem echo_token_exact (digest : Array Std.U8 32#usize) :
    derived_tokens.echo_token_bytes digest ⦃ actual => vecBytes actual = token .echo (digestBytes digest) ⦄ := by
  unfold derived_tokens.echo_token_bytes
  step with copy_bytes_spec as ⟨prefixValue, prefixEq⟩
  have fits : prefixValue.val.length + 64 < 4294967295 := by rw [prefixEq]; decide
  step with append_digest_hex_exact as ⟨actual, meaning⟩
  simpa [token, prefix, echoPrefix, vecBytes, byteList, prefixEq] using meaning

@[step] theorem idempotency_token_exact (digest : Array Std.U8 32#usize) :
    derived_tokens.idempotency_token_bytes digest ⦃ actual => vecBytes actual = token .idempotency (digestBytes digest) ⦄ := by
  unfold derived_tokens.idempotency_token_bytes
  step with copy_bytes_spec as ⟨prefixValue, prefixEq⟩
  have fits : prefixValue.val.length + 64 < 4294967295 := by rw [prefixEq]; decide
  step with append_digest_hex_exact as ⟨actual, meaning⟩
  simpa [token, prefix, idempotencyPrefix, vecBytes, byteList, prefixEq] using meaning

theorem source_echo_token_has_fixed_ascii_envelope (digest : Array Std.U8 32#usize) :
    derived_tokens.echo_token_bytes digest ⦃ actual =>
      actual.val.length = 73 ∧ ∀ byte ∈ vecBytes actual, byte < 128 ⦄ := by
  apply spec_mono (echo_token_exact digest)
  intro actual meaning
  have size := token_length .echo (digestBytes digest) (digest_size digest)
  have ascii := token_ascii .echo (digestBytes digest) (digest_byte_bounds digest)
  rw [← meaning] at size ascii
  exact ⟨by simpa [vecBytes, byteList] using size, ascii⟩

theorem source_idempotency_token_has_fixed_ascii_envelope (digest : Array Std.U8 32#usize) :
    derived_tokens.idempotency_token_bytes digest ⦃ actual =>
      actual.val.length = 73 ∧ ∀ byte ∈ vecBytes actual, byte < 128 ⦄ := by
  apply spec_mono (idempotency_token_exact digest)
  intro actual meaning
  have size := token_length .idempotency (digestBytes digest) (digest_size digest)
  have ascii := token_ascii .idempotency (digestBytes digest) (digest_byte_bounds digest)
  rw [← meaning] at size ascii
  exact ⟨by simpa [vecBytes, byteList] using size, ascii⟩


@[step] theorem echo_preimage_exact (namespaceBytes operation : Slice Std.U8) (commitment : Array Std.U8 32#usize)
    (namespaceBound : namespaceBytes.val.length ≤ 64) (operationBound : operation.val.length ≤ 128) :
    derived_tokens.echo_preimage namespaceBytes operation commitment ⦃ actual =>
      vecBytes actual = echoPreimage (sliceBytes namespaceBytes) (sliceBytes operation) (byteList commitment.val) ⦄ := by
  unfold derived_tokens.echo_preimage
  step with copy_bytes_spec as ⟨prefixValue, prefixEq⟩
  have namespaceFits : prefixValue.val.length + namespaceBytes.val.length < 4294967295 := by
    rw [prefixEq]
    change 21 + namespaceBytes.val.length < 4294967295
    omega
  step with append_bytes_spec as ⟨withNamespace, namespaceEq⟩
  have separatorFits : withNamespace.val.length < Usize.max := by
    apply lt_usize_max
    rw [namespaceEq, List.length_append, prefixEq]
    change 21 + namespaceBytes.val.length < 4294967295
    omega
  step as ⟨separated, separatorEq⟩
  have operationFits : separated.val.length + operation.val.length < 4294967295 := by
    rw [separatorEq, List.length_append, List.length_singleton, namespaceEq, List.length_append, prefixEq]
    change 21 + namespaceBytes.val.length + 1 + operation.val.length < 4294967295
    omega
  step with append_bytes_spec as ⟨withOperation, operationEq⟩
  have secondSeparatorFits : withOperation.val.length < Usize.max := by
    apply lt_usize_max
    rw [operationEq, List.length_append, separatorEq, List.length_append, List.length_singleton,
      namespaceEq, List.length_append, prefixEq]
    change 21 + namespaceBytes.val.length + 1 + operation.val.length < 4294967295
    omega
  step as ⟨withSeparator, secondSeparatorEq⟩
  have commitmentSize : commitment.val.length = 32 := by simpa using commitment.property
  have commitmentFits : withSeparator.val.length + commitment.val.length < 4294967295 := by
    rw [secondSeparatorEq, List.length_append, List.length_singleton, operationEq, List.length_append,
      separatorEq, List.length_append, List.length_singleton, namespaceEq, List.length_append, prefixEq,
      commitmentSize]
    change 21 + namespaceBytes.val.length + 1 + operation.val.length + 1 + 32 < 4294967295
    omega
  step with append_bytes_spec as ⟨actual, actualEq⟩
  simp [vecBytes, byteList, actualEq, secondSeparatorEq, operationEq, separatorEq, namespaceEq,
    prefixEq, echoPreimage, echoDomain, sliceBytes, List.map_append, List.append_assoc]


@[step] theorem idempotency_preimage_exact (namespaceBytes operation : Slice Std.U8)
    (namespaceBound : namespaceBytes.val.length ≤ 64) (operationBound : operation.val.length ≤ 128) :
    derived_tokens.idempotency_preimage namespaceBytes operation ⦃ actual =>
      vecBytes actual = idempotencyPreimage (sliceBytes namespaceBytes) (sliceBytes operation) ⦄ := by
  unfold derived_tokens.idempotency_preimage
  step with copy_bytes_spec as ⟨prefixValue, prefixEq⟩
  have namespaceFits : prefixValue.val.length + namespaceBytes.val.length < 4294967295 := by
    rw [prefixEq]
    change 32 + namespaceBytes.val.length < 4294967295
    omega
  step with append_bytes_spec as ⟨withNamespace, namespaceEq⟩
  have separatorFits : withNamespace.val.length < Usize.max := by
    apply lt_usize_max
    rw [namespaceEq, List.length_append, prefixEq]
    change 32 + namespaceBytes.val.length < 4294967295
    omega
  step as ⟨separated, separatorEq⟩
  have operationFits : separated.val.length + operation.val.length < 4294967295 := by
    rw [separatorEq, List.length_append, List.length_singleton, namespaceEq, List.length_append, prefixEq]
    change 32 + namespaceBytes.val.length + 1 + operation.val.length < 4294967295
    omega
  step with append_bytes_spec as ⟨withOperation, operationEq⟩
  simp [vecBytes, byteList, operationEq, separatorEq, namespaceEq, prefixEq,
    idempotencyPreimage, idempotencyDomain, sliceBytes, List.map_append, List.append_assoc]


end Auths.Product.DerivedTokens.Refinement

