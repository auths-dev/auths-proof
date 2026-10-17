import qualification.aeneas.generated.gateway.Funs
import Auths.Product.CounterFrames
import Auths.Crypto.Endian
import Auths.Crypto.FramingTotality
import Auths.Product.Refinement.Gateway
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.CounterFrames.Refinement
set_option maxHeartbeats 2000000
set_option Elab.async false
open Auths.Product.Refinement.Gateway

private theorem append_exact (output : alloc.vec.Vec Std.U8) (value : Slice Std.U8)
    (fits : output.val.length + value.val.length < 4294967295) :
    _root_.auths_gateway_kernel.construct.append_bytes output value ⦃ actual =>
      actual.val = output.val ++ value.val ⦄ := by
  exact Auths.Product.Refinement.Gateway.append_bytes_spec output value fits

@[step] theorem word_exact (output : alloc.vec.Vec Std.U8) (value : Std.U64)
    (fits : output.val.length + 8 < 4294967295) :
    counter_preimages.append_word output value ⦃ actual =>
      vecBytes actual = vecBytes output ++ Auths.Codec.bigEndian 8 value.val ⦄ := by
  unfold counter_preimages.append_word
  simp only [lift, bind_tc_ok]
  apply spec_mono (append_exact _ _ (by simpa using fits))
  intro actual same
  simp only [vecBytes, byteList, same, List.map_append]
  exact congrArg (fun bytes => output.val.map (·.val) ++ bytes) (Auths.Crypto.Endian.be64_exact value)

@[step] theorem component_exact (output : alloc.vec.Vec Std.U8) (value : Slice Std.U8)
    (fits : output.val.length + 8 + value.val.length < 4294967295) :
    counter_preimages.append_component output value ⦃ actual =>
      vecBytes actual = vecBytes output ++ Auths.Codec.bigEndian 8 value.val.length ++ sliceBytes value ⦄ := by
  unfold counter_preimages.append_component
  simp only [_root_.U64.Insts.CoreConvertTryFromUsizeTryFromIntError.try_from]
  step with Auths.Crypto.FramingTotality.convert_total as ⟨length, lengthMeaning⟩
  cases length with
  | Err reason =>
    have impossible : value.val.length ≤ U64.max := by rw [U64.max_eq]; omega
    simp only [Slice.len_val, Slice.length, UScalar.max_UScalarTy_U64_eq] at lengthMeaning
    omega
  | Ok length =>
    simp only [_root_.core.result.Result.unwrap_or, bind_tc_ok]
    have nativeLength : length.val = value.val.length := by simpa using lengthMeaning
    apply spec_bind (word_exact output length (by omega))
    intro framedLength lengthBytes
    have framedSize : framedLength.val.length = output.val.length + 8 := by
      have size := congrArg List.length lengthBytes
      simpa [vecBytes, byteList, Auths.Codec.bigEndian_length] using size
    apply spec_mono (append_exact _ _ (by omega))
    intro actual actualBytes
    simp [vecBytes, byteList, actualBytes, List.map_append] at lengthBytes ⊢
    rw [lengthBytes, nativeLength]
    simp [sliceBytes, byteList]

@[step] theorem coordinates_exact (output : alloc.vec.Vec Std.U8) (window index : Std.U64)
    (fits : output.val.length + 16 < 4294967295) :
    counter_preimages.append_coordinates output window index ⦃ actual =>
      vecBytes actual = vecBytes output ++ Auths.Codec.bigEndian 8 window.val ++ Auths.Codec.bigEndian 8 index.val ⦄ := by
  unfold counter_preimages.append_coordinates
  apply spec_bind (word_exact output window (by omega))
  intro first firstBytes
  have firstSize : first.val.length = output.val.length + 8 := by
    have size := congrArg List.length firstBytes
    simpa [vecBytes, byteList, Auths.Codec.bigEndian_length] using size
  apply spec_mono (word_exact first index (by omega))
  intro actual actualBytes
  rw [actualBytes, firstBytes]

private theorem component_size (output actual : alloc.vec.Vec Std.U8) (value : Slice Std.U8)
    (same : vecBytes actual = vecBytes output ++ Auths.Codec.bigEndian 8 value.val.length ++ sliceBytes value) :
    actual.val.length = output.val.length + 8 + value.val.length := by
  have size := congrArg List.length same
  simpa [vecBytes, byteList, sliceBytes, Auths.Codec.bigEndian_length, Nat.add_assoc] using size

@[step] theorem count_exact (namespaceBytes subject evaluator : Slice Std.U8) (window index : Std.U64)
    (namespaceBound : namespaceBytes.val.length ≤ 64)
    (subjectBound : subject.val.length ≤ 512) (evaluatorBound : evaluator.val.length ≤ 128) :
    counter_preimages.count_counter_preimage namespaceBytes subject evaluator window index ⦃ actual =>
      vecBytes actual = CounterFrames.encode ⟨.count,
        [sliceBytes namespaceBytes, sliceBytes subject, sliceBytes evaluator], window.val, index.val⟩ ⦄ := by
  unfold counter_preimages.count_counter_preimage
  simp only [lift, bind_tc_ok]
  apply spec_bind (Auths.Product.Refinement.Gateway.copy_bytes_spec _ (by decide))
  intro tagged prefixBytes
  have prefixSize : tagged.val.length = 30 := by simp [prefixBytes]
  apply spec_bind (component_exact tagged namespaceBytes (by omega))
  intro one oneBytes
  have oneSize := component_size tagged one namespaceBytes oneBytes
  apply spec_bind (component_exact one subject (by omega))
  intro two twoBytes
  have twoSize := component_size one two subject twoBytes
  apply spec_bind (component_exact two evaluator (by omega))
  intro three threeBytes
  have threeSize := component_size two three evaluator threeBytes
  apply spec_mono (coordinates_exact three window index (by omega))
  intro actual actualBytes
  rw [actualBytes, threeBytes, twoBytes, oneBytes]
  simp only [vecBytes, byteList, prefixBytes, CounterFrames.encode, CounterFrames.domain,
    CounterFrames.fields, sliceBytes, List.map_append, List.map_cons, List.map_nil,
    List.append_assoc, List.append_nil, List.length_map]
  rfl

@[step] theorem sum_exact (namespaceBytes subject evaluator partitionBytes : Slice Std.U8) (window index : Std.U64)
    (namespaceBound : namespaceBytes.val.length ≤ 64)
    (subjectBound : subject.val.length ≤ 512) (evaluatorBound : evaluator.val.length ≤ 128)
    (partitionBound : partitionBytes.val.length ≤ 64) :
    counter_preimages.sum_counter_preimage namespaceBytes subject evaluator partitionBytes window index ⦃ actual =>
      vecBytes actual = CounterFrames.encode ⟨.sum,
        [sliceBytes namespaceBytes, sliceBytes subject, sliceBytes evaluator, sliceBytes partitionBytes], window.val, index.val⟩ ⦄ := by
  unfold counter_preimages.sum_counter_preimage
  simp only [lift, bind_tc_ok]
  apply spec_bind (Auths.Product.Refinement.Gateway.copy_bytes_spec _ (by decide))
  intro tagged prefixBytes
  have prefixSize : tagged.val.length = 28 := by simp [prefixBytes]
  apply spec_bind (component_exact tagged namespaceBytes (by omega))
  intro one oneBytes
  have oneSize := component_size tagged one namespaceBytes oneBytes
  apply spec_bind (component_exact one subject (by omega))
  intro two twoBytes
  have twoSize := component_size one two subject twoBytes
  apply spec_bind (component_exact two evaluator (by omega))
  intro three threeBytes
  have threeSize := component_size two three evaluator threeBytes
  apply spec_bind (component_exact three partitionBytes (by omega))
  intro four fourBytes
  have fourSize := component_size three four partitionBytes fourBytes
  apply spec_mono (coordinates_exact four window index (by omega))
  intro actual actualBytes
  rw [actualBytes, fourBytes, threeBytes, twoBytes, oneBytes]
  simp only [vecBytes, byteList, prefixBytes, CounterFrames.encode, CounterFrames.domain,
    CounterFrames.fields, sliceBytes, List.map_append, List.map_cons, List.map_nil,
    List.append_assoc, List.append_nil, List.length_map]
  rfl

@[step] private theorem slot_generic (domainBytes : Slice Std.U8) (counter : Array Std.U8 32#usize) (slot : Std.U64)
    (bounded : domainBytes.val.length ≤ 35) :
    counter_preimages.slot_preimage domainBytes counter slot ⦃ actual =>
      vecBytes actual = sliceBytes domainBytes ++ byteList counter.val ++ Auths.Codec.bigEndian 8 slot.val ⦄ := by
  unfold counter_preimages.slot_preimage
  apply spec_bind (Auths.Product.Refinement.Gateway.copy_bytes_spec _ (by omega))
  intro copied copiedBytes
  simp only [lift, bind_tc_ok]
  have counterSize : counter.val.length = 32 := by simpa using counter.property
  apply spec_bind (append_exact copied _ (by simp only [copiedBytes]; change domainBytes.val.length + counter.val.length < 4294967295; omega))
  intro combined combinedBytes
  have combinedSize : combined.val.length = domainBytes.val.length + 32 := by
    simp [combinedBytes, copiedBytes, counterSize]
  apply spec_mono (word_exact combined slot (by omega))
  intro actual actualBytes
  simp [vecBytes, byteList, combinedBytes, copiedBytes, List.map_append, sliceBytes] at actualBytes ⊢
  exact actualBytes

@[step] theorem count_slot_exact (counter : Array Std.U8 32#usize) (slot : Std.U64) :
    counter_preimages.count_slot_preimage counter slot ⦃ actual =>
      vecBytes actual = CounterFrames.slotEncode ⟨.count, byteList counter.val, slot.val⟩ ⦄ := by
  unfold counter_preimages.count_slot_preimage
  simp only [lift, bind_tc_ok]
  apply spec_mono (slot_generic _ counter slot (by decide))
  intro actual actualBytes
  rw [actualBytes]
  rfl

@[step] theorem sum_slot_exact (counter : Array Std.U8 32#usize) (slot : Std.U64) :
    counter_preimages.sum_slot_preimage counter slot ⦃ actual =>
      vecBytes actual = CounterFrames.slotEncode ⟨.sum, byteList counter.val, slot.val⟩ ⦄ := by
  unfold counter_preimages.sum_slot_preimage
  simp only [lift, bind_tc_ok]
  apply spec_mono (slot_generic _ counter slot (by decide))
  intro actual actualBytes
  rw [actualBytes]
  rfl

private theorem count_model_valid (namespaceBytes subject evaluator : Slice Std.U8) (window index : Std.U64)
    (namespaceBytesBound : namespaceBytes.val.length ≤ 64)
    (subjectBound : subject.val.length ≤ 512)
    (evaluatorBound : evaluator.val.length ≤ 128)
    : (CounterFrames.Counter.mk .count [sliceBytes namespaceBytes, sliceBytes subject, sliceBytes evaluator] window.val index.val).Valid := by
  have windowBound : window.val < 2 ^ 64 := window.bv.isLt
  have indexBound : index.val < 2 ^ 64 := index.bv.isLt
  simp [CounterFrames.Counter.Valid, CounterFrames.Bounded, sliceBytes, byteList]
  omega

/-- Equal outputs of two actual builders recover every budget identity field.
    Successful source results are identified; no hash property is assumed. -/
theorem count_source_binds_inputs
    (leftNamespaceBytes leftSubject leftEvaluator : Slice Std.U8)
    (leftWindow leftIndex : Std.U64)
    (leftNamespaceBytesBound : leftNamespaceBytes.val.length ≤ 64)
    (leftSubjectBound : leftSubject.val.length ≤ 512)
    (leftEvaluatorBound : leftEvaluator.val.length ≤ 128)
    (rightNamespaceBytes rightSubject rightEvaluator : Slice Std.U8)
    (rightWindow rightIndex : Std.U64)
    (rightNamespaceBytesBound : rightNamespaceBytes.val.length ≤ 64)
    (rightSubjectBound : rightSubject.val.length ≤ 512)
    (rightEvaluatorBound : rightEvaluator.val.length ≤ 128)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftProduced : counter_preimages.count_counter_preimage leftNamespaceBytes leftSubject leftEvaluator leftWindow leftIndex = ok leftOutput)
    (rightProduced : counter_preimages.count_counter_preimage rightNamespaceBytes rightSubject rightEvaluator rightWindow rightIndex = ok rightOutput)
    (same : vecBytes leftOutput = vecBytes rightOutput) :
    (CounterFrames.Counter.mk .count [sliceBytes leftNamespaceBytes, sliceBytes leftSubject, sliceBytes leftEvaluator] leftWindow.val leftIndex.val) = (CounterFrames.Counter.mk .count [sliceBytes rightNamespaceBytes, sliceBytes rightSubject, sliceBytes rightEvaluator] rightWindow.val rightIndex.val) := by
  have leftMeaning := count_exact leftNamespaceBytes leftSubject leftEvaluator leftWindow leftIndex leftNamespaceBytesBound leftSubjectBound leftEvaluatorBound
  have rightMeaning := count_exact rightNamespaceBytes rightSubject rightEvaluator rightWindow rightIndex rightNamespaceBytesBound rightSubjectBound rightEvaluatorBound
  rw [leftProduced, spec_ok] at leftMeaning
  rw [rightProduced, spec_ok] at rightMeaning
  apply CounterFrames.encode_injective _ _
    (count_model_valid leftNamespaceBytes leftSubject leftEvaluator leftWindow leftIndex leftNamespaceBytesBound leftSubjectBound leftEvaluatorBound)
    (count_model_valid rightNamespaceBytes rightSubject rightEvaluator rightWindow rightIndex rightNamespaceBytesBound rightSubjectBound rightEvaluatorBound)
  rw [← leftMeaning, ← rightMeaning]
  exact same

private theorem sum_model_valid (namespaceBytes subject evaluator partitionBytes : Slice Std.U8) (window index : Std.U64)
    (namespaceBytesBound : namespaceBytes.val.length ≤ 64)
    (subjectBound : subject.val.length ≤ 512)
    (evaluatorBound : evaluator.val.length ≤ 128)
    (partitionBytesBound : partitionBytes.val.length ≤ 64)
    : (CounterFrames.Counter.mk .sum [sliceBytes namespaceBytes, sliceBytes subject, sliceBytes evaluator, sliceBytes partitionBytes] window.val index.val).Valid := by
  have windowBound : window.val < 2 ^ 64 := window.bv.isLt
  have indexBound : index.val < 2 ^ 64 := index.bv.isLt
  simp [CounterFrames.Counter.Valid, CounterFrames.Bounded, sliceBytes, byteList]
  omega

/-- Equal outputs of two actual builders recover every budget identity field.
    Successful source results are identified; no hash property is assumed. -/
theorem sum_source_binds_inputs
    (leftNamespaceBytes leftSubject leftEvaluator leftPartitionBytes : Slice Std.U8)
    (leftWindow leftIndex : Std.U64)
    (leftNamespaceBytesBound : leftNamespaceBytes.val.length ≤ 64)
    (leftSubjectBound : leftSubject.val.length ≤ 512)
    (leftEvaluatorBound : leftEvaluator.val.length ≤ 128)
    (leftPartitionBytesBound : leftPartitionBytes.val.length ≤ 64)
    (rightNamespaceBytes rightSubject rightEvaluator rightPartitionBytes : Slice Std.U8)
    (rightWindow rightIndex : Std.U64)
    (rightNamespaceBytesBound : rightNamespaceBytes.val.length ≤ 64)
    (rightSubjectBound : rightSubject.val.length ≤ 512)
    (rightEvaluatorBound : rightEvaluator.val.length ≤ 128)
    (rightPartitionBytesBound : rightPartitionBytes.val.length ≤ 64)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftProduced : counter_preimages.sum_counter_preimage leftNamespaceBytes leftSubject leftEvaluator leftPartitionBytes leftWindow leftIndex = ok leftOutput)
    (rightProduced : counter_preimages.sum_counter_preimage rightNamespaceBytes rightSubject rightEvaluator rightPartitionBytes rightWindow rightIndex = ok rightOutput)
    (same : vecBytes leftOutput = vecBytes rightOutput) :
    (CounterFrames.Counter.mk .sum [sliceBytes leftNamespaceBytes, sliceBytes leftSubject, sliceBytes leftEvaluator, sliceBytes leftPartitionBytes] leftWindow.val leftIndex.val) = (CounterFrames.Counter.mk .sum [sliceBytes rightNamespaceBytes, sliceBytes rightSubject, sliceBytes rightEvaluator, sliceBytes rightPartitionBytes] rightWindow.val rightIndex.val) := by
  have leftMeaning := sum_exact leftNamespaceBytes leftSubject leftEvaluator leftPartitionBytes leftWindow leftIndex leftNamespaceBytesBound leftSubjectBound leftEvaluatorBound leftPartitionBytesBound
  have rightMeaning := sum_exact rightNamespaceBytes rightSubject rightEvaluator rightPartitionBytes rightWindow rightIndex rightNamespaceBytesBound rightSubjectBound rightEvaluatorBound rightPartitionBytesBound
  rw [leftProduced, spec_ok] at leftMeaning
  rw [rightProduced, spec_ok] at rightMeaning
  apply CounterFrames.encode_injective _ _
    (sum_model_valid leftNamespaceBytes leftSubject leftEvaluator leftPartitionBytes leftWindow leftIndex leftNamespaceBytesBound leftSubjectBound leftEvaluatorBound leftPartitionBytesBound)
    (sum_model_valid rightNamespaceBytes rightSubject rightEvaluator rightPartitionBytes rightWindow rightIndex rightNamespaceBytesBound rightSubjectBound rightEvaluatorBound rightPartitionBytesBound)
  rw [← leftMeaning, ← rightMeaning]
  exact same

end Auths.Product.CounterFrames.Refinement
