import Auths.Product.PathCompiler
import Auths.Product.FieldProjectionRefinement

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.PathCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def sourceView : path_compiler.NamedSegment → SourceSegment
  | .Fixed bytes => .fixed (sliceBytes bytes)
  | .Field name => .field (sliceBytes name)
  | .Unsupported => .unsupported

def pathView (path : Slice path_compiler.NamedSegment) : List SourceSegment := path.val.map sourceView

@[step] theorem fixed_scan_exact (text : Slice Std.U8) :
    path_compiler.fixed_segment_valid_loop text 0#usize ⦃ actual =>
      actual = decide (∀ byte ∈ sliceBytes text, pathLiteral byte = true) ⦄ := by
  unfold path_compiler.fixed_segment_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => text.val.length - index.val)
    (inv := fun index => index.val ≤ text.val.length ∧
      ∀ byte ∈ text.val.take index.val, pathLiteral byte.val = true)
  · intro index invariant
    unfold path_compiler.fixed_segment_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < text.val.length := by simpa using within
      step as ⟨byte, byteAt⟩
      step with is_path_literal_spec as ⟨allowed, meaning⟩
      cases allowed
      · have invalid : pathLiteral byte.val ≠ true := by simpa using meaning.symm
        have member : byte.val ∈ sliceBytes text := List.mem_map.mpr
          ⟨byte, List.mem_iff_getElem?.mpr ⟨index.val, by simpa [byteAt] using List.getElem?_eq_getElem inside⟩, rfl⟩
        have refused : ¬∀ value ∈ sliceBytes text, pathLiteral value = true := fun all => invalid (all _ member)
        simp [refused]
      · have valid : pathLiteral byte.val = true := by simpa using meaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextValue, List.take_succ_eq_append_getElem inside]
        intro current member
        rcases List.mem_append.mp member with earlier | current
        · exact invariant.2 _ earlier
        · simpa [List.mem_singleton, current, byteAt] using valid
    · simp only [spec_ok]
      have atEnd : text.val.length ≤ index.val := by simpa using within
      have valid : ∀ byte ∈ sliceBytes text, pathLiteral byte = true := by
        intro byte member
        obtain ⟨current, member, same⟩ := List.mem_map.mp member
        simpa [same] using invariant.2 current (by simpa [List.take_of_length_le atEnd] using member)
      simp [valid]
  · exact ⟨by simp, by simp⟩

@[step] theorem fixed_valid_exact (text : Slice Std.U8) :
    path_compiler.fixed_segment_valid text ⦃ actual => actual = decide (FixedValid (sliceBytes text)) ⦄ := by
  unfold path_compiler.fixed_segment_valid path_compiler.MAX_FIXED_SEGMENT_BYTES
  by_cases long : 128 < text.val.length
  · have nativeLong : text.len > 128#usize := by scalar_tac
    have invalid : ¬FixedValid (sliceBytes text) := by
      intro valid
      have size := valid.2.1
      simp only [sliceBytes, byteList, List.length_map] at size
      omega
    simp [nativeLong, invalid]
  · have nativeBound : ¬text.len > 128#usize := by scalar_tac
    simp only [nativeBound, Bool.false_or]
    step with segment_value_valid_spec as ⟨base, baseMeaning⟩
    cases base
    · have invalid : ¬FixedValid (sliceBytes text) := by
        intro valid
        have required := (fixed_iff_source_checks _).mp valid |>.2.1
        simp [← baseMeaning] at required
      simp [invalid]
    · have baseValid : segmentValueValid (sliceBytes text) = true := by simpa using baseMeaning.symm
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      step with fixed_scan_exact as ⟨actual, meaning⟩
      have bounded : (sliceBytes text).length ≤ 128 := by simp [sliceBytes, byteList]; omega
      simpa only [fixed_iff_source_checks, bounded, baseValid, true_and] using meaning

@[step] theorem lower_field_exact (names : Slice (alloc.vec.Vec Std.U8)) (name : Slice Std.U8) :
    path_compiler.lower_field names name ⦃ actual =>
      resultOf UScalar.val actual = lowerField (namesView names) (sliceBytes name) ⦄ := by
  unfold path_compiler.lower_field arguments.MAX_PROFILE_FIELDS
  by_cases large : 32 < names.val.length
  · have nativeLarge : names.len > 32#usize := by scalar_tac
    simp [nativeLarge, lowerField, namesView, Nat.not_le.mpr large, resultOf, errorOf]
  · have bounded : names.val.length ≤ 32 := by omega
    have nativeBound : ¬names.len > 32#usize := by scalar_tac
    simp only [nativeBound, Bool.false_or]
    step with OperationIdentity.Refinement.token_exact as ⟨valid, validMeaning⟩
    cases valid
    · have invalid : OperationIdentity.validToken (sliceBytes name) 64 ≠ true := by simpa using validMeaning.symm
      simp [lowerField, invalid, resultOf, errorOf]
    · have valid : OperationIdentity.validToken (sliceBytes name) 64 = true := by simpa using validMeaning.symm
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      step with field_index_spec as ⟨index, indexMeaning⟩
      cases index with
      | none => simp [lowerField, namesView, bounded, valid, ← indexMeaning, resultOf, errorOf, sliceBytes]
      | some index => simp [lowerField, namesView, bounded, valid, ← indexMeaning, resultOf, sliceBytes]

@[step] theorem lower_segment_exact (names : Slice (alloc.vec.Vec Std.U8)) (source : path_compiler.NamedSegment) :
    path_compiler.lower_segment names source ⦃ actual =>
      resultOf segmentOf actual = lowerOne (namesView names) (sourceView source) ⦄ := by
  cases source with
  | Fixed text =>
    unfold path_compiler.lower_segment
    step with fixed_valid_exact as ⟨valid, meaning⟩
    cases valid
    · have invalid : ¬FixedValid (sliceBytes text) := by simpa using meaning.symm
      simp [sourceView, lowerOne, invalid, resultOf, errorOf]
    · have valid : FixedValid (sliceBytes text) := by simpa using meaning.symm
      have fits : text.val.length < 4294967295 := by
        have size := valid.2.1
        simp only [sliceBytes, byteList, List.length_map] at size
        omega
      step with copy_bytes_spec as ⟨copied, same⟩
      simp [sourceView, lowerOne, valid, resultOf, segmentOf, vecBytes, sliceBytes, same]
  | Field name =>
    unfold path_compiler.lower_segment
    step with lower_field_exact as ⟨position, meaning⟩
    cases position <;> simp [sourceView, lowerOne, ← meaning, resultOf, segmentOf]
  | Unsupported => simp [path_compiler.lower_segment, sourceView, lowerOne, resultOf, errorOf]

end Auths.Product.PathCompiler.Refinement
