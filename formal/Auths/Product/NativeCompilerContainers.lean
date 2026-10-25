import Auths.Product.NativeCompilerValues
import qualification.aeneas.generated.native_recipe.FunsExternal

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.StdModel

@[simp] theorem native_text_bytes (text : String) :
    (AuthsNativeRecipe.NativeModel.textBytes text).map (·.val) = textBytes text := by
  simp only [AuthsNativeRecipe.NativeModel.textBytes, textBytes, List.map_map]
  rfl

@[simp] theorem native_text_length (text : String) :
    (AuthsNativeRecipe.NativeModel.textBytes text).length = text.toByteArray.size := by
  simp [AuthsNativeRecipe.NativeModel.textBytes]

@[step] theorem borrow_text_exact (text : String) (fits : TextFits text) :
    AuthsNativeRecipe.alloc.string.String.as_bytes text ⦃ actual =>
      actual.val.map (·.val) = textBytes text ⦄ := by
  unfold AuthsNativeRecipe.alloc.string.String.as_bytes
  have bounded : (AuthsNativeRecipe.NativeModel.textBytes text).length ≤ Usize.max := by
    simpa only [native_text_length] using fits
  simp only [dif_pos bounded, spec_ok]
  exact native_text_bytes text

@[step] theorem copy_u8_exact (input : Slice Std.U8) :
    AuthsNativeRecipe.alloc.slice.Slice.to_vec core.clone.CloneU8 input ⦃ actual =>
      bytes actual = input.val.map (·.val) ⦄ := by
  unfold AuthsNativeRecipe.alloc.slice.Slice.to_vec
  step with Aeneas.Std.alloc.slice.Slice.to_vec_spec core.clone.CloneU8 input
    (by intro value _; rfl) as ⟨copied, same⟩
  subst copied
  simp [bytes, AuthsNativeRecipe.alloc.vec.Vec.ofBase, AuthsNativeRecipe.alloc.vec.Vec.val,
    auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
    auths_composition.alloc.vec.SizedList.toList_ofList]

@[step] theorem native_push_exact {T : Type} (prefix : NativeVec T) (value : T)
    (room : prefix.val.length < Usize.max) :
    AuthsNativeRecipe.alloc.vec.Vec.push prefix value ⦃ actual =>
      actual.val = prefix.val ++ [value] ⦄ :=
  AuthsProtocolCodec.alloc.vec.push_spec prefix value room

@[simp] theorem native_empty_contents (T : Type) :
    (AuthsNativeRecipe.alloc.vec.Vec.new T).val = [] :=
  AuthsProtocolCodec.alloc.vec.new_contents T

@[simp] theorem native_deref_contents {T : Type} (input : NativeVec T) :
    (AuthsNativeRecipe.alloc.vec.Vec.deref input).val = input.val := rfl

/-- Complete standard-vector cloning preserves the positive carrier when the
actual element clone preserves each original element. No prefix is discarded. -/
@[step] theorem native_vector_clone_exact {T : Type} (clone : core.clone.Clone T)
    (input : NativeVec T) (elements : ∀ value ∈ input.val, clone.clone value = ok value) :
    AuthsNativeRecipe.alloc.vec.CloneVec.clone clone input ⦃ actual => actual = input ⦄ := by
  change (do
      let copied ← Aeneas.Std.alloc.vec.CloneVec.clone clone input.toBase
      ok (AuthsNativeRecipe.alloc.vec.Vec.ofBase copied)) ⦃ actual => actual = input ⦄
  unfold Aeneas.Std.alloc.vec.CloneVec.clone
  step with Slice.clone_spec (by simpa using elements) as ⟨copied, same⟩
  subst copied
  simpa only [bind_tc_ok, spec_ok] using AuthsProtocolCodec.alloc.vec.of_base_to_base input

theorem native_vector_clone_result {T : Type} (clone : core.clone.Clone T)
    (input : NativeVec T) (elements : ∀ value ∈ input.val, clone.clone value = ok value) :
    AuthsNativeRecipe.alloc.vec.CloneVec.clone clone input = ok input := by
  obtain ⟨actual, evaluates, same⟩ := spec_imp_exists (native_vector_clone_exact clone input elements)
  simpa only [same] using evaluates

@[step] theorem native_option_clone_exact {T : Type} (clone : core.clone.Clone T)
    (input : Option T) (elements : ∀ value, input = some value → clone.clone value = ok value) :
    AuthsNativeRecipe.core.option.Option.Insts.CoreCloneClone.clone clone input
      ⦃ actual => actual = input ⦄ := by
  cases input with
  | none => simp [AuthsNativeRecipe.core.option.Option.Insts.CoreCloneClone.clone]
  | some value =>
      simp [AuthsNativeRecipe.core.option.Option.Insts.CoreCloneClone.clone, elements value rfl]

/-- Both actual native map iterators share only this read-only suffix contract.
It preserves the supplied sequence; it does not sort a JSON object's keys. -/
@[step] theorem next_pair_exact {K V : Type}
    (iterator : AuthsNativeRecipe.alloc.collections.btree.map.Iter K V) :
    AuthsNativeRecipe.NativeModel.nextPair iterator ⦃ actual =>
      match iterator.val with
      | [] => actual.1 = none ∧ actual.2.val = []
      | pair :: rest => actual.1 = some pair ∧ actual.2.val = rest ⦄ := by
  cases iterator with
  | mk size entries bound =>
    cases entries with
    | nil => simp [AuthsNativeRecipe.NativeModel.nextPair,
        AuthsNativeRecipe.alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList]
    | cons first rest => simp [AuthsNativeRecipe.NativeModel.nextPair,
        AuthsNativeRecipe.alloc.vec.Vec.val, auths_composition.alloc.vec.Vec.val,
        auths_composition.alloc.vec.SizedList.toList]

end Auths.Product.NativeCompiler.StdModel
