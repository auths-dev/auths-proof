import qualification.aeneas.generated.codec.Funs
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
set_option cbv.warning false
/-!
Kernel-proved evaluation rules for the qualified codec closure. These rules
preserve the original result for every input. The conservative word-size branch
works on both supported machine widths; all other inputs retain the original
checked operation. They introduce no native-evaluation or platform-width axiom.
-/
namespace Auths.Codec.Evaluation
attribute [cbv_eval] U8.max_eq U16.max_eq U32.max_eq U64.max_eq U128.max_eq

/-- A proved portable fast path; the remaining inputs retain the exact original definition. -/
@[cbv_eval] theorem try_mk (value : Nat) :
    UScalar.tryMk .Usize value =
      if bounded : value ≤ UScalar.cMax .Usize then
        ok (UScalar.ofNat value bounded : Std.Usize)
      else Result.ofOption (UScalar.tryMkOpt .Usize value) .integerOverflow := by
  by_cases bounded : value ≤ UScalar.cMax .Usize
  · have within := UScalar.bound_suffices .Usize value bounded
    change value < 2 ^ System.Platform.numBits at within
    simp [bounded, UScalar.tryMk, UScalar.tryMkOpt, UScalar.check_bounds,
      within, UScalar.ofNat]
  · simp [bounded, UScalar.tryMk]

@[cbv_eval] theorem cast {source : UScalarTy} (target : UScalarTy) (value : UScalar source) :
    UScalar.cast target value =
      if bounded : value.val ≤ UScalar.cMax target then
        (UScalar.ofNat value.val bounded : UScalar target)
      else ⟨value.bv.zeroExtend target.numBits⟩ := by
  by_cases bounded : value.val ≤ UScalar.cMax target
  · simp only [bounded, ↓reduceDIte]
    apply UScalar.eq_of_val_eq
    have within := UScalar.bound_suffices target value.val bounded
    simp only [UScalar.ofNat, UScalar.ofNatCore_val_eq]
    simp only [UScalar.cast, UScalar.val, BitVec.zeroExtend, BitVec.toNat_setWidth]
    exact Nat.mod_eq_of_lt within
  · simp [bounded, UScalar.cast]

@[cbv_eval] theorem try_from {source : UScalarTy} (target : UScalarTy) (value : UScalar source) :
    core.num.tryFromUScalar target value =
      if bounded : value.val ≤ UScalar.cMax target then
        ok (.Ok (UScalar.ofNat value.val bounded : UScalar target))
      else if value.val ≤ UScalar.max target then
        ok (.Ok (UScalar.cast target value))
      else ok (.Err ()) := by
  by_cases bounded : value.val ≤ UScalar.cMax target
  · have within : value.val ≤ UScalar.max target := by
      have bound := UScalar.bound_suffices target value.val bounded
      simp only [UScalar.max] at *
      omega
    simp [bounded, core.num.tryFromUScalar, within, cast]
  · simp [bounded, core.num.tryFromUScalar]

@[cbv_eval] theorem subtract (left right : Std.Usize) :
    UScalar.sub left right =
      if _ordered : right.val ≤ left.val then
        if bounded : left.val - right.val ≤ UScalar.cMax .Usize then
          ok (UScalar.ofNat (left.val - right.val) bounded : Std.Usize)
        else ok ⟨BitVec.ofNat _ (left.val - right.val)⟩
      else fail .integerOverflow := by
  by_cases ordered : right.val ≤ left.val
  · by_cases bounded : left.val - right.val ≤ UScalar.cMax .Usize
    · simp only [ordered, bounded, ↓reduceDIte]
      have contract := UScalar.sub_spec ordered
      rw [spec_equiv_exists] at contract
      obtain ⟨result, evaluates, meaning, _⟩ := contract
      change UScalar.sub left right = ok result at evaluates
      rw [evaluates]
      congr 1
      apply UScalar.eq_of_val_eq
      simpa only [UScalar.ofNat, UScalar.ofNatCore_val_eq] using meaning
    · simp [ordered, bounded, UScalar.sub, Nat.not_lt_of_ge ordered]
  · have reversed : left.val < right.val := Nat.lt_of_not_ge ordered
    simp [ordered, UScalar.sub, reversed]

@[cbv_eval] theorem append_bytes (output : alloc.vec.Vec Std.U8) (input : Slice Std.U8) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 output input =
      if small : output.val.length + input.val.length ≤ UScalar.cMax .Usize then
        ok ⟨output.val ++ input.val, by
          simp only [List.length_append]
          have := UScalar.bound_suffices .Usize _ small
          scalar_tac⟩
      else if within : output.val.length + input.val.length ≤ Usize.max then
        ok ⟨output.val ++ input.val, by simpa only [List.length_append] using within⟩
      else fail .panic := by
  have cloned : Slice.clone core.clone.CloneU8.clone input = ok input := by
    have contract := Slice.clone_spec (s := input) (clone := core.clone.CloneU8.clone)
      (by intro value _; rfl)
    obtain ⟨result, evaluates, meaning⟩ := spec_imp_exists contract
    simpa only [← meaning] using evaluates
  change Slice.clone (liftFun1 core.clone.impls.CloneU8.clone) input = ok input at cloned
  unfold alloc.vec.Vec.extend_from_slice
  split
  · rename_i within
    split
    · rename_i copied evaluated
      have same : copied = input := by
        have equality := evaluated.symm.trans cloned
        exact Result.ok.inj equality
      subst copied
      by_cases small : output.val.length + input.val.length ≤ UScalar.cMax .Usize
      · simp [small]
      · simp [small]
    · rename_i failure evaluated
      have impossible := evaluated.symm.trans cloned
      cases impossible
    · rename_i evaluated
      have impossible := evaluated.symm.trans cloned
      cases impossible
  · rename_i outside
    have notSmall : ¬ output.val.length + input.val.length ≤ UScalar.cMax .Usize := by
      intro small
      have := UScalar.bound_suffices .Usize _ small
      apply outside
      scalar_tac
    simp [notSmall]

@[cbv_eval] theorem push {α : Type} (output : alloc.vec.Vec α) (value : α) :
    alloc.vec.Vec.push output value =
      if small : output.val.length + 1 ≤ UScalar.cMax .Usize then
        ok ⟨output.val ++ [value], by
          simp only [List.length_append, List.length_singleton]
          have := UScalar.bound_suffices .Usize _ small
          scalar_tac⟩
      else
        if within : output.val.length + 1 ≤ U32.max || output.val.length + 1 ≤ Usize.max then
          ok ⟨output.val.concat value, by simp; scalar_tac⟩
        else fail .maximumSizeExceeded := by
  by_cases small : output.val.length + 1 ≤ UScalar.cMax .Usize
  · have within : output.val.length + 1 ≤ U32.max := by
      simpa only [UScalar.cMax, UScalar.rMax, U32.rMax, U32.max_eq] using small
    simp [small, alloc.vec.Vec.push, within]
  · simp only [small, ↓reduceDIte]
    unfold alloc.vec.Vec.push
    rfl

@[cbv_eval] theorem hard_bundle_bytes : auths_codec.auths_model.HARD_MAX_BUNDLE_BYTES = ok (8388608#usize) := by
  have contract : auths_codec.auths_model.HARD_MAX_BUNDLE_BYTES ⦃ value => value = 8388608#usize ⦄ := by
    unfold auths_codec.auths_model.HARD_MAX_BUNDLE_BYTES
    step as ⟨first, firstEq⟩
    step as ⟨second, secondEq⟩
    scalar_tac
  rw [spec_equiv_exists] at contract
  obtain ⟨value, evaluates, exactValue⟩ := contract
  simpa only [exactValue] using evaluates

@[cbv_eval] theorem hard_action_bytes : auths_codec.auths_model.HARD_MAX_ACTION_BYTES = ok (16777216#usize) := by
  have contract : auths_codec.auths_model.HARD_MAX_ACTION_BYTES ⦃ value => value = 16777216#usize ⦄ := by
    unfold auths_codec.auths_model.HARD_MAX_ACTION_BYTES
    step as ⟨first, firstEq⟩
    step as ⟨second, secondEq⟩
    scalar_tac
  rw [spec_equiv_exists] at contract
  obtain ⟨value, evaluates, exactValue⟩ := contract
  simpa only [exactValue] using evaluates

@[cbv_eval] theorem hard_context_bytes : auths_codec.auths_model.HARD_MAX_CONTEXT_BYTES = ok (16777216#usize) := by
  have contract : auths_codec.auths_model.HARD_MAX_CONTEXT_BYTES ⦃ value => value = 16777216#usize ⦄ := by
    unfold auths_codec.auths_model.HARD_MAX_CONTEXT_BYTES
    step as ⟨first, firstEq⟩
    step as ⟨second, secondEq⟩
    scalar_tac
  rw [spec_equiv_exists] at contract
  obtain ⟨value, evaluates, exactValue⟩ := contract
  simpa only [exactValue] using evaluates

@[cbv_eval] theorem hard_evidence_bytes : auths_codec.auths_model.HARD_MAX_EVIDENCE_BYTES = ok (2097152#usize) := by
  have contract : auths_codec.auths_model.HARD_MAX_EVIDENCE_BYTES ⦃ value => value = 2097152#usize ⦄ := by
    unfold auths_codec.auths_model.HARD_MAX_EVIDENCE_BYTES
    step as ⟨first, firstEq⟩
    step as ⟨second, secondEq⟩
    scalar_tac
  rw [spec_equiv_exists] at contract
  obtain ⟨value, evaluates, exactValue⟩ := contract
  simpa only [exactValue] using evaluates

@[cbv_eval] theorem hard_attachment_bytes : auths_codec.auths_model.HARD_MAX_ATTACHMENT_BYTES = ok (8388608#usize) := by
  have contract : auths_codec.auths_model.HARD_MAX_ATTACHMENT_BYTES ⦃ value => value = 8388608#usize ⦄ := by
    unfold auths_codec.auths_model.HARD_MAX_ATTACHMENT_BYTES
    step as ⟨first, firstEq⟩
    step as ⟨second, secondEq⟩
    scalar_tac
  rw [spec_equiv_exists] at contract
  obtain ⟨value, evaluates, exactValue⟩ := contract
  simpa only [exactValue] using evaluates

@[cbv_eval] theorem hard_canonical_body_bytes : auths_codec.auths_model.HARD_MAX_CANONICAL_BODY_BYTES = ok (8388608#usize) := by
  have contract : auths_codec.auths_model.HARD_MAX_CANONICAL_BODY_BYTES ⦃ value => value = 8388608#usize ⦄ := by
    unfold auths_codec.auths_model.HARD_MAX_CANONICAL_BODY_BYTES
    step as ⟨first, firstEq⟩
    step as ⟨second, secondEq⟩
    scalar_tac
  rw [spec_equiv_exists] at contract
  obtain ⟨value, evaluates, exactValue⟩ := contract
  simpa only [exactValue] using evaluates

end Auths.Codec.Evaluation
