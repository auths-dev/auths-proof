import Auths.Product.OperationIdentity
import Auths.Product.Refinement.Gateway
import Auths.Verifier.StatusLeaves
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
namespace Auths.Product.OperationIdentity.Refinement
open Auths.Product.Refinement.Gateway
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096
local instance (byte : Nat) : Decidable (Alphanumeric byte) := inferInstanceAs (Decidable (_ ∨ _))
local instance (byte : Nat) : Decidable (TailByte byte) := inferInstanceAs (Decidable (_ ∨ _))

@[step] theorem logical_preimage_exact (namespaceBytes operation : Slice Std.U8)
    (namespaceBound : namespaceBytes.val.length ≤ 64) (operationBound : operation.val.length ≤ 128) :
    identity.logical_operation_preimage namespaceBytes operation ⦃ output =>
      vecBytes output = OperationIdentity.preimage ⟨sliceBytes namespaceBytes, sliceBytes operation⟩ ⦄ := by
  unfold identity.logical_operation_preimage
  simp only [lift, bind_tc_ok]
  apply spec_bind (copy_bytes_spec _ (by decide))
  intro prefixValue prefixEq
  apply spec_bind (append_bytes_spec _ _ (by simp only [prefixEq]; change 34 + namespaceBytes.val.length < 4294967295; omega))
  intro withNamespace namespaceEq
  have pushBound : withNamespace.val.length < Usize.max := by
    apply lt_usize_max
    simp only [namespaceEq, List.length_append, prefixEq]
    change 34 + namespaceBytes.val.length < 4294967295
    omega
  apply spec_bind (alloc.vec.Vec.push_spec _ _ pushBound)
  intro separated separatorEq
  apply spec_mono (append_bytes_spec _ _ (by
    simp only [separatorEq, List.length_append, List.length_singleton, namespaceEq, prefixEq]
    change 34 + namespaceBytes.val.length + 1 + operation.val.length < 4294967295
    omega))
  intro output outputEq
  simp only [vecBytes, byteList, OperationIdentity.preimage, OperationIdentity.domain,
    outputEq, separatorEq, namespaceEq, prefixEq, List.map_append, List.map_cons,
    List.map_nil, UScalar.ofNatCore_val_eq, List.append_assoc, sliceBytes]
  rfl

private def byteAt (position byte : Nat) : Prop :=
  if position = 0 then Alphanumeric byte else TailByte byte
local instance (position byte : Nat) : Decidable (byteAt position byte) := by
  unfold byteAt
  infer_instance

private def scan : Nat → List Nat → Bool
  | _, [] => true
  | position, byte :: rest => decide (byteAt position byte) && scan (position + 1) rest

private theorem scan_tail (position : Nat) (positive : 0 < position) (bytes : List Nat) :
    scan position bytes = bytes.all (fun byte => decide (TailByte byte)) := by
  induction bytes generalizing position with
  | nil => rfl
  | cons byte rest ih => simp [scan, byteAt, Nat.ne_of_gt positive, ih (position + 1) (by omega)]

private theorem classify_exact (position : Std.Usize) (byte : Std.U8) :
    (do
      let b ← construct.is_alphanumeric byte
      if b then ok true else if position > 0#usize then
        if byte = 46#u8 then ok true else if byte = 95#u8 then ok true else ok (byte = 45#u8)
      else ok false) = ok (decide (byteAt position.val byte.val)) := by
  rw [show construct.is_alphanumeric byte = ok (Auths.Product.RequestConstruction.alphanumeric byte.val) from
    (spec_imp_exists (is_alphanumeric_spec byte)).choose_spec.1.trans
      (congrArg ok (spec_imp_exists (is_alphanumeric_spec byte)).choose_spec.2)]
  simp only [bind_tc_ok]
  unfold byteAt TailByte Auths.Product.RequestConstruction.alphanumeric
  simp only [UScalar.lt_equiv, UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
  split_ifs <;> simp_all [Alphanumeric]
  all_goals try omega

private theorem stopped (value : Slice Std.U8) (position : Std.Usize) :
    identity.valid_token_loop value position false = ok false := by
  unfold identity.valid_token_loop
  rw [loop.eq_def]
  unfold identity.valid_token_loop.body
  by_cases guard : position < value.len <;> simp [guard]

private theorem loop_suffix (remaining : List Std.U8) (value : Slice Std.U8) (position : Std.Usize)
    (suffix : value.val.drop position.val = remaining) :
    identity.valid_token_loop value position true ⦃ actual => actual = scan position.val (byteList remaining) ⦄ := by
  induction remaining generalizing position with
  | nil =>
    have finished : ¬position < value.len := by
      have size := congrArg List.length suffix
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    unfold identity.valid_token_loop
    rw [loop.eq_def]
    simp [identity.valid_token_loop.body, finished, scan, byteList]
  | cons head rest ih =>
    obtain ⟨guard, indexed⟩ := Auths.StatusSelection.indexed_head value position head rest suffix
    obtain ⟨next, addition, nextValue, nextSuffix⟩ := Auths.StatusSelection.indexed_next value position head rest suffix
    unfold identity.valid_token_loop
    rw [loop.eq_def]
    simp only [identity.valid_token_loop.body, guard, ↓reduceIte, indexed, bind_tc_ok,
      addition]
    have classification := classify_exact position head
    obtain ⟨alpha, alphaEval, alphaMeaning⟩ := spec_imp_exists (is_alphanumeric_spec head)
    simp only [alphaEval, bind_tc_ok] at classification ⊢
    rw [classification]
    simp only [bind_tc_ok]
    change (do
      let valid := decide (byteAt position.val head.val)
      identity.valid_token_loop value next valid) ⦃ actual => actual = scan position.val (byteList (head :: rest)) ⦄
    by_cases valid : byteAt position.val head.val
    · simp only [valid, decide_true]
      simpa only [scan, byteList, List.map_cons, valid, decide_true, Bool.true_and, nextValue] using ih next nextSuffix
    · simp [valid, stopped, scan, byteList]

/-- The actual bounded ASCII parser agrees with the independent token grammar
    on every source carrier, including empty and oversized refusals. -/
@[step] theorem token_exact (value : Slice Std.U8) (maximum : Std.Usize) :
    identity.valid_token value maximum ⦃ actual =>
      actual = OperationIdentity.validToken (sliceBytes value) maximum.val ⦄ := by
  unfold identity.valid_token
  simp only [core.slice.Slice.is_empty, bind_tc_ok, decide_eq_true_eq, Slice.len_val,
    Slice.length, UScalar.lt_equiv]
  by_cases empty : value.val.length = 0
  · have values : value.val = [] := List.length_eq_zero_iff.mp empty
    simp [values, OperationIdentity.validToken, sliceBytes, byteList]
  · simp only [empty, ↓reduceIte]
    by_cases oversized : maximum.val < value.val.length
    · have refused : OperationIdentity.validToken (sliceBytes value) maximum.val = false := by
        cases values : value.val with
        | nil => simp [sliceBytes, byteList, values, OperationIdentity.validToken]
        | cons first rest =>
          have bound : ¬rest.length < maximum.val := by rw [values] at oversized; simp only [List.length_cons] at oversized; omega
          simp [sliceBytes, byteList, values, OperationIdentity.validToken, bound]
      simp [oversized, refused]
    · simp only [oversized, ↓reduceIte]
      apply spec_mono (loop_suffix value.val value 0#usize (by simp))
      intro result resultEq
      rw [resultEq]
      cases values : value.val with
      | nil => simp [values] at empty
      | cons first rest =>
        have bound : rest.length < maximum.val := by rw [values] at oversized; simp only [List.length_cons] at oversized; omega
        simp [sliceBytes, byteList, values, OperationIdentity.validToken, scan, byteAt,
          scan_tail, bound]
        rfl

/-- Successful native namespace checks earn separator safety. Equal actual
    preimage bytes then bind both input fields without any hash assumption. -/
theorem source_preimage_binds_identity
    (leftNamespace leftOperation rightNamespace rightOperation : Slice Std.U8)
    (leftNamespaceBound : leftNamespace.val.length ≤ 64)
    (rightNamespaceBound : rightNamespace.val.length ≤ 64)
    (leftOperationBound : leftOperation.val.length ≤ 128)
    (rightOperationBound : rightOperation.val.length ≤ 128)
    (leftChecked : identity.valid_token leftNamespace 64#usize = ok true)
    (rightChecked : identity.valid_token rightNamespace 64#usize = ok true)
    (leftOutput rightOutput : alloc.vec.Vec Std.U8)
    (leftProduced : identity.logical_operation_preimage leftNamespace leftOperation = ok leftOutput)
    (rightProduced : identity.logical_operation_preimage rightNamespace rightOperation = ok rightOutput)
    (same : leftOutput.val = rightOutput.val) :
    leftNamespace.val = rightNamespace.val ∧ leftOperation.val = rightOperation.val := by
  have leftGrammar := token_exact leftNamespace 64#usize
  have rightGrammar := token_exact rightNamespace 64#usize
  rw [leftChecked, spec_ok] at leftGrammar
  rw [rightChecked, spec_ok] at rightGrammar
  have leftFraming := logical_preimage_exact leftNamespace leftOperation leftNamespaceBound leftOperationBound
  have rightFraming := logical_preimage_exact rightNamespace rightOperation rightNamespaceBound rightOperationBound
  rw [leftProduced, spec_ok] at leftFraming
  rw [rightProduced, spec_ok] at rightFraming
  have framed : OperationIdentity.preimage ⟨sliceBytes leftNamespace, sliceBytes leftOperation⟩ =
      OperationIdentity.preimage ⟨sliceBytes rightNamespace, sliceBytes rightOperation⟩ := by
    rw [← leftFraming, ← rightFraming]
    exact congrArg byteList same
  have bound := valid_tokens_bind_identity _ _ leftGrammar.symm rightGrammar.symm framed
  constructor
  · exact byteList_inj.mp (congrArg Identity.namespaceBytes bound)
  · exact byteList_inj.mp (congrArg Identity.operation bound)

end Auths.Product.OperationIdentity.Refinement
