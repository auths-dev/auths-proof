import Auths.Product.TemplateMembers
import Auths.Product.FieldProjectionNames

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity

namespace Auths.Product.TemplateMembers.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def keysView (keys : Slice template_members.NamedKey) : List Bytes := keys.val.map (fun key => sliceBytes key.name)
def domainOf : template_members.MemberDomain → Domain | .Json => .json | .Form => .form
def choiceOf : template_members.MemberChoice → Choice | .Source index => .source index.val | .Echo => .echo
def targetOf : template_members.EchoTarget → Target | .Insert => .insert | .Descend index => .descend index.val
def memberErrorOf : template_members.MemberError → Error | .Members => .members | .EchoConflict => .echoConflict

private theorem less_drop_prefix (left right : Bytes) (index : Nat)
    (leftBound : index ≤ left.length) (rightBound : index ≤ right.length)
    (same : left.take index = right.take index) :
    byteLess left right = byteLess (left.drop index) (right.drop index) := by
  induction index generalizing left right with
  | zero => simp
  | succ index ih =>
    cases left with
    | nil => simp at leftBound
    | cons first rest =>
      cases right with
      | nil => simp at rightBound
      | cons other tail =>
        have heads : first = other := by simpa using congrArg (List.head?) same
        have tails : rest.take index = tail.take index := by simpa using congrArg List.tail same
        subst other
        simpa [byteLess] using ih rest tail (by simp at leftBound; omega) (by simp at rightBound; omega) tails

@[step] theorem byte_less_exact (left right : Slice Std.U8) :
    template_members.byte_less left right ⦃ actual =>
      actual = decide (sliceBytes left < sliceBytes right) ⦄ := by
  unfold template_members.byte_less template_members.byte_less_loop
  apply loop.spec_decr_nat
    (measure := fun index => min left.val.length right.val.length - index.val)
    (inv := fun index => index.val ≤ left.val.length ∧ index.val ≤ right.val.length ∧
      left.val.take index.val = right.val.take index.val)
  · intro index invariant
    unfold template_members.byte_less_loop.body
    dsimp only
    split <;> rename_i guard
    · have insideLeft : index.val < left.val.length := by scalar_tac
      have insideRight : index.val < right.val.length := by scalar_tac
      step as ⟨first, firstAt⟩
      step as ⟨other, otherAt⟩
      have suffixLeft : (sliceBytes left).drop index.val = first.val :: (sliceBytes left).drop (index.val + 1) := by
        simpa [sliceBytes, byteList, firstAt, List.drop_map] using congrArg byteList (List.drop_eq_getElem_cons insideLeft)
      have suffixRight : (sliceBytes right).drop index.val = other.val :: (sliceBytes right).drop (index.val + 1) := by
        simpa [sliceBytes, byteList, otherAt, List.drop_map] using congrArg byteList (List.drop_eq_getElem_cons insideRight)
      have prefix : byteLess (sliceBytes left) (sliceBytes right) =
          byteLess ((sliceBytes left).drop index.val) ((sliceBytes right).drop index.val) :=
        less_drop_prefix _ _ index.val (by simpa [sliceBytes, byteList] using invariant.1)
          (by simpa [sliceBytes, byteList] using invariant.2.1)
          (by simpa [sliceBytes, byteList, List.take_map] using congrArg byteList invariant.2.2)
      split <;> rename_i below
      · have strict : first.val < other.val := by scalar_tac
        have meaning : byteLess (sliceBytes left) (sliceBytes right) = true := by
          simp [prefix, suffixLeft, suffixRight, byteLess, strict]
        simp [byte_less_iff.mp meaning]
      · split <;> rename_i above
        · have strict : other.val < first.val := by scalar_tac
          have different : ¬first.val < other.val := by omega
          have meaning : byteLess (sliceBytes left) (sliceBytes right) = false := by
            simp [prefix, suffixLeft, suffixRight, byteLess, strict, different]
          have refused : ¬sliceBytes left < sliceBytes right := by
            intro accepted
            have admitted := byte_less_iff.mpr accepted
            simp [meaning] at admitted
          simp [refused]
        · have equal : first.val = other.val := by scalar_tac
          have nativeEqual : first = other := UScalar.eq_of_val_eq equal
          step as ⟨next, nextValue⟩
          refine ⟨by omega, by omega, ?_, by omega⟩
          rw [nextValue, List.take_succ_eq_append_getElem insideLeft, List.take_succ_eq_append_getElem insideRight]
          simpa [firstAt, otherAt, nativeEqual] using congrArg (fun prefix => prefix ++ [first]) invariant.2.2
    · have terminal : index.val = left.val.length ∨ index.val = right.val.length := by scalar_tac
      have prefix := less_drop_prefix (sliceBytes left) (sliceBytes right) index.val
        (by simpa [sliceBytes, byteList] using invariant.1)
        (by simpa [sliceBytes, byteList] using invariant.2.1)
        (by simpa [sliceBytes, byteList, List.take_map] using congrArg byteList invariant.2.2)
      rcases terminal with leftEnd | rightEnd
      · have leftDrop : (sliceBytes left).drop index.val = [] := by simp [leftEnd, sliceBytes, byteList]
        have semantic : byteLess (sliceBytes left) (sliceBytes right) = decide (left.val.length < right.val.length) := by
          rw [prefix, leftDrop]
          cases suffix : (sliceBytes right).drop index.val with
          | nil =>
            have size := congrArg List.length suffix
            simp only [List.length_drop, sliceBytes, byteList, List.length_map, List.length_nil] at size
            have equal : left.val.length = right.val.length := by omega
            simp [byteLess, equal]
          | cons first rest =>
            have size := congrArg List.length suffix
            simp only [List.length_drop, sliceBytes, byteList, List.length_map, List.length_cons] at size
            have smaller : left.val.length < right.val.length := by omega
            simp [byteLess, smaller]
        have boolEq : byteLess (sliceBytes left) (sliceBytes right) = decide (sliceBytes left < sliceBytes right) := by
          exact Bool.eq_iff_iff.mpr (by simp [byte_less_iff])
        simpa only [spec_ok, UScalar.lt_equiv, Slice.len_val, Slice.length] using semantic.symm.trans boolEq
      · have rightDrop : (sliceBytes right).drop index.val = [] := by simp [rightEnd, sliceBytes, byteList]
        have modelFalse : byteLess (sliceBytes left) (sliceBytes right) = false := by
          rw [prefix, rightDrop]
          cases (sliceBytes left).drop index.val <;> rfl
        have refused : ¬sliceBytes left < sliceBytes right := by
          intro accepted
          have admitted := byte_less_iff.mpr accepted
          simp [modelFalse] at admitted
        have nativeRefused : ¬left.len < right.len := by scalar_tac
        simp [nativeRefused, refused]
  · exact ⟨by simp, by simp, by simp⟩

@[step] theorem key_position_exact (keys : Slice template_members.NamedKey) (name : Slice Std.U8) :
    template_members.key_position keys name ⦃ actual =>
      actual.map UScalar.val = keyPosition (sliceBytes name) (keysView keys) ⦄ := by
  unfold template_members.key_position template_members.key_position_loop
  apply loop.spec_decr_nat
    (measure := fun index => keys.val.length - index.val)
    (inv := fun index => index.val ≤ keys.val.length ∧
      keyPosition (sliceBytes name) (keysView keys) =
        (keyPosition (sliceBytes name) ((keysView keys).drop index.val)).map (· + index.val))
  · intro index invariant
    unfold template_members.key_position_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < keys.val.length := by scalar_tac
      step as ⟨key, keyAt⟩
      have suffix : (keysView keys).drop index.val = sliceBytes key.name :: (keysView keys).drop (index.val + 1) := by
        simpa [keysView, List.drop_map, keyAt] using
          congrArg (List.map (fun key => sliceBytes key.name)) (List.drop_eq_getElem_cons inside)
      rw [suffix, keyPosition] at invariant
      step with field_name_equal_exact as ⟨same, sameMeaning⟩
      cases same
      · have different : sliceBytes key.name ≠ sliceBytes name := by
          intro equal
          have raw := byteList_inj _ _ |>.mp equal
          simp [raw] at sameMeaning
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        simpa [different, nextValue, Option.map_map, Function.comp_def, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using invariant.2
      · have equal : sliceBytes key.name = sliceBytes name := by
          simpa [sliceBytes] using congrArg byteList sameMeaning.symm
        simpa [equal] using invariant.2.symm
    · have endBound : (keysView keys).length ≤ index.val := by simpa [keysView] using (show keys.val.length ≤ index.val by scalar_tac)
      simpa [List.drop_of_length_le endBound, keyPosition] using invariant.2.symm
  · exact ⟨by simp, by simp⟩

theorem source_key_position_preserves_original_name (keys : Slice template_members.NamedKey) (name : Slice Std.U8) :
    template_members.key_position keys name ⦃ actual => ∀ index, actual = some index →
      (keysView keys)[index.val]? = some (sliceBytes name) ⦄ := by
  apply spec_mono (key_position_exact keys name)
  intro actual meaning index found
  rw [found] at meaning
  exact key_position_is_exact _ _ _ meaning.symm

end Auths.Product.TemplateMembers.Refinement
