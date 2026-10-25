import Auths.Product.NativeCompilerAstKeys
import Auths.Product.TemplateMemberDomains

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeMemberDomain := AuthsNativeRecipe.auths_gateway_kernel.template_members.MemberDomain
abbrev NativeChoice := AuthsNativeRecipe.auths_gateway_kernel.template_members.MemberChoice
abbrev NativeTarget := AuthsNativeRecipe.auths_gateway_kernel.template_members.EchoTarget

def nativeKeyColumn (keys : Slice NativeKey) : List (List Nat) := keys.val.map (fun key => bytes key.name)
def nativeMemberDomain : NativeMemberDomain → TemplateMembers.Domain | .Json => .json | .Form => .form
def nativeChoice : NativeChoice → TemplateMembers.Choice | .Source index => .source index.val | .Echo => .echo
def nativeTarget : NativeTarget → TemplateMembers.Target | .Insert => .insert | .Descend index => .descend index.val

@[simp] theorem native_key_column_deref (keys : NativeVec NativeKey) :
    nativeKeyColumn (AuthsNativeRecipe.alloc.vec.Vec.deref keys) = nativeKeys keys := rfl

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateMembers
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_byte_less_suffix (left right : Slice Std.U8) (position : Std.Usize)
    (leftBound : position.val ≤ left.val.length) (rightBound : position.val ≤ right.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.byte_less_loop left right position ⦃ actual =>
      actual = byteLess ((schemaSliceBytes left).drop position.val) ((schemaSliceBytes right).drop position.val) ⦄ := by
  generalize remaining : min left.val.length right.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.byte_less_loop
      by_cases insideLeft : position.val < left.val.length
      · have nativeLeft : position < left.len := by scalar_tac
        simp only [nativeLeft, ↓reduceIte]
        by_cases insideRight : position.val < right.val.length
        · have nativeRight : position < right.len := by scalar_tac
          simp only [nativeRight, ↓reduceIte]
          step with Slice.index_usize_spec left position insideLeft as ⟨first, firstAt⟩
          step with Slice.index_usize_spec right position insideRight as ⟨second, secondAt⟩
          have leftSuffix : (schemaSliceBytes left).drop position.val =
              first.val :: (schemaSliceBytes left).drop (position.val + 1) := by
            simpa only [schemaSliceBytes, List.drop_map, List.map_cons, firstAt] using
              congrArg (List.map (fun byte : Std.U8 => byte.val)) (List.drop_eq_getElem_cons insideLeft)
          have rightSuffix : (schemaSliceBytes right).drop position.val =
              second.val :: (schemaSliceBytes right).drop (position.val + 1) := by
            simpa only [schemaSliceBytes, List.drop_map, List.map_cons, secondAt] using
              congrArg (List.map (fun byte : Std.U8 => byte.val)) (List.drop_eq_getElem_cons insideRight)
          by_cases smaller : first.val < second.val
          · have nativeSmaller : first < second := by scalar_tac
            simp [nativeSmaller, leftSuffix, rightSuffix, byteLess, smaller]
          · have nativeSmaller : ¬first < second := by scalar_tac
            simp only [nativeSmaller, ↓reduceIte]
            by_cases larger : second.val < first.val
            · have nativeLarger : first > second := by scalar_tac
              simp [nativeLarger, leftSuffix, rightSuffix, byteLess, smaller, larger]
            · have nativeLarger : ¬first > second := by scalar_tac
              have same : first.val = second.val := by omega
              simp only [nativeLarger, ↓reduceIte]
              step as ⟨next, nextValue⟩
              apply spec_mono (ih _ (by omega) next (by omega) (by omega) rfl)
              intro actual exact
              simpa [leftSuffix, rightSuffix, byteLess, smaller, larger, same, nextValue] using exact
        · have endRight : position.val = right.val.length := by omega
          have nativeRight : ¬position < right.len := by scalar_tac
          have nativeNotLess : ¬left.len < right.len := by scalar_tac
          have rightEmpty : (schemaSliceBytes right).drop position.val = [] := by
            simp [schemaSliceBytes, List.drop_map, endRight]
          cases suffixLeft : (schemaSliceBytes left).drop position.val <;>
            simp [nativeRight, nativeNotLess, rightEmpty, suffixLeft, byteLess]
      · have endLeft : position.val = left.val.length := by omega
        have nativeLeft : ¬position < left.len := by scalar_tac
        have leftEmpty : (schemaSliceBytes left).drop position.val = [] := by
          simp [schemaSliceBytes, List.drop_map, endLeft]
        by_cases equalLength : left.val.length = right.val.length
        · have nativeNotLess : ¬left.len < right.len := by scalar_tac
          have rightEmpty : (schemaSliceBytes right).drop position.val = [] := by
            simp [schemaSliceBytes, List.drop_map, endLeft, equalLength]
          simp [nativeLeft, nativeNotLess, leftEmpty, rightEmpty, byteLess]
        · have longerRight : left.val.length < right.val.length := by omega
          have nativeLess : left.len < right.len := by scalar_tac
          have nonemptyRight : (schemaSliceBytes right).drop position.val ≠ [] := by
            intro empty
            have length := congrArg List.length empty
            simp only [List.length_drop, schemaSliceBytes, List.length_map, List.length_nil] at length
            omega
          cases rest : (schemaSliceBytes right).drop position.val with
          | nil => exact False.elim (nonemptyRight rest)
          | cons byte tail => simp [nativeLeft, nativeLess, leftEmpty, rest, byteLess]

@[step] theorem native_byte_less_exact (left right : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.byte_less left right ⦃ actual =>
      actual = byteLess (schemaSliceBytes left) (schemaSliceBytes right) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.byte_less
  apply spec_mono (native_byte_less_suffix left right 0#usize (by simp) (by simp))
  intro actual exact
  simpa only [List.drop_zero] using exact

private theorem native_key_position_suffix (keys : Slice NativeKey) (name : Slice Std.U8)
    (position : Std.Usize) (positionBound : position.val ≤ keys.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.key_position_loop keys name position ⦃ actual =>
      actual.map UScalar.val = (keyPosition (schemaSliceBytes name)
        ((nativeKeyColumn keys).drop position.val)).map (position.val + ·) ⦄ := by
  generalize remaining : keys.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.key_position_loop
      by_cases inside : position.val < keys.val.length
      · have nativeInside : position < keys.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        step with Slice.index_usize_spec keys position inside as ⟨key, keyAt⟩
        have suffix : (nativeKeyColumn keys).drop position.val = bytes key.name ::
            (nativeKeyColumn keys).drop (position.val + 1) := by
          simpa only [nativeKeyColumn, List.drop_map, List.map_cons, keyAt] using
            congrArg (List.map (fun key : NativeKey => bytes key.name)) (List.drop_eq_getElem_cons inside)
        step with native_schema_byte_equality (AuthsNativeRecipe.alloc.vec.Vec.deref key.name) name
          as ⟨same, sameMeaning⟩
        have nameMeaning : same = decide (bytes key.name = schemaSliceBytes name) := by
          simpa only [schemaSliceBytes, bytes, native_deref_contents] using sameMeaning
        cases same with
        | true => simp [suffix, keyPosition, ← nameMeaning]
        | false =>
            simp only [Bool.false_eq_true, ↓reduceIte]
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) next (by omega) rfl)
            intro actual exact
            simpa [suffix, keyPosition, ← nameMeaning, nextValue, Option.map_map,
              Function.comp_def, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using exact
      · have ended : keys.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < keys.len := by scalar_tac
        have modelEnded : (nativeKeyColumn keys).length ≤ position.val := by
          simpa only [nativeKeyColumn, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, keyPosition]

@[step] theorem native_key_position_exact (keys : Slice NativeKey) (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.key_position keys name ⦃ actual =>
      actual.map UScalar.val = keyPosition (schemaSliceBytes name) (nativeKeyColumn keys) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.key_position
  apply spec_mono (native_key_position_suffix keys name 0#usize (by simp))
  intro actual exact
  simpa only [List.drop_zero, Nat.zero_add, Option.map_id] using exact

@[step] theorem native_key_in_order_exact (keys : Slice NativeKey) (position : Std.Usize)
    (inside : position.val < keys.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.key_in_order keys position ⦃ actual =>
      actual = decide (KeyHead (nativeKeyColumn keys) position.val) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.key_in_order
  step with Slice.index_usize_spec keys position inside as ⟨key, keyAt⟩
  have atKey : (nativeKeyColumn keys)[position.val]? = some (bytes key.name) := by
    simp only [nativeKeyColumn, List.getElem?_map, List.getElem?_eq_getElem inside,
      Option.map_some, keyAt]
  step with native_schema_token_exact (AuthsNativeRecipe.alloc.vec.Vec.deref key.name) 64#usize
    as ⟨lexical, lexicalMeaning⟩
  have tokenMeaning : lexical = OperationIdentity.validToken (bytes key.name) 64 := by
    simpa only [schemaSliceBytes, bytes, native_deref_contents] using lexicalMeaning
  cases lexical with
  | false => simp [KeyHead, atKey, ← tokenMeaning]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      by_cases first : position.val = 0
      · have nativeFirst : position = 0#usize := by scalar_tac
        simp [nativeFirst, KeyHead, atKey, previousAt, first, ← tokenMeaning]
      · have nativeFirst : position ≠ 0#usize := by scalar_tac
        simp only [nativeFirst, ↓reduceIte]
        step as ⟨previousPosition, previousPositionMeaning⟩
        have previousInside : previousPosition.val < keys.val.length := by omega
        step with Slice.index_usize_spec keys previousPosition previousInside as ⟨previous, previousAt⟩
        have previousMeaning : TemplateMembers.previousAt (nativeKeyColumn keys) position.val =
            some (bytes previous.name) := by
          simp [TemplateMembers.previousAt, first, nativeKeyColumn, List.getElem?_map,
            List.getElem?_eq_getElem previousInside, previousAt, previousPositionMeaning]
        step with native_byte_less_exact (AuthsNativeRecipe.alloc.vec.Vec.deref previous.name)
          (AuthsNativeRecipe.alloc.vec.Vec.deref key.name) as ⟨ordered, orderedMeaning⟩
        have comparison : ordered = decide (bytes previous.name < bytes key.name) := by
          have boolMeaning : byteLess (bytes previous.name) (bytes key.name) =
              decide (bytes previous.name < bytes key.name) := Bool.eq_iff_iff.mpr (by simp [byte_less_iff])
          simpa only [schemaSliceBytes, bytes, native_deref_contents, boolMeaning] using orderedMeaning
        simpa [KeyHead, atKey, previousMeaning, ← tokenMeaning] using comparison

private theorem native_keys_order_suffix (keys : Slice NativeKey) (position : Std.Usize) (ordered : Bool)
    (positionBound : position.val ≤ keys.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.keys_ordered_loop keys position ordered ⦃ actual =>
      actual = (ordered && decide (KeyTail (previousAt (nativeKeyColumn keys) position.val)
        ((nativeKeyColumn keys).drop position.val))) ⦄ := by
  generalize remaining : keys.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position ordered with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.keys_ordered_loop
      by_cases inside : position.val < keys.val.length
      · have nativeInside : position < keys.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases ordered with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with native_key_in_order_exact keys position inside as ⟨head, headMeaning⟩
            step as ⟨next, nextValue⟩
            apply spec_mono (ih _ (by omega) next head (by omega) rfl)
            intro actual exact
            have modelInside : position.val < (nativeKeyColumn keys).length := by
              simpa only [nativeKeyColumn, List.length_map] using inside
            simpa only [Bool.true_and, key_tail_step _ _ modelInside, decide_and,
              ← headMeaning, nextValue] using exact
      · have ended : keys.val.length ≤ position.val := by omega
        have nativeEnded : ¬position < keys.len := by scalar_tac
        have modelEnded : (nativeKeyColumn keys).length ≤ position.val := by
          simpa only [nativeKeyColumn, List.length_map] using ended
        simp [nativeEnded, List.drop_eq_nil_of_le modelEnded, KeyTail]

@[step] theorem native_keys_ordered_exact (keys : Slice NativeKey) (domain : NativeMemberDomain) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.keys_ordered keys domain ⦃ actual =>
      actual = decide (KeyColumn (nativeKeyColumn keys) (nativeMemberDomain domain)) ⦄ := by
  cases domain with
  | Json =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.keys_ordered
      simp only [bind_tc_ok]
      by_cases empty : keys.val = []
      · simp [core.slice.Slice.is_empty, empty, nativeKeyColumn, KeyColumn, nativeMemberDomain]
      · have positive : 0 < keys.val.length := List.length_pos.mpr empty
        simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
          Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
        by_cases large : 32 < keys.val.length
        · have nativeLarge : keys.len > 32#usize := by scalar_tac
          simp [nativeLarge, KeyColumn, nativeKeyColumn, nativeMemberDomain, maximum, Nat.not_le.mpr large]
        · have bounded : keys.val.length ≤ 32 := by omega
          have nativeBound : ¬keys.len > 32#usize := by scalar_tac
          simp only [nativeBound, ↓reduceIte]
          apply spec_mono (native_keys_order_suffix keys 0#usize true (by simp))
          intro actual exact
          simpa [key_column_iff, nativeMemberDomain, nativeKeyColumn, positive, bounded,
            maximum, previousAt] using exact
  | Form =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.keys_ordered
      simp only [bind_tc_ok]
      by_cases empty : keys.val = []
      · simp [core.slice.Slice.is_empty, empty, nativeKeyColumn, KeyColumn, nativeMemberDomain]
      · have positive : 0 < keys.val.length := List.length_pos.mpr empty
        simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
          Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
        by_cases large : 16 < keys.val.length
        · have nativeLarge : keys.len > 16#usize := by scalar_tac
          simp [nativeLarge, KeyColumn, nativeKeyColumn, nativeMemberDomain, maximum, Nat.not_le.mpr large]
        · have bounded : keys.val.length ≤ 16 := by omega
          have nativeBound : ¬keys.len > 16#usize := by scalar_tac
          simp only [nativeBound, ↓reduceIte]
          apply spec_mono (native_keys_order_suffix keys 0#usize true (by simp))
          intro actual exact
          simpa [key_column_iff, nativeMemberDomain, nativeKeyColumn, positive, bounded,
            maximum, previousAt] using exact

end Auths.Product.NativeCompiler.Refinement
