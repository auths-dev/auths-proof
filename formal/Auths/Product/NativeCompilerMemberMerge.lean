import Auths.Product.NativeCompilerMemberTargets
import Auths.Product.TemplateMemberMerge

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeChoices (choices : NativeVec NativeChoice) : List TemplateMembers.Choice :=
  choices.val.map nativeChoice

/-- Selects the two actual extracted loops. Neither source body is modeled
as an external operation or replaced with an assumed merge result. -/
def nativeMergeLoop (keys : Slice NativeKey) (echo : Option (Slice Std.U8))
    (output : NativeVec NativeChoice) (inserted : Bool) (position : Std.Usize) :=
  match echo with
  | none => AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members_loop0 keys output inserted position
  | some name => AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members_loop1 keys name output inserted position

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateMembers
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_echo_before_exact (keys : Slice NativeKey) (position : Std.Usize)
    (echo : Option (Slice Std.U8)) (inserted : Bool) (inside : position.val < keys.val.length) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_before keys position echo inserted ⦃ actual =>
      actual = match echo with
        | none => false
        | some name => !inserted && byteLess (schemaSliceBytes name)
            ((nativeKeyColumn keys)[position.val]'(by simpa [nativeKeyColumn] using inside)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_before
  cases echo with
  | none => rfl
  | some name =>
      cases inserted with
      | true => rfl
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          step with Slice.index_usize_spec keys position inside as ⟨key, keyAt⟩
          step with native_byte_less_exact name (AuthsNativeRecipe.alloc.vec.Vec.deref key.name)
            as ⟨before, exact⟩
          simpa [nativeKeyColumn, keyAt, bytes, schemaSliceBytes] using exact

private theorem native_merge_suffix (keys : Slice NativeKey) (echo : Option (Slice Std.U8))
    (output : NativeVec NativeChoice) (inserted : Bool) (position : Std.Usize)
    (positionBound : position.val ≤ keys.val.length)
    (room : output.val.length + (keys.val.length - position.val) +
      pendingEcho (echo.map schemaSliceBytes) inserted ≤ Usize.max) :
    nativeMergeLoop keys echo output inserted position ⦃ actual =>
      (nativeChoices actual.1, actual.2) =
        let tail := mergeState ((nativeKeyColumn keys).drop position.val)
          (echo.map schemaSliceBytes) position.val inserted
        (nativeChoices output ++ tail.1, tail.2) ⦄ := by
  generalize remaining : keys.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing output inserted position with
  | h count ih =>
      by_cases inside : position.val < keys.val.length
      · have nativeInside : position < keys.len := by scalar_tac
        let key := keys.val[position.val]
        have suffix : (nativeKeyColumn keys).drop position.val = bytes key.name ::
            (nativeKeyColumn keys).drop (position.val + 1) := by
          simpa [nativeKeyColumn, key, List.drop_map] using
            congrArg (List.map (fun key : NativeKey => bytes key.name)) (List.drop_eq_getElem_cons inside)
        cases echo with
        | none =>
            unfold nativeMergeLoop AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members_loop0
            simp only [nativeInside, ↓reduceIte]
            step with native_echo_before_exact keys position none inserted inside as ⟨before, beforeMeaning⟩
            simp only [beforeMeaning, Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
            step with native_push_exact output (.Source position) (by omega) as ⟨grown, grownMeaning⟩
            step as ⟨next, nextMeaning⟩
            have nextRoom : grown.val.length + (keys.val.length - next.val) + pendingEcho none inserted ≤ Usize.max := by
              simp only [grownMeaning, List.length_append, List.length_singleton, pendingEcho,
                Option.isSome_none, Bool.false_and, Bool.false_eq_true, ↓reduceIte] at *
              omega
            apply spec_mono (ih _ (by omega) grown inserted next (by omega) nextRoom rfl)
            intro actual exact
            simpa [nativeMergeLoop, suffix, mergeState, nativeChoices, grownMeaning, nativeChoice,
              List.map_append, List.append_assoc, nextMeaning] using exact
        | some name =>
            unfold nativeMergeLoop AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members_loop1
            simp only [nativeInside, ↓reduceIte]
            step with native_echo_before_exact keys position (some name) inserted inside as ⟨before, beforeMeaning⟩
            have originalBefore : before = (!inserted && byteLess (schemaSliceBytes name) (bytes key.name)) := by
              simpa [nativeKeyColumn, key] using beforeMeaning
            have charge : (if before then 2 else 1) + pendingEcho (some (schemaSliceBytes name)) (inserted || before) =
                1 + pendingEcho (some (schemaSliceBytes name)) inserted := by
              cases inserted <;> cases before <;> simp_all [pendingEcho]
            cases before with
            | false =>
                simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
                step with native_push_exact output (.Source position) (by omega) as ⟨grown, grownMeaning⟩
                step as ⟨next, nextMeaning⟩
                have nextRoom : grown.val.length + (keys.val.length - next.val) +
                    pendingEcho (some (schemaSliceBytes name)) inserted ≤ Usize.max := by
                  simp only [grownMeaning, List.length_append, List.length_singleton]
                  omega
                apply spec_mono (ih _ (by omega) grown inserted next (by omega) nextRoom rfl)
                intro actual exact
                simpa [nativeMergeLoop, suffix, mergeState, ← originalBefore, nativeChoices,
                  grownMeaning, nativeChoice, List.map_append, List.append_assoc, nextMeaning] using exact
            | true =>
                simp only [Bool.true_eq_true, ↓reduceIte]
                have echoRoom : output.val.length < Usize.max := by omega
                step with native_push_exact output .Echo echoRoom as ⟨withEcho, withEchoMeaning⟩
                simp only [bind_tc_ok]
                have sourceRoom : withEcho.val.length < Usize.max := by
                  simp only [withEchoMeaning, List.length_append, List.length_singleton]
                  simp only [Bool.or_true] at charge
                  omega
                step with native_push_exact withEcho (.Source position) sourceRoom as ⟨grown, grownMeaning⟩
                step as ⟨next, nextMeaning⟩
                have nextRoom : grown.val.length + (keys.val.length - next.val) +
                    pendingEcho (some (schemaSliceBytes name)) true ≤ Usize.max := by
                  simp only [grownMeaning, withEchoMeaning, List.length_append, List.length_singleton]
                  simp only [Bool.or_true] at charge
                  omega
                apply spec_mono (ih _ (by omega) grown true next (by omega) nextRoom rfl)
                intro actual exact
                simpa [nativeMergeLoop, suffix, mergeState, ← originalBefore, nativeChoices,
                  grownMeaning, withEchoMeaning, nativeChoice, List.map_append, List.append_assoc,
                  nextMeaning] using exact
      · have ended : position.val = keys.val.length := by omega
        have nativeEnded : ¬position < keys.len := by scalar_tac
        have empty : (nativeKeyColumn keys).drop position.val = [] := by
          simp [nativeKeyColumn, List.drop_map, ended]
        cases echo <;> simp [nativeMergeLoop,
          AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members_loop0,
          AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members_loop1,
          nativeEnded, empty, mergeState]

/-- Private merge contract on the count domain earned by canonical_members.
No orderedness, lexical validity, echo freshness or successful output is
assumed. The actual collision preflight earns any freshness used below. -/
@[step] theorem native_merge_members_exact (keys : Slice NativeKey) (echo : Option (Slice Std.U8))
    (count : keys.val.length ≤ 32) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members keys echo ⦃ actual =>
      nativeMemberResult nativeChoices actual = membersFrom (nativeKeyColumn keys)
        (echo.map schemaSliceBytes) 0 false ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.merge_members
  cases echo with
  | none =>
      have room : 0 + (keys.val.length - (0#usize).val) + pendingEcho none false ≤ Usize.max := by
        simp only [pendingEcho, Option.isSome_none, Bool.false_and, Bool.false_eq_true, ↓reduceIte]
        scalar_tac
      step with native_merge_suffix keys none (AuthsNativeRecipe.alloc.vec.Vec.new NativeChoice)
        false 0#usize (by simp) (by simpa using room) as ⟨merged, mergeMeaning⟩
      have fresh : ∀ name, (none : Option Bytes) = some name → name ∉ nativeKeyColumn keys := by simp
      have full := merge_state_full_meaning (nativeKeyColumn keys) none 0 false fresh
      have selected : nativeChoices merged.1 = (mergeState (nativeKeyColumn keys) none 0 false).1 := by
        simpa [nativeChoices, native_empty_contents, List.drop_zero] using congrArg Prod.fst mergeMeaning
      simp [core.option.Option.is_some, nativeMemberResult, full, selected, finalEcho]
  | some name =>
      step with native_key_position_exact keys name as ⟨found, foundMeaning⟩
      by_cases collision : schemaSliceBytes name ∈ nativeKeyColumn keys
      · have foundSome : found.isSome = true := by
          cases found with
          | none =>
              have absent := (key_position_none_iff _ _).mp (by simpa using foundMeaning.symm)
              exact False.elim (absent collision)
          | some position => rfl
        simp [core.option.Option.is_some, foundSome, nativeMemberResult, nativeMemberErrorMeaning,
          members_from_collision_refuses _ _ _ _ collision]
      · have absent : keyPosition (schemaSliceBytes name) (nativeKeyColumn keys) = none :=
          (key_position_none_iff _ _).mpr collision
        have notFound : found = none := by
          cases found <;> simp_all
        simp only [notFound, core.option.Option.is_some, Bool.false_eq_true, ↓reduceIte]
        have room : (AuthsNativeRecipe.alloc.vec.Vec.new NativeChoice).val.length +
            (keys.val.length - (0#usize).val) + pendingEcho (some (schemaSliceBytes name)) false ≤ Usize.max := by
          simp only [native_empty_contents, List.length_nil, pendingEcho, Option.isSome_some,
            Bool.not_false, Bool.true_and, ↓reduceIte]
          scalar_tac
        step with native_merge_suffix keys (some name) (AuthsNativeRecipe.alloc.vec.Vec.new NativeChoice)
          false 0#usize (by simp) room as ⟨merged, mergeMeaning⟩
        have full := merge_state_full_meaning (nativeKeyColumn keys) (some (schemaSliceBytes name)) 0 false
          (by intro other same; cases same; exact collision)
        have pairMeaning : (nativeChoices merged.1, merged.2) =
            mergeState (nativeKeyColumn keys) (some (schemaSliceBytes name)) 0 false := by
          simpa [native_empty_contents, nativeChoices, List.drop_zero] using mergeMeaning
        have lengthMeaning := merge_state_length (nativeKeyColumn keys) (some (schemaSliceBytes name)) 0 false
        rw [← pairMeaning] at lengthMeaning
        simp only [nativeChoices, List.length_map, nativeKeyColumn, List.length_map] at lengthMeaning
        simp only [core.option.Option.is_some, Bool.true_eq_true, ↓reduceIte]
        cases insertedMeaning : merged.2 with
        | true =>
            simp [nativeMemberResult, full, ← pairMeaning, finalEcho, insertedMeaning]
        | false =>
            have capacity : merged.1.val.length < Usize.max := by
              simp [insertedMeaning, pendingEcho] at lengthMeaning
              scalar_tac
            step with native_push_exact merged.1 .Echo capacity as ⟨finished, finishedMeaning⟩
            simp [nativeMemberResult, full, ← pairMeaning, finalEcho, insertedMeaning,
              nativeChoices, finishedMeaning, nativeChoice, List.map_append]

end Auths.Product.NativeCompiler.Refinement
