import Auths.Product.TemplateMemberDomainsRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway

namespace Auths.Product.TemplateMembers.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def memberResult {α β : Type} (view : α → β) : core.result.Result α template_members.MemberError → Except Error β
  | .Ok value => .ok (view value)
  | .Err error => .error (memberErrorOf error)

@[step] theorem json_echo_target_exact (keys : Slice template_members.NamedKey)
    (tokens : Slice (alloc.vec.Vec Std.U8)) :
    template_members.json_echo_target keys tokens ⦃ actual =>
      memberResult targetOf actual = jsonEchoTarget (keysView keys) (tokensView tokens) ⦄ := by
  unfold template_members.json_echo_target
  step with keys_ordered_exact as ⟨keysAllowed, keysMeaning⟩
  cases keysAllowed
  · have invalid : ¬KeyColumn (keysView keys) .json := by simpa [domainOf] using keysMeaning.symm
    simp [jsonEchoTarget, invalid, memberResult, memberErrorOf]
  · have keysValid : KeyColumn (keysView keys) .json := by simpa [domainOf] using keysMeaning.symm
    simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
    step with pointer_tokens_exact as ⟨pointerAllowed, pointerMeaning⟩
    cases pointerAllowed
    · have invalid : ¬PointerDomain (tokensView tokens) := by simpa using pointerMeaning.symm
      simp [jsonEchoTarget, keysValid, invalid, memberResult, memberErrorOf]
    · have pointerValid : PointerDomain (tokensView tokens) := by simpa using pointerMeaning.symm
      have nonempty : 0 < tokens.val.length := by simpa [tokensView] using pointerValid.1
      simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
      step as ⟨first, firstAt⟩
      have firstMeaning : vecBytes first = (tokensView tokens).headD [] := by
        cases values : tokens.val with
        | nil => simp [values] at nonempty
        | cons head rest => simpa [tokensView, values, firstAt] using rfl
      step with key_position_exact as ⟨found, foundMeaning⟩
      have selected : found.map UScalar.val = keyPosition ((tokensView tokens).headD []) (keysView keys) := by
        simpa [alloc.vec.Vec.deref, vecBytes, sliceBytes, firstMeaning] using foundMeaning
      by_cases last : tokens.val.length = 1
      · have nativeLast : tokens.len = 1#usize := by scalar_tac
        have modelLast : (tokensView tokens).length = 1 := by simpa [tokensView] using last
        simp only [nativeLast, beq_self_eq_true, ↓reduceIte]
        cases found with
        | none =>
          have absent : (tokensView tokens).headD [] ∉ keysView keys := by
            apply (key_position_none_iff _ _).mp
            simpa using selected.symm
          by_cases full : 32 ≤ keys.val.length
          · have nativeFull : keys.len ≥ 32#usize := by scalar_tac
            have modelFull : 32 ≤ (keysView keys).length := by simpa [keysView] using full
            simp [nativeFull, jsonEchoTarget, keysValid, pointerValid, modelLast, modelFull,
              memberResult, memberErrorOf]
          · have nativeRoom : ¬keys.len ≥ 32#usize := by scalar_tac
            have modelRoom : ¬32 ≤ (keysView keys).length := by simpa [keysView] using full
            simp [nativeRoom, jsonEchoTarget, keysValid, pointerValid, modelLast, absent, modelRoom,
              memberResult, targetOf]
        | some index =>
          have present : (tokensView tokens).headD [] ∈ keysView keys := by
            have lookup : (keysView keys)[index.val]? = some ((tokensView tokens).headD []) :=
              key_position_is_exact _ _ _ selected.symm
            exact List.mem_iff_getElem?.mpr ⟨index.val, lookup⟩
          simp [jsonEchoTarget, keysValid, pointerValid, modelLast, present, memberResult, memberErrorOf]
      · have nativeNotLast : ¬tokens.len = 1#usize := by scalar_tac
        have modelNotLast : ¬(tokensView tokens).length = 1 := by simpa [tokensView] using last
        simp only [nativeNotLast, beq_eq_false_iff_ne, ↓reduceIte]
        cases found with
        | none => simpa [jsonEchoTarget, keysValid, pointerValid, modelNotLast, memberResult, memberErrorOf] using
            congrArg (fun found => match found with | none => Except.error Error.echoConflict | some index => .ok (.descend index)) selected
        | some index => simpa [jsonEchoTarget, keysValid, pointerValid, modelNotLast, memberResult, targetOf] using
            congrArg (fun found => match found with | none => Except.error Error.echoConflict | some index => .ok (.descend index)) selected

theorem source_targets_earn_pointer_domain (keys : Slice template_members.NamedKey)
    (tokens : Slice (alloc.vec.Vec Std.U8)) :
    template_members.json_echo_target keys tokens ⦃ actual => ∀ target, actual = .Ok target →
      KeyColumn (keysView keys) .json ∧ PointerDomain (tokensView tokens) ⦄ := by
  apply spec_mono (json_echo_target_exact keys tokens)
  intro actual meaning target same
  rw [same] at meaning
  exact target_success_retains_pointer _ _ _ meaning.symm

theorem source_target_descends_to_original_name (keys : Slice template_members.NamedKey)
    (tokens : Slice (alloc.vec.Vec Std.U8)) :
    template_members.json_echo_target keys tokens ⦃ actual => ∀ index, actual = .Ok (.Descend index) →
      1 < (tokensView tokens).length ∧ (keysView keys)[index.val]? = some ((tokensView tokens).headD []) ⦄ := by
  apply spec_mono (json_echo_target_exact keys tokens)
  intro actual meaning index same
  rw [same] at meaning
  exact target_descends_to_original_name _ _ _ meaning.symm

theorem source_target_insertion_is_new (keys : Slice template_members.NamedKey)
    (tokens : Slice (alloc.vec.Vec Std.U8)) :
    template_members.json_echo_target keys tokens ⦃ actual => actual = .Ok .Insert →
      (tokensView tokens).length = 1 ∧ (tokensView tokens).headD [] ∉ keysView keys ∧ (keysView keys).length < 32 ⦄ := by
  apply spec_mono (json_echo_target_exact keys tokens)
  intro actual meaning same
  rw [same] at meaning
  exact target_insert_is_new_member _ _ meaning.symm

theorem source_admitted_targets_compile (keys : Slice template_members.NamedKey)
    (tokens : Slice (alloc.vec.Vec Std.U8))
    (admitted : TargetAdmitted (keysView keys) (tokensView tokens)) :
    template_members.json_echo_target keys tokens ⦃ actual => ∃ target, actual = .Ok target ⦄ := by
  apply spec_mono (json_echo_target_exact keys tokens)
  intro actual meaning
  obtain ⟨target, run⟩ := target_admitted_compiles _ _ admitted
  rw [run] at meaning
  cases actual with
  | Err error => simp [memberResult] at meaning
  | Ok target => exact ⟨target, rfl⟩

theorem source_unadmitted_targets_refuse (keys : Slice template_members.NamedKey)
    (tokens : Slice (alloc.vec.Vec Std.U8))
    (invalid : ¬TargetAdmitted (keysView keys) (tokensView tokens)) :
    template_members.json_echo_target keys tokens ⦃ actual => ∀ target, actual ≠ .Ok target ⦄ := by
  apply spec_mono (json_echo_target_exact keys tokens)
  intro actual meaning target same
  rw [same] at meaning
  exact invalid (target_success_earns_admission _ _ _ meaning.symm)

end Auths.Product.TemplateMembers.Refinement
