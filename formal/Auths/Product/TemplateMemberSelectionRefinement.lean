import Auths.Product.TemplateMemberSelection
import Auths.Product.TemplateFormRefinement
import Auths.Product.TemplateTargetRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity

namespace Auths.Product.TemplateMembers.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def choicesOf (output : alloc.vec.Vec template_members.MemberChoice) : List Choice := output.val.map choiceOf

/-- The actual private selector has only a source-column count premise. Its
public caller earns that premise before entry. Every index/echo decision and
typed collision refusal is retained; no expected output is supplied. -/
@[step] theorem merge_members_exact (keys : Slice template_members.NamedKey) (echo : Option (Slice Std.U8))
    (bounded : keys.val.length ≤ 32) :
    template_members.merge_members keys echo ⦃ actual =>
      memberResult choicesOf actual = membersFrom (keysView keys) (echo.map sliceBytes) 0 false ⦄ := by
  unfold template_members.merge_members template_members.merge_members_loop
  apply loop.spec_decr_nat
    (measure := fun state => keys.val.length - state.2.2.val)
    (inv := fun state => state.2.2.val ≤ keys.val.length ∧
      state.1.val.length = state.2.2.val + (if state.2.1 then 1 else 0) ∧
      membersFrom (keysView keys) (echo.map sliceBytes) 0 false =
        (membersFrom ((keysView keys).drop state.2.2.val) (echo.map sliceBytes) state.2.2.val state.2.1)
          .map (choicesOf state.1 ++ ·))
  · rintro ⟨current, inserted, index⟩ invariant
    unfold template_members.merge_members_loop.body
    dsimp only
    split <;> rename_i guard
    · have inside : index.val < keys.val.length := by scalar_tac
      step as ⟨key, keyAt⟩
      have suffix : (keysView keys).drop index.val = sliceBytes key.name :: (keysView keys).drop (index.val + 1) := by
        simpa [keysView, List.drop_map, keyAt] using
          congrArg (List.map (fun key => sliceBytes key.name)) (List.drop_eq_getElem_cons inside)
      have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
      cases echo with
      | none =>
        step as ⟨updated, updatedValue⟩
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, ?_, by omega⟩
        · simp only [updatedValue, List.length_append, List.length_singleton]
          rw [nextValue]
          omega
        · have semantic := invariant.2.2
          rw [suffix, membersFrom] at semantic
          cases tail : membersFrom ((keysView keys).drop (index.val + 1)) none (index.val + 1) inserted <;>
            simpa [nextValue, tail, Except.map, choicesOf, updatedValue, List.map_append,
              choiceOf, List.append_assoc] using semantic
      | some name =>
        step with field_name_equal_exact as ⟨collision, collisionMeaning⟩
        cases collision
        · have different : sliceBytes key.name ≠ sliceBytes name := by
            intro equal
            have raw := byteList_inj _ _ |>.mp equal
            simp [raw] at collisionMeaning
          cases inserted with
          | true =>
            simp only [Bool.not_true, Bool.false_and, Bool.false_eq_true, ↓reduceIte]
            step as ⟨updated, updatedValue⟩
            step as ⟨next, nextValue⟩
            refine ⟨by omega, ?_, ?_, by omega⟩
            · simp only [updatedValue, List.length_append, List.length_singleton, nextValue]
              omega
            · have semantic := invariant.2.2
              rw [suffix, membersFrom] at semantic
              cases tail : membersFrom ((keysView keys).drop (index.val + 1)) (some (sliceBytes name)) (index.val + 1) true <;>
                simpa [different, nextValue, tail, Except.map, choicesOf, updatedValue,
                  List.map_append, choiceOf, List.append_assoc] using semantic
          | false =>
            simp only [Bool.not_false, Bool.true_and, ↓reduceIte]
            step with byte_less_exact as ⟨before, beforeMeaning⟩
            cases before
            · have notBefore : byteLess (sliceBytes name) (sliceBytes key.name) = false := by
                have refused : ¬sliceBytes name < sliceBytes key.name := by simpa using beforeMeaning.symm
                exact Bool.eq_false_iff.mpr (by simpa [byte_less_iff] using refused)
              step as ⟨updated, updatedValue⟩
              step as ⟨next, nextValue⟩
              refine ⟨by omega, ?_, ?_, by omega⟩
              · simp only [updatedValue, List.length_append, List.length_singleton, nextValue]
                omega
              · have semantic := invariant.2.2
                rw [suffix, membersFrom] at semantic
                cases tail : membersFrom ((keysView keys).drop (index.val + 1)) (some (sliceBytes name)) (index.val + 1) false <;>
                  simpa [different, notBefore, nextValue, tail, Except.map, choicesOf, updatedValue,
                    List.map_append, choiceOf, List.append_assoc] using semantic
            · have before : byteLess (sliceBytes name) (sliceBytes key.name) = true :=
                byte_less_iff.mpr (by simpa using beforeMeaning.symm)
              step as ⟨withEcho, echoValue⟩
              have secondRoom : withEcho.length < Usize.max := lt_usize_max (by
                change withEcho.val.length < _
                simp only [echoValue, List.length_append, List.length_singleton]
                omega)
              step as ⟨updated, updatedValue⟩
              step as ⟨next, nextValue⟩
              refine ⟨by omega, ?_, ?_, by omega⟩
              · simp only [updatedValue, echoValue, List.length_append, List.length_singleton, nextValue]
                omega
              · have semantic := invariant.2.2
                rw [suffix, membersFrom] at semantic
                cases tail : membersFrom ((keysView keys).drop (index.val + 1)) (some (sliceBytes name)) (index.val + 1) true <;>
                  simpa [different, before, nextValue, tail, Except.map, choicesOf, updatedValue, echoValue,
                    List.map_append, choiceOf, List.append_assoc] using semantic
        · have collision : sliceBytes key.name = sliceBytes name := by
            simpa [sliceBytes] using congrArg byteList collisionMeaning.symm
          have refused : membersFrom (keysView keys) (some (sliceBytes name)) 0 false = .error .echoConflict := by
            simpa [suffix, membersFrom, collision, Except.map] using invariant.2.2
          simp [memberResult, memberErrorOf, refused]
    · have endBound : (keysView keys).length ≤ index.val := by
        simpa [keysView] using (show keys.val.length ≤ index.val by scalar_tac)
      have semantic := invariant.2.2
      rw [List.drop_of_length_le endBound, membersFrom] at semantic
      have room : current.length < Usize.max := lt_usize_max (by change current.val.length < _; omega)
      cases echo <;> cases inserted
      all_goals try simpa [memberResult, choicesOf, Except.map] using semantic.symm
      step as ⟨updated, updatedValue⟩
      simpa [memberResult, choicesOf, updatedValue, List.map_append, choiceOf, Except.map] using semantic.symm
  · exact ⟨by simp, by simp, by simp [choicesOf]⟩

@[step] theorem canonical_members_exact (keys : Slice template_members.NamedKey) (echo : Option (Slice Std.U8))
    (domain : template_members.MemberDomain) :
    template_members.canonical_members keys echo domain ⦃ actual =>
      memberResult choicesOf actual = canonicalMembers (keysView keys) (echo.map sliceBytes) (domainOf domain) ⦄ := by
  unfold template_members.canonical_members
  step with keys_ordered_exact as ⟨allowed, keysMeaning⟩
  cases allowed
  · have invalid : ¬KeyColumn (keysView keys) (domainOf domain) := by simpa using keysMeaning.symm
    simp [canonicalMembers, invalid, memberResult, memberErrorOf]
  · have column : KeyColumn (keysView keys) (domainOf domain) := by simpa using keysMeaning.symm
    have bounded : keys.val.length ≤ 32 := by
      have count := column.2.1
      cases domain <;> simp only [keysView, List.length_map, domainOf, maximum] at count <;> omega
    simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
    cases domain with
    | Json =>
      cases echo with
      | none =>
        apply spec_mono (merge_members_exact keys none bounded)
        intro actual meaning
        simpa [canonicalMembers, column, domainOf] using meaning
      | some name =>
        step with OperationIdentity.Refinement.token_exact as ⟨valid, validMeaning⟩
        cases valid
        · have invalid : ¬EchoName .json (sliceBytes name) := by simpa [EchoName] using validMeaning.symm
          simp [canonicalMembers, column, domainOf, invalid, memberResult, memberErrorOf]
        · have valid : EchoName .json (sliceBytes name) := by simpa [EchoName] using validMeaning.symm
          by_cases full : 32 ≤ keys.val.length
          · have nativeFull : keys.len ≥ 32#usize := by scalar_tac
            have noRoom : ¬(keysView keys).length < maximum .json := by simpa [keysView, maximum] using Nat.not_lt.mpr full
            simp [nativeFull, canonicalMembers, column, domainOf, noRoom, memberResult, memberErrorOf]
          · have nativeRoom : ¬keys.len ≥ 32#usize := by scalar_tac
            have room : (keysView keys).length < maximum .json := by simp only [keysView, List.length_map, maximum]; omega
            simp only [nativeRoom, Bool.not_true, Bool.false_or, Bool.false_eq_true, ↓reduceIte]
            apply spec_mono (merge_members_exact keys (some name) bounded)
            intro actual meaning
            simpa [canonicalMembers, column, domainOf, valid, room] using meaning
    | Form =>
      cases echo with
      | none =>
        apply spec_mono (merge_members_exact keys none bounded)
        intro actual meaning
        simpa [canonicalMembers, column, domainOf] using meaning
      | some name =>
        step with form_echo_name_exact as ⟨valid, validMeaning⟩
        cases valid
        · have invalid : ¬EchoName .form (sliceBytes name) := by simpa [EchoName] using validMeaning.symm
          simp [canonicalMembers, column, domainOf, invalid, memberResult, memberErrorOf]
        · have valid : EchoName .form (sliceBytes name) := by simpa [EchoName] using validMeaning.symm
          by_cases full : 16 ≤ keys.val.length
          · have nativeFull : keys.len ≥ 16#usize := by scalar_tac
            have noRoom : ¬(keysView keys).length < maximum .form := by simpa [keysView, maximum] using Nat.not_lt.mpr full
            simp [nativeFull, canonicalMembers, column, domainOf, noRoom, memberResult, memberErrorOf]
          · have nativeRoom : ¬keys.len ≥ 16#usize := by scalar_tac
            have room : (keysView keys).length < maximum .form := by simp only [keysView, List.length_map, maximum]; omega
            simp only [nativeRoom, Bool.not_true, Bool.false_or, Bool.false_eq_true, ↓reduceIte]
            apply spec_mono (merge_members_exact keys (some name) bounded)
            intro actual meaning
            simpa [canonicalMembers, column, domainOf, valid, room] using meaning

theorem source_members_earn_admission (keys : Slice template_members.NamedKey) (echo : Option (Slice Std.U8))
    (domain : template_members.MemberDomain) :
    template_members.canonical_members keys echo domain ⦃ actual => ∀ output, actual = .Ok output →
      Admitted (keysView keys) (echo.map sliceBytes) (domainOf domain) ⦄ := by
  apply spec_mono (canonical_members_exact keys echo domain)
  intro actual meaning output same
  rw [same] at meaning
  exact canonical_success_earns_admission _ _ _ _ meaning.symm

theorem source_members_preserve_original_indices (keys : Slice template_members.NamedKey) (echo : Option (Slice Std.U8))
    (domain : template_members.MemberDomain) :
    template_members.canonical_members keys echo domain ⦃ actual => ∀ output, actual = .Ok output →
      sourceIndices (choicesOf output) = sourcePositions 0 (keysView keys) ∧
      echoCount (choicesOf output) = if echo.isSome then 1 else 0 ⦄ := by
  apply spec_mono (canonical_members_exact keys echo domain)
  intro actual meaning output same
  rw [same] at meaning
  simpa using canonical_success_preserves_source _ _ _ _ meaning.symm

theorem source_members_select_canonical_original_labels (keys : Slice template_members.NamedKey)
    (echo : Option (Slice Std.U8)) (domain : template_members.MemberDomain) :
    template_members.canonical_members keys echo domain ⦃ actual => ∀ output, actual = .Ok output →
      ∃ labels, selectedNames (keysView keys) (echo.map sliceBytes) (choicesOf output) = some labels ∧
        labels.Pairwise (· < ·) ∧ labels.Perm (keysView keys ++ (echo.map sliceBytes).toList) ⦄ := by
  apply spec_mono (canonical_members_exact keys echo domain)
  intro actual meaning output same
  rw [same] at meaning
  exact canonical_selected_names _ _ _ _ meaning.symm

theorem source_admitted_members_compile (keys : Slice template_members.NamedKey) (echo : Option (Slice Std.U8))
    (domain : template_members.MemberDomain) (admitted : Admitted (keysView keys) (echo.map sliceBytes) (domainOf domain)) :
    template_members.canonical_members keys echo domain ⦃ actual => ∃ output, actual = .Ok output ⦄ := by
  apply spec_mono (canonical_members_exact keys echo domain)
  intro actual meaning
  obtain ⟨output, run⟩ := canonical_useful_acceptance _ _ _ admitted
  rw [run] at meaning
  cases actual with
  | Err error => simp [memberResult] at meaning
  | Ok output => exact ⟨output, rfl⟩

theorem source_unadmitted_members_refuse (keys : Slice template_members.NamedKey) (echo : Option (Slice Std.U8))
    (domain : template_members.MemberDomain) (invalid : ¬Admitted (keysView keys) (echo.map sliceBytes) (domainOf domain)) :
    template_members.canonical_members keys echo domain ⦃ actual => ∀ output, actual ≠ .Ok output ⦄ := by
  apply spec_mono (canonical_members_exact keys echo domain)
  intro actual meaning output same
  rw [same] at meaning
  exact invalid (canonical_success_earns_admission _ _ _ _ meaning.symm)

end Auths.Product.TemplateMembers.Refinement
