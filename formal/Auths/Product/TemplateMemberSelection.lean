import Auths.Product.TemplateFormGrammar

namespace Auths.Product.TemplateMembers

/-- Interprets a choice against the original source map, not a rendered value
or a positional action-argument vector. Invalid indices cannot select data. -/
def selectedNames (keys : List Bytes) (echo : Option Bytes) : List Choice → Option (List Bytes)
  | [] => some []
  | .source index :: rest => do
      let name ← keys[index]?
      let tail ← selectedNames keys echo rest
      pure (name :: tail)
  | .echo :: rest => do
      let name ← echo
      let tail ← selectedNames keys echo rest
      pure (name :: tail)

def namedMerge : List Bytes → Option Bytes → Bool → List Bytes
  | [], echo, inserted => if inserted then [] else echo.toList
  | key :: rest, echo, inserted =>
    match echo with
    | none => key :: namedMerge rest none inserted
    | some name =>
      if !inserted && byteLess name key then name :: key :: namedMerge rest echo true
      else key :: namedMerge rest echo inserted

theorem named_merge_after_insertion (keys : List Bytes) (echo : Option Bytes) : namedMerge keys echo true = keys := by
  induction keys with
  | nil => simp [namedMerge]
  | cons key rest ih => cases echo <;> simp [namedMerge, ih]

theorem named_merge_absent (keys : List Bytes) (inserted : Bool) : namedMerge keys none inserted = keys := by
  induction keys with
  | nil => cases inserted <;> rfl
  | cons key rest ih => simp [namedMerge, ih]

theorem named_merge_permutation (keys : List Bytes) (echo : Option Bytes) :
    (namedMerge keys echo false).Perm (keys ++ echo.toList) := by
  cases echo with
  | none => simp [named_merge_absent]
  | some name =>
    induction keys with
    | nil => simp [namedMerge]
    | cons key rest ih =>
      by_cases before : byteLess name key = true
      · simpa [namedMerge, before, named_merge_after_insertion] using List.perm_append_comm [name] (key :: rest)
      · simpa [namedMerge, before] using List.Perm.cons key ih

theorem named_merge_is_canonical (keys : List Bytes) (echo : Option Bytes)
    (sorted : keys.Pairwise (· < ·)) (fresh : ∀ name, echo = some name → name ∉ keys) :
    (namedMerge keys echo false).Pairwise (· < ·) := by
  cases echo with
  | none => simpa [named_merge_absent] using sorted
  | some name =>
    have absent : name ∉ keys := fresh name rfl
    clear fresh
    revert sorted absent
    induction keys with
    | nil => intro sorted absent; simp [namedMerge]
    | cons key rest ih =>
      intro sorted absent
      obtain ⟨keyRest, restSorted⟩ := List.pairwise_cons.mp sorted
      have notKey : key ≠ name := by intro same; simp [same] at absent
      have restAbsent : name ∉ rest := by simp only [List.mem_cons, not_or] at absent; exact absent.2
      by_cases before : byteLess name key = true
      · have nameKey : name < key := byte_less_iff.mp before
        simp only [namedMerge, Bool.not_false, Bool.true_and, before, ↓reduceIte, named_merge_after_insertion]
        apply List.pairwise_cons.mpr
        refine ⟨?_, sorted⟩
        intro member present
        rcases List.mem_cons.mp present with same | inRest
        · simpa [same] using nameKey
        · exact lt_trans nameKey (keyRest member inRest)
      · have notBefore : ¬name < key := by simpa [← byte_less_iff] using before
        have keyName : key < name := lt_of_le_of_ne (le_of_not_gt notBefore) notKey
        have tailSorted : (namedMerge rest (some name) false).Pairwise (· < ·) := ih restSorted restAbsent
        simp only [namedMerge, Bool.not_false, Bool.true_and, before, Bool.false_eq_true, ↓reduceIte]
        apply List.pairwise_cons.mpr
        refine ⟨?_, tailSorted⟩
        intro member present
        have original : member ∈ rest ++ [name] := (named_merge_permutation rest (some name)).mem_iff.mp present
        rcases List.mem_append.mp original with original | inserted
        · exact keyRest member original
        · have same : member = name := by simpa only [List.mem_singleton] using inserted
          simpa [same] using keyName

theorem members_from_select_original_names (prefix keys : List Bytes) (echo : Option Bytes)
    (inserted : Bool) (output : List Choice)
    (run : membersFrom keys echo prefix.length inserted = .ok output) :
    selectedNames (prefix ++ keys) echo output = some (namedMerge keys echo inserted) := by
  induction keys generalizing prefix inserted output with
  | nil =>
    cases echo <;> cases inserted <;> simp [membersFrom] at run <;> subst output <;> rfl
  | cons key rest ih =>
    have lookup : (prefix ++ key :: rest)[prefix.length]? = some key := by simp
    cases echo with
    | none =>
      cases tail : membersFrom rest none (prefix.length + 1) inserted with
      | error error => simp [membersFrom, tail, Except.map] at run
      | ok tail =>
        have same : .source prefix.length :: tail = output := by simpa [membersFrom, tail, Except.map] using run
        subst output
        have recursive := ih (prefix ++ [key]) inserted tail (by simpa using tail)
        simpa [selectedNames, lookup, namedMerge, List.append_assoc] using congrArg (Option.map (key :: ·)) recursive
    | some name =>
      by_cases collision : key = name
      · simp [membersFrom, collision] at run
      · by_cases before : !inserted && byteLess name key
        · cases tail : membersFrom rest (some name) (prefix.length + 1) true with
          | error error => simp [membersFrom, collision, before, tail, Except.map] at run
          | ok tail =>
            have same : .echo :: .source prefix.length :: tail = output := by simpa [membersFrom, collision, before, tail, Except.map] using run
            subst output
            have recursive := ih (prefix ++ [key]) true tail (by simpa using tail)
            simpa [selectedNames, lookup, namedMerge, before, List.append_assoc] using
              congrArg (Option.map (fun tail => name :: key :: tail)) recursive
        · cases tail : membersFrom rest (some name) (prefix.length + 1) inserted with
          | error error => simp [membersFrom, collision, before, tail, Except.map] at run
          | ok tail =>
            have same : .source prefix.length :: tail = output := by simpa [membersFrom, collision, before, tail, Except.map] using run
            subst output
            have recursive := ih (prefix ++ [key]) inserted tail (by simpa using tail)
            simpa [selectedNames, lookup, namedMerge, before, List.append_assoc] using
              congrArg (Option.map (key :: ·)) recursive

/-- Whole model success earns canonical selected labels, complete original
membership, safe original indices and exactly the fresh declared echo. -/
theorem canonical_selected_names (keys : List Bytes) (echo : Option Bytes) (domain : Domain)
    (output : List Choice) (run : canonicalMembers keys echo domain = .ok output) :
    ∃ labels, selectedNames keys echo output = some labels ∧ labels.Pairwise (· < ·) ∧ labels.Perm (keys ++ echo.toList) := by
  have admitted := canonical_success_earns_admission _ _ _ _ run
  have merge : membersFrom keys echo 0 false = .ok output := by
    cases echo with
    | none => simpa [canonicalMembers, admitted.1] using run
    | some name => simpa [canonicalMembers, admitted.1, admitted.2.1, admitted.2.2.1] using run
  have selection := members_from_select_original_names [] keys echo false output merge
  have fresh : ∀ name, echo = some name → name ∉ keys := by
    intro name same
    subst echo
    exact admitted.2.2.2
  exact ⟨namedMerge keys echo false, by simpa using selection,
    named_merge_is_canonical keys echo admitted.1.2.2.2 fresh, named_merge_permutation keys echo⟩

end Auths.Product.TemplateMembers
