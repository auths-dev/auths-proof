import Auths.Product.NativeCompilerPointerSpans
import Auths.Product.RecipeRuleAdmission

namespace Auths.Product.RecipeRuleAdmission
open NativeCompiler RecipeAdmissionAtoms

def selectTemplateChild (value : TemplateAst.Value) (token : Bytes) : Option TemplateAst.Value :=
  match value with
  | .object members => findMember token members
  | .array children => (arrayIndex Aeneas.Std.Usize.max token).bind (fun index => children[index]?)
  | _ => none

theorem select_template_cons (value : TemplateAst.Value) (token : Bytes) (rest : List Bytes) :
    selectTemplate value (token :: rest) =
      (selectTemplateChild value token).bind (fun selected => selectTemplate selected rest) := by
  cases value <;> simp [selectTemplate, selectTemplateChild, Option.bind_assoc]

theorem split_pointer_span (prefix bytes : Bytes) :
    splitPointer prefix bytes =
      match bytes.drop (bytes.takeWhile (· != 47)).length with
      | [] => [prefix ++ bytes.takeWhile (· != 47)]
      | _ :: rest => (prefix ++ bytes.takeWhile (· != 47)) :: splitPointer [] rest := by
  induction bytes generalizing prefix with
  | nil => simp [splitPointer]
  | cons first rest ih =>
      by_cases slash : first = 47
      · simp [splitPointer, slash]
      · simpa [splitPointer, slash, List.drop_succ_cons, List.append_assoc] using ih (prefix ++ [first])

theorem split_pointer_at (bytes : Bytes) (start : Nat) (within : start ≤ bytes.length) :
    splitPointer [] (bytes.drop start) =
      if pointerTokenEnd bytes start = bytes.length then [pointerToken bytes start]
      else pointerToken bytes start :: splitPointer [] (bytes.drop (pointerTokenEnd bytes start + 1)) := by
  rw [split_pointer_span]
  have rest : (bytes.drop start).drop ((bytes.drop start).takeWhile (· != 47)).length =
      bytes.drop (pointerTokenEnd bytes start) := by simp [List.drop_drop, pointerTokenEnd]
  rw [rest]
  rcases StdModel.pointer_token_end_delimiter bytes start within with ended | ⟨inside, slash⟩
  · simp [ended, pointerToken]
  · have suffix := List.drop_eq_getElem_cons inside
    rw [suffix]
    simp [pointerToken, slash, Nat.ne_of_lt inside]

/-- A direct independent byte-offset presentation of the same token-list
selector. The equality below connects it to selectTemplate; no selected child
or native outcome is supplied to either presentation. -/
def selectPointerFrom (value : TemplateAst.Value) (bytes : Bytes) (start : Nat) : Option TemplateAst.Value :=
  if within : start ≤ bytes.length then
    let end1 := pointerTokenEnd bytes start
    let selected := selectTemplateChild value (pointerToken bytes start)
    if end1 = bytes.length then selected
    else selected.bind (fun child => selectPointerFrom child bytes (end1 + 1))
  else none
termination_by bytes.length - start
decreasing_by
  have bounds := StdModel.pointer_token_end_bounds bytes start within
  omega

theorem select_pointer_from_tokens (value : TemplateAst.Value) (bytes : Bytes) (start : Nat)
    (within : start ≤ bytes.length) :
    selectPointerFrom value bytes start = selectTemplate value (splitPointer [] (bytes.drop start)) := by
  generalize remaining : bytes.length - start = count
  induction count using Nat.strong_induction_on generalizing value start with
  | h count ih =>
      rw [split_pointer_at bytes start within, selectPointerFrom]
      simp only [dif_pos within]
      by_cases ended : pointerTokenEnd bytes start = bytes.length
      · simp [ended, select_template_cons, selectTemplate]
      · have bounds := StdModel.pointer_token_end_bounds bytes start within
        simp only [ended, ↓reduceIte, select_template_cons]
        cases selected : selectTemplateChild value (pointerToken bytes start) with
        | none => simp
        | some child =>
            simp only [Option.bind_some]
            exact ih _ (by omega) child _ (by omega) rfl

theorem template_at_original_pointer (value : TemplateAst.Value) (pointer : Bytes) :
    templateAt value pointer =
      if ResponsePointer pointer ∧ 126 ∉ pointer then selectPointerFrom value pointer 1 else none := by
  unfold templateAt
  split <;> rename_i admitted
  · have nonempty : pointer ≠ [] := fun empty => by simp [empty, ResponsePointer] at admitted
    have within : 1 ≤ pointer.length := List.length_pos.mpr nonempty
    exact (select_pointer_from_tokens value pointer 1 within).symm
  · rfl

end Auths.Product.RecipeRuleAdmission
