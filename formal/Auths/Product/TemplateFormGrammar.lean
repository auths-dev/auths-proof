import Auths.Product.TemplateMemberDomains

namespace Auths.Product.TemplateMembers

theorem token_shape_bounds (name : Bytes) (valid : OperationIdentity.validToken name 64 = true) :
    0 < name.length ∧ name.length ≤ 64 ∧ ∀ byte ∈ name, byte ≠ 91 ∧ byte ≠ 93 := by
  cases name with
  | nil => simp [OperationIdentity.validToken] at valid
  | cons first rest =>
    simp only [OperationIdentity.validToken, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at valid
    refine ⟨by simp, valid.1.1, ?_⟩
    intro byte member
    rcases List.mem_cons.mp member with same | tail
    · subst byte
      have alpha := valid.1.2
      unfold OperationIdentity.Alphanumeric at alpha
      constructor <;> omega
    · have allowed := valid.2 byte tail
      simp only [decide_eq_true_eq] at allowed
      unfold OperationIdentity.TailByte OperationIdentity.Alphanumeric at allowed
      constructor <;> omega

private theorem first_open_after_prefix (base suffix : Bytes)
    (safe : ∀ byte ∈ base, byte ≠ 91) :
    (base ++ suffix).findIdx (· == 91) = base.length + suffix.findIdx (· == 91) := by
  induction base with
  | nil => simp
  | cons first rest ih =>
    have firstSafe := safe first (by simp)
    have restSafe : ∀ byte ∈ rest, byte ≠ 91 := fun byte member => safe byte (by simp [member])
    simp [List.findIdx_cons, firstSafe, ih restSafe, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]

private theorem scanned_name_decomposes (name : Bytes) (position : Nat)
    (inside : position < name.length) (opening : name[position]? = some 91)
    (spare : position + 2 < name.length) (closing : name.getLast? = some 93) :
    name = name.take position ++ [91] ++
      ((name.drop (position + 1)).take (name.length - position - 2)) ++ [93] := by
  have leftSize : (name.take position).length = position := by simp [List.length_take, Nat.min_eq_left (by omega)]
  have middleSize : ((name.drop (position + 1)).take (name.length - position - 2)).length = name.length - position - 2 := by
    simp only [List.length_take, List.length_drop]
    omega
  have closingAt : name[name.length - 1]? = some 93 := by simpa [List.getLast?_eq_getElem?] using closing
  apply List.ext_getElem?
  intro index
  by_cases outside : name.length ≤ index
  · have allSize : (name.take position ++ [91] ++
        ((name.drop (position + 1)).take (name.length - position - 2)) ++ [93]).length ≤ index := by
      simp only [List.length_append, leftSize, middleSize, List.length_singleton]
      omega
    simp [List.getElem?_eq_none outside, List.getElem?_eq_none allSize]
  · by_cases before : index < position
    · simp [List.getElem?_append, leftSize, before, List.getElem?_take, List.getElem?_drop]
    · by_cases atOpen : index = position
      · subst index
        simpa [List.getElem?_append, leftSize] using opening
      · by_cases middle : index < name.length - 1
        · have afterOpen : position + 1 ≤ index := by omega
          have withinMiddle : index - position - 1 < name.length - position - 2 := by omega
          simp only [List.getElem?_append, leftSize, middleSize, List.length_singleton]
          simp [before, atOpen, afterOpen, withinMiddle, List.getElem?_take, List.getElem?_drop,
            show index - position - 1 + (position + 1) = index by omega]
        · have last : index = name.length - 1 := by omega
          subst index
          simpa [List.getElem?_append, leftSize, middleSize, List.length_singleton,
            show ¬name.length - 1 < position by omega,
            show ¬name.length - 1 - position < 1 by omega,
            show name.length - 1 - position - 1 = name.length - position - 2 by omega] using closingAt

/-- The executable scan admits exactly the existing structural form grammar. -/
theorem form_echo_valid_iff_grammar (name : Bytes) : formEchoValid name = true ↔ FormEchoGrammar name := by
  constructor
  · intro valid
    by_cases empty : name.isEmpty = true
    · simp [formEchoValid, empty] at valid
    · by_cases large : 130 < name.length
      · simp [formEchoValid, empty, large] at valid
      · let position := name.findIdx (· == 91)
        by_cases found : position < name.length
        · have safe : ¬(position = 0 ∨ position + 2 ≥ name.length ∨ name.getLast? ≠ some 93) := by
            intro invalid
            simp [formEchoValid, empty, large, ← show name.findIdx (· == 91) = position from rfl, found, invalid] at valid
          have grammar : OperationIdentity.validToken (name.take position) 64 = true ∧
              OperationIdentity.validToken ((name.drop (position + 1)).take (name.length - position - 2)) 64 = true := by
            simpa [formEchoValid, empty, large, ← show name.findIdx (· == 91) = position from rfl, found, safe] using valid
          have opening : name[position]? = some 91 := by
            have hit := List.findIdx_getElem (xs := name) (p := (· == 91)) (w := found)
            have equal : name[position] = 91 := by simpa [position] using hit
            simpa [List.getElem?_eq_getElem found] using congrArg some equal
          have space : position + 2 < name.length := by omega
          have closing : name.getLast? = some 93 := by tauto
          exact Or.inr ⟨name.take position, (name.drop (position + 1)).take (name.length - position - 2),
            scanned_name_decomposes _ _ found opening space closing, grammar⟩
        · exact Or.inl (by simpa [formEchoValid, empty, large, ← show name.findIdx (· == 91) = position from rfl, found] using valid)
  · intro grammar
    rcases grammar with plain | ⟨base, inner, same, baseValid, innerValid⟩
    · obtain ⟨nonempty, bound, delimiters⟩ := token_shape_bounds name plain
      have noOpen : name.findIdx (· == 91) = name.length := List.findIdx_eq_length_of_false
        (fun byte member => by simpa using (delimiters byte member).1)
      have nonemptyBool : name.isEmpty = false := by cases name <;> simp_all
      simp [formEchoValid, nonemptyBool, show ¬130 < name.length by omega, noOpen, plain]
    · obtain ⟨baseNonempty, baseBound, delimiters⟩ := token_shape_bounds base baseValid
      obtain ⟨innerNonempty, innerBound, innerDelimiters⟩ := token_shape_bounds inner innerValid
      subst name
      have position : (base ++ [91] ++ inner ++ [93]).findIdx (· == 91) = base.length := by
        simpa [List.append_assoc, List.findIdx_cons] using first_open_after_prefix base ([91] ++ inner ++ [93])
          (fun byte member => (delimiters byte member).1)
      have nameSize : (base ++ [91] ++ inner ++ [93]).length = base.length + inner.length + 2 := by simp; omega
      have nonempty : (base ++ [91] ++ inner ++ [93]).isEmpty = false := by simp
      have openingInside : base.length < (base ++ [91] ++ inner ++ [93]).length := by omega
      have safe : ¬(base.length = 0 ∨ base.length + 2 ≥ (base ++ [91] ++ inner ++ [93]).length ∨
          (base ++ [91] ++ inner ++ [93]).getLast? ≠ some 93) := by simp; omega
      have baseTake : (base ++ [91] ++ inner ++ [93]).take base.length = base := by simp [List.append_assoc]
      have innerSlice : ((base ++ [91] ++ inner ++ [93]).drop (base.length + 1)).take
          ((base ++ [91] ++ inner ++ [93]).length - base.length - 2) = inner := by
        simp [List.append_assoc, nameSize, show base.length + inner.length + 2 - base.length - 2 = inner.length by omega]
      simp [formEchoValid, position, nonempty, show ¬130 < (base ++ [91] ++ inner ++ [93]).length by omega,
        openingInside, safe, baseTake, innerSlice, baseValid, innerValid]

end Auths.Product.TemplateMembers
