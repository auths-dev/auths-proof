import Auths.Product.TemplateAstKeyAdmission
import Auths.Product.TemplateAstTraversal

namespace Auths.Product.TemplateAst

theorem json_object_nonlexical_refuses (fields : List (RequestConstruction.Bytes × Value))
    (echo : Option (List RequestConstruction.Bytes)) (depth : Nat) (output : JsonBuild)
    (invalid : ¬LexicalKeys (fields.map Prod.fst)) :
    jsonObject fields echo depth output = .error .shape := by
  unfold jsonObject
  split
  · cases echo with
    | none => simp [objectTarget, objectInsertion, nonlexical_members_refuse _ _ _ invalid, memberError]
    | some tokens => simp [objectTarget, nonlexical_target_refuses _ _ invalid, memberError]
  · rfl

/-- Hoisting the lexical guard before allocating the owned key column changes
neither complete original outcome nor ordinary-key-before-echo error order. -/
theorem json_object_key_preflight (fields : List (RequestConstruction.Bytes × Value))
    (echo : Option (List RequestConstruction.Bytes)) (depth : Nat) (output : JsonBuild) :
    jsonObject fields echo depth output = do
      let keys ← keyNames 32 (fields.map Prod.fst)
      let target ← objectTarget keys echo
      let insertion ← objectInsertion target echo
      let order ← (TemplateMembers.canonicalMembers keys insertion .json).mapError memberError
      let opened ← pushJson output (.raw [123])
      let folded ← objectFrom fields order target echo insertion depth 0 opened
      pushJson folded (.raw [125]) := by
  by_cases count : 0 < fields.length ∧ fields.length ≤ 32
  · by_cases lexical : LexicalKeys (fields.map Prod.fst)
    · simp [jsonObject, keyNames, count, lexical]
    · rw [json_object_nonlexical_refuses fields echo depth output lexical]
      simp [keyNames, lexical]
  · simp [jsonObject, keyNames, count]

def formProgram (fields : List (RequestConstruction.Bytes × FormValue))
    (insertion : Option RequestConstruction.Bytes) : Except Error NamedTemplate := do
  let order ← (TemplateMembers.canonicalMembers (fields.map Prod.fst) insertion .form).mapError memberError
  let output ← formMembers fields order insertion
  .ok (.form output.pieces)

theorem form_program_key_preflight (fields : List (RequestConstruction.Bytes × FormValue))
    (insertion : Option RequestConstruction.Bytes) :
    formProgram fields insertion = do
      let keys ← keyNames 16 (fields.map Prod.fst)
      let order ← (TemplateMembers.canonicalMembers keys insertion .form).mapError memberError
      let output ← formMembers fields order insertion
      .ok (.form output.pieces) := by
  by_cases count : 0 < fields.length ∧ fields.length ≤ 16
  · by_cases lexical : LexicalKeys (fields.map Prod.fst)
    · simp [formProgram, keyNames, count, lexical]
    · simp [formProgram, keyNames, lexical, nonlexical_members_refuse _ _ _ lexical, memberError]
  · have invalidColumn : ¬TemplateMembers.KeyColumn (fields.map Prod.fst) .form := by
      intro column
      exact count (by simpa [TemplateMembers.maximum] using And.intro column.1 column.2.1)
    simp [formProgram, keyNames, count, TemplateMembers.canonicalMembers, invalidColumn, memberError]

/-- Count refusal precedes echo-kind refusal; lexical preallocation admission
is reached only after the declared echo has the matching form kind. -/
theorem compile_body_form_normalized (fields : List (RequestConstruction.Bytes × FormValue)) (echo : Option Echo) :
    compileBody (.form fields) echo =
      if 0 < fields.length ∧ fields.length ≤ 16 then do
        let insertion ← match echo with
          | none => .ok none
          | some (.form name) => .ok (some name)
          | some (.json _) => .error .echoConflict
        formProgram fields insertion
      else .error .shape := by
  simp [compileBody, formProgram, formMembers, formFrom, formStep]

end Auths.Product.TemplateAst
