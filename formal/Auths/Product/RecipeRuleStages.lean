import Auths.Product.RecipeRuleAdmission

namespace Auths.Product.RecipeRuleAdmission

def sourceFieldUse (fields : Fields) (state : State) : Outcome :=
  if RecipeConsumption.allFieldsConsumed fields state then accepted state else refused .unsafeTemplate state

def sourceBoundTail (fields : Fields) (source : Source) (state : State) : Outcome :=
  andThen (boundRules fields source state) (sourceFieldUse fields)

def sourceHeaderTail (fields : Fields) (source : Source) (state : State) : Outcome :=
  andThen (applyPure (headerGuardRules source) state) (sourceBoundTail fields source)

def sourceFactTail (fields : Fields) (source : Source) (state : State) : Outcome :=
  andThen (factRules fields source state) (sourceHeaderTail fields source)

def sourceResponseTail (fields : Fields) (source : Source) (state : State) : Outcome :=
  andThen (responseRules fields source state) (sourceFactTail fields source)

theorem validate_from_original_stages (fields : Fields) (source : Source) (state : State) :
    validateFrom fields source state =
      andThen (writeRules fields source state) (sourceResponseTail fields source) := rfl

/-- The final refusal records missing use; it does not silently remove an
original unconsumed field or mark it rendered/bound to make admission succeed. -/
theorem source_field_use_keeps_state (fields : Fields) (state : State) :
    (sourceFieldUse fields state).2 = state := by
  unfold sourceFieldUse
  split <;> rfl

end Auths.Product.RecipeRuleAdmission
