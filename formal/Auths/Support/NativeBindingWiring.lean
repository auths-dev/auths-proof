import Auths.Support.NativeProjectorLevels

/-!
Typed, injective names between the actual focused native registry and the
existing generated ending program. These are not names for a fabricated
complete original synthesis environment. The constructor retains every source
expression and closes the new native program before reflecting its whole AST.
No lookup follows a variable's default. Scripts await final elaboration.
-/
namespace Auths.Support.NativeBindingWiring
open NativeDefaultBindings

structure Pair where
  native : Variable
  lowered : Variable
  deriving DecidableEq, Repr

def valid (pairs : List Pair) : Bool :=
  decide ((pairs.map (·.native.identity)).Nodup) &&
    decide ((pairs.map (·.lowered.identity)).Nodup) &&
    pairs.all (fun pair => pair.native.type == pair.lowered.type)

def rename (pairs : List Pair) : Expression → Option Expression
  | .unit => some .unit
  | .variable variable => do
      let pair ← pairs.find? (fun pair => pair.native == variable)
      pure (.variable pair.lowered)

structure Use where
  native : Expression
  lowered : Expression
  deriving DecidableEq, Repr

def usesValid (pairs : List Pair) (uses : List Use) : Bool :=
  valid pairs && uses.all (fun use => decide (rename pairs use.native = some use.lowered))

example : rename [] .unit = some .unit := rfl
example (variable : Variable) : rename [] (.variable variable) = none := rfl

theorem rename_names_immediate_variable (pairs : List Pair) (variable : Variable) :
    rename pairs (.variable variable) =
      (pairs.find? (fun pair => pair.native == variable)).map (fun pair => .variable pair.lowered) := by rfl

example (type : NativePurePayload.Ty) (left right : Nat) :
    valid [⟨⟨0, type⟩, ⟨left, type⟩⟩, ⟨⟨0, type⟩, ⟨right, type⟩⟩] = false := by
  simp [valid]

example (type : NativePurePayload.Ty) (left right : Nat) :
    valid [⟨⟨left, type⟩, ⟨0, type⟩⟩, ⟨⟨right, type⟩, ⟨0, type⟩⟩] = false := by
  simp [valid]

end Auths.Support.NativeBindingWiring
