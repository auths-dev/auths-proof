/-!
Structural metadata for native Pure types. Generic dictionaries, constants,
de Bruijn depths and dynamic parameters remain explicit rather than being
discarded to fit a field-value codec. The source emitter reconstructs the
original native type before accepting its reflection. This syntax alone
provides no runtime dictionary, payload or Rust layout/loan interpretation.
-/
namespace Auths.Support.NativeTypeSyntax

inductive Tag where
  | adt | nominal | tuple | builtin | arguments | types | constants | traits
  | typeVariable | free | bound | literalType | arrow | never | error | dynamic
  | trait | traitDeclaration | self | implementation | clause | parent | builtinTrait | unknownTrait
  | associatedType | globalConstant | variableConstant | valueConstant
  | scalar | boolean | byteString | string | naturalValue | integerValue
  | parameters | typeParameter | constantParameter | traitParameter
  | predicates | associatedConstraint
  deriving DecidableEq, Repr

inductive Expr where
  | natural (value : Nat)
  | integer (value : Int)
  | bytes (value : List Nat)
  | node (tag : Tag) (fields : List Expr)
  deriving DecidableEq, Repr

def tuple (types : List Expr) : Expr :=
  .node .adt [.node .tuple [], .node .arguments
    [.node .types types, .node .constants [], .node .traits []]]

def validBytes : Expr → Bool
  | .bytes values => values.all fun value => decide (value < 256)
  | _ => false

def validVariable : Expr → Bool
  | .node .free [.natural _] | .node .bound [.natural _, .natural _] => true
  | _ => false

def validIdentity : Expr → Bool
  | .node .nominal [.natural _] | .node .tuple [] => true
  | .node .builtin [.natural code] => decide (code < 10)
  | _ => false

def validLiteral : Expr → Bool
  | .node .scalar [.natural kind, .integer value] =>
      decide (kind < 12) && (decide (kind ≥ 6) || decide (value ≥ 0))
  | .node .boolean [.natural value] => decide (value < 2)
  | .node .byteString values => values.all fun value =>
      match value with .natural value => decide (value < 256) | _ => false
  | .node .string [value] => validBytes value
  | .node .naturalValue [.integer value] => decide (value ≥ 0)
  | .node .integerValue [.integer _] => true
  | _ => false

/-- Syntax validation retains dictionaries and binder depths. It is not a
trait-resolution, type-variable scope, scalar-range or Rust layout theorem. -/
mutual
  def validType : Nat → Expr → Bool
    | 0, _ => false
    | fuel + 1, .node .adt [identity, arguments] => validIdentity identity && validArguments fuel arguments
    | _, .node .typeVariable [value] => validVariable value
    | _, .node .literalType [.natural kind] => decide (kind < 20)
    | fuel + 1, .node .arrow [input, output] => validType fuel input && validType fuel output
    | fuel + 1, .node .associatedType [trait, .natural _] => validTrait fuel trait
    | _, .node .never [] | _, .node .error [] => true
    | fuel + 1, .node .dynamic [parameters] => validParameters fuel parameters
    | _, _ => false
  def validArguments : Nat → Expr → Bool
    | 0, _ => false
    | fuel + 1, .node .arguments [.node .types types, .node .constants constants, .node .traits traits] =>
        types.all (validType fuel) && constants.all (validConstant fuel) && traits.all (validTrait fuel)
    | _, _ => false
  def validConstant : Nat → Expr → Bool
    | 0, _ => false
    | _, .node .globalConstant [.natural _] => true
    | _, .node .variableConstant [value] => validVariable value
    | _, .node .valueConstant [value] => validLiteral value
    | _, _ => false
  def validTrait : Nat → Expr → Bool
    | 0, _ => false
    | fuel + 1, .node .trait [instance, .node .traitDeclaration [.natural _, arguments]] =>
        validInstance fuel instance && validArguments fuel arguments
    | _, _ => false
  def validInstance : Nat → Expr → Bool
    | 0, _ => false
    | _, .node .self [] => true
    | fuel + 1, .node .implementation [.natural _, arguments] => validArguments fuel arguments
    | _, .node .clause [value] => validVariable value
    | fuel + 1, .node .parent [instance, .natural _, .natural _] => validInstance fuel instance
    | _, .node .builtinTrait [.natural kind] => decide (kind < 6)
    | _, .node .unknownTrait [name] => validBytes name
    | _, _ => false
  def validParameters : Nat → Expr → Bool
    | 0, _ => false
    | fuel + 1, .node .parameters [.node .types types, .node .constants constants, .node .traits traits] =>
        types.all (fun parameter => match parameter with
          | .node .typeParameter [.natural _, name] => validBytes name | _ => false) &&
        constants.all (fun parameter => match parameter with
          | .node .constantParameter [.natural _, name, .natural kind] => validBytes name && decide (kind < 20)
          | _ => false) &&
        traits.all (fun parameter => match parameter with
          | .node .traitParameter [.natural _, .natural _, arguments] => validArguments fuel arguments
          | _ => false)
    | _, _ => false
end

def validPredicates (fuel : Nat) : Expr → Bool
  | .node .predicates constraints => constraints.all fun constraint => match constraint with
      | .node .associatedConstraint [trait, .natural _, type] => validTrait fuel trait && validType fuel type
      | _ => false
  | _ => false

end Auths.Support.NativeTypeSyntax
