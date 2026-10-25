import Auths.Support.NativePurePayload

/-!
An explicit closed fragment of the native Pure expression AST. Type annotations,
constructor generics, patterns, variable scopes and slots are retained. Unknown
syntax is refused by the source reflector. Internal interpreter failure (`none`)
is distinct from a represented native Result failure constructor.
These helper terms do not replace original Rust calls or establish complete
current-environment/continuation/heap adequacy. Scripts await final checks.
-/
namespace Auths.Support.NativePureExpressions
open NativePurePayload
universe u

inductive Constructor where
  | nominal (identity : Nat)
  | tuple | result | error
  deriving DecidableEq, Repr

inductive Pattern where
  | bound (type : Ty) (name : Option (List Nat))
  | constructor (type : Ty) (variant : Option Nat) (fields : List Pattern)
  deriving DecidableEq, Repr

def Pattern.type : Pattern → Ty
  | .bound type _ | .constructor type _ _ => type

def Pattern.bindings : Pattern → List Ty
  | .bound type _ => [type]
  | .constructor _ _ fields => fields.flatMap Pattern.bindings

inductive Term where
  | bound (type : Ty) (scope slot : Nat)
  | constructor (type : Ty) (identity : Constructor) (variant : Option Nat) (arguments : List Ty)
  | application (type : Ty) (function argument : Term)
  | lambda (type : Ty) (pattern : Pattern) (body : Term)
  | switch (type : Ty) (scrutinee : Term) (branches : List (Pattern × Term))
  | binding (type : Ty) (pattern : Pattern) (value body : Term)
  deriving DecidableEq, Repr

def Term.type : Term → Ty
  | .bound type _ _ | .constructor type _ _ _ | .application type _ _
  | .lambda type _ _ | .switch type _ _ | .binding type _ _ _ => type

structure Schema where
  type : Ty
  variants : List (Option Nat × List Ty)
  deriving DecidableEq, Repr

structure Builtins where
  resultOk : Nat
  resultFail : Nat
  errorFailure : Nat
  errorOutOfFuel : Nat
  deriving DecidableEq, Repr

def constructors (builtins : Builtins) (schemas : List Schema) : Ty → Option (List (Option Nat × List Ty))
  | .tuple arguments => some [(none, arguments)]
  | .result output => some [(some builtins.resultOk, [output]), (some builtins.resultFail, [.error])]
  | .error => some [(some builtins.errorFailure, []), (some builtins.errorOutOfFuel, [])]
  | type => (schemas.find? fun schema => schema.type == type).map Schema.variants

def fields (builtins : Builtins) (schemas : List Schema) (type : Ty) (variant : Option Nat) : Option (List Ty) := do
  let rows ← constructors builtins schemas type
  (rows.find? fun row => row.1 == variant).map Prod.snd

def resultType : Constructor → List Ty → Option Ty
  | .nominal identity, arguments => some (.nominal identity arguments)
  | .tuple, arguments => some (.tuple arguments)
  | .result, [output] => some (.result output)
  | .error, [] => some .error
  | _, _ => none

def arrows (inputs : List Ty) (output : Ty) : Ty := inputs.foldr Ty.arrow output

def signature (builtins : Builtins) (schemas : List Schema) (identity : Constructor)
    (variant : Option Nat) (arguments : List Ty) : Option Ty := do
  let output ← resultType identity arguments
  let inputs ← fields builtins schemas output variant
  pure (arrows inputs output)

def checkPattern (builtins : Builtins) (schemas : List Schema) : Nat → Ty → Pattern → Bool
  | 0, _, _ => false
  | _, expected, .bound actual _ => decide (expected = actual)
  | fuel + 1, expected, .constructor actual variant patterns =>
      expected == actual && match fields builtins schemas actual variant with
        | none => false
        | some types => types.length == patterns.length &&
            (types.zip patterns).all fun (type, pattern) => checkPattern builtins schemas fuel type pattern

def check (builtins : Builtins) (schemas : List Schema) : Nat → List (List Ty) → Term → Bool
  | 0, _, _ => false
  | _, scopes, .bound type scope slot => decide (scopes[scope]?.bind (·[slot]?) = some type)
  | _, _, .constructor type identity variant arguments => decide (signature builtins schemas identity variant arguments = some type)
  | fuel + 1, scopes, .application type function argument =>
      function.type == .arrow argument.type type && check builtins schemas fuel scopes function && check builtins schemas fuel scopes argument
  | fuel + 1, scopes, .lambda type pattern body =>
      type == .arrow pattern.type body.type && checkPattern builtins schemas fuel pattern.type pattern &&
        check builtins schemas fuel (pattern.bindings :: scopes) body
  | fuel + 1, scopes, .binding type pattern value body =>
      type == body.type && value.type == pattern.type && checkPattern builtins schemas fuel value.type pattern &&
        check builtins schemas fuel scopes value && check builtins schemas fuel (pattern.bindings :: scopes) body
  | fuel + 1, scopes, .switch type scrutinee branches =>
      check builtins schemas fuel scopes scrutinee && match constructors builtins schemas scrutinee.type with
        | none => false
        | some rows =>
            decide (branches.map (fun branch => match branch.1 with
              | .constructor _ variant _ => variant | _ => none) = rows.map Prod.fst) &&
            branches.all fun (pattern, body) =>
              (match pattern with .constructor _ _ _ => true | _ => false) &&
              checkPattern builtins schemas fuel scrutinee.type pattern && body.type == type &&
              check builtins schemas fuel (pattern.bindings :: scopes) body

inductive Dynamic (Atom : Ty → Type u) where
  | atom (type : Ty) (value : Atom type)
  | constructor (type : Ty) (variant : Option Nat) (fields : List (Dynamic Atom))
  | closure (type : Ty) (pattern : Pattern) (body : Term) (scopes : List (List (Dynamic Atom)))

def Dynamic.type {Atom : Ty → Type u} : Dynamic Atom → Ty
  | .atom type _ | .constructor type _ _ | .closure type _ _ _ => type

def matchPattern {Atom : Ty → Type u} : Nat → Pattern → Dynamic Atom → Option (List (Dynamic Atom))
  | 0, _, _ => none
  | _, .bound type _, value => if type = value.type then some [value] else none
  | fuel + 1, .constructor type variant patterns, .constructor actual actualVariant values => do
      if type ≠ actual ∨ variant ≠ actualVariant ∨ patterns.length ≠ values.length then none else do
        let bindings ← (patterns.zip values).mapM fun (pattern, value) => matchPattern fuel pattern value
        pure bindings.flatten
  | _, _, _ => none

def applications : Term → List Term → Term × List Term
  | .application _ function argument, arguments => applications function (argument :: arguments)
  | head, arguments => (head, arguments)

def selectBranch {Atom : Ty → Type u} (fuel : Nat) (value : Dynamic Atom) :
    List (Pattern × Term) → Option (List (Dynamic Atom) × Term)
  | [] => none
  | (pattern, body) :: rest => match matchPattern fuel pattern value with
      | some bindings => some (bindings, body)
      | none => selectBranch fuel value rest

def evaluate {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) :
    Nat → List (List (Dynamic Atom)) → Term → Option (Dynamic Atom)
  | 0, _, _ => none
  | _, scopes, .bound type scope slot => do
      let value ← scopes[scope]?.bind (·[slot]?)
      if value.type = type then some value else none
  | fuel + 1, scopes, term@(.constructor _ _ _ _) | fuel + 1, scopes, term@(.application _ _ _) => do
      let (head, arguments) := applications term []
      match head with
      | .constructor type identity variant parameters => do
          let output ← resultType identity parameters
          let inputs ← fields builtins schemas output variant
          if inputs.length ≠ arguments.length ∨ type ≠ arrows inputs output ∨ term.type ≠ output then none else do
            let values ← arguments.mapM (evaluate builtins schemas fuel scopes)
            if values.map Dynamic.type = inputs then some (.constructor output variant values) else none
      | _ => none
  | fuel + 1, scopes, .switch type scrutinee branches => do
      let value ← evaluate builtins schemas fuel scopes scrutinee
      let branch ← selectBranch fuel value branches
      let result ← evaluate builtins schemas fuel (branch.1 :: scopes) branch.2
      if result.type = type then some result else none
  | fuel + 1, scopes, .binding type pattern value body => do
      let value ← evaluate builtins schemas fuel scopes value
      let bindings ← matchPattern fuel pattern value
      let result ← evaluate builtins schemas fuel (bindings :: scopes) body
      if result.type = type then some result else none
  | _, _, .lambda _ _ _ => none

mutual
  def pack {Atom : Ty → Type u} : Nat → {layout : Layout} → Value Atom layout → Option (Dynamic Atom)
    | 0, _, _ => none
    | _, .atom type, .atom value => some (.atom type value)
    | fuel + 1, .named (.nominal type) _, .named value => do
        let (variant, values) ← packBody fuel value
        pure (.constructor type variant values)
    | _, _, _ => none
  def packBody {Atom : Ty → Type u} : Nat → {layout : Layout} → Value Atom layout → Option (Option Nat × List (Dynamic Atom))
    | 0, _, _ => none
    | fuel + 1, .sum _ _, .left value => packVariant fuel value
    | fuel + 1, .sum _ _, .right value => packBody fuel value
    | fuel + 1, _, value => (packFields fuel 0 value).map (none, ·)
  def packVariant {Atom : Ty → Type u} : Nat → {layout : Layout} → Value Atom layout → Option (Option Nat × List (Dynamic Atom))
    | fuel + 1, .named (.variant identity) _, .named value =>
        (packFields fuel 0 value).map (some identity, ·)
    | _, _, _ => none
  def packFields {Atom : Ty → Type u} : Nat → Nat → {layout : Layout} → Value Atom layout → Option (List (Dynamic Atom))
    | 0, _, _, _ => none
    | _, _, .unit, .unit => some []
    | fuel + 1, index, .product (.named (.field actual _) _) _, .product (.named value) rest => do
        if index ≠ actual then none else do
          let value ← pack fuel value
          let rest ← packFields fuel (index + 1) rest
          pure (value :: rest)
    | _, _, _, _ => none
end

def executeBody {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) {currentLayout inputLayout} (current : Value Atom currentLayout) (incoming : Value Atom inputLayout) :
    Option (Dynamic Atom) := do
    match term with
    | .lambda _ (.bound currentType _) (.lambda _ (.bound incomingType _) body) => do
        let current ← pack fuel current
        let incoming ← pack fuel incoming
        if current.type ≠ currentType ∨ incoming.type ≠ incomingType then none else
          evaluate builtins schemas fuel [[incoming], [current]] body
    | .lambda _ (.bound incomingType _) body => do
        let incoming ← pack fuel incoming
        if incoming.type ≠ incomingType then none else evaluate builtins schemas fuel [[incoming]] body
    | _ => none

def execute {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) {currentLayout inputLayout} (current : Value Atom currentLayout) (incoming : Value Atom inputLayout) :
    Option (Dynamic Atom) :=
  if check builtins schemas fuel [] term then executeBody builtins schemas fuel term current incoming else none

theorem checked_runs_body {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) (accepted : check builtins schemas fuel [] term = true)
    {currentLayout inputLayout} (current : Value Atom currentLayout) (incoming : Value Atom inputLayout) :
    execute builtins schemas fuel term current incoming = executeBody builtins schemas fuel term current incoming := by
  simp [execute, accepted]

def expected {Atom : Ty → Type u} (builtins : Builtins) (fuel : Nat) (output : Ty)
    {layout : Layout} : Option (Value Atom layout) → Option (Dynamic Atom)
  | none => some (.constructor (.result output) (some builtins.resultFail)
      [.constructor .error (some builtins.errorFailure) []])
  | some value => (pack fuel value).map fun value =>
      .constructor (.result output) (some builtins.resultOk) [value]

def applyArguments {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) :
    Nat → List (List (Dynamic Atom)) → Term → List (Dynamic Atom) → Option (Dynamic Atom)
  | 0, _, _, _ => none
  | fuel + 1, scopes, body, [] => evaluate builtins schemas fuel scopes body
  | fuel + 1, scopes, .lambda _ pattern body, value :: rest => do
      let bindings ← matchPattern fuel pattern value
      applyArguments builtins schemas fuel (bindings :: scopes) body rest
  | _, _, _, _ => none

def executePackedBody {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) (arguments : List (Option (Dynamic Atom))) : Option (Dynamic Atom) := do
  let arguments ← arguments.mapM id
  applyArguments builtins schemas fuel [] term arguments

def executePacked {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) (arguments : List (Option (Dynamic Atom))) : Option (Dynamic Atom) :=
  if check builtins schemas fuel [] term then executePackedBody builtins schemas fuel term arguments else none

theorem checked_packed_runs_body {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) (accepted : check builtins schemas fuel [] term = true) (arguments : List (Option (Dynamic Atom))) :
    executePacked builtins schemas fuel term arguments = executePackedBody builtins schemas fuel term arguments := by
  simp [executePacked, accepted]

def tupleType : List Ty → Ty
  | [type] => type
  | types => .tuple types

def expectedMany {Atom : Ty → Type u} (builtins : Builtins) (types : List Ty) :
    Option (List (Option (Dynamic Atom))) → Option (Dynamic Atom)
  | none => some (.constructor (.result (tupleType types)) (some builtins.resultFail)
      [.constructor .error (some builtins.errorFailure) []])
  | some packed => do
      let values ← packed.mapM id
      if values.map Dynamic.type ≠ types then none else do
        let value ← match values with
          | [value] => some value
          | values => some (.constructor (.tuple types) none values)
        pure (.constructor (.result (tupleType types)) (some builtins.resultOk) [value])

end Auths.Support.NativePureExpressions
