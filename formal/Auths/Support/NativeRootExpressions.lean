import Auths.Support.NativeRootPayload

/-!
Closed native Pure expression semantics with complete native types, including
constant and dictionary arguments. Patterns retain ignored binders and ordered
fallback branches. There are no host callbacks or supplied function results.
This fragment supports native context reconstruction; it does not establish
Rust/native ending or heap/loan adequacy. Scripts await final elaboration.
-/
namespace Auths.Support.NativeRootExpressions
open NativeRootPayload
abbrev Ty := NativeTypeSyntax.Expr
universe u

inductive Pattern where
  | bound (type : Ty) (name : Option (List Nat))
  | ignored (type : Ty)
  | constructor (type : Ty) (variant : Option Nat) (fields : List Pattern)
  deriving DecidableEq, Repr

def Pattern.type : Pattern → Ty
  | .bound type _ | .ignored type | .constructor type _ _ => type

def Pattern.bindings : Pattern → List Ty
  | .bound type _ => [type]
  | .ignored _ => []
  | .constructor _ _ fields => fields.flatMap Pattern.bindings

inductive Term where
  | bound (type : Ty) (scope slot : Nat)
  | constructor (type owner : Ty) (variant : Option Nat)
  | application (type : Ty) (function argument : Term)
  | lambda (type : Ty) (pattern : Pattern) (body : Term)
  | binding (type : Ty) (pattern : Pattern) (value body : Term)
  | switch (type : Ty) (scrutinee : Term) (branches : List (Pattern × Term))
  deriving DecidableEq, Repr

def Term.type : Term → Ty
  | .bound type _ _ | .constructor type _ _ | .application type _ _
  | .lambda type _ _ | .binding type _ _ _ | .switch type _ _ => type

def arrow (input output : Ty) : Ty := .node .arrow [input, output]
def arrows (inputs : List Ty) (output : Ty) : Ty := inputs.foldr arrow output

def rows (schemas : List Schema) (type : Ty) : Option (List (Option Nat × List Ty)) :=
  match type with
  | .node .adt [.node .tuple [], .node .arguments [.node .types types, .node .constants [], .node .traits []]] =>
      some [(none, types)]
  | .node .adt [.node .builtin [.natural 0], .node .arguments [.node .types [result], .node .constants [], .node .traits []]] =>
      some [(some 0, [result]), (some 1, [.node .adt [.node .builtin [.natural 3],
        .node .arguments [.node .types [], .node .constants [], .node .traits []]]])]
  | .node .adt [.node .builtin [.natural 3], .node .arguments [.node .types [], .node .constants [], .node .traits []]] =>
      some [(some 0, []), (some 1, [])]
  | _ => (schemaRows schemas type).map fun variants =>
      variants.map fun row => (row.1, row.2.map Field.type)

def fields (schemas : List Schema) (type : Ty) (variant : Option Nat) : Option (List Ty) := do
  let variants ← rows schemas type
  (variants.find? fun row => row.1 == variant).map Prod.snd

/- These are the original native Pure TResult/TError constructor rows:
   result_ok_id = 0, result_fail_id = 1, error_failure_id = 0 and
   error_out_of_fuel_id = 1. Neither row invents an actual failure value. -/
theorem native_result_success_keeps_complete_payload_type (schemas : List Schema) (payload : Ty) :
    fields schemas (.node .adt [.node .builtin [.natural 0], .node .arguments
      [.node .types [payload], .node .constants [], .node .traits []]]) (some 0) = some [payload] := by rfl

theorem native_result_failure_has_the_original_error_type (schemas : List Schema) (payload : Ty) :
    fields schemas (.node .adt [.node .builtin [.natural 0], .node .arguments
      [.node .types [payload], .node .constants [], .node .traits []]]) (some 1) =
      some [.node .adt [.node .builtin [.natural 3], .node .arguments
        [.node .types [], .node .constants [], .node .traits []]]] := by rfl

def checkPattern (schemas : List Schema) : Nat → Ty → Pattern → Bool
  | 0, _, _ => false
  | fuel + 1, expected, .bound actual _ | fuel + 1, expected, .ignored actual =>
      expected == actual && NativeTypeSyntax.validType (fuel + 1) actual
  | fuel + 1, expected, .constructor actual variant patterns =>
      expected == actual && NativeTypeSyntax.validType (fuel + 1) actual &&
        match fields schemas actual variant with
        | none => false
        | some types => types.length == patterns.length &&
            (types.zip patterns).all fun pair => checkPattern schemas fuel pair.1 pair.2

/-- Closed syntax/type checking. Totality of an arbitrary term is separate;
ordered match failure is represented by `none`, never a fabricated value. -/
def check (schemas : List Schema) : Nat → List (List Ty) → Term → Bool
  | 0, _, _ => false
  | fuel + 1, scopes, .bound type scope slot =>
      NativeTypeSyntax.validType (fuel + 1) type && decide (scopes[scope]?.bind (·[slot]?) = some type)
  | fuel + 1, _, .constructor type owner variant =>
      NativeTypeSyntax.validType (fuel + 1) type &&
        match fields schemas owner variant with
        | none => false | some inputs => type == arrows inputs owner
  | fuel + 1, scopes, .application type function argument =>
      function.type == arrow argument.type type && check schemas fuel scopes function && check schemas fuel scopes argument
  | fuel + 1, scopes, .lambda type pattern body =>
      type == arrow pattern.type body.type && checkPattern schemas fuel pattern.type pattern &&
        check schemas fuel (pattern.bindings :: scopes) body
  | fuel + 1, scopes, .binding type pattern value body =>
      type == body.type && value.type == pattern.type && check schemas fuel scopes value &&
        checkPattern schemas fuel value.type pattern && check schemas fuel (pattern.bindings :: scopes) body
  | fuel + 1, scopes, .switch type scrutinee branches =>
      check schemas fuel scopes scrutinee && !branches.isEmpty && branches.all fun branch =>
        checkPattern schemas fuel scrutinee.type branch.1 && branch.2.type == type &&
          check schemas fuel (branch.1.bindings :: scopes) branch.2

inductive Dynamic (Atom : Ty → Type u) where
  | atom (type : Ty) (value : Atom type)
  | constructor (type : Ty) (variant : Option Nat) (fields : List (Dynamic Atom))
  | closure (type : Ty) (pattern : Pattern) (body : Term) (scopes : List (List (Dynamic Atom)))

def Dynamic.type {Atom : Ty → Type u} : Dynamic Atom → Ty
  | .atom type _ | .constructor type _ _ | .closure type _ _ _ => type

def matchPattern {Atom : Ty → Type u} : Nat → Pattern → Dynamic Atom → Option (List (Dynamic Atom))
  | 0, _, _ => none
  | _, .bound type _, value => if type = value.type then some [value] else none
  | _, .ignored type, value => if type = value.type then some [] else none
  | fuel + 1, .constructor type variant patterns, .constructor actual actualVariant values => do
      if type ≠ actual ∨ variant ≠ actualVariant ∨ patterns.length ≠ values.length then none else do
        let bindings ← (patterns.zip values).mapM fun pair => matchPattern fuel pair.1 pair.2
        pure bindings.flatten
  | _, _, _ => none

def selectBranch {Atom : Ty → Type u} (fuel : Nat) (value : Dynamic Atom) :
    List (Pattern × Term) → Option (List (Dynamic Atom) × Term)
  | [] => none
  | (pattern, body) :: rest => match matchPattern fuel pattern value with
      | some bindings => some (bindings, body)
      | none => selectBranch fuel value rest

def applications : Term → List Term → Term × List Term
  | .application _ function argument, arguments => applications function (argument :: arguments)
  | head, arguments => (head, arguments)

/-- Lambda values capture only explicit native scopes. Evaluation never calls
an OCaml/Rust/Lean host function to obtain a missing native result. -/
def evaluate {Atom : Ty → Type u} (schemas : List Schema) :
    Nat → List (List (Dynamic Atom)) → Term → Option (Dynamic Atom)
  | 0, _, _ => none
  | _, scopes, .bound type scope slot => do
      let value ← scopes[scope]?.bind (·[slot]?)
      if value.type = type then some value else none
  | _, scopes, .lambda type pattern body => some (.closure type pattern body scopes)
  | fuel + 1, scopes, term@(.constructor _ _ _) | fuel + 1, scopes, term@(.application _ _ _) => do
      let (head, arguments) := applications term []
      match head with
      | .constructor type owner variant => do
          let inputs ← fields schemas owner variant
          if inputs.length ≠ arguments.length ∨ type ≠ arrows inputs owner ∨ term.type ≠ owner then none else do
            let values ← arguments.mapM (evaluate schemas fuel scopes)
            if values.map Dynamic.type = inputs then some (.constructor owner variant values) else none
      | _ =>
          match term with
          | .application type function argument => do
              let function ← evaluate schemas fuel scopes function
              let argument ← evaluate schemas fuel scopes argument
              match function with
              | .closure actual pattern body captured => do
                  if actual ≠ arrow argument.type type then none else do
                    let bindings ← matchPattern fuel pattern argument
                    let result ← evaluate schemas fuel (bindings :: captured) body
                    if result.type = type then some result else none
              | _ => none
          | _ => none
  | fuel + 1, scopes, .binding type pattern value body => do
      let value ← evaluate schemas fuel scopes value
      let bindings ← matchPattern fuel pattern value
      let result ← evaluate schemas fuel (bindings :: scopes) body
      if result.type = type then some result else none
  | fuel + 1, scopes, .switch type scrutinee branches => do
      let value ← evaluate schemas fuel scopes scrutinee
      let branch ← selectBranch fuel value branches
      let result ← evaluate schemas fuel (branch.1 :: scopes) branch.2
      if result.type = type then some result else none

mutual
  def pack {Atom : Ty → Type u} : Nat → {layout : Layout} → Value Atom layout → Option (Dynamic Atom)
    | 0, _, _ => none
    | _, .atom type, .atom value => some (.atom type value)
    | _, .unit, .unit => some (.constructor (NativeTypeSyntax.tuple []) none [])
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
    | fuel + 1, .named (.variant identity) _, .named value => (packFields fuel 0 value).map (some identity, ·)
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

def applyArguments {Atom : Ty → Type u} (schemas : List Schema) :
    Nat → List (List (Dynamic Atom)) → Term → List (Dynamic Atom) → Option (Dynamic Atom)
  | 0, _, _, _ => none
  | fuel + 1, scopes, body, [] => evaluate schemas fuel scopes body
  | fuel + 1, scopes, .lambda _ pattern body, value :: rest => do
      let bindings ← matchPattern fuel pattern value
      applyArguments schemas fuel (bindings :: scopes) body rest
  | _, _, _, _ => none

/-- Reject malformed dynamic argument trees before an ignored/fallback pattern
can match them. Source codec values retain every constructor field; opaque
atoms are permitted only where the complete schema has no constructor rows. -/
def validValue {Atom : Ty → Type u} (schemas : List Schema) : Nat → Dynamic Atom → Bool
  | 0, _ => false
  | fuel + 1, .atom type _ => NativeTypeSyntax.validType (fuel + 1) type && (rows schemas type).isNone
  | fuel + 1, .constructor type variant values =>
      NativeTypeSyntax.validType (fuel + 1) type && match fields schemas type variant with
        | none => false
        | some types => values.map Dynamic.type == types && values.all (validValue schemas fuel)
  | _, .closure _ _ _ _ => false

def execute {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (term : Term) (arguments : List (Dynamic Atom)) : Option (Dynamic Atom) :=
  if check schemas fuel [] term && arguments.all (validValue schemas fuel) then
    applyArguments schemas fuel [] term arguments else none

def executeValues {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (term : Term) (arguments : List (Option (Dynamic Atom))) : Option (Dynamic Atom) := do
  let values ← arguments.mapM id
  execute schemas fuel term values

/-- Apply a returned native closure through its captured scopes and actual
body. No host callback or supplied expected result implements the call. -/
def applyReturnedValue {Atom : Ty → Type u} (schemas : List Schema) :
    Nat → Dynamic Atom → List (Dynamic Atom) → Option (Dynamic Atom)
  | 0, _, _ => none
  | _, function, [] => some function
  | fuel + 1, .closure type pattern body captured, argument :: rest => do
      match type with
      | .node .arrow [input, output] =>
          if argument.type ≠ input then none else do
            let bindings ← matchPattern fuel pattern argument
            let result ← evaluate schemas fuel (bindings :: captured) body
            if result.type ≠ output then none else applyReturnedValue schemas fuel result rest
      | _ => none
  | _, _, _ => none

def applyReturned {Atom : Ty → Type u} (schemas : List Schema) (fuel : Nat)
    (function : Dynamic Atom) (arguments : List (Dynamic Atom)) : Option (Dynamic Atom) :=
  if arguments.all (validValue schemas fuel) then applyReturnedValue schemas fuel function arguments else none

theorem a_nonfunction_cannot_receive_a_returned_closure_call {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (type : Ty) (value : Atom type)
    (first : Dynamic Atom) (rest : List (Dynamic Atom)) :
    applyReturnedValue schemas fuel (.atom type value) (first :: rest) = none := by
  cases fuel <;> rfl

/-- Even an ignored argument pattern cannot conceal a changed original
native input type when invoking the closure that the function returned. -/
theorem a_returned_closure_refuses_a_changed_argument_type {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (input output : Ty) (pattern : Pattern)
    (body : Term) (captured : List (List (Dynamic Atom))) (argument : Dynamic Atom)
    (rest : List (Dynamic Atom)) (changed : argument.type ≠ input) :
    applyReturnedValue schemas (fuel + 1)
      (.closure (.node .arrow [input, output]) pattern body captured) (argument :: rest) = none := by
  simp [applyReturnedValue, changed]

/-- Independent logical reconstruction. An unmatched partial enum view keeps
the supplied current context. A whole owned value can still replace its tag.
Whether a Rust ending supplies these particular current/returned values is a
separate source-state correspondence obligation. -/
def reconstruct {Atom : SourceClosureRegions.Expr → Type u} {shape : BorrowProjection.Shape}
    (plan : BorrowProjection.Plan shape) (current returned : BorrowProjection.Data Atom shape) :
    BorrowProjection.Data Atom shape :=
  (BorrowProjection.put plan current (BorrowProjection.get plan returned)).getD current

theorem reconstruct_current_is_identity {Atom : SourceClosureRegions.Expr → Type u}
    {shape : BorrowProjection.Shape} (plan : BorrowProjection.Plan shape) (current : BorrowProjection.Data Atom shape) :
    reconstruct plan current current = current := by simp [reconstruct, BorrowProjection.get_then_put]

theorem reconstruct_unmatched_view_preserves_current {Atom : SourceClosureRegions.Expr → Type u}
    {shape : BorrowProjection.Shape} (plan : BorrowProjection.Plan shape)
    (current returned : BorrowProjection.Data Atom shape)
    (unmatched : BorrowProjection.put plan current (BorrowProjection.get plan returned) = none) :
    reconstruct plan current returned = current := by simp [reconstruct, unmatched]

theorem malformed_arguments_cannot_select_a_fallback {Atom : Ty → Type u}
    (schemas : List Schema) (fuel : Nat) (term : Term) (arguments : List (Dynamic Atom))
    (malformed : arguments.all (validValue schemas fuel) = false) :
    execute schemas fuel term arguments = none := by simp [execute, malformed]

theorem ignored_pattern_binds_no_variable {Atom : Ty → Type u} (fuel : Nat) (type : Ty)
    (value : Dynamic Atom) (same : value.type = type) :
    matchPattern (fuel + 1) (.ignored type) value = some [] := by simp [matchPattern, same]

theorem missed_pattern_selects_explicit_fallback {Atom : Ty → Type u}
    (fuel : Nat)
    (pattern : Pattern) (first fallback : Term) (value : Dynamic Atom)
    (missed : matchPattern (fuel + 1) pattern value = none) (type : Ty) (same : value.type = type) :
    selectBranch (fuel + 1) value [(pattern, first), (.ignored type, fallback)] = some ([], fallback) := by
  simp [selectBranch, missed, matchPattern, same]

theorem fallback_evaluates_in_the_original_scope {Atom : Ty → Type u}
    (fuel : Nat) (schemas : List Schema) (scopes : List (List (Dynamic Atom)))
    (scrutinee first fallback : Term) (pattern : Pattern) (output : Ty) (value : Dynamic Atom)
    (prepared : evaluate schemas (fuel + 1) scopes scrutinee = some value)
    (missed : matchPattern (fuel + 1) pattern value = none) :
    evaluate schemas (fuel + 2) scopes
      (.switch output scrutinee [(pattern, first), (.ignored value.type, fallback)]) =
      (do
        let result ← evaluate schemas (fuel + 1) ([] :: scopes) fallback
        if result.type = output then some result else none) := by
  simp only [evaluate, prepared, selectBranch, missed, matchPattern, if_pos rfl]
  rfl

end Auths.Support.NativeRootExpressions
