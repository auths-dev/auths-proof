import Auths.Support.NativePureExpressions

/-!
Lexical closures for the reflected native Pure fragment. Closures retain the
entire explicit data environment, pattern and body; no host-language function
or opaque native environment supplies their result. The first-order evaluator
remains unchanged. This interpreter has its own fuel-bounded applications and
checks complete closed syntax before entry. Rust lifetime/loan and the original
native translation adequacy remain separate. Scripts await final elaboration.
-/
namespace Auths.Support.NativePureClosures
open NativePurePayload NativePureExpressions
universe u

mutual
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
        | _ => do
            let function ← evaluate builtins schemas fuel scopes head
            let arguments ← arguments.mapM (evaluate builtins schemas fuel scopes)
            let value ← applyValues builtins schemas fuel function arguments
            if value.type = term.type then some value else none
    | fuel + 1, scopes, .lambda type pattern body =>
        if type = .arrow pattern.type body.type ∧ checkPattern builtins schemas fuel pattern.type pattern then
          some (.closure type pattern body scopes)
        else none
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

  def applyValues {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) :
      Nat → Dynamic Atom → List (Dynamic Atom) → Option (Dynamic Atom)
    | 0, _, _ => none
    | _, value, [] => some value
    | fuel + 1, .closure type pattern body scopes, argument :: rest => do
        if type ≠ .arrow pattern.type body.type then none else do
          let bindings ← matchPattern fuel pattern argument
          let value ← evaluate builtins schemas fuel (bindings :: scopes) body
          if value.type ≠ body.type then none else applyValues builtins schemas fuel value rest
    | _, _, _ => none
end

def executeBody {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) (arguments : List (Option (Dynamic Atom))) : Option (Dynamic Atom) := do
  let function ← evaluate builtins schemas fuel [] term
  let arguments ← arguments.mapM id
  applyValues builtins schemas fuel function arguments

def execute {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) (arguments : List (Option (Dynamic Atom))) : Option (Dynamic Atom) :=
  if check builtins schemas fuel [] term then executeBody builtins schemas fuel term arguments else none

theorem checked_runs_body {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (term : Term) (accepted : check builtins schemas fuel [] term = true) (arguments : List (Option (Dynamic Atom))) :
    execute builtins schemas fuel term arguments = executeBody builtins schemas fuel term arguments := by
  simp [execute, accepted]

def invoke {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema) (fuel : Nat)
    (bundle : Dynamic Atom) (index : Nat) (arguments : List (Option (Dynamic Atom))) : Option (Dynamic Atom) := do
  match bundle with
  | .constructor (.tuple types) none functions => do
      if functions.map Dynamic.type ≠ types then none else do
        let function ← functions[index]?
        let arguments ← arguments.mapM id
        applyValues builtins schemas fuel function arguments
  | _ => none

theorem missing_bundle_member_is_refused {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema)
    (fuel index : Nat) (types : List Ty) (functions : List (Dynamic Atom))
    (arguments : List (Option (Dynamic Atom))) (missing : functions[index]? = none) :
    invoke builtins schemas fuel (.constructor (.tuple types) none functions) index arguments = none := by
  simp [invoke, missing]

theorem non_function_cannot_consume_argument {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema)
    (fuel : Nat) (type : Ty) (value : Atom type) (argument : Dynamic Atom) (rest : List (Dynamic Atom)) :
    applyValues builtins schemas fuel (.atom type value) (argument :: rest) = none := by
  cases fuel <;> rfl

theorem exhausted_evaluation_is_refused {Atom : Ty → Type u} (builtins : Builtins) (schemas : List Schema)
    (scopes : List (List (Dynamic Atom))) (term : Term) : evaluate builtins schemas 0 scopes term = none := rfl

end Auths.Support.NativePureClosures
