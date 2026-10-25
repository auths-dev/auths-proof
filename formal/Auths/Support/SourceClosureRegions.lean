import Mathlib.Data.List.Basic

/-!
Structural lifetime reconstruction for the actual returned-closure certificate.
The producer reflects every supported type/argument/dictionary constructor, not
a type name, digest, erased skeleton or supplied ordinary function result.
Unsupported source constructors refuse reflection. A missing output region is
represented by an output-slot hole, never by a fabricated native lifetime.

Matching starts with no assignments. Only an actual public input lifetime at
the corresponding field position may fill a hole. Every other constructor,
identifier, binder, metadata item and known lifetime must match exactly.
The native LLBC/typed-reference/loan/opaque-interface relation remains required;
these component definitions and proof scripts await final elaboration/audits.
-/
namespace Auths.Support.SourceClosureRegions

inductive Region where
  | literalStatic
  | parameter (index : Nat)
  | bound (depth index : Nat)
  | body (index : Nat)
  | erased
  deriving DecidableEq, Repr

inductive Tag where
  | adt | tuple | boxType | strType | arguments | regions | types | constants | traits
  | literal | mutRef | sharedRef | mutPtr | sharedPtr | neverType | typeFree | typeBound
  | traitReference | traitImplementation | traitDeclaration | clauseFree | clauseBound
  | parentClause | itemClause | selfClause | builtinClause | dynamicClause | associatedTypes
  | associatedType | regionBinder | regionParameters | regionParameter | someName | noName
  | noneValue | someValue | sourceLocation | sourceFile | sourceSpanData | sourceSpan
  | localFile | virtualFile | notRealFile | typeParameter | predicateOrigin | predicateBinder
  | dynamicType | genericParameters | typeParameters | constantParameters | traitParameters
  | traitParameter | regionOutlives | typeOutlives | regionPredicates | typePredicates | associatedConstraints
  deriving DecidableEq, Repr

inductive Expr where
  | natural (value : Nat)
  | bytes (value : List Nat)
  | region (value : Region)
  | outputSlot (index : Nat)
  | node (tag : Tag) (children : List Expr)
  | binder (parameters : List Nat) (contents : Expr)
  deriving DecidableEq, Repr

structure Binding where
  outputSlot : Nat
  region : Region
  deriving DecidableEq, Repr

def lookup (bindings : List Binding) (slot : Nat) : Option Region :=
  (bindings.find? fun binding => binding.outputSlot == slot).map Binding.region

def publicRegion (parameters : List Nat) : Region → Bool
  | .literalStatic => true
  | .parameter index => decide (index ∈ parameters)
  | _ => false

def scopedRegion (parameters : List Nat) (scopes : List (List Nat)) : Region → Bool
  | .bound depth index => match scopes[depth]? with
      | some parameters => decide (index ∈ parameters)
      | none => false
  | region => publicRegion parameters region

def bind (parameters : List Nat) (bindings : List Binding) (slot : Nat)
    (actual : Region) : Option (List Binding) :=
  if !publicRegion parameters actual then none else
    match lookup bindings slot with
    | none => some (bindings ++ [⟨slot, actual⟩])
    | some previous => if previous = actual then some bindings else none

structure Work where
  scopes : List (List Nat)
  pattern : Expr
  actual : Expr

/-- Explicit fuel bounds a finite structural worklist. Running out refuses.
The producer cannot supply a successful inferred result or initial bindings. -/
def inferWork (parameters : List Nat) : Nat → List Work → List Binding → Option (List Binding)
  | _, [], bindings => some bindings
  | 0, _ :: _, _ => none
  | fuel + 1, work :: rest, bindings =>
      match work.pattern, work.actual with
      | .outputSlot slot, .region actual => do
          let after ← bind parameters bindings slot actual
          inferWork parameters fuel rest after
      | .natural expected, .natural actual =>
          if expected = actual then inferWork parameters fuel rest bindings else none
      | .bytes expected, .bytes actual =>
          if expected = actual then inferWork parameters fuel rest bindings else none
      | .region expected, .region actual =>
          if expected = actual ∧ scopedRegion parameters work.scopes actual then
            inferWork parameters fuel rest bindings
          else none
      | .node expectedTag expected, .node actualTag actual =>
          if expectedTag = actualTag ∧ expected.length = actual.length then
            inferWork parameters fuel
              ((expected.zip actual).map (fun (pattern, actual) => ⟨work.scopes, pattern, actual⟩) ++ rest) bindings
          else none
      | .binder expected contents, .binder actual body =>
          if expected = actual ∧ expected.Nodup then
            inferWork parameters fuel (⟨expected :: work.scopes, contents, body⟩ :: rest) bindings
          else none
      | _, _ => none

def infer (parameters : List Nat) (patterns actuals : List Expr) : Option (List Binding) :=
  if patterns.length ≠ actuals.length ∨ ¬ parameters.Nodup then none else
    inferWork parameters (sizeOf patterns + sizeOf actuals + 1)
      ((patterns.zip actuals).map fun (pattern, actual) => ⟨[], pattern, actual⟩) []

def fillSlot (bindings : List Binding) (index : Nat) : Region → Option Region
  | .erased => lookup bindings index
  | region => some region

def fillFrom (bindings : List Binding) : Nat → List Region → Option (List Region)
  | _, [] => some []
  | index, region :: rest => do
      let actual ← fillSlot bindings index region
      let rest ← fillFrom bindings (index + 1) rest
      pure (actual :: rest)

def erasedSlotsFrom : Nat → List Region → List Nat
  | _, [] => []
  | index, region :: rest =>
      (if region = .erased then [index] else []) ++ erasedSlotsFrom (index + 1) rest

def capturedInputs (inputs : List Expr) (movedParameters : List Nat) : Option (List Expr) :=
  if movedParameters.length ≠ inputs.length ∨ ¬ movedParameters.Nodup then none else
    movedParameters.mapM fun index => inputs[index]?

/-- Inference is driven by the exact original field/input pairing. Additional
assignments, unresolved slots and guessed values are not accepted arguments. -/
def reconstruct (parameters : List Nat) (originalRegions : List Region)
    (fieldPatterns declaredInputs : List Expr) (movedParameters : List Nat) : Option (List Region) := do
  if !(originalRegions.all fun region => region == .erased || publicRegion parameters region) then none else do
    let actuals ← capturedInputs declaredInputs movedParameters
    let bindings ← infer parameters fieldPatterns actuals
    let missing := erasedSlotsFrom 0 originalRegions
    if (bindings.map Binding.outputSlot).length ≠ missing.length ∨
        ¬ (bindings.map Binding.outputSlot).Nodup ∨
        ¬ (bindings.map Binding.outputSlot).all (fun slot => decide (slot ∈ missing)) then none
    else fillFrom bindings 0 originalRegions

/-- Only the original nominal return's top-level region vector is replaced.
Every type, const, dictionary argument and nominal identity is retained. -/
def completeOutput (original : Expr) (regions : List Region) : Option Expr :=
  match original with
  | .node .adt [.natural identity, .node .arguments [.node .regions old, types, constants, traits]] =>
      if old.length = regions.length then
        some (.node .adt [.natural identity,
          .node .arguments [.node .regions (regions.map Expr.region), types, constants, traits]])
      else none
  | _ => none

def outputRegions (output : Expr) : Option (List Region) :=
  match output with
  | .node .adt [.natural _, .node .arguments [.node .regions regions, _, _, _]] =>
      regions.mapM fun expression => match expression with
        | .region region => some region
        | _ => none
  | _ => none

def reconstructOutput (parameters : List Nat) (originalOutput : Expr)
    (fieldPatterns declaredInputs : List Expr) (movedParameters : List Nat) : Option Expr := do
  let originalRegions ← outputRegions originalOutput
  let regions ← reconstruct parameters originalRegions fieldPatterns declaredInputs movedParameters
  let output ← completeOutput originalOutput regions
  let assignments ← infer parameters [output] [output]
  if assignments.isEmpty then some output else none

theorem private_body_cannot_fill_output (parameters : List Nat) (bindings : List Binding)
    (slot index : Nat) : bind parameters bindings slot (.body index) = none := by
  simp [bind, publicRegion]

theorem bound_lifetime_cannot_fill_output (parameters : List Nat) (bindings : List Binding)
    (slot depth index : Nat) : bind parameters bindings slot (.bound depth index) = none := by
  simp [bind, publicRegion]

theorem erased_lifetime_cannot_fill_output (parameters : List Nat) (bindings : List Binding)
    (slot : Nat) : bind parameters bindings slot .erased = none := by
  simp [bind, publicRegion]

theorem undeclared_parameter_cannot_fill_output (parameters : List Nat) (bindings : List Binding)
    (slot index : Nat) (absent : index ∉ parameters) :
    bind parameters bindings slot (.parameter index) = none := by
  simp [bind, publicRegion, absent]

theorem conflicting_source_lifetimes_refused (parameters : List Nat) (bindings : List Binding)
    (slot : Nat) (first second : Region) (previous : lookup bindings slot = some first)
    (different : first ≠ second) : bind parameters bindings slot second = none := by
  simp [bind, previous, different]

theorem known_output_lifetime_preserved (bindings : List Binding) (index : Nat)
    (region : Region) (known : region ≠ .erased) : fillSlot bindings index region = some region := by
  cases region <;> simp_all [fillSlot]

theorem unconstrained_output_refused (bindings : List Binding) (index : Nat)
    (absent : lookup bindings index = none) : fillSlot bindings index .erased = none := by
  simp [fillSlot, absent]

theorem accepted_binding_is_public (parameters : List Nat) (before after : List Binding)
    (slot : Nat) (actual : Region) (accepted : bind parameters before slot actual = some after) :
    publicRegion parameters actual = true := by
  cases allowed : publicRegion parameters actual <;> simp_all [bind]

theorem new_binding_keeps_actual_source_lifetime (parameters : List Nat) (bindings : List Binding)
    (slot : Nat) (actual : Region) (allowed : publicRegion parameters actual = true)
    (fresh : lookup bindings slot = none) :
    bind parameters bindings slot actual = some (bindings ++ [⟨slot, actual⟩]) := by
  simp [bind, allowed, fresh]

end Auths.Support.SourceClosureRegions
