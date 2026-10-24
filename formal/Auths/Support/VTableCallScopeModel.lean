import Auths.Support.VTableDispatchModel

/-!
Region-name transport for actual source return captures. A declared callee
parameter uses its actual caller argument; a private callee-body label retains
a distinct activation binder. Equal numeric labels do not identify scopes.
Capture transport preserves the paired implementation and concrete value.

This is an authored component model, not an elaborated/qualified source bridge.
The producer still must bind these labels to the actual call/return/capture
ASTs and prove fresh native activations, returned loan liveness, exclusive
ownership, narrowing, allocator/drop/unwind and native source simulation.
-/
namespace Auths.Support.VTableCallScope

universe u v w x y z

inductive SourceRegion (parameters bodies : Nat) where
  | literalStatic
  | param (index : Fin parameters)
  | body (index : Fin bodies)
  deriving DecidableEq, Repr

inductive Argument (Caller : Type u) where
  | literalStatic
  | caller (region : Caller)

inductive ExportedRegion (Caller : Type u) (Activation : Type v) where
  | literalStatic
  | caller (region : Caller)
  | privateBody (activation : Activation) (sourceBodyIndex : Nat)

def transportRegion {parameters bodies : Nat} {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation) :
    SourceRegion parameters bodies → ExportedRegion Caller Activation
  | .literalStatic => .literalStatic
  | .param index => match actual index with
      | .literalStatic => .literalStatic
      | .caller region => .caller region
  | .body index => .privateBody activation index.val

theorem private_region_ne_static {parameters bodies : Nat} {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation) (index : Fin bodies) :
    transportRegion actual activation (.body index) ≠ .literalStatic := by
  simp [transportRegion]

theorem private_region_ne_caller {parameters bodies : Nat} {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation) (index : Fin bodies) (region : Caller) :
    transportRegion actual activation (.body index) ≠ .caller region := by
  simp [transportRegion]

theorem private_region_ne_parameter {parameters bodies : Nat} {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation)
    (body : Fin bodies) (parameter : Fin parameters) :
    transportRegion actual activation (.body body) ≠ transportRegion actual activation (.param parameter) := by
  cases argument : actual parameter <;> simp [transportRegion, argument]

theorem body_aliases_are_exact {parameters bodies : Nat} {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation) (left right : Fin bodies) :
    transportRegion actual activation (.body left) = transportRegion actual activation (.body right) ↔ left = right := by
  simp only [transportRegion, ExportedRegion.privateBody.injEq, true_and]
  exact ⟨fun same => Fin.ext same, fun same => congrArg Fin.val same⟩

theorem declared_argument_is_exact {parameters bodies : Nat} {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation) (index : Fin parameters)
    (region : Caller) (argument : actual index = .caller region) :
    transportRegion (bodies := bodies) actual activation (.param index) = .caller region := by
  simp [transportRegion, argument]

theorem explicit_static_argument_is_exact {parameters bodies : Nat} {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation) (index : Fin parameters)
    (argument : actual index = .literalStatic) :
    transportRegion (bodies := bodies) actual activation (.param index) = .literalStatic := by
  simp [transportRegion, argument]

/-- A native consumer must produce this witness from its actual activation
allocator/state. A source statement ID alone cannot supply freshness. -/
structure FreshActivation (Activation : Type v) (activeBefore : Activation → Prop) where
  token : Activation
  fresh : ¬ activeBefore token

theorem fresh_activation_ne_active {Activation : Type v} {activeBefore : Activation → Prop}
    (current : FreshActivation Activation activeBefore) (previous : Activation) (active : activeBefore previous) :
    current.token ≠ previous := by
  intro same
  apply current.fresh
  simpa [same] using active

theorem different_activations_keep_private_regions_distinct {Caller : Type u} {Activation : Type v}
    (first second : Activation) (different : first ≠ second) (left right : Nat) :
    (ExportedRegion.privateBody first left : ExportedRegion Caller Activation) ≠ .privateBody second right := by
  intro same
  exact different (ExportedRegion.privateBody.inj same).1

structure Captured (Index : Type w) (Self : Index → Type x) (Region : Type y) where
  implementation : Index
  value : Self implementation
  environment : List Region

def transport {Index : Type w} {Self : Index → Type x} {parameters bodies : Nat}
    {Caller : Type u} {Activation : Type v}
    (actual : Fin parameters → Argument Caller) (activation : Activation)
    (captured : Captured Index Self (SourceRegion parameters bodies)) :
    Captured Index Self (ExportedRegion Caller Activation) :=
  ⟨captured.implementation, captured.value, captured.environment.map (transportRegion actual activation)⟩

theorem transport_keeps_implementation {Index : Type w} {Self : Index → Type x} {parameters bodies : Nat}
    {Caller : Type u} {Activation : Type v} (actual : Fin parameters → Argument Caller) (activation : Activation)
    (captured : Captured Index Self (SourceRegion parameters bodies)) :
    (transport actual activation captured).implementation = captured.implementation := rfl

theorem transport_keeps_concrete_value {Index : Type w} {Self : Index → Type x} {parameters bodies : Nat}
    {Caller : Type u} {Activation : Type v} (actual : Fin parameters → Argument Caller) (activation : Activation)
    (captured : Captured Index Self (SourceRegion parameters bodies)) :
    (transport actual activation captured).value = captured.value := rfl

def dispatch {Index : Type w} {Self : Index → Type x} {Region : Type y} {Input Output : Type z}
    (sourceBodies : (index : Index) → Self index → Input → Output)
    (captured : Captured Index Self Region) (input : Input) : Output :=
  sourceBodies captured.implementation captured.value input

theorem transported_dispatch_is_original {Index : Type w} {Self : Index → Type x} {parameters bodies : Nat}
    {Caller : Type u} {Activation : Type v} {Input Output : Type z}
    (sourceBodies : (index : Index) → Self index → Input → Output)
    (actual : Fin parameters → Argument Caller) (activation : Activation)
    (captured : Captured Index Self (SourceRegion parameters bodies)) (input : Input) :
    dispatch sourceBodies (transport actual activation captured) input = dispatch sourceBodies captured input := rfl

example : (ExportedRegion.privateBody 5 3 : ExportedRegion Nat Nat) ≠ .caller 3 := by
  intro same
  cases same

end Auths.Support.VTableCallScope
