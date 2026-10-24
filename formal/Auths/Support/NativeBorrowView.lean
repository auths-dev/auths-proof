import Auths.Support.NativeBorrowWiring
import Auths.Support.BorrowProjection

/-!
Concrete candidate-regionful views for backward payload families. A direct
owned borrow carries its entire pointee; symbolic ports carry the selected
region view of their candidate carrier. Unknown normalized keys are empty.
These pure-data schemas do not establish native projection/region/layout or
original Rust heap/loan adequacy, including the conditional writer overlay.
-/
namespace Auths.Support.NativeBorrowView
open SourceClosureRegions BorrowProjection
universe u

inductive Selection where
  | whole
  | regions (values : List Region)
  deriving DecidableEq, Repr

structure Schema where
  payloadKey : Expr
  candidateType : Expr
  shape : Shape
  selection : Selection
  deriving DecidableEq, Repr

/-- A syntactic alpha instance preserves the entire type/dictionary tree and
the alias partition. It is not an outlives or reference-validity theorem. -/
structure TypeInstance where
  pattern : Expr
  candidate : Expr
  native : Expr
  candidateParameters : List Nat
  nativeParameters : List Nat
  candidateBindings : List Binding
  nativeBindings : List Binding
  deriving DecidableEq, Repr

def checkTypeInstance (witness : TypeInstance) : Bool :=
  let sourceSlots := witness.candidateBindings.map Binding.outputSlot
  let targetSlots := witness.nativeBindings.map Binding.outputSlot
  let sourceRegions := witness.candidateBindings.map Binding.region
  let targetRegions := witness.nativeBindings.map Binding.region
  decide (infer witness.candidateParameters [witness.pattern] [witness.candidate] = some witness.candidateBindings) &&
  decide (infer witness.nativeParameters [witness.pattern] [witness.native] = some witness.nativeBindings) &&
  decide (sourceSlots = targetSlots) && sourceSlots.eraseDups.length == sourceSlots.length &&
  decide sourceRegions.Nodup && decide targetRegions.Nodup

def Schema.plan (schema : Schema) : Plan schema.shape :=
  match schema.selection with
  | .whole => .keep
  | .regions regions => BorrowProjection.select regions schema.shape

def Schema.Payload (schema : Schema) (Atom : Expr → Type u) : Type u :=
  View Atom schema.plan

def Family : List Schema → (Expr → Type u) → Expr → Type u
  | [], _, _ => PEmpty
  | schema :: rest, Atom, key =>
      if schema.payloadKey = key then schema.Payload Atom else Family rest Atom key

def scopedType (parameters : List Nat) : Nat → List (List Nat) → Expr → Bool
  | 0, _, _ => false
  | _ + 1, _, .natural _ | _ + 1, _, .bytes _ => true
  | _ + 1, scopes, .region region => scopedRegion parameters scopes region
  | _, _, .outputSlot _ => false
  | fuel + 1, scopes, .node _ children => children.all (scopedType parameters fuel scopes)
  | fuel + 1, scopes, .binder names contents => scopedType parameters fuel (names :: scopes) contents

def scopedShape (parameters : List Nat) : Nat → Shape → Bool
  | 0, _ => false
  | fuel + 1, .atom sort => scopedType parameters fuel [] sort
  | _ + 1, .empty | _ + 1, .unit => true
  | fuel + 1, .product first second | fuel + 1, .sum first second =>
      scopedShape parameters fuel first && scopedShape parameters fuel second
  | fuel + 1, .named identity contents =>
      (match identity with
       | .nominal sort => scopedType parameters fuel [] sort
       | _ => true) && scopedShape parameters fuel contents
  | fuel + 1, .borrow _ region contents =>
      scopedRegion parameters [] region && scopedShape parameters fuel contents

def rootType : Nat → Shape → Option Expr
  | 0, _ => none
  | _ + 1, .atom sort => some sort
  | _ + 1, .named (.nominal sort) _ => some sort
  | fuel + 1, .named .boxed contents => do
      let inner ← rootType fuel contents
      pure (.node .boxType [.node .arguments [.node .regions [], .node .types [inner],
        .node .constants [], .node .traits []]])
  | fuel + 1, .borrow mutable region contents => do
      let inner ← rootType fuel contents
      pure (.node (if mutable then .mutRef else .sharedRef) [.region region, inner])
  | _, _ => none

def hasSelectedMutable (regions : List Region) : Shape → Bool
  | .atom _ | .empty | .unit => false
  | .product first second | .sum first second =>
      hasSelectedMutable regions first || hasSelectedMutable regions second
  | .named _ contents => hasSelectedMutable regions contents
  | .borrow false _ _ => false
  | .borrow true region contents => decide (region ∈ regions) || hasSelectedMutable regions contents

def check (parameters : List Nat) (fuel : Nat) (schema : Schema) : Bool :=
  scopedType parameters fuel [] schema.candidateType && scopedShape parameters fuel schema.shape &&
  decide (rootType fuel schema.shape = some schema.candidateType) &&
  decide (NativeBorrowProtocol.typeShape fuel schema.candidateType = some schema.payloadKey) &&
  match schema.selection with
  | .whole => true
  | .regions regions =>
      !regions.isEmpty && regions.all (fun region => match region with
        | .parameter identity => decide (identity ∈ parameters)
        | _ => false) && hasSelectedMutable regions schema.shape

def extract (schema : Schema) {Atom : Expr → Type u}
    (value : Data Atom schema.shape) : schema.Payload Atom :=
  get schema.plan value

def restore (schema : Schema) {Atom : Expr → Type u} (before : Data Atom schema.shape)
    (update : schema.Payload Atom) : Option (Data Atom schema.shape) :=
  put schema.plan before update

theorem extract_then_restore_keeps_carrier (schema : Schema) {Atom : Expr → Type u}
    (value : Data Atom schema.shape) : restore schema value (extract schema value) = some value :=
  get_then_put _ _

theorem restored_carrier_has_exact_update (schema : Schema) {Atom : Expr → Type u}
    (before after : Data Atom schema.shape) (update : schema.Payload Atom)
    (accepted : restore schema before update = some after) : extract schema after = update :=
  put_then_get _ _ _ _ accepted

theorem whole_pointee_is_restored (key candidateType : Expr) (shape : Shape)
    {Atom : Expr → Type u} (before update : Data Atom shape) :
    restore ⟨key, candidateType, shape, .whole⟩ before update = some update := rfl

theorem absent_key_has_no_payload (schemas : List Schema) (Atom : Expr → Type u) (key : Expr)
    (absent : key ∉ schemas.map Schema.payloadKey) : IsEmpty (Family schemas Atom key) := by
  induction schemas with
  | nil => exact inferInstance
  | cons schema schemas ih =>
      have different : schema.payloadKey ≠ key := by
        intro same
        apply absent
        simp [same]
      have tailAbsent : key ∉ schemas.map Schema.payloadKey := by
        intro present
        apply absent
        exact List.mem_cons_of_mem _ present
      simpa only [Family, if_neg different] using ih tailAbsent

end Auths.Support.NativeBorrowView
