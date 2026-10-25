import Auths.Support.NativeBorrowLevels
import Auths.Support.NativeTypeSyntax

/-!
Finite backward type selection over complete original instantiated field trees.
Selected nominal values keep their entire actual forward type. Nothing here
supplies a runtime value, a continuation, a default or Rust loan permission.
The forward-type table is emitted from the actual native translator and checked
for unique source keys; its source/layout adequacy remains a separate boundary.
New scripts await final elaboration.
-/
namespace Auths.Support.NativeBackwardTypes
open SourceClosureRegions NativeBorrowLevels
abbrev NativeType := NativeTypeSyntax.Expr

abbrev ForwardTypes := List (Expr × NativeType)

def sourceType : Tree → Expr
  | .atom source | .shared source _ _ | .mutable source _ _ _
  | .boxed source _ | .tuple source _ | .nominal source _ _ => source

def forwardType (types : ForwardTypes) (source : Expr) : Option NativeType :=
  (types.find? fun pair => pair.1 == source).map Prod.snd

def forwardComplete : Nat → ForwardTypes → Tree → Bool
  | 0, _, _ => false
  | fuel + 1, types, tree =>
      (match forwardType types (sourceType tree) with
        | none => false | some type => NativeTypeSyntax.validType (fuel + 1) type) &&
      (children tree).all (forwardComplete fuel types)

def stop (types : ForwardTypes) (level : Nat) (outer : List Nat) (source : Expr) : Option (Option NativeType) :=
  if outer.length > level then (forwardType types source).map some else some none

def simplifiedTuple : List NativeType → Option NativeType
  | [] => none
  | [type] => some type
  | types => some (NativeTypeSyntax.tuple types)

def select : Nat → ForwardTypes → Nat → Nat → List Nat → Tree → Option (Option NativeType)
  | 0, _, _, _, _, _ => none
  | fuel + 1, types, target, level, outer, tree =>
      match tree with
      | .atom source | .shared source _ _ => stop types level outer source
      | .mutable _ _ group child => do
          let nested ← mentions fuel target child
          if nested then select fuel types target level (insert group outer) child
          else if group = target then stop types level (insert group outer) (sourceType child)
          else some none
      | .boxed _ child => select fuel types target level outer child
      | .tuple _ fields => do
          let fields ← fields.mapM (select fuel types target level outer)
          pure (simplifiedTuple (fields.filterMap id))
      | .nominal source _ _ => do
          let count ← maximum fuel target outer tree
          if count > level then (forwardType types source).map some else some none

def checked (fuel : Nat) (mapping : List (Region × Nat)) (types : ForwardTypes)
    (target level : Nat) (tree : Tree) : Option (Option NativeType) :=
  let keys := types.map Prod.fst
  if keys.eraseDups.length == keys.length && regionsMatch fuel mapping tree &&
      forwardComplete fuel types tree then select fuel types target level [] tree else none

structure Root where
  input : Option Nat
  tree : Tree
  deriving DecidableEq, Repr

/-- Keep the original distinction between a root's origin and its role in
the backward signature. Higher input/output rows come from different roots. -/
def rootIncluded (toInput fromInput : Bool) (level : Nat) : Bool :=
  if fromInput then toInput || level == 0 else !toInput || level == 0

def rootRole (toInput fromInput : Bool) (level : Nat) : Bool :=
  if toInput then !(fromInput && level == 0) else !(!fromInput && level == 0)

def signatureRows (fuel : Nat) (mapping : List (Region × Nat)) (types : ForwardTypes)
    (roots : List Root) (target levels : Nat) (toInput : Bool) : Option (List (Nat × List NativeType)) := do
  let rows ← (List.range levels).reverse.mapM fun level => do
    let selected ← roots.mapM fun root => do
      if rootIncluded toInput root.input.isSome level && rootRole toInput root.input.isSome level then
        checked fuel mapping types target level root.tree
      else some none
    pure (level, selected.filterMap id)
  pure (rows.filter fun row => !row.2.isEmpty)

theorem exhausted_type_selection_is_refused (types : ForwardTypes) (target level : Nat)
    (outer : List Nat) (tree : Tree) : select 0 types target level outer tree = none := rfl

theorem incomplete_forward_table_is_refused (fuel : Nat) (mapping : List (Region × Nat))
    (types : ForwardTypes) (target level : Nat) (tree : Tree)
    (missing : forwardComplete fuel types tree = false) :
    checked fuel mapping types target level tree = none := by
  simp [checked, missing]

theorem level_zero_input_comes_from_output : rootRole true true 0 = false := rfl
theorem level_zero_output_comes_from_input : rootRole false false 0 = false := rfl
theorem higher_output_root_is_not_an_extra_input (level : Nat) :
    rootIncluded true false (level + 1) = false := by simp [rootIncluded]

end Auths.Support.NativeBackwardTypes
