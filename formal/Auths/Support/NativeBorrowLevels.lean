import Auths.Support.SourceClosureRegions

/-!
Finite instantiated source-field trees for the checked native mutable-borrow
level extension. All source types, nominal rows/fields and instantiated
requirement bytes remain present. Requirement bytes are retained metadata, not
a proof of Rust wellformedness. Region/group membership is checked separately.
Shared references freeze level traversal but retain children for the original
native region-occurrence predicate. No full signature or loan rule is supplied.
Scripts await final elaboration.
-/
namespace Auths.Support.NativeBorrowLevels
open SourceClosureRegions

inductive Tree where
  | atom (source : Expr)
  | shared (source : Expr) (region : Region) (child : Tree)
  | mutable (source : Expr) (region : Region) (group : Nat) (child : Tree)
  | boxed (source : Expr) (child : Tree)
  | tuple (source : Expr) (fields : List Tree)
  | nominal (source : Expr) (requirements : List Nat)
      (rows : List (Option Nat × List (Nat × Option (List Nat) × Tree)))
  deriving DecidableEq, Repr

def children : Tree → List Tree
  | .atom _ => []
  | .shared _ _ child | .mutable _ _ _ child | .boxed _ child => [child]
  | .tuple _ fields => fields
  | .nominal _ _ rows => rows.flatMap (fun row => row.2.map (fun field => field.2.2))

def insert (group : Nat) : List Nat → List Nat
  | [] => [group]
  | first :: rest => if group = first then first :: rest
      else if group < first then group :: first :: rest else first :: insert group rest

def regionsMatch : Nat → List (Region × Nat) → Tree → Bool
  | 0, _, _ => false
  | fuel + 1, mapping, tree =>
      (match tree with
        | .mutable _ region group _ => decide ((mapping.find? (fun pair => pair.1 == region)).map Prod.snd = some group)
        | _ => true) && (children tree).all (regionsMatch fuel mapping)

def mentions : Nat → Nat → Tree → Option Bool
  | 0, _, _ => none
  | fuel + 1, target, tree => do
      let nested ← (children tree).mapM (mentions fuel target)
      pure ((match tree with .mutable _ _ group _ => group == target | _ => false) || nested.any id)

def maximum : Nat → Nat → List Nat → Tree → Option Nat
  | 0, _, _, _ => none
  | fuel + 1, target, outer, tree =>
      match tree with
      | .atom _ | .shared _ _ _ => some outer.length
      | .mutable _ _ group child => do
          if group = target then some (insert group outer).length else do
            let ancestor ← mentions fuel target child
            if ancestor then maximum fuel target (insert group outer) child else some outer.length
      | .boxed _ child => maximum fuel target outer child
      | .tuple _ _ | .nominal _ _ _ => do
          let levels ← (children tree).mapM (maximum fuel target outer)
          pure (levels.foldl max outer.length)

def checked (fuel : Nat) (mapping : List (Region × Nat)) (target : Nat) (tree : Tree) : Option Nat :=
  if regionsMatch fuel mapping tree then maximum fuel target [] tree else none

example (source : Expr) : maximum 4 3 []
    (.mutable source (.parameter 1) 1 (.mutable source (.parameter 2) 2
      (.mutable source (.parameter 3) 3 (.atom source)))) = some 3 := by decide

example (source : Expr) : maximum 3 3 []
    (.shared source (.parameter 1) (.mutable source (.parameter 3) 3 (.atom source))) = some 0 := rfl

example (source : Expr) : mentions 3 3
    (.shared source (.parameter 1) (.mutable source (.parameter 3) 3 (.atom source))) = some true := rfl

example (source : Expr) : maximum 3 1 []
    (.mutable source (.parameter 1) 1 (.mutable source (.parameter 1) 1 (.atom source))) = some 1 := rfl

end Auths.Support.NativeBorrowLevels
