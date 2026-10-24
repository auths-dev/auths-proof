import Auths.Support.BorrowProjection

/-!
Value-preserving transport between matched pure-data field shapes. Atoms must
have exactly the same complete type: no operation, result, cast or erased atom
adapter is supplied. Metadata checks constrain names/regions separately from
the structural value isomorphism. Native permissions, lifetime validity,
allocation/layout and original Rust execution are not modeled by this module.
-/
namespace Auths.Support.BorrowTransport
open SourceClosureRegions BorrowProjection
universe u

def lookupRegion (identity : Nat) : List (Nat × Nat) → Option Nat
  | [] => none
  | (source, target) :: rest => if source = identity then some target else lookupRegion identity rest

def renameRegion (mapping : List (Nat × Nat)) : Region → Option Region
  | .parameter identity => (lookupRegion identity mapping).map Region.parameter
  | .literalStatic => some .literalStatic
  | .bound depth identity => some (.bound depth identity)
  | .body _ | .erased => none

def renameExpr (mapping : List (Nat × Nat)) : Nat → Expr → Option Expr
  | 0, _ => none
  | _ + 1, .natural value => some (.natural value)
  | _ + 1, .bytes value => some (.bytes value)
  | _ + 1, .region value => (renameRegion mapping value).map Expr.region
  | _, .outputSlot _ => none
  | fuel + 1, .node tag children => do
      let children ← children.mapM (renameExpr mapping fuel)
      pure (.node tag children)
  | fuel + 1, .binder names contents => do
      let contents ← renameExpr mapping fuel contents
      pure (.binder names contents)

def labelsMatch (mapping : List (Nat × Nat)) (fuel : Nat) : Label → Label → Bool
  | .nominal source, .nominal target => decide (renameExpr mapping fuel source = some target)
  | .variant source, .variant target => source == target
  | .field source sourceName, .field target targetName => source == target && decide (sourceName = targetName)
  | .boxed, .boxed => true
  | _, _ => false

inductive Change : Shape → Shape → Type where
  | atom (sort : Expr) : Change (.atom sort) (.atom sort)
  | empty : Change .empty .empty
  | unit : Change .unit .unit
  | product {sl sr tl tr} (first : Change sl tl) (second : Change sr tr) :
      Change (.product sl sr) (.product tl tr)
  | sum {sl sr tl tr} (first : Change sl tl) (second : Change sr tr) :
      Change (.sum sl sr) (.sum tl tr)
  | named {source target sl tl} (contents : Change sl tl) : Change (.named source sl) (.named target tl)
  | borrow {source target sl tl} (mutable : Bool) (contents : Change sl tl) :
      Change (.borrow mutable source sl) (.borrow mutable target tl)

def metadataMatch (mapping : List (Nat × Nat)) (fuel : Nat) :
    {source target : Shape} → Change source target → Bool
  | _, _, .atom sort => decide (renameExpr mapping fuel sort = some sort)
  | _, _, .empty | _, _, .unit => true
  | _, _, .product first second | _, _, .sum first second =>
      metadataMatch mapping fuel first && metadataMatch mapping fuel second
  | .named source _, .named target _, .named contents =>
      labelsMatch mapping fuel source target && metadataMatch mapping fuel contents
  | .borrow _ source _, .borrow _ target _, .borrow _ contents =>
      decide (renameRegion mapping source = some target) && metadataMatch mapping fuel contents

def validMap (mapping : List (Nat × Nat)) : Bool :=
  let sources := mapping.map Prod.fst
  let targets := mapping.map Prod.snd
  sources.eraseDups.length == sources.length && targets.eraseDups.length == targets.length

def inverse : {source target : Shape} → Change source target → Change target source
  | _, _, .atom sort => .atom sort
  | _, _, .empty => .empty
  | _, _, .unit => .unit
  | _, _, .product first second => .product (inverse first) (inverse second)
  | _, _, .sum first second => .sum (inverse first) (inverse second)
  | _, _, .named contents => .named (inverse contents)
  | _, _, .borrow mutable contents => .borrow mutable (inverse contents)

def forward {Atom : Expr → Type u} : {source target : Shape} →
    Change source target → Data Atom source → Data Atom target
  | _, _, .atom _, .atom value => .atom value
  | _, _, .unit, .unit => .unit
  | _, _, .product first second, .product left right => .product (forward first left) (forward second right)
  | _, _, .sum first _, .left value => .left (forward first value)
  | _, _, .sum _ second, .right value => .right (forward second value)
  | _, _, .named contents, .named value => .named (forward contents value)
  | _, _, .borrow _ contents, .borrow value => .borrow (forward contents value)

theorem forward_inverse {Atom : Expr → Type u} {source target : Shape}
    (change : Change source target) (value : Data Atom source) :
    forward (inverse change) (forward change value) = value := by
  induction change generalizing value with
  | atom => cases value; rfl
  | empty => cases value
  | unit => cases value; rfl
  | product first second firstIH secondIH =>
      cases value with
      | product left right => simp [forward, inverse, firstIH, secondIH]
  | sum first second firstIH secondIH =>
      cases value with
      | left value => simp [forward, inverse, firstIH]
      | right value => simp [forward, inverse, secondIH]
  | named contents ih => cases value with
      | named value => simp [forward, inverse, ih]
  | borrow mutable contents ih => cases value with
      | borrow value => simp [forward, inverse, ih]

theorem inverse_forward {Atom : Expr → Type u} {source target : Shape}
    (change : Change source target) (value : Data Atom target) :
    forward change (forward (inverse change) value) = value := by
  induction change generalizing value with
  | atom => cases value; rfl
  | empty => cases value
  | unit => cases value; rfl
  | product first second firstIH secondIH =>
      cases value with
      | product left right => simp [forward, inverse, firstIH, secondIH]
  | sum first second firstIH secondIH =>
      cases value with
      | left value => simp [forward, inverse, firstIH]
      | right value => simp [forward, inverse, secondIH]
  | named contents ih => cases value with
      | named value => simp [forward, inverse, ih]
  | borrow mutable contents ih => cases value with
      | borrow value => simp [forward, inverse, ih]

def mapPlan : {source target : Shape} → Change source target → Plan source → Plan target
  | _, _, _, .keep => .keep
  | _, _, _, .skip => .skip
  | _, _, .empty, .empty => .empty
  | _, _, .product first second, .product left right => .product (mapPlan first left) (mapPlan second right)
  | _, _, .sum first second, .sum left right => .sum (mapPlan first left) (mapPlan second right)
  | _, _, .named contents, .named plan => .named (mapPlan contents plan)
  | _, _, .borrow _ contents, .borrow plan => .borrow (mapPlan contents plan)

def forwardView {Atom : Expr → Type u} : {source target : Shape} →
    (change : Change source target) → (plan : Plan source) → View Atom plan → View Atom (mapPlan change plan)
  | _, _, change, .keep, value => forward change value
  | _, _, _, .skip, _ => PUnit.unit
  | _, _, .empty, .empty, value => nomatch value
  | _, _, .product first second, .product left right, (x, y) =>
      (forwardView first left x, forwardView second right y)
  | _, _, .sum first second, .sum left right, .inl value => .inl (forwardView first left value)
  | _, _, .sum first second, .sum left right, .inr value => .inr (forwardView second right value)
  | _, _, .named contents, .named plan, value => forwardView contents plan value
  | _, _, .borrow _ contents, .borrow plan, value => forwardView contents plan value

def backwardView {Atom : Expr → Type u} : {source target : Shape} →
    (change : Change source target) → (plan : Plan source) → View Atom (mapPlan change plan) → View Atom plan
  | _, _, change, .keep, value => forward (inverse change) value
  | _, _, _, .skip, _ => PUnit.unit
  | _, _, .empty, .empty, value => nomatch value
  | _, _, .product first second, .product left right, (x, y) =>
      (backwardView first left x, backwardView second right y)
  | _, _, .sum first second, .sum left right, .inl value => .inl (backwardView first left value)
  | _, _, .sum first second, .sum left right, .inr value => .inr (backwardView second right value)
  | _, _, .named contents, .named plan, value => backwardView contents plan value
  | _, _, .borrow _ contents, .borrow plan, value => backwardView contents plan value

theorem view_forward_inverse {Atom : Expr → Type u} {source target : Shape}
    (change : Change source target) (plan : Plan source) (value : View Atom plan) :
    backwardView change plan (forwardView change plan value) = value := by
  induction plan generalizing target value with
  | keep => exact forward_inverse change value
  | skip => cases value; rfl
  | empty => cases value
  | product left right leftIH rightIH => cases change with
      | product first second => rcases value with ⟨x, y⟩; exact Prod.ext (leftIH first x) (rightIH second y)
  | sum left right leftIH rightIH => cases change with
      | sum first second => cases value with
        | inl value => exact congrArg Sum.inl (leftIH first value)
        | inr value => exact congrArg Sum.inr (rightIH second value)
  | named plan ih => cases change with
      | named contents => exact ih contents value
  | borrow plan ih => cases change with
      | borrow mutable contents => exact ih contents value

theorem view_inverse_forward {Atom : Expr → Type u} {source target : Shape}
    (change : Change source target) (plan : Plan source) (value : View Atom (mapPlan change plan)) :
    forwardView change plan (backwardView change plan value) = value := by
  induction plan generalizing target value with
  | keep => exact inverse_forward change value
  | skip => cases value; rfl
  | empty => cases change; cases value
  | product left right leftIH rightIH => cases change with
      | product first second => rcases value with ⟨x, y⟩; exact Prod.ext (leftIH first x) (rightIH second y)
  | sum left right leftIH rightIH => cases change with
      | sum first second => cases value with
        | inl value => exact congrArg Sum.inl (leftIH first value)
        | inr value => exact congrArg Sum.inr (rightIH second value)
  | named plan ih => cases change with
      | named contents => exact ih contents value
  | borrow plan ih => cases change with
      | borrow mutable contents => exact ih contents value

theorem extraction_commutes {Atom : Expr → Type u} {source target : Shape}
    (change : Change source target) (plan : Plan source) (value : Data Atom source) :
    forwardView change plan (get plan value) = get (mapPlan change plan) (forward change value) := by
  induction plan generalizing target value with
  | keep => rfl
  | skip => rfl
  | empty => cases value
  | product left right leftIH rightIH => cases change with
      | product first second => cases value with
        | product x y => exact Prod.ext (leftIH first x) (rightIH second y)
  | sum left right leftIH rightIH => cases change with
      | sum first second => cases value with
        | left value => exact congrArg Sum.inl (leftIH first value)
        | right value => exact congrArg Sum.inr (rightIH second value)
  | named plan ih => cases change with
      | named contents => cases value with
        | named value => exact ih contents value
  | borrow plan ih => cases change with
      | borrow mutable contents => cases value with
        | borrow value => exact ih contents value

theorem restoration_commutes {Atom : Expr → Type u} {source target : Shape}
    (change : Change source target) (plan : Plan source) (before : Data Atom source)
    (update : View Atom plan) :
    put (mapPlan change plan) (forward change before) (forwardView change plan update) =
      (put plan before update).map (forward change) := by
  induction plan generalizing target before update with
  | keep => rfl
  | skip => rfl
  | empty => cases before
  | product left right leftIH rightIH => cases change with
      | product first second => cases before with
        | product x y =>
            rcases update with ⟨u, v⟩
            cases leftResult : put left x u <;> cases rightResult : put right y v <;>
              simp [put, mapPlan, forward, forwardView, leftIH, rightIH, leftResult, rightResult]
  | sum left right leftIH rightIH => cases change with
      | sum first second => cases before with
        | left value => cases update with
          | inl update =>
              cases result : put left value update <;>
                simp [put, mapPlan, forward, forwardView, leftIH, result]
          | inr update => rfl
        | right value => cases update with
          | inl update => rfl
          | inr update =>
              cases result : put right value update <;>
                simp [put, mapPlan, forward, forwardView, rightIH, result]
  | named plan ih => cases change with
      | named contents => cases before with
        | named value =>
            cases result : put plan value update <;>
              simp [put, mapPlan, forward, forwardView, ih, result]
  | borrow plan ih => cases change with
      | borrow mutable contents => cases before with
        | borrow value =>
            cases result : put plan value update <;>
              simp [put, mapPlan, forward, forwardView, ih, result]

end Auths.Support.BorrowTransport
