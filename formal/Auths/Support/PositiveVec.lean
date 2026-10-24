import Aeneas
open Aeneas Aeneas.Std
namespace auths_composition.alloc.vec

-- Equivalent bounded vectors whose element occurrences are strictly positive.
inductive SizedList (α : Type u) : Nat → Type u where
  | nil : SizedList α 0
  | cons {n : Nat} (head : α) (tail : SizedList α n) : SizedList α (n + 1)

structure Vec (α : Type u) where
  size : Nat
  elements : SizedList α size
  bound : size ≤ Usize.max

def SizedList.toList {α : Type u} {n : Nat} : SizedList α n → List α
  | .nil => []
  | .cons head tail => head :: tail.toList

theorem SizedList.length {α : Type u} {n : Nat} (value : SizedList α n) : value.toList.length = n := by
  induction value with
  | nil => rfl
  | cons head tail ih => simp [toList, ih]

/-- List projection shared by later positive-carrier extraction units. -/
def Vec.val {α : Type u} (value : Vec α) : List α := value.elements.toList

theorem Vec.property {α : Type u} (value : Vec α) : value.val.length ≤ Usize.max := by
  simpa only [Vec.val, SizedList.length] using value.bound

def SizedList.ofList {α : Type u} : (values : List α) → SizedList α values.length
  | [] => .nil
  | head :: tail => .cons head (ofList tail)

theorem SizedList.toList_ofList {α : Type u} (values : List α) :
    (ofList values).toList = values := by
  induction values with
  | nil => rfl
  | cons head tail ih => simp [ofList, toList, ih]

def Vec.toBase {α : Type u} (value : Vec α) : Aeneas.Std.alloc.vec.Vec α :=
  ⟨value.elements.toList, by rw [SizedList.length]; exact value.bound⟩

def Vec.ofBase {α : Type u} (value : Aeneas.Std.alloc.vec.Vec α) : Vec α :=
  ⟨value.val.length, SizedList.ofList value.val, value.property⟩

theorem Vec.toBase_ofBase {α : Type u} (value : Aeneas.Std.alloc.vec.Vec α) :
    (ofBase value).toBase = value := by
  apply Subtype.ext
  simp [toBase, ofBase, SizedList.toList_ofList]

theorem SizedList.toList_injective {α : Type u} {n : Nat} (left right : SizedList α n)
    (same : left.toList = right.toList) : left = right := by
  induction left with
  | nil => cases right; rfl
  | cons head tail ih =>
    cases right with
    | cons other rest =>
      simp only [toList, List.cons.injEq] at same
      obtain ⟨rfl, sameTail⟩ := same
      have sameTail := ih rest sameTail
      cases sameTail
      rfl

theorem Vec.toBase_injective {α : Type u} (left right : Vec α)
    (same : left.toBase = right.toBase) : left = right := by
  cases left with
  | mk n elements bound =>
    cases right with
    | mk m other otherBound =>
      have values : elements.toList = other.toList := congrArg Subtype.val same
      have sizes : n = m := by
        have length := congrArg List.length values
        simpa only [SizedList.length] using length
      cases sizes
      have elementsEqual := SizedList.toList_injective elements other values
      cases elementsEqual
      rfl

theorem Vec.ofBase_toBase {α : Type u} (value : Vec α) :
    ofBase value.toBase = value := by
  apply toBase_injective
  exact toBase_ofBase value.toBase

-- Exact delegation to the pinned library; no Auths algorithm is replaced.
def Vec.deref {α : Type} (value : Vec α) : Slice α :=
  Aeneas.Std.alloc.vec.Vec.deref value.toBase

theorem Vec.deref_exact {α : Type} (value : Vec α) :
    (deref value).val = value.elements.toList := rfl

end auths_composition.alloc.vec
